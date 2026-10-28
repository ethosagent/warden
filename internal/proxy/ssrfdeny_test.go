package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dnstest"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// ssrfTestDialer returns a real SafeDialer whose DNS resolver is the in-process
// dnstest stub, so a NAME in records resolves to a blocked address and the
// dialer's SSRF refusal is exercised end to end (resolve → classify → refuse).
// Optional allowPrivate CIDRs are honored (pass "127.0.0.0/8" to build a dialer
// whose failures are ordinary connection-refused, not address blocks).
func ssrfTestDialer(t *testing.T, records map[string]string, allowPrivate ...string) *SafeDialer {
	t.Helper()
	stub := dnstest.New(t, records)
	d, err := NewSafeDialerWithResolver(2*time.Second, allowPrivate, NewUpstreamResolver(stub.Addr(), nil))
	if err != nil {
		t.Fatalf("NewSafeDialerWithResolver: %v", err)
	}
	return d
}

// closedLoopbackPort returns a loopback port with nothing listening on it, so a
// dial to it fails with an ordinary connection-refused.
func closedLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// waitForEvents polls the store until at least n events exist, then returns the
// snapshot. Decision events are written by handler goroutines, possibly just
// after the client sees its response.
func waitForEvents(t *testing.T, s *syncStore, n int) []analytics.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := s.snapshot()
		if len(evs) >= n {
			return evs
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("expected %d event(s), got %d: %+v", n, len(evs), evs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeMetrics is an in-memory MetricsRecorder. Every record call is kept — as
// a per-label count and as an ordered log line for failure messages — so a
// test can assert exactly which metrics a refusal path emitted, and how many
// times.
type fakeMetrics struct {
	mu       sync.Mutex
	blocked  map[string]int
	requests map[[2]string]int
	identity map[[2]string]int
	scoped   map[string]int
	signin   map[string]int
	log      []string
	// blocklistEntries is the last RecordBlocklistEntries value (-1: never set);
	// blocklistClosed sums RecordBlocklistSessionsClosed.
	blocklistEntries int
	blocklistClosed  int
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{blocked: map[string]int{}, requests: map[[2]string]int{}, identity: map[[2]string]int{}, scoped: map[string]int{}, signin: map[string]int{}, blocklistEntries: -1}
}

func (m *fakeMetrics) record(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log = append(m.log, fmt.Sprintf(format, args...))
}

func (m *fakeMetrics) RecordRequest(decision, protocol string) {
	m.mu.Lock()
	m.requests[[2]string{decision, protocol}]++
	m.mu.Unlock()
	m.record("RecordRequest(%q, %q)", decision, protocol)
}

func (m *fakeMetrics) RecordBlocked(reason string) {
	m.mu.Lock()
	m.blocked[reason]++
	m.mu.Unlock()
	m.record("RecordBlocked(%q)", reason)
}

func (m *fakeMetrics) RecordSecretSwap(placeholderRef string) {
	m.record("RecordSecretSwap(%q)", placeholderRef)
}
func (m *fakeMetrics) RecordScanFinding(kind string) { m.record("RecordScanFinding(%q)", kind) }
func (m *fakeMetrics) RecordJudge(outcome string)    { m.record("RecordJudge(%q)", outcome) }
func (m *fakeMetrics) ObserveAddedLatency(stage string, d time.Duration) {
	m.record("ObserveAddedLatency(%q)", stage)
}
func (m *fakeMetrics) RecordIdentityVerify(result, reason string) {
	m.mu.Lock()
	m.identity[[2]string{result, reason}]++
	m.mu.Unlock()
	m.record("RecordIdentityVerify(%q, %q)", result, reason)
}

func (m *fakeMetrics) RecordBlocklistEntries(n int) {
	m.mu.Lock()
	m.blocklistEntries = n
	m.mu.Unlock()
	m.record("RecordBlocklistEntries(%d)", n)
}

func (m *fakeMetrics) RecordBlocklistSessionsClosed(n int) {
	m.mu.Lock()
	m.blocklistClosed += n
	m.mu.Unlock()
	m.record("RecordBlocklistSessionsClosed(%d)", n)
}

func (m *fakeMetrics) RecordSignInStarted(outcome string) {
	m.mu.Lock()
	m.signin[outcome]++
	m.mu.Unlock()
	m.record("RecordSignInStarted(%q)", outcome)
}

// signInCount returns how often RecordSignInStarted saw the outcome.
func (m *fakeMetrics) signInCount(outcome string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.signin[outcome]
}

func (m *fakeMetrics) RecordScoped(result string) {
	m.mu.Lock()
	m.scoped[result]++
	m.mu.Unlock()
	m.record("RecordScoped(%q)", result)
}

// scopedCount returns how often RecordScoped saw the result.
func (m *fakeMetrics) scopedCount(result string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scoped[result]
}

// identityCount returns how often RecordIdentityVerify saw the result/reason pair.
func (m *fakeMetrics) identityCount(result, reason string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.identity[[2]string{result, reason}]
}

// blockedCount returns how often RecordBlocked saw the reason.
func (m *fakeMetrics) blockedCount(reason string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blocked[reason]
}

// requestCount returns how often RecordRequest saw the decision/protocol pair.
func (m *fakeMetrics) requestCount(decision, protocol string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests[[2]string{decision, protocol}]
}

// describe dumps the ordered record log for a failure message.
func (m *fakeMetrics) describe() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.Join(m.log, "; ")
}

// waitForBlocked polls until RecordBlocked has seen reason at least once (the
// refusal is recorded by the handler goroutine, possibly just after the client
// sees its response).
func waitForBlocked(t *testing.T, m *fakeMetrics, reason string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for m.blockedCount(reason) == 0 {
		if !time.Now().Before(deadline) {
			t.Fatalf("RecordBlocked(%q) never recorded; metric calls: %s", reason, m.describe())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// wantSSRFDeny asserts one event is the single deny decision for a refused dial:
// decision, bounded reason, address class, destination and protocol.
func wantSSRFDeny(t *testing.T, e analytics.Event, domain, protocol, reason, class string) {
	t.Helper()
	if e.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", e.Decision)
	}
	if e.Reason != reason {
		t.Fatalf("reason = %q, want %q", e.Reason, reason)
	}
	if e.AddrClass != class {
		t.Fatalf("addr class = %q, want %q", e.AddrClass, class)
	}
	if e.Domain != domain {
		t.Fatalf("domain = %q, want %q", e.Domain, domain)
	}
	if e.Protocol != protocol {
		t.Fatalf("protocol = %q, want %q", e.Protocol, protocol)
	}
}

// connectTunnel performs the CONNECT through the raw proxy and returns the
// connected conn (post-200), for clients that then speak their own protocol.
func connectTunnel(t *testing.T, proxyAddr, domain string, port int) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, _ = fmt.Fprintf(conn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", domain, port, domain, port)
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected CONNECT 200, got %q", resp)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, br
}

// dialTLSTunnel CONNECTs and then completes the client TLS handshake against
// the MITM leaf (no ALPN: the h1 termination path), for a destination whose
// allowlist port is not 443.
func dialTLSTunnel(t *testing.T, proxyAddr, domain string, port int, caCertPEM []byte) *tls.Conn {
	t.Helper()
	conn, br := connectTunnel(t, proxyAddr, domain, port)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)
	tlsClient := tls.Client(&bufferedTLSConn{Reader: br, Conn: conn}, &tls.Config{
		ServerName: domain,
		RootCAs:    caPool,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	t.Cleanup(func() { _ = tlsClient.Close() })
	return tlsClient
}

// startProxy starts a proxy allowing loop.test:<port> with the caller's
// analytics store; CA paths enable TLS termination, their absence leaves the
// raw-tunnel path. Optional opts tweak the Config before New (e.g. a metrics
// recorder, or a different allowlist entry).
func startProxy(t *testing.T, store *syncStore, caCertPEM, caKeyPEM []byte, port int, opts ...func(*Config)) *Proxy {
	t.Helper()
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: "loop.test", Port: port},
		}}),
		Secrets:   &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics: store,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(caCertPEM) > 0 {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "ca.crt")
		keyFile := filepath.Join(dir, "ca.key")
		if err := os.WriteFile(certFile, caCertPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, caKeyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.CACertPath = certFile
		cfg.CAKeyPath = keyFile
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 200 && p.Addr() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy did not start")
	}
	return p
}

// --- SafeDialer: the refusal is a typed error -----------------------------

// A dial the SSRF-safe dialer refuses must fail with a *SSRFError carrying the
// bounded reason and the resolved address class, so callers can audit it as a
// policy decision instead of an ordinary dial failure.
func TestSafeDialer_RefusalIsTypedSSRFError(t *testing.T) {
	d := ssrfTestDialer(t, map[string]string{
		"loop.test":     "127.0.0.1",
		"priv.test":     "10.1.2.3",
		"link.test":     "169.254.5.5",
		"meta.test":     "169.254.169.254",
		"reserved.test": "198.51.100.7",
	})
	cases := []struct {
		host      string
		wantClass string
	}{
		{"loop.test", "loopback"},
		{"priv.test", "private"},
		{"link.test", "link_local"},
		{"meta.test", "metadata"},
		{"reserved.test", "reserved"},
		// Hard-denied hostname: refused before any resolution.
		{"metadata.google.internal", "metadata"},
		// IP literals are classified too (no DNS involved).
		{"127.0.0.1", "loopback"},
		{"169.254.169.254", "metadata"},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			_, err := d.Dial("tcp", net.JoinHostPort(tc.host, "443"))
			var se *SSRFError
			if !errors.As(err, &se) {
				t.Fatalf("errors.As(*SSRFError) = false, got %T: %v", err, err)
			}
			if tc.host == "metadata.google.internal" {
				if se.Reason != SSRFReasonDeniedHostname {
					t.Fatalf("reason = %q, want %q", se.Reason, SSRFReasonDeniedHostname)
				}
			} else if se.Reason != SSRFReasonBlocked {
				t.Fatalf("reason = %q, want %q", se.Reason, SSRFReasonBlocked)
			}
			if se.AddrClass != tc.wantClass {
				t.Fatalf("addr class = %q, want %q", se.AddrClass, tc.wantClass)
			}
			// For a hostname destination the refusal message must not leak the
			// resolved address (the list stays out of errors, events and logs).
			// An IP-literal destination IS the address the agent supplied — the
			// same value the event's Domain field carries — so it may name it.
			if net.ParseIP(tc.host) == nil &&
				(strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "169.254.169.254")) {
				t.Fatalf("error text leaks a resolved address: %v", err)
			}
		})
	}
}

// Ordinary dial failures are NOT SSRF refusals: a connection refused or a DNS
// lookup failure must never come back as a *SSRFError (they must not be
// mis-audited as ssrf_* denies).
func TestSafeDialer_OrdinaryFailureIsNotSSRFError(t *testing.T) {
	// allowPrivate admits loopback, so the failure below is an ordinary
	// connection-refused on a closed port — never an address block.
	d := ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}, "127.0.0.0/8")
	_, err := d.Dial("tcp", net.JoinHostPort("loop.test", fmt.Sprintf("%d", closedLoopbackPort(t))))
	if err == nil {
		t.Fatal("dial to a closed port should fail")
	}
	var se *SSRFError
	if errors.As(err, &se) {
		t.Fatalf("connection refused must not be a *SSRFError: %v", err)
	}

	// A name the resolver cannot answer is a DNS failure, not an SSRF block.
	dns := ssrfTestDialer(t, nil)
	if _, err := dns.Dial("tcp", "missing.stub.test:443"); err == nil {
		t.Fatal("NXDOMAIN lookup should fail")
	} else if errors.As(err, &se) {
		t.Fatalf("resolve failure must not be a *SSRFError: %v", err)
	}
}

// --- raw tunnel (no TLS termination): CONNECT admitted, dial refused -------

// TestDialRefusal_RawTunnelDenyEvent drives the raw-tunnel CONNECT path (no CA)
// with a name that resolves to loopback: the CONNECT is admitted, the tunnel
// then closes, and the request is audited as EXACTLY ONE deny event with the
// SSRF reason and address class — never the pre-dial allow followed by a deny.
func TestDialRefusal_RawTunnelDenyEvent(t *testing.T) {
	store := &syncStore{}
	p := startProxy(t, store, nil, nil, 443)
	p.dialFunc = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).Dial

	conn, br := connectTunnel(t, p.Addr().String(), "loop.test", 443)
	// The refused dial closes the tunnel: the agent sees EOF and no bytes.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := io.ReadAll(br); err == nil && len(n) > 0 {
		t.Fatalf("tunnel should close without data, got %q", n)
	}

	evs := waitForEvents(t, store, 1)
	if len(evs) != 1 {
		t.Fatalf("expected EXACTLY ONE decision event, got %d: %+v", len(evs), evs)
	}
	wantSSRFDeny(t, evs[0], "loop.test", "tcp", SSRFReasonBlocked, "loopback")
}

// --- MITM h1: 502 in-tunnel, one deny event --------------------------------

// TestDialRefusal_H1DenyEvent drives the TLS-intercepted HTTP/1.1 path: before
// #391 a refused dial wrote NO event at all (the 502 was silent). The request
// must get the same 502 and produce exactly one deny event.
func TestDialRefusal_H1DenyEvent(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	store := &syncStore{}
	p := startProxy(t, store, caCertPEM, caKeyPEM, 443)
	p.dialTLS = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).DialTLS

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "loop.test", caCertPEM)
	req, _ := http.NewRequest("GET", "https://loop.test/v1/chat", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 502 {
		t.Fatalf("agent should still see 502, got %d", resp.StatusCode)
	}

	evs := waitForEvents(t, store, 1)
	if len(evs) != 1 {
		t.Fatalf("expected EXACTLY ONE decision event, got %d: %+v", len(evs), evs)
	}
	wantSSRFDeny(t, evs[0], "loop.test", "https", SSRFReasonBlocked, "loopback")
}

// --- MITM h2 and gRPC: same pipeline, one deny event each ------------------

func TestDialRefusal_H2DenyEvent(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	store := &syncStore{}
	p := startProxy(t, store, caCertPEM, caKeyPEM, 443)
	p.dialTLS = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).DialTLS

	cc := dialGRPCClient(t, p.Addr().String(), "loop.test", caCertPEM)
	req, err := http.NewRequest("POST", "https://loop.test/v1/chat", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 502 {
		t.Fatalf("agent should still see 502, got %d", resp.StatusCode)
	}

	evs := waitForEvents(t, store, 1)
	if len(evs) != 1 {
		t.Fatalf("expected EXACTLY ONE decision event, got %d: %+v", len(evs), evs)
	}
	wantSSRFDeny(t, evs[0], "loop.test", "http2", SSRFReasonBlocked, "loopback")
}

func TestDialRefusal_GRPCDenyEvent(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	store := &syncStore{}
	p := startProxy(t, store, caCertPEM, caKeyPEM, 443)
	p.dialTLS = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).DialTLS

	cc := dialGRPCClient(t, p.Addr().String(), "loop.test", caCertPEM)
	req, err := http.NewRequest("POST", "https://loop.test/pkg.Svc/Call", strings.NewReader("\x00\x00\x00\x00"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 502 {
		t.Fatalf("agent should still see 502, got %d", resp.StatusCode)
	}

	evs := waitForEvents(t, store, 1)
	if len(evs) != 1 {
		t.Fatalf("expected EXACTLY ONE decision event, got %d: %+v", len(evs), evs)
	}
	wantSSRFDeny(t, evs[0], "loop.test", "grpc", SSRFReasonBlocked, "loopback")
}

// --- MITM raw-TLS passthrough and unknown-protocol-inside-TLS --------------

// A CONNECT whose payload is not a TLS ClientHello is raw-forwarded through the
// SSRF-safe dialer; a refused dial must be audited (it was silent before).
func TestDialRefusal_RawTLSPassthroughDenyEvent(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	store := &syncStore{}
	p := startProxy(t, store, caCertPEM, caKeyPEM, 443)
	p.dialFunc = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).Dial

	conn, br := connectTunnel(t, p.Addr().String(), "loop.test", 443)
	// Not a TLS record (no 0x16 first byte): the passthrough branch dials raw.
	if _, err := conn.Write([]byte("PLAINTEXT\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := io.ReadAll(br); err == nil && len(n) > 0 {
		t.Fatalf("tunnel should close without data, got %q", n)
	}

	evs := waitForEvents(t, store, 1)
	if len(evs) != 1 {
		t.Fatalf("expected EXACTLY ONE decision event, got %d: %+v", len(evs), evs)
	}
	wantSSRFDeny(t, evs[0], "loop.test", "tcp", SSRFReasonBlocked, "loopback")
}

// TLS-terminated traffic that is neither HTTP/1.1 nor HTTP/2 is forwarded over
// a raw TLS dial; a refused dial must be audited under the same "raw" protocol
// label the allow would have used.
func TestDialRefusal_UnknownProtoDenyEvent(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	store := &syncStore{}
	p := startProxy(t, store, caCertPEM, caKeyPEM, 443)
	p.dialTLS = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).DialTLS

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "loop.test", caCertPEM)
	if _, err := tlsClient.Write([]byte("SOMEPROTO v1\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = tlsClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	// The tunnel closes after the refused dial: the agent gets no data (a TLS
	// close reads back as a clean EOF, so the bytes, not the error, matter).
	if n, _ := io.ReadAll(tlsClient); len(n) > 0 {
		t.Fatalf("tunnel should close without data, got %q", n)
	}

	evs := waitForEvents(t, store, 1)
	if len(evs) != 1 {
		t.Fatalf("expected EXACTLY ONE decision event, got %d: %+v", len(evs), evs)
	}
	wantSSRFDeny(t, evs[0], "loop.test", "raw", SSRFReasonBlocked, "loopback")
}

// --- ordinary dial failures are not ssrf_* ---------------------------------

// TestDialRefusal_OrdinaryDialFailureNoSSRFEvent pins the contrast: an ordinary
// dial failure (connection refused to an allowed, non-blocked address) must
// never produce an ssrf_* deny. On the in-tunnel HTTP path the 502 stays silent
// (an upstream failure is not a policy decision), and on the raw-tunnel path
// the CONNECT keeps its allow audit — exactly as before #391.
func TestDialRefusal_OrdinaryDialFailureNoSSRFEvent(t *testing.T) {
	t.Run("h1_in_tunnel", func(t *testing.T) {
		caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
		store := &syncStore{}
		// loop.test resolves to 127.0.0.1, which allowPrivate admits, on a port
		// with no listener: the DIAL fails ordinarily (connection refused), not
		// on the blocklist.
		port := closedLoopbackPort(t)
		p := startProxy(t, store, caCertPEM, caKeyPEM, port)
		p.dialTLS = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}, "127.0.0.0/8").DialTLS

		tlsClient := dialTLSTunnel(t, p.Addr().String(), "loop.test", port, caCertPEM)
		req, _ := http.NewRequest("GET", fmt.Sprintf("https://loop.test:%d/v1/chat", port), nil)
		if err := req.Write(tlsClient); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 502 {
			t.Fatalf("expected 502, got %d", resp.StatusCode)
		}
		// Any deny would be written before the 502 is: none may be an ssrf_*.
		for _, e := range store.snapshot() {
			if strings.HasPrefix(e.Reason, "ssrf") {
				t.Fatalf("ordinary dial failure audited as ssrf_*: %+v", e)
			}
		}
	})

	t.Run("raw_tunnel_keeps_allow", func(t *testing.T) {
		store := &syncStore{}
		port := closedLoopbackPort(t)
		p := startProxy(t, store, nil, nil, port)
		p.dialFunc = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}, "127.0.0.0/8").Dial

		conn, br := connectTunnel(t, p.Addr().String(), "loop.test", port)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadAll(br)

		evs := waitForEvents(t, store, 1)
		if len(evs) != 1 {
			t.Fatalf("expected exactly one event (the pre-existing allow audit), got %d: %+v", len(evs), evs)
		}
		if evs[0].Decision != "allow" {
			t.Fatalf("ordinary dial failure must keep the CONNECT allow audit, got %+v", evs[0])
		}
		if strings.HasPrefix(evs[0].Reason, "ssrf") {
			t.Fatalf("ordinary dial failure audited as ssrf_*: %+v", evs[0])
		}
	})
}

// --- the blocked metric: every refusal path counts warden.blocked.total ----

// TestDialRefusal_MetricsOnEveryPath drives each refusal path with a fake
// metrics recorder: a refusal counts one deny request AND increments
// warden.blocked.total with the bounded ssrf_* reason — ssrf_blocked for a
// blocked address, ssrf_denied_hostname for a refused hostname. Each metric is
// recorded exactly once per refused request, and the raw tunnel emits no allow
// counter (the refused CONNECT is not audited as an allow first).
func TestDialRefusal_MetricsOnEveryPath(t *testing.T) {
	// refusedH1 sends one request through the TLS-intercepted tunnel and
	// expects the 502 the refused dial produces.
	refusedH1 := func(t *testing.T, p *Proxy, caCertPEM []byte) {
		t.Helper()
		tlsClient := dialProxyAndConnect(t, p.Addr().String(), "loop.test", caCertPEM)
		req, _ := http.NewRequest("GET", "https://loop.test/v1/chat", nil)
		if err := req.Write(tlsClient); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 502 {
			t.Fatalf("agent should still see 502, got %d", resp.StatusCode)
		}
	}

	t.Run("raw_tunnel", func(t *testing.T) {
		store := &syncStore{}
		metrics := newFakeMetrics()
		p := startProxy(t, store, nil, nil, 443, func(c *Config) { c.Metrics = metrics })
		p.dialFunc = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).Dial

		conn, br := connectTunnel(t, p.Addr().String(), "loop.test", 443)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadAll(br)

		waitForEvents(t, store, 1)
		waitForBlocked(t, metrics, SSRFReasonBlocked)
		if got := metrics.blockedCount(SSRFReasonBlocked); got != 1 {
			t.Fatalf("RecordBlocked(%q) = %d calls, want 1: %s", SSRFReasonBlocked, got, metrics.describe())
		}
		if got := metrics.requestCount("deny", "tcp"); got != 1 {
			t.Fatalf("RecordRequest(deny,tcp) = %d calls, want 1: %s", got, metrics.describe())
		}
		if got := metrics.requestCount("allow", "tcp"); got != 0 {
			t.Fatalf("refused CONNECT counted as allow %d time(s): %s", got, metrics.describe())
		}
	})

	t.Run("mitm_h1", func(t *testing.T) {
		caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
		store := &syncStore{}
		metrics := newFakeMetrics()
		p := startProxy(t, store, caCertPEM, caKeyPEM, 443, func(c *Config) { c.Metrics = metrics })
		p.dialTLS = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).DialTLS

		refusedH1(t, p, caCertPEM)
		waitForEvents(t, store, 1)
		waitForBlocked(t, metrics, SSRFReasonBlocked)
		if got := metrics.blockedCount(SSRFReasonBlocked); got != 1 {
			t.Fatalf("RecordBlocked(%q) = %d calls, want 1: %s", SSRFReasonBlocked, got, metrics.describe())
		}
		if got := metrics.requestCount("deny", "https"); got != 1 {
			t.Fatalf("RecordRequest(deny,https) = %d calls, want 1: %s", got, metrics.describe())
		}
	})

	// h2 and gRPC share forwardH2; each protocol label must reach both counters.
	// The content type picks the label: application/json is plain http2,
	// application/grpc is grpc (same split the events use).
	for name, proto := range map[string]string{"h2": "http2", "grpc": "grpc"} {
		contentType := "application/json"
		if proto == "grpc" {
			contentType = "application/grpc"
		}
		t.Run(name, func(t *testing.T) {
			caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
			store := &syncStore{}
			metrics := newFakeMetrics()
			p := startProxy(t, store, caCertPEM, caKeyPEM, 443, func(c *Config) { c.Metrics = metrics })
			p.dialTLS = ssrfTestDialer(t, map[string]string{"loop.test": "127.0.0.1"}).DialTLS

			cc := dialGRPCClient(t, p.Addr().String(), "loop.test", caCertPEM)
			req, err := http.NewRequest("POST", "https://loop.test/v1/chat", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", contentType)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != 502 {
				t.Fatalf("agent should still see 502, got %d", resp.StatusCode)
			}

			waitForEvents(t, store, 1)
			waitForBlocked(t, metrics, SSRFReasonBlocked)
			if got := metrics.blockedCount(SSRFReasonBlocked); got != 1 {
				t.Fatalf("RecordBlocked(%q) = %d calls, want 1: %s", SSRFReasonBlocked, got, metrics.describe())
			}
			if got := metrics.requestCount("deny", proto); got != 1 {
				t.Fatalf("RecordRequest(deny,%s) = %d calls, want 1: %s", proto, got, metrics.describe())
			}
		})
	}

	// The hostname case refuses the NAME before any resolution; the blocked
	// metric carries ssrf_denied_hostname, not ssrf_blocked.
	t.Run("denied_hostname", func(t *testing.T) {
		store := &syncStore{}
		metrics := newFakeMetrics()
		p := startProxy(t, store, nil, nil, 443, func(c *Config) {
			c.Metrics = metrics
			// The allowlist admits the metadata hostname; the SSRF-safe dialer
			// hard-denies it anyway — exactly the decision this metric exposes.
			c.Policy = policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
				{Domain: "metadata.google.internal", Port: 443},
			}})
		})
		p.dialFunc = ssrfTestDialer(t, nil).Dial // stub resolver; never queried

		conn, br := connectTunnel(t, p.Addr().String(), "metadata.google.internal", 443)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadAll(br)

		waitForEvents(t, store, 1)
		waitForBlocked(t, metrics, SSRFReasonDeniedHostname)
		if got := metrics.blockedCount(SSRFReasonDeniedHostname); got != 1 {
			t.Fatalf("RecordBlocked(%q) = %d calls, want 1: %s", SSRFReasonDeniedHostname, got, metrics.describe())
		}
		if got := metrics.blockedCount(SSRFReasonBlocked); got != 0 {
			t.Fatalf("hostname refusal counted as %q %d time(s)", SSRFReasonBlocked, got)
		}
		if got := metrics.requestCount("deny", "tcp"); got != 1 {
			t.Fatalf("RecordRequest(deny,tcp) = %d calls, want 1: %s", got, metrics.describe())
		}
	})
}

// --- stale keep-alive conn: the refused redial ------------------------------

// TestDialRefusal_StaleRedialOneDenyEvent: an upstream keep-alive conn the
// origin has silently closed is detected stale, and the transparent redial is
// REFUSED by the SSRF-safe dialer. The client sees the 502, and the redial is
// audited as EXACTLY ONE deny event — not one per dial attempt, and not zero
// because the session itself was admitted and served a request earlier.
func TestDialRefusal_StaleRedialOneDenyEvent(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	// One request per conn, NO Connection: close — the proxy carries the conn
	// as reusable while the origin has already dropped it (the idle keep-alive
	// close). That drives the stale-reused-conn redial path.
	backendLn := startEphemeralBackend(t, caCert, caKey, false)

	store := &syncStore{}
	p := startProxy(t, store, caCertPEM, caKeyPEM, 443, func(c *Config) {
		c.Policy = policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: "backend.test", Port: 443},
		}})
	})
	var dials int32
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		if atomic.AddInt32(&dials, 1) == 1 {
			// The session's first dial reaches the real, allowed origin.
			return dialBackend(backendLn)(network, addr, cfg)
		}
		// The redial the SSRF-safe dialer refuses, typed like every refusal.
		return nil, &SSRFError{
			Reason:    SSRFReasonBlocked,
			AddrClass: "loopback",
			msg:       `proxy: all resolved IPs for "backend.test" are blocked (SSRF protection)`,
		}
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	br := bufio.NewReader(tlsClient)

	// Request 1 succeeds on the fresh conn.
	req, _ := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("request 1 should succeed, got %d", resp.StatusCode)
	}

	// Request 2 reuses the now-dead conn, detects it stale — and the redial is
	// refused: 502 to the client.
	req2, _ := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
	if err := req2.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.ReadResponse(br, req2)
	if err != nil {
		t.Fatalf("expected the 502 response, got transport error: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != 502 {
		t.Fatalf("refused stale redial should yield 502, got %d", resp2.StatusCode)
	}

	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Fatalf("expected exactly 2 dials (initial + refused redial), got %d", got)
	}
	// Request 1's allow plus EXACTLY ONE deny for the refused redial.
	evs := waitForEvents(t, store, 2)
	var denies []analytics.Event
	for _, e := range evs {
		if e.Decision == "deny" {
			denies = append(denies, e)
		}
	}
	if len(denies) != 1 {
		t.Fatalf("expected EXACTLY ONE deny event, got %d: %+v", len(denies), evs)
	}
	wantSSRFDeny(t, denies[0], "backend.test", "https", SSRFReasonBlocked, "loopback")
}
