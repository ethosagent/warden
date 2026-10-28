package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// recordingMetrics captures the RecordBlocked labels so a test can prove the
// blocked metric and the analytics event name the SAME reason (#409).
type recordingMetrics struct {
	mu      sync.Mutex
	blocked []string
}

func (m *recordingMetrics) RecordRequest(decision, protocol string)           {}
func (m *recordingMetrics) RecordBlocked(reason string)                       { m.add(reason) }
func (m *recordingMetrics) RecordSecretSwap(placeholderRef string)            {}
func (m *recordingMetrics) RecordScanFinding(kind string)                     {}
func (m *recordingMetrics) RecordJudge(outcome string)                        {}
func (m *recordingMetrics) RecordScoped(result string)                        {}
func (m *recordingMetrics) ObserveAddedLatency(stage string, d time.Duration) {}
func (m *recordingMetrics) RecordIdentityVerify(result, reason string)        {}
func (m *recordingMetrics) RecordSignInStarted(outcome string)                {}
func (m *recordingMetrics) RecordBlocklistEntries(n int)                      {}
func (m *recordingMetrics) RecordBlocklistSessionsClosed(n int)               {}

func (m *recordingMetrics) add(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocked = append(m.blocked, reason)
}

func (m *recordingMetrics) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.blocked))
	copy(out, m.blocked)
	return out
}

// startReasonProxy is startJudgeProxy with a metrics recorder attached and an
// optional CA (no CA = the CONNECT gate answers before TLS termination).
func startReasonProxy(t *testing.T, pol config.Policy, judge Judge, caCertPEM, caKeyPEM []byte) (*Proxy, *syncStore, *recordingMetrics) {
	t.Helper()
	store := &syncStore{}
	metrics := &recordingMetrics{}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(pol),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
		Judge:      judge,
		AgentID:    "default",
		Metrics:    metrics,
	}
	if len(caCertPEM) > 0 {
		certFile := filepath.Join(t.TempDir(), "ca.crt")
		keyFile := filepath.Join(t.TempDir(), "ca.key")
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
	for i := 0; i < 100 && p.Addr() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy did not start")
	}
	return p, store, metrics
}

// connectDenied dials CONNECT and reports the response status line; it drains
// the response so the handler goroutine can finish writing the audit event.
func connectDenied(t *testing.T, proxyAddr, domain string) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", domain, domain)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(br)
	return line
}

// waitDenies polls the store until it holds at least n deny events.
func waitDenies(t *testing.T, store *syncStore, n int) []analytics.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var denies []analytics.Event
		for _, e := range store.snapshot() {
			if e.Decision == "deny" {
				denies = append(denies, e)
			}
		}
		if len(denies) >= n {
			return denies
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("only %d/%d deny events: %+v", len(denies), n, store.snapshot())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// requireDeclaredDeny asserts one deny event: non-empty Reason, from the
// declared set, and the blocked metric carries the SAME value (#409).
func requireDeclaredDeny(t *testing.T, e analytics.Event, want string, metrics *recordingMetrics) {
	t.Helper()
	if string(e.Reason) != want {
		t.Fatalf("deny reason = %q, want %q (event %+v)", e.Reason, want, e)
	}
	if !denyreason.Reason(e.Reason).Declared() {
		t.Fatalf("reason %q is not in the declared set", e.Reason)
	}
	blocked := metrics.snapshot()
	if len(blocked) != 1 || blocked[0] != want {
		t.Fatalf("RecordBlocked = %v, want exactly [%s] (metric must match the event reason)", blocked, want)
	}
}

// TestServe_ConnectPolicyDenyCarriesReason (#409): a policy deny at CONNECT
// names WHY on the analytics event — not just on the metric. default-deny is
// policy_no_match, a denylist hit is policy_denylist, a guard rejection names
// its guard (time_window). "0-0" is a time window that excludes every hour, so
// the case is clock-independent.
func TestServe_ConnectPolicyDenyCarriesReason(t *testing.T) {
	cases := []struct {
		name   string
		pol    config.Policy
		domain string
		want   string
	}{
		{
			name:   "default deny",
			pol:    config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "allowed.test", Port: 443}}},
			domain: "evil.example.com",
			want:   "policy_no_match",
		},
		{
			name: "denylist",
			pol: config.Policy{
				Allowlist: []config.AllowlistEntry{{Domain: "allowed.test", Port: 443}},
				Denylist:  []config.DenylistEntry{{Domain: "blocked.test", Port: 443}},
			},
			domain: "blocked.test",
			want:   "policy_denylist",
		},
		{
			name:   "time window",
			pol:    config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "tw.test", Port: 443, TimeWindow: "0-0"}}},
			domain: "tw.test",
			want:   "time_window",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, store, metrics := startReasonProxy(t, tc.pol, nil, nil, nil)
			line := connectDenied(t, p.Addr().String(), tc.domain)
			if !strings.Contains(line, "403") {
				t.Fatalf("CONNECT = %q, want 403", line)
			}
			denies := waitDenies(t, store, 1)
			if len(denies) != 1 {
				t.Fatalf("deny events = %d, want 1", len(denies))
			}
			requireDeclaredDeny(t, denies[0], tc.want, metrics)
		})
	}
}

// TestServe_ConnectRateLimitedDenyCarriesReason (#409): the CONNECT gate peeks
// (never consumes) the rate limit; once a request through the tunnel has used
// the entry's budget, the next CONNECT is denied with rate_limited — on the
// event and on the metric.
func TestServe_ConnectRateLimitedDenyCarriesReason(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	pol := config.Policy{Allowlist: []config.AllowlistEntry{
		{Domain: "rl.test", Port: 443, RateLimit: "1/minute"},
	}}
	p, store, metrics := startReasonProxy(t, pol, nil, caCertPEM, caKeyPEM)
	p.dialTLS = dialBackend(backendLn)

	// Request 1 rides the tunnel and consumes the single allowed slot.
	c := dialProxyAndConnect(t, p.Addr().String(), "rl.test", caCertPEM)
	req, _ := http.NewRequest("GET", "https://rl.test/v1/x", nil)
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first request = %d, want 200", resp.StatusCode)
	}
	_ = c.Close()

	// CONNECT 2: the window is exhausted — denied, and named.
	line := connectDenied(t, p.Addr().String(), "rl.test")
	if !strings.Contains(line, "403") {
		t.Fatalf("second CONNECT = %q, want 403", line)
	}
	denies := waitDenies(t, store, 1)
	requireDeclaredDeny(t, denies[0], "rate_limited", metrics)
}

// TestServe_ConnectFloorDenyCarriesReason (#409): the TCP default-deny floor
// records its reason on the event too — storeDeny used to put the reason on the
// metric only.
func TestServe_ConnectFloorDenyCarriesReason(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"not a CONNECT", "GET http://evil.example.com/ HTTP/1.1\r\nHost: evil.example.com\r\n\r\n", "unsupported_protocol"},
		{"CONNECT without a parsable target", "CONNECT not-a-hostport HTTP/1.1\r\nHost: x\r\n\r\n", "malformed_connect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, store, metrics := startReasonProxy(t, config.Policy{}, nil, nil, nil)
			conn, err := net.Dial("tcp", p.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_, _ = conn.Write([]byte(tc.raw))
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = io.ReadAll(bufio.NewReader(conn))
			_ = conn.Close()

			denies := waitDenies(t, store, 1)
			requireDeclaredDeny(t, denies[0], tc.want, metrics)
		})
	}
}

// TestServe_NoCA_NoMatch_JudgeEnabled_DeniesWithReason (#409): with no TLS
// termination the judge cannot inspect an opaque tunnel, so a NoMatch CONNECT
// fails closed at the gate — recorded as policy_no_match.
func TestServe_NoCA_NoMatch_JudgeEnabled_DeniesWithReason(t *testing.T) {
	pol := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "allowed.test", Port: 443}}}
	p, store, metrics := startReasonProxy(t, pol, &fakeJudge{verdict: Verdict{Decision: "allow"}}, nil, nil)
	line := connectDenied(t, p.Addr().String(), "unlisted.test")
	if !strings.Contains(line, "403") {
		t.Fatalf("CONNECT = %q, want 403", line)
	}
	denies := waitDenies(t, store, 1)
	requireDeclaredDeny(t, denies[0], "policy_no_match", metrics)
}

// TestServe_NoTLS_JudgeEnabled_DeniesWithReason: egress that needs the judge but
// is not a terminable TLS session fails closed with the bounded no_tls reason —
// now on the event, not only on the metric.
func TestServe_NoTLS_JudgeEnabled_DeniesWithReason(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	pol := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "allowed.test", Port: 443}}}
	p, store, metrics := startReasonProxy(t, pol, &fakeJudge{verdict: Verdict{Decision: "allow"}}, caCertPEM, caKeyPEM)

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// CONNECT is admitted (NoMatch + judge); what arrives inside is NOT a TLS
	// ClientHello, so the judge can never run — fail closed.
	_, _ = fmt.Fprintf(conn, "CONNECT unlisted.test:443 HTTP/1.1\r\nHost: unlisted.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	_, _ = fmt.Fprint(conn, "plain bytes, no clienthello")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(br)

	denies := waitDenies(t, store, 1)
	requireDeclaredDeny(t, denies[0], "no_tls", metrics)
}

// TestJudge_DenyCarriesBoundedReason (#409): a judge-denied request gets BOTH
// fields — the free-text rationale in JudgeReason (as before) and the bounded
// `judge` reason on the event, matching the metric label.
func TestJudge_DenyCarriesBoundedReason(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	fj := &fakeJudge{verdict: Verdict{Decision: "deny", Reason: "not permitted"}}
	pol := config.Policy{} // backend.test is on neither list -> NoMatch -> judge
	p, store, metrics := startReasonProxy(t, pol, fj, caCertPEM, caKeyPEM)

	status, connected := connectAndRequest(t, p.Addr().String(), "backend.test", caCertPEM, backendLn.Addr().String(), p)
	if !connected {
		t.Fatal("CONNECT should proceed for NoMatch when judge enabled")
	}
	if status != 403 {
		t.Fatalf("expected 403 from judge-denied request, got %d", status)
	}
	denies := waitDenies(t, store, 1)
	requireDeclaredDeny(t, denies[0], "judge", metrics)
	if denies[0].JudgeReason != "not permitted" {
		t.Fatalf("JudgeReason = %q, want the free-text rationale", denies[0].JudgeReason)
	}
}

// TestDenyEvents_CarryDeclaredReasons_h2: the h2 edge denies keep their exact
// reasons (pinned by h2_edge_test) AND the h2 constraint denies carry the same
// declared values as h1 — one set for both protocols (#409).
func TestDenyEvents_CarryDeclaredReasons_h2(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	be := startGRPCBackend(t)
	backendAddr := strings.TrimPrefix(be.server.URL, "https://")
	pol := config.Policy{Allowlist: []config.AllowlistEntry{
		{Domain: "grpc.test", Port: 443, Methods: []string{"POST"}, Paths: []string{"/allowed/*"}},
	}}
	p, store, metrics := startReasonProxy(t, pol, nil, caCertPEM, caKeyPEM)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}

	cc := dialGRPCClient(t, p.Addr().String(), "grpc.test", caCertPEM)
	req, _ := http.NewRequest("GET", "https://grpc.test/allowed/x", nil) // method not allowed
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	denies := waitDenies(t, store, 1)
	requireDeclaredDeny(t, denies[0], "method_not_allowed", metrics)
}
