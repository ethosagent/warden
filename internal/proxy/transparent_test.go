package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dnstest"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// The transparent-mode behavior tests (#376). The environment boots a real
// proxy in transparent mode (listeners on port 0) with the SAME fake upstream,
// canary secret provider and sinks the invariant suite uses, so a transparent
// request provably runs the one pipeline: same swap, same events, same reasons.

// transparentDenyHost is a name the denylist rows refuse.
const transparentDenyHost = "denied.test"

// transparentOpts are the per-test knobs.
type transparentOpts struct {
	// allow is the allowlist; nil = {backend.test} with no port, which matches
	// both the :443/https and :80/http evaluations (inferredPort: 0 -> scheme
	// default). The default upstream dial goes to the fake TLS backend.
	allow []config.AllowlistEntry
	// denylist entries, for the explicit-deny parity case.
	denylist []config.DenylistEntry
	// plainHTTP also binds the plain-HTTP listener.
	plainHTTP bool
	// allowPrivateCIDRs feeds the production SafeDialer.
	allowPrivateCIDRs []string
	// judge enables the judge seam.
	judge Judge
	// prodDial keeps the PRODUCTION dial path (SafeDialer + its loop guard)
	// instead of overriding the dial seams; o.dns then supplies the upstream
	// records. Used by the loop-guard test, which must exercise the real
	// dialer — an overridden dialTLS seam bypasses the guard entirely.
	prodDial bool
	// dns records for the dnstest stub (prodDial only).
	dns map[string]string
}

// transparentEnv is one transparent-mode world.
type transparentEnv struct {
	t       *testing.T
	p       *Proxy
	store   *syncStore
	logs    *lockedBuf
	metrics *metricSink
	backend *invBackend
	caPEM   []byte

	hitMu sync.Mutex
	hit   map[Path]bool
}

func newTransparentEnv(t *testing.T, o transparentOpts) *transparentEnv {
	t.Helper()
	certPath, keyPath, caPEM := invCA(t)
	e := &transparentEnv{
		t:       t,
		store:   &syncStore{},
		logs:    &lockedBuf{},
		metrics: &metricSink{},
		backend: newInvBackend(t),
		caPEM:   caPEM,
		hit:     map[Path]bool{},
	}
	allow := o.allow
	if allow == nil {
		allow = []config.AllowlistEntry{{Domain: invHost}}
	}
	cfg := Config{
		ListenAddr:       "127.0.0.1:0", // never bound in transparent-only mode
		Mode:             config.ProxyModeTransparent,
		Policy:           policy.NewEvaluator(config.Policy{Allowlist: allow, Denylist: o.denylist}),
		Secrets:          &fakes.FakeSecretProvider{Values: map[string]string{invPlaceholder: invCanary}},
		Analytics:        e.store,
		CACertPath:       certPath,
		CAKeyPath:        keyPath,
		AgentID:          "default",
		Metrics:          e.metrics,
		Logger:           slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Judge:            o.judge,
		PlaceholderNames: []string{invPlaceholder},

		TransparentHTTPSListen:    "127.0.0.1:0",
		UpstreamAllowPrivateCIDRs: o.allowPrivateCIDRs,
	}
	if o.plainHTTP {
		cfg.TransparentHTTPListen = "127.0.0.1:0"
	}
	if o.prodDial {
		// The production SafeDialer resolves through the stub, so the loop
		// guard sees the addresses the agent's DNS would hand it.
		cfg.UpstreamResolver = NewUpstreamResolver(dnstest.New(t, o.dns).Addr(), nil)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.p = p

	registered := map[Path]bool{}
	for _, rp := range ProtocolPaths() {
		registered[rp] = true
	}
	p.pathHook = func(path Path) {
		if !registered[path] {
			t.Errorf("dispatch reached unregistered path %q", path)
		}
		e.hitMu.Lock()
		e.hit[path] = true
		e.hitMu.Unlock()
	}
	if !o.prodDial {
		// Route the TLS upstream dials to the fake backend; the real cert is
		// not verified (the dial seam only routes — the pipeline is under
		// test, as in newInvEnv). The plain-HTTP dialFunc goes to a plain
		// sibling of the same backend handler.
		p.dialTLS = func(_, addr string, c *tls.Config) (*tls.Conn, error) {
			return tls.Dial("tcp", e.backend.srv.Listener.Addr().String(),
				&tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
		}
		plain := httptest.NewServer(http.HandlerFunc(e.backend.handle))
		t.Cleanup(plain.Close)
		p.dialFunc = func(_, _ string) (net.Conn, error) {
			return net.Dial("tcp", plain.Listener.Addr().String())
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 200 && e.tlsAddr() == ""; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if e.tlsAddr() == "" {
		t.Fatal("transparent TLS listener did not start")
	}
	if o.plainHTTP && e.httpAddr() == "" {
		t.Fatal("transparent HTTP listener did not start")
	}
	// Transparent-only mode must not bind the forward CONNECT listener.
	if p.Addr() != nil {
		t.Fatal("transparent-only mode bound the forward CONNECT listener")
	}
	return e
}

func (e *transparentEnv) tlsAddr() string {
	if a := e.p.TransparentHTTPSAddr(); a != nil {
		return a.String()
	}
	return ""
}

func (e *transparentEnv) httpAddr() string {
	if a := e.p.TransparentHTTPAddr(); a != nil {
		return a.String()
	}
	return ""
}

func (e *transparentEnv) reached(path Path) bool {
	e.hitMu.Lock()
	defer e.hitMu.Unlock()
	return e.hit[path]
}

// tlsDialSNI opens a TLS connection to the transparent listener with the given
// SNI, trusting the proxy CA, and completes the MITM handshake.
func (e *transparentEnv) tlsDialSNI(sni string, nextProtos ...string) (*tls.Conn, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.caPEM)
	conn, err := net.DialTimeout("tcp", e.tlsAddr(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(conn, &tls.Config{
		ServerName: sni,
		RootCAs:    pool,
		NextProtos: nextProtos,
	})
	if err := tc.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

// sendHello writes raw bytes to the transparent listener (a ClientHello the
// tests built by hand) and returns what came back before the close.
func (e *transparentEnv) sendHello(wire []byte) (string, error) {
	conn, err := net.DialTimeout("tcp", e.tlsAddr(), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(wire); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, conn)
	return buf.String(), nil
}

// doH1 sends one request over a fresh SNI connection and returns the agent's
// full view plus the status.
func (e *transparentEnv) doH1(sni string, req *http.Request) (string, int, error) {
	tc, err := e.tlsDialSNI(sni)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = tc.Close() }()
	if err := req.Write(tc); err != nil {
		return "", 0, err
	}
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", resp.Status)
	_ = resp.Header.Write(&sb)
	sb.Write(body)
	return sb.String(), resp.StatusCode, nil
}

// h1KeepAlive sends a first request (which must be allowed) and then second on
// the SAME connection, returning both statuses — the second is 0 when the
// connection was closed before a response arrived — plus the events so far.
func (e *transparentEnv) h1KeepAlive(second *http.Request) (int, int, []analytics.Event) {
	e.t.Helper()
	tc, err := e.tlsDialSNI(invHost)
	if err != nil {
		e.t.Fatalf("dial: %v", err)
	}
	defer func() { _ = tc.Close() }()
	first, _ := http.NewRequest(http.MethodGet, "https://"+invHost+"/first", nil)
	if err := first.Write(tc); err != nil {
		e.t.Fatalf("write first: %v", err)
	}
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(tc)
	r1, err := http.ReadResponse(br, first)
	if err != nil {
		e.t.Fatalf("read first: %v", err)
	}
	_, _ = io.Copy(io.Discard, r1.Body)
	_ = r1.Body.Close()
	status1 := r1.StatusCode
	if err := second.Write(tc); err != nil {
		return status1, 0, e.store.snapshot()
	}
	r2, err := http.ReadResponse(br, second)
	if err != nil {
		return status1, 0, e.store.snapshot()
	}
	_, _ = io.Copy(io.Discard, r2.Body)
	_ = r2.Body.Close()
	return status1, r2.StatusCode, e.store.snapshot()
}

// wantDenied polls the store until a deny event with the given domain and
// reason arrives.
func (e *transparentEnv) wantDenied(domain, reason string) analytics.Event {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range e.store.snapshot() {
			if ev.Decision == "deny" && ev.Domain == domain && ev.Reason == reason {
				return ev
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("no deny event for (%s, %s); events: %+v", domain, reason, e.store.snapshot())
	return analytics.Event{}
}

// wantNoDeny fails when a deny event naming reason appeared.
func (e *transparentEnv) wantNoDeny(reason string) {
	e.t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		for _, ev := range e.store.snapshot() {
			if ev.Decision == "deny" && ev.Reason == reason {
				e.t.Fatalf("unexpected deny event %+v", ev)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// wantAllow polls the store until the allow event for domain arrives.
func (e *transparentEnv) wantAllow(domain string) analytics.Event {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range e.store.snapshot() {
			if ev.Decision == "allow" && ev.Domain == domain {
				return ev
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("no allow event for %s: %+v", domain, e.store.snapshot())
	return analytics.Event{}
}

// plainDo sends a raw request over the transparent plain-HTTP listener and
// returns the agent's full view plus the status.
func (e *transparentEnv) plainDo(host, raw string) (string, int, error) {
	conn, err := net.DialTimeout("tcp", e.httpAddr(), 2*time.Second)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		return "", 0, err
	}
	req := &http.Request{Method: http.MethodGet, Host: host}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", resp.Status)
	_ = resp.Header.Write(&sb)
	sb.Write(body)
	return sb.String(), resp.StatusCode, nil
}

// --- tests ---

func TestTransparentTLS_AllowedRequestRunsThePipeline(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	// /plain does not reflect request headers back, so the response is exactly
	// the pipeline's forward — the swap is proven by what the UPSTREAM saw.
	req, _ := http.NewRequest(http.MethodGet, "https://"+invHost+"/plain", nil)
	req.Header.Set("Authorization", "Bearer "+invPlaceholder)
	view, status, err := e.doH1(invHost, req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != 200 {
		t.Fatalf("status = %d, view:\n%s", status, view)
	}
	// The one pipeline ran: the swap replaced the placeholder on the way out…
	if !e.backend.upstreamSawCanary() {
		t.Error("upstream never saw the swapped canary")
	}
	// …and the real value never reached the agent.
	if strings.Contains(view, invCanary) {
		t.Error("agent response carries the canary")
	}
	// The allow event carries the https protocol label and the swap reference,
	// exactly as a CONNECT-tunnelled request's event does.
	ev := e.wantAllow(invHost)
	if ev.Protocol != "https" {
		t.Errorf("protocol = %q, want https", ev.Protocol)
	}
	if ev.SecretRef == "" {
		t.Error("allow event carries no secret reference; the swap did not register")
	}
	if !e.reached(PathTransparentTLS) {
		t.Error("PathTransparentTLS was never announced")
	}
}

func TestTransparentTLS_NoSNIIsRefused(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	// A well-formed ClientHello with no server_name extension (the ECH case
	// looks identical to the gate: a readable hello naming no server).
	resp, err := e.sendHello(tlsRecord(0x16, helloWithSNI("")))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp != "" {
		t.Errorf("server answered a no-SNI hello with %q, want a bare close", resp)
	}
	e.wantDenied("", "transparent_no_sni")
}

func TestTransparentTLS_GarbageIsDenied(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	if _, err := e.sendHello([]byte("NOT-TLS-AT-ALL\r\n\r\n")); err != nil {
		t.Fatalf("send: %v", err)
	}
	e.wantDenied("", "transparent_bad_client_hello")
}

func TestTransparentTLS_H2PriorKnowledgeIsDenied(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	if _, err := e.sendHello([]byte(h2ClientPreface)); err != nil {
		t.Fatalf("send: %v", err)
	}
	e.wantDenied("", "transparent_h2_prior_knowledge")
}

func TestTransparentTLS_TruncatedHelloIsSilent(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	full := tlsRecord(0x16, helloWithSNI(invHost))
	if _, err := e.sendHello(full[:len(full)-8]); err != nil {
		t.Fatalf("send: %v", err)
	}
	// The client vanished mid-hello: nothing was gated, no deny (CONNECT-floor
	// parity for a preamble that never completed).
	e.wantNoDeny("transparent_bad_client_hello")
	e.wantNoDeny("transparent_no_sni")
}

func TestTransparentTLS_UnknownSNIDefaultDenies(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	if _, err := e.tlsDialSNI("stranger.test"); err == nil {
		t.Fatal("handshake succeeded for an unknown SNI; want refusal")
	}
	e.wantDenied("stranger.test", "policy_no_match")
}

func TestTransparentTLS_DenylistedSNINamesTheReason(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{
		denylist: []config.DenylistEntry{{Domain: transparentDenyHost}},
	})
	if _, err := e.tlsDialSNI(transparentDenyHost); err == nil {
		t.Fatal("handshake succeeded for a denylisted SNI; want refusal")
	}
	e.wantDenied(transparentDenyHost, "policy_denylist")
}

func TestTransparentTLS_HostMismatchOnH1KeepAlive(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	// The connection was admitted on SNI backend.test; the SECOND keep-alive
	// request names a different Host. It must be refused and the connection
	// closed — only the first request may reach the upstream.
	second, _ := http.NewRequest(http.MethodGet, "https://"+invHost+"/second", nil)
	second.Host = "evil.test"
	s1, s2, evs := e.h1KeepAlive(second)
	if s1 != 200 {
		t.Errorf("first request status = %d, want 200", s1)
	}
	if s2 != 0 {
		t.Errorf("second (mismatched) request got status %d, want none/connection close", s2)
	}
	e.wantDenied(invHost, "host_mismatch")
	for _, ev := range evs {
		if ev.Decision == "allow" && strings.Contains(ev.URL, "/second") {
			t.Errorf("the mismatched request reached the upstream: %+v", ev)
		}
	}
}

func TestTransparentTLS_HostMismatchOnH2Stream(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	// h2 via ALPN: every stream re-runs the pipeline, so a stream whose
	// :authority differs from the SNI the connection was admitted on is
	// refused per stream (421 Misdirected Request), while a matching stream
	// on a sibling connection succeeds.
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return e.tlsDialSNI(invHost, "h2")
		},
	}
	defer tr.CloseIdleConnections()
	okReq, _ := http.NewRequest(http.MethodGet, "https://"+invHost+"/first", nil)
	resp1, err := tr.RoundTrip(okReq)
	if err != nil {
		t.Fatalf("first stream: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != 200 {
		t.Errorf("first stream status = %d, want 200", resp1.StatusCode)
	}
	// A second transport whose request names evil.test while the SNI stays
	// backend.test: net/http would never reuse a conn across hosts, so this
	// is a fresh connection admitted on the backend.test SNI.
	badTr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return e.tlsDialSNI(invHost, "h2")
		},
	}
	defer badTr.CloseIdleConnections()
	badReq, _ := http.NewRequest(http.MethodGet, "https://evil.test/second", nil)
	resp2, err := badTr.RoundTrip(badReq)
	if err != nil {
		t.Fatalf("mismatched stream: %v (want a 421 response)", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("mismatched :authority status = %d, want 421", resp2.StatusCode)
	}
	e.wantDenied(invHost, "host_mismatch")
}

func TestTransparentHTTP_ServesAllowedHost(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{plainHTTP: true})
	raw := "GET /plain HTTP/1.1\r\nHost: " + invHost + "\r\nAuthorization: Bearer " + invPlaceholder + "\r\nConnection: close\r\n\r\n"
	view, status, err := e.plainDo(invHost, raw)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != 200 {
		t.Fatalf("status = %d, view:\n%s", status, view)
	}
	// The swap ran over plain HTTP too, and the echo guard held the value.
	if !e.backend.upstreamSawCanary() {
		t.Error("upstream never saw the swapped canary")
	}
	if strings.Contains(view, invCanary) {
		t.Error("agent response carries the canary")
	}
	ev := e.wantAllow(invHost)
	if ev.Protocol != "http" {
		t.Errorf("protocol = %q, want http", ev.Protocol)
	}
	if !strings.HasPrefix(ev.URL, "http://") {
		t.Errorf("event URL = %q, want an http:// prefix", ev.URL)
	}
	if ev.SecretRef == "" {
		t.Error("allow event carries no secret reference")
	}
	if !e.reached(PathTransparentHTTP) {
		t.Error("PathTransparentHTTP was never announced")
	}
}

func TestTransparentHTTP_MissingHostIsDenied(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{plainHTTP: true})
	_, status, err := e.plainDo("", "GET / HTTP/1.0\r\n\r\n")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != 400 {
		t.Errorf("status = %d, want 400", status)
	}
	e.wantDenied("", "malformed_request")
}

func TestTransparentHTTP_UnknownHostDefaultDenies(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{plainHTTP: true})
	if _, status, err := e.plainDo("stranger.test", "GET / HTTP/1.1\r\nHost: stranger.test\r\nConnection: close\r\n\r\n"); err != nil || status != 403 {
		t.Errorf("status = %d (err %v), want 403", status, err)
	}
	e.wantDenied("stranger.test", "policy_no_match")
}

func TestTransparentHTTP_HeaderBlockOverBudgetIsDenied(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{plainHTTP: true})
	var raw bytes.Buffer
	raw.WriteString("GET / HTTP/1.1\r\nHost: " + invHost + "\r\n")
	for raw.Len() < maxPlainHeaderBytes {
		raw.WriteString("X-Filler: 0123456789012345678901234567890123456789\r\n")
	}
	raw.WriteString("\r\n")
	_, status, err := e.plainDo(invHost, raw.String())
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("status = %d, want 431", status)
	}
	e.wantDenied("", "malformed_request")
}

func TestNew_TransparentModeValidation(t *testing.T) {
	base := func(mut func(*Config)) Config {
		cfg := Config{
			ListenAddr:             "127.0.0.1:0",
			Policy:                 policy.NewEvaluator(config.Policy{}),
			Secrets:                &fakes.FakeSecretProvider{},
			Analytics:              &syncStore{},
			TransparentHTTPSListen: "127.0.0.1:0",
		}
		mut(&cfg)
		return cfg
	}
	t.Run("transparent without CA", func(t *testing.T) {
		_, err := New(base(func(c *Config) { c.Mode = config.ProxyModeTransparent }))
		if err == nil || !strings.Contains(err.Error(), "CA") {
			t.Errorf("err = %v, want a CA requirement", err)
		}
	})
	t.Run("transparent without https listener", func(t *testing.T) {
		_, err := New(base(func(c *Config) {
			c.Mode = config.ProxyModeTransparent
			c.TransparentHTTPSListen = ""
		}))
		if err == nil || !strings.Contains(err.Error(), "listener") {
			t.Errorf("err = %v, want a listener requirement", err)
		}
	})
	t.Run("invalid mode", func(t *testing.T) {
		_, err := New(base(func(c *Config) { c.Mode = "sneaky" }))
		if err == nil || !strings.Contains(err.Error(), "mode") {
			t.Errorf("err = %v, want a mode error", err)
		}
	})
	t.Run("forward with transparent listeners", func(t *testing.T) {
		_, err := New(base(func(c *Config) {
			c.Mode = config.ProxyModeForward
			c.TransparentHTTPListen = "127.0.0.1:0"
		}))
		if err == nil || !strings.Contains(err.Error(), "transparent listeners") {
			t.Errorf("err = %v, want a forward-mode conflict", err)
		}
	})
	t.Run("empty mode means forward", func(t *testing.T) {
		p, err := New(base(func(c *Config) {
			c.TransparentHTTPSListen = ""
			c.TransparentHTTPListen = ""
		}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if p.cfg.Mode != config.ProxyModeForward {
			t.Errorf("mode = %q, want forward", p.cfg.Mode)
		}
	})
}

// TestServe_OnTransparentReady proves the assembly seam (#376): Serve calls it
// exactly once, after the transparent listeners are bound and the loop guard is
// installed, with the BOUND addresses — "" for the plain-HTTP address when
// httpListen is unset — so an assembler learns the real port-0 addresses before
// any client dials (the kernel backlog holds early connections).
func TestServe_OnTransparentReady(t *testing.T) {
	base := func(mut func(*Config)) Config {
		certPath, keyPath, _ := invCA(t)
		cfg := Config{
			ListenAddr:             "127.0.0.1:0",
			Policy:                 policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: invHost}}}),
			Secrets:                &fakes.FakeSecretProvider{},
			Analytics:              &syncStore{},
			CACertPath:             certPath,
			CAKeyPath:              keyPath,
			Mode:                   config.ProxyModeTransparent,
			TransparentHTTPSListen: "127.0.0.1:0",
		}
		mut(&cfg)
		return cfg
	}
	boot := func(t *testing.T, cfg Config, wantHTTP bool) {
		t.Helper()
		var calls int
		var httpsAddr, httpAddr string
		ready := make(chan struct{}, 1)
		cfg.OnTransparentReady = func(h, pl string) {
			calls++
			httpsAddr, httpAddr = h, pl
			ready <- struct{}{}
		}
		p, err := New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- p.Serve(ctx) }()
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("Serve returned before OnTransparentReady: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("OnTransparentReady never fired")
		}
		if calls != 1 {
			t.Errorf("OnTransparentReady called %d times, want 1", calls)
		}
		if bound := p.TransparentHTTPSAddr(); bound == nil || bound.String() != httpsAddr {
			t.Errorf("reported https addr %q, want the bound %v", httpsAddr, bound)
		}
		boundHTTP := p.TransparentHTTPAddr()
		switch {
		case wantHTTP && (boundHTTP == nil || boundHTTP.String() != httpAddr):
			t.Errorf("reported http addr %q, want the bound %v", httpAddr, boundHTTP)
		case !wantHTTP && (boundHTTP != nil || httpAddr != ""):
			t.Errorf("no httpListen configured: reported %q / bound %v, want \"\" / nil", httpAddr, boundHTTP)
		}
		// The listener answers immediately after the callback: the accept loop is
		// served by the kernel backlog from here.
		conn, err := net.DialTimeout("tcp", httpsAddr, 2*time.Second)
		if err != nil {
			t.Errorf("dial the reported https addr: %v", err)
		} else {
			_ = conn.Close()
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return after cancel")
		}
	}

	t.Run("both listeners", func(t *testing.T) {
		boot(t, base(func(c *Config) { c.TransparentHTTPListen = "127.0.0.1:0" }), true)
	})
	t.Run("https only", func(t *testing.T) {
		boot(t, base(func(c *Config) {}), false)
	})
}

// TestParity_ForwardAndTransparentDecideAlike is the parity table (#376): the
// SAME destination — allowed-with-swap, denylisted, unknown — produces the
// same decision, the same deny reason and the same swap through the CONNECT
// tunnel and through the transparent listener. (Host re-validation downstream
// of admission is shared code — readRequest — so it is parity by construction
// and covered by the transparent tests above.)
func TestParity_ForwardAndTransparentDecideAlike(t *testing.T) {
	type row struct {
		name    string
		allow   []config.AllowlistEntry
		deny    []config.DenylistEntry
		host    string
		want    string // "allow" or the deny reason
		hasSwap bool
	}
	rows := []row{
		{
			name:    "allow with swap",
			allow:   []config.AllowlistEntry{{Domain: invHost}},
			host:    invHost,
			want:    "allow",
			hasSwap: true,
		},
		{
			name: "denylist",
			deny: []config.DenylistEntry{{Domain: transparentDenyHost}},
			host: transparentDenyHost,
			want: "policy_denylist",
		},
		{
			name: "no match",
			host: "stranger.test",
			want: "policy_no_match",
		},
	}
	for _, r := range rows {
		t.Run(r.name+"/forward", func(t *testing.T) {
			e := newInvEnv(t, invOpts{allow: r.allow, denylist: r.deny})
			tc, err := e.connectTLS(r.host)
			if r.want != "allow" && err != nil {
				// Forward mode refuses at CONNECT; the event tells the story.
				checkParity(t, waitDeny(t, e.store, r.host, r.want), r)
				return
			}
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			checkParity(t, allowThrough(t, tc, r.host, e.store), r)
		})
		t.Run(r.name+"/transparent", func(t *testing.T) {
			e := newTransparentEnv(t, transparentOpts{allow: r.allow, denylist: r.deny})
			tc, err := e.tlsDialSNI(r.host)
			if r.want != "allow" && err != nil {
				// Transparent mode refuses at the SNI gate (the handshake
				// never completes); the event must name the same decision.
				checkParity(t, waitDeny(t, e.store, r.host, r.want), r)
				return
			}
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			checkParity(t, allowThrough(t, tc, r.host, e.store), r)
		})
	}
}

// allowThrough sends the canonical GET /plain (the non-echoing path, so the
// response is the plain forward) with the placeholder through an established
// MITM conn and waits for its allow event.
func allowThrough(t *testing.T, tc *tls.Conn, host string, store *syncStore) analytics.Event {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/plain", nil)
	req.Header.Set("Authorization", "Bearer "+invPlaceholder)
	if err := req.Write(tc); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range store.snapshot() {
			if ev.Decision == "allow" && ev.Domain == host {
				return ev
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no allow event for %s: %+v", host, store.snapshot())
	return analytics.Event{}
}

// waitDeny polls the store for one deny event with the given domain and reason.
func waitDeny(t *testing.T, store *syncStore, domain, reason string) analytics.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range store.snapshot() {
			if ev.Decision == "deny" && ev.Domain == domain && ev.Reason == reason {
				return ev
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no deny event for (%s, %s): %+v", domain, reason, store.snapshot())
	return analytics.Event{}
}

// checkParity asserts the shared decision shape: same decision, same reason,
// same destination — and on allow rows, a swap that registered on both paths.
func checkParity(t *testing.T, ev analytics.Event, r struct {
	name    string
	allow   []config.AllowlistEntry
	deny    []config.DenylistEntry
	host    string
	want    string
	hasSwap bool
}) {
	t.Helper()
	if r.want == "allow" {
		if ev.Decision != "allow" {
			t.Fatalf("decision = %q (%s), want allow", ev.Decision, ev.Reason)
		}
		if r.hasSwap && ev.SecretRef == "" {
			t.Error("no swap reference on the allow event")
		}
		return
	}
	if ev.Decision != "deny" || ev.Reason != r.want {
		t.Fatalf("decision = %q reason = %q, want deny %q", ev.Decision, ev.Reason, r.want)
	}
	if ev.Domain != r.host {
		t.Errorf("domain = %q, want %q", ev.Domain, r.host)
	}
}
