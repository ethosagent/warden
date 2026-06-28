package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// fakeJudge records its calls and returns a fixed verdict.
type fakeJudge struct {
	mu       sync.Mutex
	calls    int
	verdict  Verdict
	lastAuth bool
	lastURL  string
}

func (f *fakeJudge) Evaluate(_, _, url, _, _ string, hasAuth bool) Verdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastAuth = hasAuth
	f.lastURL = url
	return f.verdict
}

func (f *fakeJudge) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// startJudgeProxy builds a TLS-terminating proxy with the given allow/deny
// lists and an optional judge.
func startJudgeProxy(t *testing.T, allow []config.AllowlistEntry, deny []config.DenylistEntry, caCertPEM, caKeyPEM []byte, judge Judge) (*Proxy, *syncStore) {
	t.Helper()
	store := &syncStore{}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: allow, Denylist: deny}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
		Judge:      judge,
		AgentID:    "default",
	}
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

	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 100; i++ {
		if p.Addr() != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy did not start")
	}
	return p, store
}

// connectExpectStatus dials CONNECT and returns the status line; if the CONNECT
// is allowed it then sends an HTTP request over TLS and returns the response
// status code. wantConnect indicates whether CONNECT should yield 200.
func connectAndRequest(t *testing.T, proxyAddr, domain string, caCertPEM []byte, backendAddr string, p *Proxy) (int, bool) {
	t.Helper()
	// Point upstream dial at the backend.
	p.dialTLS = func(_, _ string, _ *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true})
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	_, _ = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", domain, domain)
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	if !containsStatus(statusLine, "200") {
		return 0, false // CONNECT denied
	}

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

	req, _ := http.NewRequest("GET", "https://"+domain+"/v1/data", nil)
	req.Header.Set("Authorization", "Bearer placeholder")
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, true
}

func containsStatus(line, code string) bool {
	return len(line) >= 12 && line[9:12] == code
}

// NoMatch + judge allow: request reaches the backend (200) and the judge was
// consulted with hasAuth=true (auth presence only).
func TestJudge_NoMatchAllow(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	fj := &fakeJudge{verdict: Verdict{Decision: "allow", Reason: "policy permits read"}}
	// backend.test is on NEITHER list -> NoMatch -> judge.
	p, store := startJudgeProxy(t, nil, nil, caCertPEM, caKeyPEM, fj)

	status, connected := connectAndRequest(t, p.Addr().String(), "backend.test", caCertPEM, backendLn.Addr().String(), p)
	if !connected {
		t.Fatal("CONNECT should proceed for NoMatch when judge enabled")
	}
	if status != 200 {
		t.Fatalf("expected 200 from judge-allowed request, got %d", status)
	}
	if fj.callCount() != 1 {
		t.Fatalf("expected judge called once, got %d", fj.callCount())
	}
	if !fj.lastAuth {
		t.Error("judge should receive hasAuth=true")
	}

	time.Sleep(50 * time.Millisecond)
	if !hasJudgeReason(store, "policy permits read", "allow") {
		t.Error("expected an allow event carrying the judge reason")
	}
}

// NoMatch + judge deny: backend returns 403 and the judge reason is logged.
func TestJudge_NoMatchDeny(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	fj := &fakeJudge{verdict: Verdict{Decision: "deny", Reason: "not permitted"}}
	p, store := startJudgeProxy(t, nil, nil, caCertPEM, caKeyPEM, fj)

	status, connected := connectAndRequest(t, p.Addr().String(), "backend.test", caCertPEM, backendLn.Addr().String(), p)
	if !connected {
		t.Fatal("CONNECT should proceed to TLS so the judge can inspect")
	}
	if status != 403 {
		t.Fatalf("expected 403 from judge-denied request, got %d", status)
	}
	if fj.callCount() != 1 {
		t.Fatalf("expected judge called once, got %d", fj.callCount())
	}
	time.Sleep(50 * time.Millisecond)
	if !hasJudgeReason(store, "not permitted", "deny") {
		t.Error("expected a deny event carrying the judge reason")
	}
}

// Static allow: the judge must NOT be consulted (static rules win).
func TestJudge_StaticAllowSkipsJudge(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	fj := &fakeJudge{verdict: Verdict{Decision: "deny", Reason: "should never run"}}
	allow := []config.AllowlistEntry{{Domain: "backend.test", Port: 443}}
	p, _ := startJudgeProxy(t, allow, nil, caCertPEM, caKeyPEM, fj)

	status, connected := connectAndRequest(t, p.Addr().String(), "backend.test", caCertPEM, backendLn.Addr().String(), p)
	if !connected || status != 200 {
		t.Fatalf("static allow should reach backend; connected=%v status=%d", connected, status)
	}
	if fj.callCount() != 0 {
		t.Fatalf("judge must not be consulted for statically allowed requests, got %d calls", fj.callCount())
	}
}

// Static deny: CONNECT is rejected and the judge must NOT be consulted.
func TestJudge_StaticDenySkipsJudge(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	fj := &fakeJudge{verdict: Verdict{Decision: "allow", Reason: "should never run"}}
	allow := []config.AllowlistEntry{{Domain: "backend.test", Port: 443}}
	deny := []config.DenylistEntry{{Domain: "backend.test", Port: 443}}
	p, _ := startJudgeProxy(t, allow, deny, caCertPEM, caKeyPEM, fj)

	_, connected := connectAndRequest(t, p.Addr().String(), "backend.test", caCertPEM, backendLn.Addr().String(), p)
	if connected {
		t.Fatal("static deny should reject CONNECT with 403")
	}
	if fj.callCount() != 0 {
		t.Fatalf("judge must not be consulted for statically denied requests, got %d calls", fj.callCount())
	}
}

// hasJudgeReason reports whether any stored event has the given decision and
// carries the judge reason in JudgeReason (and never in a body field — Event
// has none).
func hasJudgeReason(store *syncStore, reason, decision string) bool {
	for _, e := range store.snapshot() {
		if e.Decision == decision && e.JudgeReason == reason {
			return true
		}
	}
	return false
}
