package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// startConstraintProxy is startTestProxyWithSecrets for a fully-specified
// allowlist: entries carry their own ports and #371 method/path constraints.
func startConstraintProxy(t testing.TB, entries []config.AllowlistEntry, caCertPEM, caKeyPEM []byte, secretValues map[string]string, placeholderNames []string) (*Proxy, *syncStore) {
	t.Helper()
	store := &syncStore{}
	cfg := Config{
		ListenAddr:       "127.0.0.1:0",
		Policy:           policy.NewEvaluator(config.Policy{Allowlist: entries}),
		Secrets:          &fakes.FakeSecretProvider{Values: secretValues},
		Analytics:        store,
		PlaceholderNames: placeholderNames,
	}
	if len(caCertPEM) > 0 {
		certFile := filepath.Join(t.TempDir(), "ca.crt")
		keyFile := filepath.Join(t.TempDir(), "ca.key")
		if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, caKeyPEM, 0600); err != nil {
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

// TestConstraint_DeniedMethodNeverReachesBackend (#371): a POST against a
// GET-only entry is denied before the swap and before any upstream write.
func TestConstraint_DeniedMethodNeverReachesBackend(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	p, store := startConstraintProxy(t,
		[]config.AllowlistEntry{{Domain: "backend.test", Port: 443, Methods: []string{"GET"}}},
		caCertPEM, caKeyPEM,
		map[string]string{"PLACEHOLDER_001": scopeReal}, []string{"PLACEHOLDER_001"})
	p.dialTLS = dialBackend(backendLn)

	c := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("POST", "https://backend.test/v1/chat", strings.NewReader(`{"k":"PLACEHOLDER_001"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	time.Sleep(50 * time.Millisecond)
	// The backend never saw the request — so it never saw the real secret.
	rb.mu.Lock()
	saw := rb.method + rb.path + rb.body + fmtHeaders(rb.headers)
	rb.mu.Unlock()
	if strings.Contains(saw, scopeReal) || rb.method == "POST" {
		t.Fatalf("backend saw the denied request: method=%q path=%q", rb.method, rb.path)
	}
	// The deny is an analytics decision carrying method + path, and no swap.
	var deny bool
	for _, e := range store.snapshot() {
		if e.Decision == "deny" && e.Protocol == "https" {
			deny = true
			if e.Method != "POST" || !strings.Contains(e.URL, "/v1/chat") {
				t.Fatalf("deny event missing method/path: %+v", e)
			}
			if e.SecretRef != "" {
				t.Fatalf("deny event carries a swap record: %+v", e)
			}
			if eventContains(t, e, scopeReal) {
				t.Fatalf("deny event leaks secret: %+v", e)
			}
		}
	}
	if !deny {
		t.Fatalf("no https deny event: %+v", store.snapshot())
	}
}

// TestConstraint_DeniedPathNeverReachesBackend: a path-confused target is
// denied even though it string-matches the pattern.
func TestConstraint_DeniedPathNeverReachesBackend(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	p, store := startConstraintProxy(t,
		[]config.AllowlistEntry{{Domain: "backend.test", Port: 443, Paths: []string{"/acme/app/*"}}},
		caCertPEM, caKeyPEM, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	for _, target := range []string{"/acme/app/../evil", "/acme/other", "/acme/app%2f..%2fevil"} {
		c := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
		req, _ := http.NewRequest("GET", "https://backend.test"+target, nil)
		if err := req.Write(c); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("%s: status = %d, want 403", target, resp.StatusCode)
		}
	}
	time.Sleep(50 * time.Millisecond)
	rb.mu.Lock()
	saw := rb.method + rb.path
	rb.mu.Unlock()
	if saw != "" {
		t.Fatalf("backend saw a denied request: %q", saw)
	}
	var reasons []string
	for _, e := range store.snapshot() {
		if e.Decision == "deny" {
			reasons = append(reasons, e.Reason)
		}
	}
	if len(reasons) != 3 {
		t.Fatalf("deny events = %v, want 3", reasons)
	}
}

// TestConstraint_MatrixParamPathNeverReachesBackend (#371 review): matrix
// parameters (";params", raw or %3b-encoded) are stripped per segment by Java
// servers (Tomcat, Jetty, Spring), so "/v1/..;/admin" is "/admin" upstream —
// traversal through a path that string-matches "/v1/*". Fail closed: such a
// path is denied (path_not_canonical) and never reaches the backend.
func TestConstraint_MatrixParamPathNeverReachesBackend(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	p, store := startConstraintProxy(t,
		[]config.AllowlistEntry{{Domain: "backend.test", Port: 443, Paths: []string{"/v1/*"}}},
		caCertPEM, caKeyPEM, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	for _, target := range []string{"/v1/..;/admin", "/v1/.;/admin", "/v1/..%3b/y", "/v1/x%3B"} {
		c := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
		req, _ := http.NewRequest("GET", "https://backend.test"+target, nil)
		if err := req.Write(c); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("%s: status = %d, want 403", target, resp.StatusCode)
		}
	}
	time.Sleep(50 * time.Millisecond)
	rb.mu.Lock()
	saw := rb.method + rb.path
	rb.mu.Unlock()
	if saw != "" {
		t.Fatalf("backend saw a denied request: %q", saw)
	}
	var denies int
	for _, e := range store.snapshot() {
		if e.Decision == "deny" {
			denies++
			if e.Reason != "path_not_canonical" {
				t.Fatalf("deny reason = %q, want path_not_canonical: %+v", e.Reason, e)
			}
		}
	}
	if denies != 4 {
		t.Fatalf("deny events = %d, want 4", denies)
	}
}

// TestConstraint_AllowedRequestStillSwaps: the positive case of the same
// policy — a constraint-satisfying request is forwarded and swapped.
func TestConstraint_AllowedRequestStillSwaps(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	p, _ := startConstraintProxy(t,
		[]config.AllowlistEntry{{Domain: "backend.test", Port: 443, Methods: []string{"GET"}, Paths: []string{"/v1/*"}}},
		caCertPEM, caKeyPEM,
		map[string]string{"PLACEHOLDER_001": scopeReal}, []string{"PLACEHOLDER_001"})
	p.dialTLS = dialBackend(backendLn)

	c := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
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
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	rb.mu.Lock()
	auth := rb.headers.Get("Authorization")
	rb.mu.Unlock()
	if auth != "Bearer "+scopeReal {
		t.Fatalf("backend Authorization = %q, want swapped", auth)
	}
}

// TestConstraint_PathMatchedRawNotDecoded (#371 review): the path constraint
// matches the RAW request-target bytes (req.URL.EscapedPath()), never the
// decoded URL.Path. An exact `/v1/a` pattern does not admit `/v1/%61` — a
// different path as sent — and the deny happens before any upstream write.
// Guards constraintGate regressing from EscapedPath() to the decoded URL.Path.
func TestConstraint_PathMatchedRawNotDecoded(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	p, store := startConstraintProxy(t,
		[]config.AllowlistEntry{{Domain: "backend.test", Port: 443, Paths: []string{"/v1/a"}}},
		caCertPEM, caKeyPEM, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	c := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("GET", "https://backend.test/v1/%61", nil)
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403 (raw byte match, not decoded)", resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	rb.mu.Lock()
	saw := rb.method + rb.path
	rb.mu.Unlock()
	if saw != "" {
		t.Fatalf("backend saw the denied request: %q", saw)
	}
	var denies int
	for _, e := range store.snapshot() {
		if e.Decision == "deny" {
			denies++
			if e.Reason != "path_not_allowed" {
				t.Fatalf("deny reason = %q, want path_not_allowed: %+v", e.Reason, e)
			}
		}
	}
	if denies != 1 {
		t.Fatalf("deny events = %d, want 1", denies)
	}
}

// TestConstraint_KeepAliveSecondRequestDenied (#371): the per-request check
// runs on every request of a keep-alive tunnel, not once per CONNECT. Request 1
// is allowed; request 2 on the SAME tunnel is denied and ends the session.
func TestConstraint_KeepAliveSecondRequestDenied(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	p, store := startConstraintProxy(t,
		[]config.AllowlistEntry{{Domain: "backend.test", Port: 443, Methods: []string{"GET"}}},
		caCertPEM, caKeyPEM, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	// ONE tunnel, two requests.
	c := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	br := bufio.NewReader(c)

	req1, _ := http.NewRequest("GET", "https://backend.test/v1/req1", nil)
	if err := req1.Write(c); err != nil {
		t.Fatal(err)
	}
	resp1, err := http.ReadResponse(br, req1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != 200 {
		t.Fatalf("req1 = %d, want 200", resp1.StatusCode)
	}

	req2, _ := http.NewRequest("POST", "https://backend.test/v1/req2", nil)
	if err := req2.Write(c); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.ReadResponse(br, req2)
	if err != nil {
		t.Fatalf("req2 read: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != 403 {
		t.Fatalf("req2 = %d, want 403", resp2.StatusCode)
	}

	time.Sleep(50 * time.Millisecond)
	rb.mu.Lock()
	gotMethod, gotPath := rb.method, rb.path
	rb.mu.Unlock()
	if gotMethod != "GET" || gotPath != "/v1/req1" {
		t.Fatalf("backend saw %q %q; the denied second request must never arrive", gotMethod, gotPath)
	}
	var denies int
	for _, e := range store.snapshot() {
		if e.Decision == "deny" && e.Method == "POST" {
			denies++
		}
	}
	if denies != 1 {
		t.Fatalf("POST deny events = %d, want 1", denies)
	}
}

// TestConstraint_HTTP2Parity (#371 addendum): the :method and :path
// pseudo-headers flow through the same constraint check on the HTTP/2 path —
// before the metadata swap, before the upstream write.
func TestConstraint_HTTP2Parity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		method  string
		path    string
		want    int
		denyURL string
	}{
		{"allowed method+path", "POST", "/allowed/x", 200, ""},
		{"disallowed method", "GET", "/allowed/x", 403, "/allowed/x"},
		{"disallowed path", "POST", "/denied/x", 403, "/denied/x"},
		// Matrix parameters: h2 carries them raw in :path, so the same
		// fail-closed semicolon deny applies (path_not_canonical).
		{"matrix traversal", "POST", "/allowed/..;/admin", 403, "/allowed/..;/admin"},
		{"encoded matrix param", "POST", "/allowed/x%3b", 403, "/allowed/x%3b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
			be := startGRPCBackend(t)
			backendAddr := strings.TrimPrefix(be.server.URL, "https://")
			p, store := startConstraintProxy(t,
				[]config.AllowlistEntry{{Domain: "grpc.test", Port: 443, Methods: []string{"POST"}, Paths: []string{"/allowed/*"}}},
				caCertPEM, caKeyPEM,
				map[string]string{"PLACEHOLDER_001": scopeReal}, []string{"PLACEHOLDER_001"})
			p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
				return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
			}

			cc := dialGRPCClient(t, p.Addr().String(), "grpc.test", caCertPEM)
			var body io.Reader
			if tc.method == "POST" {
				body = strings.NewReader("body")
			}
			req, _ := http.NewRequest(tc.method, "https://grpc.test"+tc.path, body)
			req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			time.Sleep(50 * time.Millisecond)
			if tc.want == 403 {
				if strings.Contains(be.gotPath, tc.denyURL) {
					t.Fatalf("backend saw the denied request: %q", be.gotPath)
				}
				if strings.Contains(be.gotAuth, scopeReal) {
					t.Fatalf("real secret attached to a denied request: %q", be.gotAuth)
				}
				var deny bool
				for _, e := range store.snapshot() {
					if e.Decision == "deny" {
						deny = true
						if e.Method != tc.method || !strings.Contains(e.URL, tc.denyURL) {
							t.Fatalf("deny event missing method/path: %+v", e)
						}
					}
				}
				if !deny {
					t.Fatalf("no deny event: %+v", store.snapshot())
				}
				return
			}
			if be.gotAuth != "Bearer "+scopeReal {
				t.Fatalf("backend Authorization = %q, want swapped", be.gotAuth)
			}
		})
	}
}

// TestConstraint_HTTP2_PathMatchedRawNotDecoded: the same raw-byte guarantee on
// the HTTP/2 gate — the :path component as sent (r.URL.EscapedPath()) is what
// `paths` matches, never the decoded r.URL.Path. An exact `/v1/a` pattern does
// not admit a request sent as `/v1/%61`.
func TestConstraint_HTTP2_PathMatchedRawNotDecoded(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	be := startGRPCBackend(t)
	backendAddr := strings.TrimPrefix(be.server.URL, "https://")
	p, store := startConstraintProxy(t,
		[]config.AllowlistEntry{{Domain: "grpc.test", Port: 443, Methods: []string{"POST"}, Paths: []string{"/v1/a"}}},
		caCertPEM, caKeyPEM, nil, nil)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}

	cc := dialGRPCClient(t, p.Addr().String(), "grpc.test", caCertPEM)
	req, _ := http.NewRequest("POST", "https://grpc.test/v1/%61", strings.NewReader("body"))
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403 (raw :path match, not decoded)", resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	if be.gotPath != "" {
		t.Fatalf("backend saw the denied request: %q", be.gotPath)
	}
	var deny bool
	for _, e := range store.snapshot() {
		if e.Decision == "deny" {
			deny = true
			if e.Reason != "path_not_allowed" {
				t.Fatalf("deny reason = %q, want path_not_allowed: %+v", e.Reason, e)
			}
		}
	}
	if !deny {
		t.Fatalf("no deny event: %+v", store.snapshot())
	}
}

// TestConstraint_WebSocketUpgradeDenied: the upgrade request is an enforcement
// point — a constrained path denies the handshake before any upstream write.
func TestConstraint_WebSocketUpgradeDenied(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	p, store := startConstraintProxy(t,
		[]config.AllowlistEntry{{Domain: "backend.test", Port: 443, Paths: []string{"/allowed/*"}}},
		caCertPEM, caKeyPEM, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	c := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("GET", "https://backend.test/denied/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("upgrade status = %d, want 403", resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	rb.mu.Lock()
	saw := rb.method + rb.path
	rb.mu.Unlock()
	if saw != "" {
		t.Fatalf("backend saw the denied upgrade: %q", saw)
	}
	var deny bool
	for _, e := range store.snapshot() {
		if e.Decision == "deny" && strings.Contains(e.URL, "/denied/ws") {
			deny = true
		}
	}
	if !deny {
		t.Fatalf("no deny event for the upgrade request: %+v", store.snapshot())
	}
}
