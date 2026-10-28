package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// strippedHeaders are the proxy-only and hop-by-hop headers (#396) that must
// never reach the upstream.
var strippedHeaders = []string{
	"Proxy-Authorization", "Proxy-Connection", "X-Warden-Identity",
	"Keep-Alive", "Trailer", "Proxy-Authenticate", "X-Custom",
}

// headerBackend is a TLS backend (h1 + h2 via ALPN) that records the headers of
// the last request it received.
type headerBackend struct {
	mu  sync.Mutex
	got http.Header
	// trailer is r.Trailer after the body was drained; echo, when set, is written
	// as the response body.
	trailer http.Header
	echo    string
	// reqs counts the requests the handler served.
	reqs int
	srv  *httptest.Server
	// hold, when set, parks every handler after it counted the request until the
	// channel is closed; arrived (buffered by the test) is signalled on arrival.
	hold    chan struct{}
	arrived chan struct{}
}

// requests returns how many requests reached the backend.
func (b *headerBackend) requests() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reqs
}

func newHeaderBackend(t *testing.T, grpc bool) *headerBackend {
	t.Helper()
	b := &headerBackend{}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		b.mu.Lock()
		b.got = r.Header.Clone()
		b.reqs++
		b.trailer = r.Trailer.Clone()
		b.mu.Unlock()
		if b.arrived != nil {
			select {
			case b.arrived <- struct{}{}:
			default:
			}
		}
		if b.hold != nil {
			<-b.hold
		}
		if grpc {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
		}
		if b.echo != "" {
			_, _ = io.WriteString(w, b.echo)
		}
		_, _ = io.WriteString(w, "ok")
		if grpc {
			w.Header().Set("Grpc-Status", "0")
		}
	}))
	b.srv.EnableHTTP2 = true
	b.srv.StartTLS()
	t.Cleanup(b.srv.Close)
	return b
}

func (b *headerBackend) trailers() http.Header {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.trailer
}

func (b *headerBackend) headers() http.Header {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.got
}

func startHeaderProxy(t *testing.T, host string, secrets map[string]string, names []string) (*Proxy, []byte) {
	t.Helper()
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	dir := t.TempDir()
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: host, Port: 443},
		}}),
		Secrets:          &fakes.FakeSecretProvider{Values: secrets},
		PlaceholderNames: names,
		Analytics:        &syncStore{},
		AgentID:          "agent",
		CACertPath:       filepath.Join(dir, "ca.crt"),
		CAKeyPath:        filepath.Join(dir, "ca.key"),
	}
	if err := os.WriteFile(cfg.CACertPath, caCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.CAKeyPath, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	waitForAddr(t, p)
	return p, caCertPEM
}

func requireStripped(t *testing.T, got http.Header) {
	t.Helper()
	if got == nil {
		t.Fatal("backend saw no request")
	}
	for _, h := range strippedHeaders {
		if v := got.Values(h); len(v) > 0 {
			t.Errorf("%s reached the upstream: %q", h, v)
		}
	}
}

func TestStripProxyHeaders_H1(t *testing.T) {
	be := newHeaderBackend(t, false)
	addr := strings.TrimPrefix(be.srv.URL, "https://")
	p, caPEM := startHeaderProxy(t, "hdr.test", map[string]string{"PLACEHOLDER_001": "real"}, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
	}
	conn := dialProxyAndConnect(t, p.Addr().String(), "hdr.test", caPEM)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: hdr.test\r\n"+
		"Proxy-Authorization: Bearer PLACEHOLDER_001\r\nProxy-Connection: keep-alive\r\nX-Warden-Identity: test\r\n"+
		"Keep-Alive: timeout=5\r\nTE: trailers\r\nProxy-Authenticate: Basic\r\nTrailer: X-T\r\n"+
		"Connection: keep-alive, X-Custom\r\nX-Custom: secret\r\n"+
		"Authorization: Bearer PLACEHOLDER_001\r\nX-Keep: yes\r\nUser-Agent: ua\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("resp %v err %v", resp, err)
	}
	got := be.headers()
	requireStripped(t, got)
	if v := got.Get("Te"); v != "" {
		t.Errorf("TE reached an h1 upstream: %q", v)
	}
	if got.Get("X-Keep") != "yes" || got.Get("User-Agent") != "ua" {
		t.Errorf("end-to-end headers changed: %v", got)
	}
	if got.Get("Authorization") != "Bearer real" {
		t.Errorf("Authorization = %q, want swapped secret", got.Get("Authorization"))
	}
}

func TestStripProxyHeaders_H2(t *testing.T) {
	be := newHeaderBackend(t, false)
	addr := strings.TrimPrefix(be.srv.URL, "https://")
	p, caPEM := startHeaderProxy(t, "hdr.test", map[string]string{"PLACEHOLDER_001": "real"}, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(_, _ string, _ *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}
	cc := dialGRPCClient(t, p.Addr().String(), "hdr.test", caPEM)
	req, _ := http.NewRequest("GET", "https://hdr.test/x", nil)
	for k, v := range map[string]string{
		"Proxy-Authorization": "Bearer PLACEHOLDER_001", "Proxy-Connection": "keep-alive",
		"X-Warden-Identity": "test", "Keep-Alive": "timeout=5", "Proxy-Authenticate": "Basic",
		"X-Custom": "kept-as-plain-header-no-connection-on-h2", "X-Keep": "yes",
		"Authorization": "Bearer PLACEHOLDER_001",
	} {
		req.Header.Set(k, v)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	got := be.headers()
	for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Warden-Identity", "Keep-Alive", "Proxy-Authenticate"} {
		if v := got.Values(h); len(v) > 0 {
			t.Errorf("%s reached the upstream: %q", h, v)
		}
	}
	if got.Get("X-Keep") != "yes" || got.Get("Authorization") != "Bearer real" {
		t.Errorf("end-to-end headers wrong: %v", got)
	}
}

func TestStripProxyHeaders_GRPCKeepsTETrailers(t *testing.T) {
	be := newHeaderBackend(t, true)
	addr := strings.TrimPrefix(be.srv.URL, "https://")
	p, caPEM := startHeaderProxy(t, "hdr.test", nil, nil)
	p.dialTLS = func(_, _ string, _ *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}
	cc := dialGRPCClient(t, p.Addr().String(), "hdr.test", caPEM)
	req, _ := http.NewRequest("POST", "https://hdr.test/pkg.Svc/M", strings.NewReader("body"))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Proxy-Authorization", "Basic Zm9vOmJhcg==")
	req.Header.Set("X-Warden-Identity", "test")
	req.Header.Set("Grpc-Timeout", "5S")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	if resp.Trailer.Get("Grpc-Status") != "0" {
		t.Errorf("grpc-status trailer = %q", resp.Trailer.Get("Grpc-Status"))
	}
	got := be.headers()
	if got.Get("Te") != "trailers" {
		t.Errorf("TE: trailers dropped for gRPC: %v", got)
	}
	if got.Get("Proxy-Authorization") != "" || got.Get("X-Warden-Identity") != "" {
		t.Errorf("proxy-only headers reached the upstream: %v", got)
	}
	if got.Get("Grpc-Timeout") != "5S" {
		t.Errorf("grpc-timeout lost: %v", got)
	}
}

func TestStripProxyHeaders_WebSocketUpgradeSurvives(t *testing.T) {
	_, _, caCert, caKey := generateTestCA(t)
	b := &wsBackend{reqHeaders: make(chan string, 1)}
	ln := startWSBackend(t, caCert, caKey, b)
	p, caPEM := startHeaderProxy(t, "backend.test", nil, nil)
	p.dialTLS = dialBackend(ln)
	conn := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caPEM)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: backend.test\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade, X-Custom\r\nX-Custom: secret\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\n"+
		"Proxy-Connection: keep-alive\r\nX-Warden-Identity: test\r\nX-Keep: yes\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 101") {
		t.Fatalf("status = %q err %v, want 101", line, err)
	}
	var raw string
	select {
	case raw = <-b.reqHeaders:
	case <-time.After(5 * time.Second):
		t.Fatal("backend saw no upgrade request")
	}
	lower := strings.ToLower(raw)
	for _, h := range []string{"proxy-authorization", "proxy-connection", "x-warden-identity", "x-custom"} {
		if strings.Contains(lower, h+":") {
			t.Errorf("%s reached the upstream:\n%s", h, raw)
		}
	}
	for _, want := range []string{"upgrade: websocket", "connection: upgrade\r\n", "x-keep: yes", "sec-websocket-key:"} {
		if !strings.Contains(lower, want) {
			t.Errorf("upstream upgrade lost %q:\n%s", want, raw)
		}
	}
}

// h1Roundtrip sends raw through a fresh proxy session to be (host hdr.test) and
// returns the proxy and the response.
func h1Roundtrip(t *testing.T, be *headerBackend, secrets map[string]string, names []string, raw string) (*Proxy, *http.Response) {
	t.Helper()
	addr := strings.TrimPrefix(be.srv.URL, "https://")
	p, caPEM := startHeaderProxy(t, "hdr.test", secrets, names)
	p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	}
	conn := dialProxyAndConnect(t, p.Addr().String(), "hdr.test", caPEM)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, raw)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return p, resp
}

func TestStripProxyHeaders_RequestTrailersDenied(t *testing.T) {
	const trailerSection = "Proxy-Authorization: Bearer leaked\r\nX-Warden-Identity: evil\r\n"
	cases := []struct {
		name      string
		declared  bool
		bodyStage bool
	}{
		{"declared/body-stage", true, true},
		{"undeclared/body-stage", false, true},
		{"declared/streamed", true, false},
		{"undeclared/streamed", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newHeaderBackend(t, false)
			var secrets map[string]string
			var names []string
			if tc.bodyStage {
				secrets, names = map[string]string{"PLACEHOLDER_001": "real"}, []string{"PLACEHOLDER_001"}
			}
			decl := ""
			if tc.declared {
				decl = "Trailer: Proxy-Authorization, X-Warden-Identity\r\n"
			}
			raw := "POST /x HTTP/1.1\r\nHost: hdr.test\r\nTransfer-Encoding: chunked\r\n" + decl + "\r\n" +
				"5\r\nhello\r\n0\r\n" + trailerSection + "\r\n"
			p, resp := h1Roundtrip(t, be, secrets, names, raw)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			var denies int
			for _, e := range p.cfg.Analytics.(*syncStore).snapshot() {
				if e.Decision == "deny" && e.Reason == "request_trailers_unsupported" {
					denies++
				}
			}
			if denies != 1 {
				t.Errorf("deny events with request_trailers_unsupported = %d, want 1", denies)
			}
			time.Sleep(200 * time.Millisecond) // let a streamed upstream handler finish
			if tr := be.trailers(); len(tr) > 0 {
				t.Errorf("trailers reached the upstream: %v", tr)
			}
			if got := be.headers(); got != nil && (got.Get("Proxy-Authorization") != "" || got.Get("Trailer") != "") {
				t.Errorf("trailer declaration/values reached the upstream headers: %v", got)
			}
		})
	}
}

func TestStripProxyHeaders_ChunkedWithoutTrailersAllowed(t *testing.T) {
	for _, bodyStage := range []bool{true, false} {
		be := newHeaderBackend(t, false)
		var secrets map[string]string
		var names []string
		if bodyStage {
			secrets, names = map[string]string{"PLACEHOLDER_001": "real"}, []string{"PLACEHOLDER_001"}
		}
		_, resp := h1Roundtrip(t, be, secrets, names, "POST /x HTTP/1.1\r\nHost: hdr.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
		if resp.StatusCode != 200 {
			t.Errorf("bodyStage=%v: status = %d, want 200", bodyStage, resp.StatusCode)
		}
	}
}

// A placeholder whose ONLY occurrence is in Proxy-Authorization must not be
// swapped: the strip runs before swapSecrets, so the secret is never resolved,
// no ref is recorded and the echo guard holds no value (the upstream may echo the
// secret back without being blocked).
func TestStripProxyHeaders_RunsBeforeSwap(t *testing.T) {
	be := newHeaderBackend(t, false)
	be.echo = "real-secret-value"
	p, resp := h1Roundtrip(t, be, map[string]string{"PLACEHOLDER_001": "real-secret-value"}, []string{"PLACEHOLDER_001"},
		"GET /x HTTP/1.1\r\nHost: hdr.test\r\nProxy-Authorization: Bearer PLACEHOLDER_001\r\n\r\n")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "real-secret-value") {
		t.Fatalf("status = %d body %q: echo guard fired, so the placeholder was swapped before the strip", resp.StatusCode, body)
	}
	store := p.cfg.Analytics.(*syncStore)
	for end := time.Now().Add(3 * time.Second); len(store.snapshot()) == 0 && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond) // the allow event is stored after the response is relayed
	}
	var seen int
	for _, e := range store.snapshot() {
		if e.Decision != "allow" {
			t.Errorf("unexpected %s event reason %q", e.Decision, e.Reason)
		}
		seen++
		if len(e.SwappedRefs) > 0 || e.SecretRef != "" {
			t.Errorf("event records a swap: refs %v secretRef %q", e.SwappedRefs, e.SecretRef)
		}
	}
	if seen == 0 {
		t.Fatal("no event recorded")
	}
	if got := be.headers(); got.Get("Proxy-Authorization") != "" {
		t.Errorf("Proxy-Authorization reached the upstream: %q", got.Get("Proxy-Authorization"))
	}
}

func TestStripHopHeaders_Variants(t *testing.T) {
	cases := []struct {
		name string
		in   []string // raw header lines
		gone []string
		keep string
	}{
		{"case variants", []string{"proxy-AUTHORIZATION: a", "X-WARDEN-identity: b", "keep-ALIVE: 5", "tRaIlEr: x", "CONNECTION: close, x-Custom", "X-CUSTOM: c"},
			[]string{"Proxy-Authorization", "X-Warden-Identity", "Keep-Alive", "Trailer", "X-Custom"}, "X-Keep"},
		{"duplicate Connection lines", []string{"Connection: keep-alive", "Connection: X-One", "connection: X-Two", "X-One: 1", "X-Two: 2"},
			[]string{"X-One", "X-Two"}, "X-Keep"},
		{"obs-fold Connection", []string{"Connection: keep-alive,\r\n X-Folded", "X-Folded: 1"},
			[]string{"X-Folded"}, "X-Keep"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newHeaderBackend(t, false)
			raw := "GET /x HTTP/1.1\r\nHost: hdr.test\r\nX-Keep: yes\r\n" + strings.Join(tc.in, "\r\n") + "\r\n\r\n"
			_, resp := h1Roundtrip(t, be, nil, nil, raw)
			if resp.StatusCode != 200 {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			got := be.headers()
			for _, h := range tc.gone {
				if v := got.Values(h); len(v) > 0 {
					t.Errorf("%s reached the upstream: %q", h, v)
				}
			}
			if got.Get(tc.keep) != "yes" {
				t.Errorf("%s lost: %v", tc.keep, got)
			}
		})
	}
}

func TestStripProxyHeaders_WebSocketTokenShapes(t *testing.T) {
	for _, tc := range []struct{ name, hdrs string }{
		{"no upgrade token in Connection", "Upgrade: websocket\r\nConnection: keep-alive\r\n"},
		{"upgrade list with h2c", "Upgrade: websocket, h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n"},
		{"mixed case", "Upgrade: WebSocket\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, caCert, caKey := generateTestCA(t)
			b := &wsBackend{reqHeaders: make(chan string, 1)}
			ln := startWSBackend(t, caCert, caKey, b)
			p, caPEM := startHeaderProxy(t, "backend.test", nil, nil)
			p.dialTLS = dialBackend(ln)
			conn := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caPEM)
			t.Cleanup(func() { _ = conn.Close() })
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: backend.test\r\n"+tc.hdrs+
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "HTTP/1.1 101") {
				t.Fatalf("status = %q err %v, want 101", line, err)
			}
			raw := strings.ToLower(<-b.reqHeaders)
			for _, want := range []string{"upgrade: websocket\r\n", "connection: upgrade\r\n"} {
				if !strings.Contains(raw, want) {
					t.Errorf("upstream upgrade lost %q:\n%s", want, raw)
				}
			}
			if strings.Contains(raw, "h2c") || strings.Contains(raw, "http2-settings") {
				t.Errorf("non-websocket upgrade token leaked:\n%s", raw)
			}
		})
	}
}

func BenchmarkStripHopHeaders(b *testing.B) {
	p := &Proxy{}
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "https://hdr.test/x", nil)
		for k, v := range map[string]string{
			"Proxy-Authorization": "Bearer x", "Proxy-Connection": "keep-alive", "X-Warden-Identity": "t",
			"Keep-Alive": "5", "TE": "trailers", "Connection": "keep-alive, X-Custom", "X-Custom": "c",
			"Authorization": "Bearer y", "User-Agent": "ua", "Accept": "*/*",
		} {
			req.Header.Set(k, v)
		}
		p.stripHopHeaders(&requestScope{req: req})
	}
}
