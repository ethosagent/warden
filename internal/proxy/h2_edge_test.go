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
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// waitEvents polls the store until it holds at least n events or a deadline
// passes, then returns a snapshot. Events are written by the handler goroutine,
// possibly after the client has its response.
func waitEvents(t *testing.T, store *syncStore, n int) []analytics.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(store.snapshot()) < n && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	return store.snapshot()
}

// startEdgeProxy starts a proxy allowing parityHost:443 whose upstream hop goes to
// the given parity backend; configure may adjust the config before New.
func startEdgeProxy(t *testing.T, be *parityBackend, configure func(*Config)) (*Proxy, *syncStore, []byte) {
	t.Helper()
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	store := &syncStore{}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: parityHost, Port: 443},
		}}),
		Secrets:   &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics: store,
		AgentID:   "agent",
	}
	dir := t.TempDir()
	cfg.CACertPath = filepath.Join(dir, "ca.crt")
	cfg.CAKeyPath = filepath.Join(dir, "ca.key")
	if err := os.WriteFile(cfg.CACertPath, caCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.CAKeyPath, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(&cfg)
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
	backendAddr := strings.TrimPrefix(be.srv.URL, "https://")
	p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
	}
	return p, store, caCertPEM
}

func requireSingleDeny(t *testing.T, evs []analytics.Event, reason string) {
	t.Helper()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want exactly 1: %+v", len(evs), evs)
	}
	if evs[0].Decision != "deny" || evs[0].Reason != reason {
		t.Fatalf("event = decision %q reason %q, want deny %q", evs[0].Decision, evs[0].Reason, reason)
	}
}

// An h2 request that declares trailers is refused (400 + one deny event) instead
// of having them silently dropped, and never reaches the origin.
func TestH2_RequestTrailersDenied(t *testing.T) {
	be := newParityBackend(t, "text/plain", "ok")
	p, store, caPEM := startEdgeProxy(t, be, nil)

	req, _ := http.NewRequest("POST", "https://"+parityHost+"/up", strings.NewReader("payload"))
	req.Trailer = http.Header{"X-Checksum": nil}
	req.Body = &trailerBody{Reader: strings.NewReader("payload"), req: req}
	resp, err := dialGRPCClient(t, p.Addr().String(), parityHost, caPEM).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	requireSingleDeny(t, waitEvents(t, store, 1), "h2_request_trailers_unsupported")
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.got) != 0 {
		t.Fatalf("request reached the origin: %+v", be.got)
	}
}

// trailerBody sets the declared trailer value once the body has been read.
type trailerBody struct {
	io.Reader
	req *http.Request
}

func (b *trailerBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		b.req.Trailer.Set("X-Checksum", "abc")
	}
	return n, err
}
func (b *trailerBody) Close() error { return nil }

// Response trailers (gRPC grpc-status) keep working end to end.
func TestH2_ResponseTrailersStillRelayed(t *testing.T) {
	be := newParityBackend(t, "application/grpc", "grpc-response-body")
	p, store, caPEM := startEdgeProxy(t, be, nil)

	req, _ := http.NewRequest("POST", "https://"+parityHost+"/svc/Method", strings.NewReader("req"))
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := dialGRPCClient(t, p.Addr().String(), parityHost, caPEM).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "grpc-response-body" {
		t.Fatalf("status/body = %d %q", resp.StatusCode, body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer = %q, want 0", got)
	}
	evs := waitEvents(t, store, 1)
	if len(evs) != 1 || evs[0].Decision != "allow" {
		t.Fatalf("events = %+v, want one allow", evs)
	}
}

// RFC 8441 extended CONNECT: x/net does not advertise
// SETTINGS_ENABLE_CONNECT_PROTOCOL by default, but if a client sends :protocol
// anyway (GODEBUG=http2xconnect=1) the stream is refused with 501 + a deny event.
// Go's client cannot send extended CONNECT, so this drives the handler directly.
func TestH2_ExtendedConnectRefused(t *testing.T) {
	be := newParityBackend(t, "text/plain", "ok")
	p, store, _ := startEdgeProxy(t, be, nil)

	r := httptest.NewRequest("CONNECT", "https://"+parityHost+"/chat", nil)
	r.Host = parityHost
	r.Header.Set(":protocol", "websocket")
	w := httptest.NewRecorder()
	p.serveGRPCStream(w, r, &http2.Transport{}, parityHost, 443, deferNone, connIdentity{}, nil) //nolint:staticcheck // SA1019: same transport type the production path uses

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
	requireSingleDeny(t, store.snapshot(), "h2_extended_connect_unsupported")
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.got) != 0 {
		t.Fatalf("request reached the origin: %+v", be.got)
	}
}

// A streamed (gRPC) request to a destination with a body-reading transformer is
// refused (501 + deny event) rather than buffered, and never reaches the origin.
func TestH2_StreamBodyTransformerNeedsBodyDenied(t *testing.T) {
	be := newParityBackend(t, "application/grpc", "x")
	hm, err := auth.NewHMACSigner([]byte("k"), "X-Sig", "sha256")
	if err != nil {
		t.Fatal(err)
	}
	p, store, caPEM := startEdgeProxy(t, be, func(cfg *Config) {
		mt, _ := auth.NewMatchedTransformer(parityHost, hm)
		cfg.Transformers = []*auth.MatchedTransformer{mt}
	})
	req, _ := http.NewRequest("POST", "https://"+parityHost+"/svc/Method", strings.NewReader("req"))
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := dialGRPCClient(t, p.Addr().String(), parityHost, caPEM).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	requireSingleDeny(t, waitEvents(t, store, 1), "transform_needs_buffered_body")
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.got) != 0 {
		t.Fatalf("request reached the origin: %+v", be.got)
	}
}

// A header-only transformer still runs on a streamed request, and a body-reading
// one still runs on a non-streamed (buffered) h2 request.
func TestH2_StreamBodyHeaderOnlyTransformerRuns(t *testing.T) {
	be := newParityBackend(t, "application/grpc", "x")
	ak, err := auth.NewAPIKeyInjector("header", "X-Api-Key", "real-key")
	if err != nil {
		t.Fatal(err)
	}
	p, store, caPEM := startEdgeProxy(t, be, func(cfg *Config) {
		mt, _ := auth.NewMatchedTransformer(parityHost, ak)
		cfg.Transformers = []*auth.MatchedTransformer{mt}
	})
	req, _ := http.NewRequest("POST", "https://"+parityHost+"/svc/Method", strings.NewReader("req"))
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := dialGRPCClient(t, p.Addr().String(), parityHost, caPEM).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	be.mu.Lock()
	got := append([]parityUpstream(nil), be.got...)
	be.mu.Unlock()
	if len(got) != 1 || got[0].APIKey != "real-key" {
		t.Fatalf("upstream = %+v, want X-Api-Key injected", got)
	}
	if evs := waitEvents(t, store, 1); len(evs) != 1 || evs[0].Decision != "allow" {
		t.Fatalf("events = %+v, want one allow", evs)
	}
}

func TestH2_NonStreamBodyTransformerStillBuffers(t *testing.T) {
	be := newParityBackend(t, "text/plain", "ok")
	hm, err := auth.NewHMACSigner([]byte("k"), "X-Sig", "sha256")
	if err != nil {
		t.Fatal(err)
	}
	p, _, caPEM := startEdgeProxy(t, be, func(cfg *Config) {
		mt, _ := auth.NewMatchedTransformer(parityHost, hm)
		cfg.Transformers = []*auth.MatchedTransformer{mt}
	})
	req, _ := http.NewRequest("POST", "https://"+parityHost+"/post", strings.NewReader("body"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := dialGRPCClient(t, p.Addr().String(), parityHost, caPEM).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// A Host/:authority that differs from the CONNECT host records a host_mismatch
// deny event on both protocols (h2 also answers 421; h1 keeps closing the session).
func TestHostMismatch_DenyEvent_H2(t *testing.T) {
	be := newParityBackend(t, "text/plain", "ok")
	p, store, caPEM := startEdgeProxy(t, be, nil)
	req, _ := http.NewRequest("GET", "https://"+parityHost+"/x", nil)
	req.Host = "evil.test"
	resp, err := dialGRPCClient(t, p.Addr().String(), parityHost, caPEM).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", resp.StatusCode)
	}
	requireSingleDeny(t, waitEvents(t, store, 1), "host_mismatch")
}

func TestHostMismatch_DenyEvent_H1(t *testing.T) {
	be := newParityBackend(t, "text/plain", "ok")
	p, store, caPEM := startEdgeProxy(t, be, nil)
	c := dialProxyAndConnect(t, p.Addr().String(), parityHost, caPEM)
	req, _ := http.NewRequest("GET", "https://"+parityHost+"/x", nil)
	req.Host = "evil.test"
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, bufio.NewReader(c)) // session is closed by the proxy
	requireSingleDeny(t, waitEvents(t, store, 1), "host_mismatch")
}
