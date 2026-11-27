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

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

const costDomain = "api.openai.com"

// costEvent drives one POST through a proxy that prices api.openai.com against a
// backend replying with respBody (chunked or fixed-length) and returns the
// recorded allow event for the given protocol.
func costEvent(t *testing.T, ct, reqBody, respBody string, chunked bool, proto string) analytics.Event {
	t.Helper()
	return costEventReq(t, ct, reqBody, false, respBody, chunked, proto)
}

// costEventReq is costEvent with a choice of request framing: chunkedReq sends
// the request with Transfer-Encoding: chunked (ContentLength -1).
func costEventReq(t *testing.T, ct, reqBody string, chunkedReq bool, respBody string, chunked bool, proto string) analytics.Event {
	t.Helper()
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	rb := &mcpBackend{respStatus: 200, respCT: ct, respBody: respBody, chunked: chunked}
	backendLn := startMCPBackend(t, caCert, caKey, rb)
	p, ss := startTestProxyWithMCP(t, []string{costDomain}, caCertPEM, caKeyPEM, enforceMCPConfig(), nil)
	p.cfg.Cost = cost.NewEstimator()
	p.dialTLS = dialBackend(backendLn)

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), costDomain, caCertPEM)
	req, _ := http.NewRequest("POST", "https://"+costDomain+"/v1/x", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(reqBody))
	if chunkedReq {
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	}
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil || len(got) != len(respBody) {
		t.Fatalf("relay: read %d of %d bytes, err=%v", len(got), len(respBody), err)
	}
	_ = resp.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e := findEvent(ss.snapshot(), proto, "allow"); e != nil {
			return *e
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s allow event: %+v", proto, ss.snapshot())
	return analytics.Event{}
}

func TestCost_ChunkedResponseCounted(t *testing.T) {
	body := strings.Repeat("x", 40000)
	chunked := costEvent(t, "text/plain", `{"q":1}`, body, true, "https")
	if chunked.CostUSD <= 0 || chunked.Provider != "openai" {
		t.Fatalf("chunked response priced at %v (provider %q), want > 0", chunked.CostUSD, chunked.Provider)
	}
	// The counted bytes price exactly like the same message with a Content-Length.
	fixed := costEvent(t, "text/plain", `{"q":1}`, body, false, "https")
	if chunked.CostUSD != fixed.CostUSD {
		t.Fatalf("chunked cost %v != fixed-length cost %v", chunked.CostUSD, fixed.CostUSD)
	}
}

func TestCost_FixedLengthUnchanged(t *testing.T) {
	body := strings.Repeat("x", 40000)
	reqBody := `{"q":1}`
	e := costEvent(t, "text/plain", reqBody, body, false, "https")
	want := cost.NewEstimator().Estimate(costDomain, int64(len(reqBody)), 40000)
	if want == nil || e.CostUSD != want.TotalCost {
		t.Fatalf("fixed-length cost %v, want %v", e.CostUSD, want)
	}
}

func TestCost_SSEResponseCounted(t *testing.T) {
	var sb strings.Builder
	for sb.Len() < 40000 {
		sb.WriteString(sseEvent(`{"jsonrpc":"2.0","id":"0","result":{}}`))
	}
	sseBody := sb.String()
	e := costEvent(t, "text/event-stream", mcpToolsList, sseBody, true, "mcp")
	// Exact: the fixed-length request alone would already make the cost positive,
	// so only the full value proves the streamed response bytes were counted.
	want := cost.NewEstimator().Estimate(costDomain, int64(len(mcpToolsList)), int64(len(sseBody)))
	if e.CostUSD != want.TotalCost || e.Provider != "openai" {
		t.Fatalf("SSE cost %v (provider %q), want %v", e.CostUSD, e.Provider, want.TotalCost)
	}
}

// TestCost_ChunkedRequestCounted: a chunked h1 upload (request ContentLength -1)
// through the normal stage pipeline is priced from the bytes relayed upstream.
func TestCost_ChunkedRequestCounted(t *testing.T) {
	reqBody := strings.Repeat("q", 40000)
	respBody := strings.Repeat("x", 4000)
	e := costEventReq(t, "text/plain", reqBody, true, respBody, false, "https")
	want := cost.NewEstimator().Estimate(costDomain, 40000, 4000)
	if e.CostUSD != want.TotalCost || e.Provider != "openai" {
		t.Fatalf("chunked request cost %v (provider %q), want %v", e.CostUSD, e.Provider, want.TotalCost)
	}
}

func TestCountingReadCloser(t *testing.T) {
	var c countingReadCloser
	r := c.wrap(io.NopCloser(strings.NewReader("hello world")))
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatal(err)
	}
	if c.count() != 11 {
		t.Fatalf("count = %d, want 11", c.count())
	}
}

// BenchmarkHTTPCountingWrap pins the per-request cost of the byte counters: the
// wrapper lives in requestScope, so wrapping and reading allocate nothing.
func BenchmarkHTTPCountingWrap(b *testing.B) {
	payload := strings.Repeat("x", 4096)
	buf := make([]byte, 512)
	s := &requestScope{}
	src := strings.NewReader(payload)
	closer := io.NopCloser(src)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		src.Reset(payload)
		rc := s.respCount.wrap(closer)
		for {
			if _, err := rc.Read(buf); err != nil {
				break
			}
		}
	}
}

// TestCost_GRPCStreamCounted: an h2 gRPC call whose response has no
// Content-Length (a server stream) is priced from the bytes relayed, and its
// allow event carries the provider.
func TestCost_GRPCStreamCounted(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	chunk := strings.Repeat("y", 10000)
	be := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		for i := 0; i < 4; i++ {
			_, _ = io.WriteString(w, chunk)
			w.(http.Flusher).Flush()
		}
	}))
	be.EnableHTTP2 = true
	be.StartTLS()
	t.Cleanup(be.Close)

	store := &syncStore{}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: costDomain, Port: 443},
		}}),
		Secrets:   &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics: store,
		AgentID:   "agent",
		Cost:      cost.NewEstimator(),
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
	backendAddr := strings.TrimPrefix(be.URL, "https://")
	p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
	}

	req, _ := http.NewRequest("POST", "https://"+costDomain+"/pkg.Svc/Stream", strings.NewReader(strings.Repeat("r", 2000)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := dialGRPCClient(t, p.Addr().String(), costDomain, caCertPEM).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if len(got) != 40000 {
		t.Fatalf("relayed %d bytes, want 40000", len(got))
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e := findEvent(store.snapshot(), "grpc", "allow"); e != nil {
			want := cost.NewEstimator().Estimate(costDomain, 2000, 40000)
			if e.CostUSD != want.TotalCost || e.Provider != "openai" {
				t.Fatalf("grpc event cost %v provider %q, want %v openai", e.CostUSD, e.Provider, want.TotalCost)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no grpc allow event: %+v", store.snapshot())
}
