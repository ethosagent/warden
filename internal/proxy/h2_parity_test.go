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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/test/fakes"
)

// parityUpstream is what the recording backend saw for one request.
type parityUpstream struct {
	Method, URI, Body, Auth, APIKey string
}

// parityBackend is a TLS backend that speaks both HTTP/1.1 and HTTP/2 (ALPN) and
// records the request it received, so the same request can be sent over either
// client protocol and the upstream bytes compared.
type parityBackend struct {
	mu       sync.Mutex
	got      []parityUpstream
	respCT   string
	respBody string
	srv      *httptest.Server
}

func newParityBackend(t *testing.T, respCT, respBody string) *parityBackend {
	t.Helper()
	b := &parityBackend{respCT: respCT, respBody: respBody}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		b.got = append(b.got, parityUpstream{
			Method: r.Method, URI: r.URL.RequestURI(), Body: string(body),
			Auth: r.Header.Get("Authorization"), APIKey: r.Header.Get("X-Api-Key"),
		})
		b.mu.Unlock()
		if b.respCT != "" {
			w.Header().Set("Content-Type", b.respCT)
		}
		if strings.HasPrefix(b.respCT, "application/grpc") {
			w.Header().Set("Trailer", "Grpc-Status")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b.respBody)))
		_, _ = io.WriteString(w, b.respBody)
		if strings.HasPrefix(b.respCT, "application/grpc") {
			w.Header().Set("Grpc-Status", "0")
		}
	}))
	b.srv.EnableHTTP2 = true
	b.srv.StartTLS()
	t.Cleanup(b.srv.Close)
	return b
}

// parityCase is one request sent over both protocols through a fresh proxy.
type parityCase struct {
	name        string
	configure   func(t *testing.T, cfg *Config)
	allowHost   string // host in the allowlist ("" = the request host, i.e. statically allowed)
	method      string
	path        string
	contentType string
	body        string
	headers     map[string]string
	respCT      string
	respBody    string
	wantStatus  int
	// wantEvents is the number of events each protocol must produce.
	wantEvents int
}

// parityResult is the observable outcome of one protocol run.
type parityResult struct {
	Status   int
	Resp     string
	Upstream []parityUpstream
	Events   []analytics.Event
}

const parityHost = "parity.test"

// normEvent strips the fields that legitimately differ between runs (time,
// latency) and maps the protocol label onto the family it belongs to: h1 events
// are "https", h2 events "http2" ("grpc" for gRPC), MCP is "mcp" on both.
func normEvent(e analytics.Event) analytics.Event {
	e.Timestamp = time.Time{}
	e.LatencyMs = 0
	switch e.Protocol {
	case "https", "http2":
		e.Protocol = "http"
	}
	return e
}

func runParity(t *testing.T, tc parityCase, h2 bool) parityResult {
	t.Helper()
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	be := newParityBackend(t, tc.respCT, tc.respBody)
	backendAddr := strings.TrimPrefix(be.srv.URL, "https://")

	allow := tc.allowHost
	if allow == "" {
		allow = parityHost
	}
	store := &syncStore{}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: allow, Port: 443},
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
	if tc.configure != nil {
		tc.configure(t, &cfg)
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
	// The upstream hop follows the client's ALPN request: the h2 path asks for h2.
	p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
	}

	req, err := http.NewRequest(tc.method, "https://"+parityHost+tc.path, strings.NewReader(tc.body))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(tc.body))
	if tc.body == "" {
		req.Body = http.NoBody
	}
	if tc.contentType != "" {
		req.Header.Set("Content-Type", tc.contentType)
	}
	for k, v := range tc.headers {
		req.Header.Set(k, v)
	}

	var resp *http.Response
	if h2 {
		resp, err = dialGRPCClient(t, p.Addr().String(), parityHost, caCertPEM).RoundTrip(req)
	} else {
		tlsClient := dialProxyAndConnect(t, p.Addr().String(), parityHost, caCertPEM)
		if err = req.Write(tlsClient); err == nil {
			resp, err = http.ReadResponse(bufio.NewReader(tlsClient), req)
		}
	}
	if err != nil {
		t.Fatalf("h2=%v: request: %v", h2, err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Events are written by the handler goroutine, possibly after the client has its
	// response: poll to a deadline for the expected count, then require it exactly so
	// a surplus event still fails the case.
	deadline := time.Now().Add(5 * time.Second)
	for len(store.snapshot()) < tc.wantEvents && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	var evs []analytics.Event
	for _, e := range store.snapshot() {
		evs = append(evs, normEvent(e))
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	return parityResult{Status: resp.StatusCode, Resp: string(respBody), Upstream: append([]parityUpstream(nil), be.got...), Events: evs}
}

const (
	parityCanary = `{"auth":"secret=sk_live_51HcanaryDLPtestValue0123456789abcd"}`
	parityLeak   = "here is a key: AKIAIOSFODNN7EXAMPLE stored in config"
)

func parityDLP(mode, action string) func(*testing.T, *Config) {
	return func(_ *testing.T, cfg *Config) {
		cfg.DLP = NewDLPScanner(config.DLPConfig{
			Mode:    mode,
			Classes: map[string]config.DLPClassDefault{"credentials": {Action: action}},
		}, false, false)
	}
}

func paritySwap(scopes map[string][]string) func(*testing.T, *Config) {
	return func(_ *testing.T, cfg *Config) {
		cfg.Secrets = &fakes.FakeSecretProvider{Values: map[string]string{"PLACEHOLDER_001": "real-secret-value"}}
		cfg.PlaceholderNames = []string{"PLACEHOLDER_001"}
		cfg.PlaceholderScopes = scopes
	}
}

func parityJudge(decision string) func(*testing.T, *Config) {
	return func(_ *testing.T, cfg *Config) {
		cfg.Judge = &fakeJudge{verdict: Verdict{Decision: decision, Reason: "fake " + decision}}
	}
}

func parityMCP(t *testing.T, cfg *Config) {
	mc := enforceMCPConfig()
	cfg.MCP = gateway.New(mc, scan.NewScanner(), nil)
}

func parityResponseScan(mode string) func(*testing.T, *Config) {
	return func(_ *testing.T, cfg *Config) {
		cfg.ResponseScan = NewResponseScanner(mode, 1<<20, false, false)
	}
}

// TestH2_StageParity sends the same request over HTTP/1.1 and HTTP/2 through the
// real proxy to a recording backend and requires the same status, response, events
// and upstream bytes (#388): a request must not avoid a control by its protocol.
func TestH2_StageParity(t *testing.T) {
	cases := []parityCase{
		{
			name: "dlp_redact", configure: parityDLP(config.DLPModeEnforce, config.DLPActionRedact),
			method: "POST", path: "/post", contentType: "application/json", body: parityCanary,
			respCT: "text/plain", respBody: "ok", wantStatus: 200, wantEvents: 1,
		},
		{
			name: "dlp_block", configure: parityDLP(config.DLPModeEnforce, config.DLPActionBlock),
			method: "POST", path: "/post", contentType: "application/json", body: parityCanary,
			respCT: "text/plain", respBody: "ok", wantStatus: 403, wantEvents: 1,
		},
		{
			name: "dlp_monitor", configure: parityDLP(config.DLPModeMonitor, config.DLPActionRedact),
			method: "POST", path: "/post", contentType: "application/json", body: parityCanary,
			respCT: "text/plain", respBody: "ok", wantStatus: 200, wantEvents: 1,
		},
		{
			name: "dlp_binary_partial", configure: parityDLP(config.DLPModeEnforce, config.DLPActionRedact),
			method: "POST", path: "/post", contentType: "application/octet-stream", body: parityCanary,
			respCT: "text/plain", respBody: "ok", wantStatus: 200, wantEvents: 1,
		},
		{
			name: "swap_query_body_in_scope", configure: paritySwap(map[string][]string{"PLACEHOLDER_001": {parityHost}}),
			method: "POST", path: "/x?k=PLACEHOLDER_001&a=1", contentType: "application/json",
			body: `{"token":"PLACEHOLDER_001"}`, headers: map[string]string{"X-Api-Key": "PLACEHOLDER_001"},
			respCT: "text/plain", respBody: "ok", wantStatus: 200, wantEvents: 1,
		},
		{
			name: "swap_out_of_scope", configure: paritySwap(map[string][]string{"PLACEHOLDER_001": {"other.test"}}),
			method: "POST", path: "/x?k=PLACEHOLDER_001", contentType: "application/json",
			body: `{"token":"PLACEHOLDER_001"}`, headers: map[string]string{"X-Api-Key": "PLACEHOLDER_001"},
			respCT: "text/plain", respBody: "ok", wantStatus: 200, wantEvents: 2,
		},
		{
			name: "body_cap_swap_413", configure: paritySwap(nil),
			method: "POST", path: "/x", contentType: "application/json",
			body:   strings.Repeat("a", maxBodySwapSize+1),
			respCT: "text/plain", respBody: "ok", wantStatus: 413, wantEvents: 0,
		},
		{
			name: "body_cap_dlp_partial", configure: parityDLP(config.DLPModeEnforce, config.DLPActionRedact),
			method: "POST", path: "/x", contentType: "application/json",
			body:   strings.Repeat("a", maxBodySwapSize+1),
			respCT: "text/plain", respBody: "ok", wantStatus: 200, wantEvents: 1,
		},
		{
			name: "response_scan_monitor", configure: parityResponseScan("monitor"),
			method: "GET", path: "/x", respCT: "text/plain", respBody: parityLeak, wantStatus: 200, wantEvents: 1,
		},
		{
			name: "response_scan_enforce", configure: parityResponseScan("enforce"),
			method: "GET", path: "/x", respCT: "text/plain", respBody: parityLeak, wantStatus: 502, wantEvents: 1,
		},
		{
			name: "judge_allow", configure: parityJudge("allow"), allowHost: "elsewhere.test",
			method: "GET", path: "/x", respCT: "text/plain", respBody: "ok", wantStatus: 200, wantEvents: 1,
		},
		{
			name: "judge_deny", configure: parityJudge("deny"), allowHost: "elsewhere.test",
			method: "GET", path: "/x", respCT: "text/plain", respBody: "ok", wantStatus: 403, wantEvents: 1,
		},
		{
			name: "mcp_allowed_tool", configure: parityMCP,
			method: "POST", path: "/mcp", contentType: "application/json", body: mcpReadFileBody,
			respCT: "application/json", respBody: `{"jsonrpc":"2.0","id":"1","result":{}}`, wantStatus: 200, wantEvents: 1,
		},
		{
			name: "mcp_denied_tool", configure: parityMCP,
			method: "POST", path: "/mcp", contentType: "application/json", body: mcpExecCmdBody,
			respCT: "application/json", respBody: `{}`, wantStatus: 403, wantEvents: 1,
		},
		{
			name: "mcp_poisoned_response", configure: parityMCP,
			method: "POST", path: "/mcp", contentType: "application/json", body: mcpToolsList,
			respCT: "application/json", respBody: mcpPoisonedList, wantStatus: 502, wantEvents: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h1 := runParity(t, tc, false)
			h2 := runParity(t, tc, true)
			if h1.Status != tc.wantStatus {
				t.Fatalf("h1 status = %d, want %d (events %+v)", h1.Status, tc.wantStatus, h1.Events)
			}
			if len(h1.Events) != tc.wantEvents {
				t.Fatalf("h1 events = %d, want %d: %+v", len(h1.Events), tc.wantEvents, h1.Events)
			}
			if h2.Status != h1.Status {
				t.Errorf("status: h1=%d h2=%d", h1.Status, h2.Status)
			}
			if h2.Resp != h1.Resp {
				t.Errorf("response body: h1=%q h2=%q", h1.Resp, h2.Resp)
			}
			if !reflect.DeepEqual(h1.Upstream, h2.Upstream) {
				t.Errorf("upstream bytes differ:\n h1=%+v\n h2=%+v", abbrevUpstream(h1.Upstream), abbrevUpstream(h2.Upstream))
			}
			if !reflect.DeepEqual(h1.Events, h2.Events) {
				t.Errorf("events differ:\n h1=%+v\n h2=%+v", h1.Events, h2.Events)
			}
		})
	}
}

func abbrevUpstream(us []parityUpstream) []parityUpstream {
	out := make([]parityUpstream, len(us))
	for i, u := range us {
		if len(u.Body) > 200 {
			u.Body = u.Body[:200] + "…"
		}
		out[i] = u
	}
	return out
}

// TestH2_StageParity_Effects pins the specific outcomes behind the table (the
// table proves h1==h2; this proves both are the RIGHT thing), including the
// issue's repro: DLP redact must scrub the credential over h2.
func TestH2_StageParity_Effects(t *testing.T) {
	redact := runParity(t, parityCase{
		configure: parityDLP(config.DLPModeEnforce, config.DLPActionRedact),
		method:    "POST", path: "/post", contentType: "application/json", body: parityCanary,
		respCT: "text/plain", respBody: "ok", wantEvents: 1,
	}, true)
	if len(redact.Upstream) != 1 || strings.Contains(redact.Upstream[0].Body, "sk_live_") ||
		!strings.Contains(redact.Upstream[0].Body, "[REDACTED:credentials") {
		t.Fatalf("h2 DLP redact did not scrub the upstream body: %+v", redact.Upstream)
	}
	if len(redact.Events) != 1 || redact.Events[0].DLPAction != "redact" {
		t.Fatalf("h2 DLP redact event: %+v", redact.Events)
	}

	swap := runParity(t, parityCase{
		configure: paritySwap(map[string][]string{"PLACEHOLDER_001": {parityHost}}),
		method:    "POST", path: "/x?k=PLACEHOLDER_001", contentType: "application/json",
		body: `{"token":"PLACEHOLDER_001"}`, respCT: "text/plain", respBody: "ok", wantEvents: 1,
	}, true)
	if u := swap.Upstream[0]; !strings.Contains(u.URI, "real-secret-value") || !strings.Contains(u.Body, "real-secret-value") ||
		strings.Contains(u.URI+u.Body, "PLACEHOLDER_001") {
		t.Fatalf("h2 query/body swap: %+v", u)
	}

	scoped := runParity(t, parityCase{
		configure: paritySwap(map[string][]string{"PLACEHOLDER_001": {"other.test"}}),
		method:    "POST", path: "/x?k=PLACEHOLDER_001", contentType: "application/json",
		body: `{"token":"PLACEHOLDER_001"}`, respCT: "text/plain", respBody: "ok", wantEvents: 2,
	}, true)
	if u := scoped.Upstream[0]; strings.Contains(u.URI+u.Body, "real-secret-value") {
		t.Fatalf("h2 out-of-scope placeholder was swapped: %+v", u)
	}
	var sawOOS bool
	for _, e := range scoped.Events {
		sawOOS = sawOOS || e.Decision == decisionSecretOutOfScope
	}
	if !sawOOS {
		t.Fatalf("h2 out-of-scope event missing: %+v", scoped.Events)
	}
}

// TestH2_GRPCUnary_StreamedVerbatim: a gRPC call keeps working through the shared
// pipeline — the protobuf body is relayed byte-for-byte (never buffered, swapped
// or redacted), DLP records it partial, the trailer survives, and the event is
// labelled "grpc".
func TestH2_GRPCUnary_StreamedVerbatim(t *testing.T) {
	// A length-prefixed frame that contains a credential-looking string and a
	// placeholder: neither may be touched.
	frame := "\x00\x00\x00\x00\x40" + "sk_live_51HcanaryDLPtestValue0123456789abcd PLACEHOLDER_001"
	tc := parityCase{
		configure: func(t *testing.T, cfg *Config) {
			parityDLP(config.DLPModeEnforce, config.DLPActionRedact)(t, cfg)
			paritySwap(nil)(t, cfg)
		},
		method: "POST", path: "/pkg.Svc/Method", contentType: "application/grpc", body: frame,
		respCT: "application/grpc", respBody: "grpc-response-body", wantEvents: 1,
	}
	got := runParity(t, tc, true)
	if got.Status != 200 || got.Resp != "grpc-response-body" {
		t.Fatalf("grpc status/body = %d %q", got.Status, got.Resp)
	}
	if len(got.Upstream) != 1 || got.Upstream[0].Body != frame || got.Upstream[0].URI != "/pkg.Svc/Method" {
		t.Fatalf("grpc upstream not verbatim: %+v", abbrevUpstream(got.Upstream))
	}
	if len(got.Events) != 1 {
		t.Fatalf("grpc events: %+v", got.Events)
	}
	if e := got.Events[0]; e.Protocol != "grpc" || e.Decision != "allow" || !e.DLPPartial {
		t.Fatalf("grpc event: %+v", e)
	}
}

// TestH2_ResponseScan_StreamsUnscannable: a response h1 would not buffer (SSE) is
// streamed on h2 too, not held back for scanning.
func TestH2_ResponseScan_StreamsUnscannable(t *testing.T) {
	got := runParity(t, parityCase{
		configure: parityResponseScan("enforce"),
		method:    "GET", path: "/x", respCT: "text/event-stream", respBody: "data: " + parityLeak + "\n\n", wantEvents: 1,
	}, true)
	if got.Status != 200 || !strings.Contains(got.Resp, "AKIA") {
		t.Fatalf("unscannable stream must pass through like h1: %d %q", got.Status, got.Resp)
	}
}
