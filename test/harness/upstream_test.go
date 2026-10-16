package harness

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// TestUpstream_RecordsAgentRequest is the Task B acceptance flow: an agent
// request through the worker reaches the fake upstream registered for the
// hostname (the dialer override maps the fake name to the fake's loopback
// address), and the recorder shows exactly what arrived after the worker's
// pipeline.
func TestUpstream_RecordsAgentRequest(t *testing.T) {
	h := New(t)
	u := h.Upstream("api.example.com")

	resp, err := h.Agent().Get("https://api.example.com/v1/models")
	if err != nil {
		t.Fatalf("GET through the worker: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET through the worker = %d, want 200", resp.StatusCode)
	}

	reqs := u.Requests()
	if len(reqs) != 1 {
		t.Fatalf("recorded upstream requests = %d, want 1", len(reqs))
	}
	req := reqs[0]
	if req.Method != http.MethodGet || req.Host != "api.example.com" || req.Path != "/v1/models" {
		t.Errorf("recorded request = %s %s%s, want GET api.example.com/v1/models", req.Method, req.Host, req.Path)
	}
	if req.Proto != "HTTP/1.1" {
		t.Errorf("recorded proto = %q, want HTTP/1.1 (the default agent speaks http/1.1)", req.Proto)
	}

	resps := h.AgentResponses()
	if len(resps) != 1 || resps[0].Status != http.StatusOK {
		t.Fatalf("agent transcript = %+v, want one 200 response", resps)
	}
}

// TestUpstream_HTTP2Leg proves the fake serves HTTP/2 (httptest EnableHTTP2)
// and that an agent negotiating h2 with the worker produces an HTTP/2 request
// on the upstream leg too.
func TestUpstream_HTTP2Leg(t *testing.T) {
	h := New(t)
	u := h.Upstream("api.example.com")

	// The h2 client: same proxy, same trust, but NextProtos h2 — the worker's
	// MITM handshake negotiates h2 and the request rides the h2 path upstream.
	h2 := &http.Client{Transport: &http.Transport{
		Proxy:             func(*http.Request) (*url.URL, error) { return url.Parse("http://" + h.ProxyAddr()) },
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			RootCAs:    h.proxyCA.pool(),
			MinVersion: tls.VersionTLS12,
		},
	}}
	// Drop this client's idle CONNECT tunnels so the worker's session
	// goroutines end with the test (the harness cannot know about this client).
	defer h2.CloseIdleConnections()
	resp, err := h2.Get("https://api.example.com/v1/models")
	if err != nil {
		t.Fatalf("h2 GET through the worker: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("h2 GET through the worker = %d, want 200", resp.StatusCode)
	}

	reqs := u.Requests()
	if len(reqs) != 1 {
		t.Fatalf("recorded upstream requests = %d, want 1", len(reqs))
	}
	if reqs[0].Proto != "HTTP/2.0" {
		t.Errorf("upstream leg negotiated %q, want HTTP/2.0 (the fake serves h2 via EnableHTTP2)", reqs[0].Proto)
	}
}

// TestFakeLLM_ServesFixedCompletionAndRecordsAuth covers the fake LLM: the
// fixed OpenAI-style completion comes back through the worker, the
// Authorization header carrying the PLACEHOLDER was swapped to the real value
// on the wire, and AuthHeaders records that real value.
func TestFakeLLM_ServesFixedCompletionAndRecordsAuth(t *testing.T) {
	secret := "sk-harness-fake-" + Canary()
	h := New(t, WithSecret("openai", secret))
	llm := h.FakeLLM()

	req, err := http.NewRequest(http.MethodPost, "https://llm.example.com/v1/chat/completions",
		strings.NewReader(`{"model":"x","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Placeholder("openai"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("POST completion through the worker: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST completion = %d %s, want 200", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(defaultLLMCompletion)) {
		t.Errorf("completion body %s does not carry the fixed completion", body)
	}

	auth := llm.AuthHeaders()
	if len(auth) != 1 || auth[0] != "Bearer "+secret {
		t.Errorf("AuthHeaders = %v, want [Bearer %s] — the swap must replace the placeholder with the real value on the wire", auth, secret)
	}

	// SetCompletion changes what the next request sees.
	llm.SetCompletion("custom text")
	resp2, err := h.Agent().Get("https://llm.example.com/v1/chat/completions")
	if err != nil {
		t.Fatalf("second POST: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if !bytes.Contains(body2, []byte("custom text")) {
		t.Errorf("body after SetCompletion = %s, want the custom text", body2)
	}
}

// TestFakeMCP_ServesPoisonedToolsList proves the shared poisoned MCP handler
// (internal/mcp/poisoned) is mounted behind the worker: tools/list carries the
// poisoned description (the payload the mcp-wedge demo and the harness share
// byte-for-byte).
func TestFakeMCP_ServesPoisonedToolsList(t *testing.T) {
	h := New(t)
	mcp := h.FakeMCP()

	req, err := http.NewRequest(http.MethodPost, "https://mcp.example.com/",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("POST tools/list through the worker: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST tools/list = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{"list_files", "run_shell", "ignore all", "previous instructions"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("tools/list body missing %q", want)
		}
	}
	if len(mcp.Requests()) != 1 {
		t.Errorf("recorded MCP requests = %d, want 1", len(mcp.Requests()))
	}
}

// TestFakeGRPC_EchoesUnary exercises the raw-h2 unary echo fake directly
// (loopback, upstream CA trust): a framed request in, the same message echoed
// back, grpc-status 0 in the trailers.
func TestFakeGRPC_EchoesUnary(t *testing.T) {
	h := New(t)
	u := h.FakeGRPC()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    h.upstreamCA.pool(),
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true, // the h2 leg is the point
	}
	defer tr.CloseIdleConnections()
	msg := []byte("harness unary payload")
	framed := grpcFrame(msg)

	req, err := http.NewRequest(http.MethodPost, u.URL()+"/pkg.Svc/Method", bytes.NewReader(framed))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("gRPC round trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gRPC = %d, want 200", resp.StatusCode)
	}
	if got := string(grpcMessage(body)); got != string(msg) {
		t.Errorf("gRPC echo = %q, want %q", got, msg)
	}
	if resp.Trailer.Get("Grpc-Status") != "0" {
		t.Errorf("grpc-status trailer = %q, want 0", resp.Trailer.Get("Grpc-Status"))
	}
}

// TestFakeWS_Echoes exercises the WebSocket echo fake directly over TLS.
func TestFakeWS_Echoes(t *testing.T) {
	h := New(t)
	u := h.FakeWS()

	cfg, err := websocket.NewConfig(strings.Replace(u.URL()+"/ws", "https", "wss", 1), "https://ws.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	cfg.TlsConfig = &tls.Config{RootCAs: h.upstreamCA.pool(), MinVersion: tls.VersionTLS12}
	conn, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping-harness")); err != nil {
		t.Fatalf("ws write: %v", err)
	}
	got := make([]byte, len("ping-harness"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ws read: %v", err)
	}
	if string(got) != "ping-harness" {
		t.Errorf("ws echo = %q, want ping-harness", got)
	}
}

// TestUpstream_WaitParkedOnlyAfterTimerArmed pins the park-counter ordering
// against the race the counter exists to close: WaitParked(n) may only return
// once the Delay timer is REGISTERED with the fake clock — never merely once
// the request has arrived. The parkGap hook holds open the exact window where
// an early increment used to let WaitParked(1) return, the Advance below fire,
// and only then the timer arm (absorbing the advance): the request hung until
// the next one. With the increment after NewTimer, an Advance issued after
// WaitParked is guaranteed to hit an armed timer.
func TestUpstream_WaitParkedOnlyAfterTimerArmed(t *testing.T) {
	h := New(t)
	u := h.Upstream("api.example.com")
	u.Delay(5 * time.Second)
	// Test-only hook: 400ms of wall time between the request ARRIVING at the
	// fake and the Delay timer being registered — the gap the old
	// increment-before-NewTimer ordering lost advances in.
	u.parkGap = 400 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := getThrough(h, "https://api.example.com/slow")
		done <- err
	}()

	u.WaitParked(1)
	h.Clock().Advance(5 * time.Second) // must fire the timer WaitParked proved armed
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("delayed request after WaitParked+Advance: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request is still parked after WaitParked(1) + Advance(5s): " +
			"parked was incremented before the Delay timer was registered, so the advance was absorbed")
	}
	if n := u.Parked(); n != 0 {
		t.Errorf("Parked() = %d after the release, want 0", n)
	}
}

// TestMappingDialer_RefusesUnknownHost pins the dialer's misuse guard: a
// request to an allowlisted name with NO registered fake upstream fails the
// upstream dial (the worker answers 502) instead of slipping through to the
// real network — the harness must never become a highway out.
func TestMappingDialer_RefusesUnknownHost(t *testing.T) {
	h := New(t, Allow("unregistered.example.com"))
	resp, err := h.Agent().Get("https://unregistered.example.com/only")
	if err != nil {
		t.Fatalf("GET with no fake upstream: %v (want a worker-generated 502)", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("GET with no fake upstream = %d, want 502 (the mapping dialer refused)", resp.StatusCode)
	}
}

// grpcFrame wraps a message in the 5-byte gRPC frame prefix.
func grpcFrame(msg []byte) []byte {
	out := make([]byte, 5+len(msg))
	out[1] = byte(len(msg) >> 24)
	out[2] = byte(len(msg) >> 16)
	out[3] = byte(len(msg) >> 8)
	out[4] = byte(len(msg))
	copy(out[5:], msg)
	return out
}

// grpcMessage strips the 5-byte gRPC frame prefix.
func grpcMessage(frame []byte) []byte {
	if len(frame) < 5 {
		return nil
	}
	return frame[5:]
}
