package harness

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// TestQuiescence_EventsWaitsForTerminalBookkeeping is the #363 red test: the
// proxy records an allowed request's event only AFTER the response is in the
// agent's hands, so a scenario that reads h.Events() immediately after a
// response used to race the record. withBookkeepingDelay widens exactly that
// post-response window by 200ms (assembly-only, test-only); the oracle must
// WAIT for the bookkeeping instead of reading short. On the pre-fix code this
// test fails: the flush drains an empty queue and 0 events come back.
func TestQuiescence_EventsWaitsForTerminalBookkeeping(t *testing.T) {
	h := New(t,
		Local(),
		WithSecret("openai", Canary(), "llm.example.com"),
		withBookkeepingDelay(200*time.Millisecond),
	)
	_ = h.FakeLLM()

	req, err := http.NewRequest(http.MethodGet, "https://llm.example.com/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Placeholder("openai"))
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("GET through the worker: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", resp.StatusCode)
	}

	// The response is in the agent's hands; the terminal bookkeeping (with the
	// injected 200ms delay) has not run yet. The oracle must still see the event.
	evs := h.Events()
	if len(evs) != 1 {
		t.Fatalf("allow events = %d, want 1 — the oracle read before the proxy finished its terminal bookkeeping (#363)", len(evs))
	}
	if evs[0].Domain != "llm.example.com" || evs[0].Decision != "allow" {
		t.Fatalf("event = %s/%s, want llm.example.com/allow", evs[0].Domain, evs[0].Decision)
	}
}

// TestQuiescence_OpenWSSessionDoesNotBlockEvents pins the long-lived-session
// half of the contract: an OPEN WebSocket session (the MCP frame pump owns the
// connection after the 101) must never hold the oracles — the request scope
// steps out of the tracker when its response is delivered — while the session's
// terminal bookkeeping after the pump ends IS still waited on (the session
// re-enters the tracker before its event is recorded).
func TestQuiescence_OpenWSSessionDoesNotBlockEvents(t *testing.T) {
	h := New(t, Local(), WithMCP(), WithQuiescenceDeadline(5*time.Second))
	_ = h.FakeWS()

	ws := dialWorkerWS(t, h, "ws.example.com", "/ws")
	defer func() { _ = ws.Close() }()

	// The session is genuinely open and pumped: a frame round-trips.
	if err := ws.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Write([]byte("ping")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if err := ws.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var msg string
	if err := websocket.Message.Receive(ws, &msg); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if msg != "ping" {
		t.Fatalf("echo = %q, want ping", msg)
	}

	// The open session must not block the oracle: Events returns promptly (the
	// delivered 101 stepped the scope out of the tracker) with no events yet —
	// the session's terminal event is only recorded when the pump ends.
	start := time.Now()
	evs := h.Events()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("h.Events() blocked %v on an open WebSocket session, want an immediate return", elapsed)
	}
	if len(evs) != 0 {
		t.Fatalf("events while the session is open = %d, want 0", len(evs))
	}

	// Closing ends the pump; the session's allow event is recorded after it,
	// and the oracles wait for that bookkeeping to finish.
	if err := ws.Close(); err != nil {
		t.Fatalf("close ws session: %v", err)
	}
	h.EventuallyWithin(5*time.Second, "the mcp ws session's allow event", func() bool {
		for _, ev := range h.Events() {
			if ev.Protocol == "mcp" && ev.Decision == "allow" {
				return true
			}
		}
		return false
	})
}

// TestQuiescence_OpenSSEStreamDoesNotBlockEvents pins the SSE half of the
// open-stream contract (the WS test below is the other half): an OPEN SSE
// stream — the relay owns the connection while it scans events — must never
// hold the oracles. The scope steps OUT of the tracker the moment the SSE
// response is delivered; removing that step-out leaves the scope tracked for
// the whole stream, h.Events() blocks until the stream ends, and this test
// fails at the quiescence deadline.
func TestQuiescence_OpenSSEStreamDoesNotBlockEvents(t *testing.T) {
	h := New(t, Local(), WithMCP(), WithQuiescenceDeadline(3*time.Second))
	// An MCP upstream whose SSE response stays open until the scenario ends
	// it: headers + one event, then hold.
	release := make(chan struct{})
	u := h.Upstream("mcp.example.com")
	u.route("/sse", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Hold until the scenario ends the stream, but answer teardown too: a
		// red run that Fatals mid-stream must not wedge the fake's Close.
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))

	// The relay is the worker's HTTP/1.1 SSE path, so the request rides a raw
	// CONNECT tunnel (h.Agent() buffers whole bodies and would hold the stream
	// closed). The JSON-RPC body is what makes the worker classify the exchange
	// as MCP and relay the response through the SSE scanner.
	conn := dialWorkerTunnel(t, h, "mcp.example.com")
	defer func() { _ = conn.Close() }()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := fmt.Sprintf("POST /sse HTTP/1.1\r\nHost: mcp.example.com\r\n"+
		"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request through the tunnel: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := make([]byte, 4096)
	var got strings.Builder
	for !strings.Contains(got.String(), "data:") {
		n, err := conn.Read(br)
		if err != nil {
			t.Fatalf("read SSE response (got %q): %v", got.String(), err)
		}
		got.Write(br[:n])
	}
	if !strings.Contains(got.String(), " 200 ") || !strings.Contains(got.String(), "text/event-stream") {
		t.Fatalf("SSE response = %q, want a 200 text/event-stream", got.String())
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	// The stream is open and its first event delivered: the oracle must return
	// promptly — the delivered response stepped the scope out of the tracker —
	// with no events yet, since the stream's terminal event is only recorded
	// when the stream ends.
	start := time.Now()
	evs := h.Events()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("h.Events() blocked %v on an open SSE stream, want an immediate return", elapsed)
	}
	if len(evs) != 0 {
		t.Fatalf("events while the SSE stream is open = %d, want 0", len(evs))
	}

	// Ending the stream (from the upstream side, as an MCP server would) lets
	// the relay record the stream's allow event — read through Eventually, the
	// documented close window for a stream's terminal event.
	close(release)
	h.EventuallyWithin(5*time.Second, "the mcp sse stream's allow event", func() bool {
		for _, ev := range h.Events() {
			if ev.Protocol == "mcp" && ev.Decision == "allow" {
				return true
			}
		}
		return false
	})
}

// TestQuiescence_WSEventRecordedBeforeTrackerDrains pins the WS re-entry
// ORDER, without Eventually: the session re-enters the tracker BEFORE its
// terminal bookkeeping and leaves it only AFTER the event is recorded. The
// BeforeTerminal trap parks the bookkeeping at its top, so both orderings are
// observed directly: while parked, InFlight must still name the session (the
// scope's done cannot have run — the event does not exist yet), and once the
// session has ended AND the tracker is idle, Events must already hold the
// session's allow event. Reordering done() ahead of the bookkeeping — or
// dropping the re-entry — fails the InFlight check.
func TestQuiescence_WSEventRecordedBeforeTrackerDrains(t *testing.T) {
	reached := make(chan struct{})
	release := make(chan struct{})
	armed := make(chan struct{})
	h := New(t, Local(), WithMCP(), withBeforeTerminal(func() {
		// Park only when the scenario has armed the trap; every other
		// terminal bookkeeping on this worker runs through untouched.
		select {
		case <-armed:
			close(reached)
			<-release
		default:
		}
	}))
	_ = h.FakeWS()

	ws := dialWorkerWS(t, h, "ws.example.com", "/ws")

	// The session is genuinely open and pumped: a frame round-trips.
	if err := ws.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Write([]byte("ping")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if err := ws.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var msg string
	if err := websocket.Message.Receive(ws, &msg); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if msg != "ping" {
		t.Fatalf("echo = %q, want ping", msg)
	}

	// Arm the trap, then end the session: the pump ends, the scope re-enters
	// the tracker, and its terminal bookkeeping parks in the trap — before the
	// event exists.
	close(armed)
	if err := ws.Close(); err != nil {
		t.Fatalf("close ws session: %v", err)
	}
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the ws session's terminal bookkeeping never started")
	}

	open := h.inflights[0].InFlight()
	if len(open) != 1 || !strings.HasPrefix(open[0], "ws ") || !strings.Contains(open[0], "ws.example.com/ws") {
		t.Fatalf("InFlight while the session's bookkeeping is parked = %v, want the tracked ws session — "+
			"handleWSUpgrade dropped the re-entry or ran its done() before the bookkeeping", open)
	}

	// Release: the event is recorded, THEN the tracker drains. No Eventually —
	// session ended AND tracker idle must mean the event is present.
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.inflights[0].WaitIdle(ctx); err != nil {
		t.Fatalf("the ws session never left the tracker: %v (in flight: %v)", err, h.inflights[0].InFlight())
	}
	evs := h.Events()
	if len(evs) != 1 || evs[0].Protocol != "mcp" || evs[0].Decision != "allow" {
		t.Fatalf("after the tracker drained, events = %+v, want exactly the ws session's allow event — "+
			"the session's done() ran before its terminal bookkeeping (the #363 race, ws form)", evs)
	}
}

// TestQuiescence_DeadlineFailsNamingInFlight pins the deadline behavior: a
// request parked on the Delay fault is genuinely in flight, so an oracle read
// before its release must FAIL THE TEST — naming what is still in flight —
// and never silently read anyway.
func TestQuiescence_DeadlineFailsNamingInFlight(t *testing.T) {
	rec := &recordingTB{T: t}
	h := New(rec, Local(), WithQuiescenceDeadline(500*time.Millisecond))
	u := h.Upstream("api.example.com")
	u.Delay(5 * time.Second)

	done := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models", nil)
		if err != nil {
			done <- err
			return
		}
		resp, err := h.Agent().Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	u.WaitParked(1) // the request is provably stuck mid-flight

	evs := h.Events() // must hit the quiescence deadline and Fatalf, naming the work
	if !rec.Failed() {
		t.Fatalf("h.Events() with a request still in flight did not fail the test — the oracles must never read short silently (events returned: %d)", len(evs))
	}
	msg := rec.failureMessage()
	if !strings.Contains(msg, "api.example.com") {
		t.Fatalf("deadline failure does not name the in-flight work:\n%s", msg)
	}
	if !strings.Contains(msg, "in flight") {
		t.Fatalf("deadline failure does not say the work is in flight:\n%s", msg)
	}
	if len(evs) != 0 {
		t.Fatalf("events read despite in-flight work = %d, want 0", len(evs))
	}

	// Release the park so the harness cleanup and leak check pass.
	h.Clock().Advance(5 * time.Second)
	if err := <-done; err != nil {
		t.Fatalf("GET after Advance: %v", err)
	}
	h.Agent().CloseIdleConnections()
}

// dialWorkerTunnel opens a CONNECT tunnel to host THROUGH a harness worker the
// way an agent would and completes the TLS handshake trusting the worker's
// MITM CA, returning the tunnel for a raw protocol conversation (the x/net
// WebSocket handshake, a hand-written HTTP/1.1 request). h.Agent() cannot
// serve these: its recording transport buffers whole bodies, so it cannot hold
// a streaming response open.
func dialWorkerTunnel(t *testing.T, h *H, host string) *tls.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", h.ProxyAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	connect := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	if _, err := conn.Write([]byte(connect)); err != nil {
		t.Fatal(err)
	}
	br := make([]byte, 4096)
	// Read until the CONNECT response's blank line (the 200 + headers).
	var got strings.Builder
	for {
		n, err := conn.Read(br)
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		got.Write(br[:n])
		if strings.Contains(got.String(), "\r\n\r\n") {
			break
		}
	}
	if !strings.Contains(got.String(), " 200 ") {
		t.Fatalf("CONNECT = %q, want 200", got.String())
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		RootCAs:    h.proxyCA.pool(),
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tunnel TLS handshake: %v", err)
	}
	return tlsConn
}

// dialWorkerWS opens a WebSocket session through a harness worker over
// dialWorkerTunnel's tunnel (NewClient takes any ReadWriteCloser, so no
// proxy-aware dialer is needed).
func dialWorkerWS(t *testing.T, h *H, host, path string) *websocket.Conn {
	t.Helper()
	tlsConn := dialWorkerTunnel(t, h, host)
	cfg, err := websocket.NewConfig("wss://"+host+path, "https://"+host+"/")
	if err != nil {
		t.Fatal(err)
	}
	cfg.TlsConfig = &tls.Config{ServerName: host, RootCAs: h.proxyCA.pool(), MinVersion: tls.VersionTLS12}
	ws, err := websocket.NewClient(cfg, tlsConn)
	if err != nil {
		t.Fatalf("websocket handshake through the worker: %v", err)
	}
	return ws
}
