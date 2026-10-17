package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestInflight_StartDoneTracksDescriptions pins the tracker's basic contract:
// a started unit is visible by its description until its done runs, done is
// idempotent, and a drained tracker reports nothing.
func TestInflight_StartDoneTracksDescriptions(t *testing.T) {
	tr := NewInflight()
	if open := tr.InFlight(); len(open) != 0 {
		t.Fatalf("a fresh tracker reports %v, want nothing in flight", open)
	}

	done := tr.Start("https GET https://api.example.com/v1/models")
	if open := tr.InFlight(); len(open) != 1 || open[0] != "https GET https://api.example.com/v1/models" {
		t.Fatalf("InFlight = %v, want the one started description", open)
	}

	done()
	if open := tr.InFlight(); len(open) != 0 {
		t.Fatalf("InFlight after done = %v, want empty", open)
	}
	done() // idempotent: the scope defers done AND steps out early on a handoff
	if open := tr.InFlight(); len(open) != 0 {
		t.Fatalf("InFlight after a second done = %v, want empty", open)
	}
}

// TestInflight_WaitIdleReturnsWhenIdle pins the fast path: the oracles call
// WaitIdle before every read, so an idle tracker must return immediately.
func TestInflight_WaitIdleReturnsWhenIdle(t *testing.T) {
	tr := NewInflight()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tr.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle on an idle tracker = %v, want nil", err)
	}
}

// TestInflight_WaitIdleWakesOnDrain pins the condition wait: a waiter blocked
// on a busy tracker returns the moment the last unit is done — never by
// polling a timer.
func TestInflight_WaitIdleWakesOnDrain(t *testing.T) {
	tr := NewInflight()
	done := tr.Start("grpc POST https://grpc.example.com/pkg.Svc/Call")

	waited := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		waited <- tr.WaitIdle(ctx)
	}()

	// Let the waiter reach WaitIdle, then finish the unit; the waiter must wake
	// on the drain alone.
	time.Sleep(20 * time.Millisecond)
	done()

	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("WaitIdle after drain = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitIdle never woke on the drain")
	}
}

// TestInflight_WaitIdleTimesOutNamingWork pins the deadline behavior the
// harness's failure message is built on: an expired wait returns the ctx error
// and the work it was waiting for is still nameable.
func TestInflight_WaitIdleTimesOutNamingWork(t *testing.T) {
	tr := NewInflight()
	doneA := tr.Start("https GET https://api.example.com/a")
	defer doneA()
	doneB := tr.Start("mcp ws session https://ws.example.com/ws")
	defer doneB()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := tr.WaitIdle(ctx); err != context.DeadlineExceeded {
		t.Fatalf("WaitIdle past its deadline = %v, want context.DeadlineExceeded", err)
	}
	open := tr.InFlight()
	if len(open) != 2 {
		t.Fatalf("InFlight after the timeout = %v, want both units still named", open)
	}
}

// TestInflight_ConcurrentStartDone is a race-detector workout: start and finish
// units from many goroutines while a waiter sits in WaitIdle, so -race sees
// every interleaving of the tracker's map and its drain broadcast. The waiter
// mirrors how the oracles use the tracker — one bounded wait, never a polling
// loop — and when the last worker finishes, the tracker must be empty and
// immediately idle again.
func TestInflight_ConcurrentStartDone(t *testing.T) {
	tr := NewInflight()
	waitErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		waitErr <- tr.WaitIdle(ctx)
	}()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				done := tr.Start("https GET https://api.example.com/x")
				done()
			}
		}()
	}
	wg.Wait()

	select {
	case err := <-waitErr:
		if err != nil {
			t.Fatalf("WaitIdle while workers churned = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("WaitIdle never returned; still in flight: %v", tr.InFlight())
	}
	if open := tr.InFlight(); len(open) != 0 {
		t.Fatalf("InFlight after every worker finished = %v, want empty", open)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tr.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle on the drained tracker = %v, want nil", err)
	}
}

// TestProxy_AllowEventRecordedBeforeScopeLeavesTracker is the property the
// harness's deterministic oracles stand on: once the tracker has drained — the
// moment a harness oracle would read — the request's allow event is ALREADY in
// the store. It fails if anyone moves the scope's done() ahead of the terminal
// bookkeeping (the #363 race), and needs no sleep: WaitIdle wakes on the
// drain, then the store must already hold the event.
func TestProxy_AllowEventRecordedBeforeScopeLeavesTracker(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)
	tr := NewInflight()

	p, ss := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, map[string]string{}, nil)
	// Installed before any connection exists, so no handler goroutine can
	// observe the assignment.
	p.cfg.Inflight = tr
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		cfg = cfg.Clone()
		cfg.InsecureSkipVerify = true
		return tls.Dial("tcp", backendLn.Addr().String(), cfg)
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, err := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", resp.StatusCode)
	}

	ctxWait, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	if err := tr.WaitIdle(ctxWait); err != nil {
		t.Fatalf("the request scope never left the tracker: %v (in flight: %v)", err, tr.InFlight())
	}
	evs := ss.snapshot()
	if len(evs) != 1 || evs[0].Decision != "allow" {
		t.Fatalf("after the tracker drained the store holds %v, want exactly the one allow event — "+
			"the scope's done() ran before its terminal bookkeeping (the #363 race)", evs)
	}
}

// TestProxy_GRPCStreamTrackedUntilTerminalEvent pins the h2/gRPC half of the
// tracking (serveGRPCStream is the one handler for both): an h2 stream's scope
// stays in the tracker until its terminal bookkeeping runs — in particular
// through the #363 window, after the response bytes are already in the agent's
// hands and before the event is recorded. BeforeTerminal (the assembly-only
// worker.Overrides.BeforeTerminal hook) parks the bookkeeping in exactly that
// window, so the assertions need no polling: while parked, InFlight must name
// the stream, and once the tracker drains the store must already hold the
// stream's grpc allow event. Removing serveGRPCStream's tracker slot fails
// this at the InFlight check.
func TestProxy_GRPCStreamTrackedUntilTerminalEvent(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	be := startGRPCBackend(t)
	backendAddr := strings.TrimPrefix(be.server.URL, "https://")
	tr := NewInflight()

	p, ss := startTestProxyWithSecrets(t, []string{"grpc.test"}, caCertPEM, caKeyPEM, map[string]string{}, nil)
	p.cfg.Inflight = tr
	reached := make(chan struct{})
	release := make(chan struct{})
	p.cfg.BeforeTerminal = func() { close(reached); <-release }
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}

	cc := dialGRPCClient(t, p.Addr().String(), "grpc.test", caCertPEM)
	req, err := http.NewRequest(http.MethodPost, "https://grpc.test/pkg.Svc/Method", strings.NewReader("request-body"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round trip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST over h2 = %d, want 200", resp.StatusCode)
	}

	// The response is delivered; the handler must now be parked in the terminal
	// bookkeeping, before its event exists. (An h2 stream's END_STREAM only
	// goes out when the handler RETURNS, so the body cannot be read to EOF
	// while the trap is held — the relayed body BYTES, on the other hand, were
	// flushed before the bookkeeping started.)
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the h2 stream's terminal bookkeeping never started")
	}
	body := make([]byte, 128)
	n, err := resp.Body.Read(body)
	if err != nil || n == 0 {
		t.Fatalf("read delivered body bytes = %d, %v, want the relayed response body", n, err)
	}

	open := tr.InFlight()
	if len(open) != 1 || !strings.Contains(open[0], "grpc POST https://grpc.test/pkg.Svc/Method") {
		t.Fatalf("InFlight while the stream's bookkeeping is parked = %v, want the tracked grpc stream — "+
			"serveGRPCStream never entered the tracker (the #363 window is unpinned for h2/gRPC)", open)
	}

	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.WaitIdle(ctx); err != nil {
		t.Fatalf("the stream never left the tracker: %v (in flight: %v)", err, tr.InFlight())
	}
	// No polling: once the tracker has drained, the event is already recorded.
	evs := ss.snapshot()
	if len(evs) != 1 || evs[0].Protocol != "grpc" || evs[0].Decision != "allow" {
		t.Fatalf("after the tracker drained the store holds %+v, want exactly the one grpc allow event — "+
			"the stream's done() ran before its terminal bookkeeping (the #363 race, h2 form)", evs)
	}
}

// TestProxy_IdleTunnelNotTracked pins the anti-hang half of the h1 tracking:
// the scope starts when a request has been READ, so a keep-alive connection
// parked in ReadRequest between requests — like every pooled agent connection
// a scenario leaves open — never holds the tracker, and the oracles never
// block on it.
func TestProxy_IdleTunnelNotTracked(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)
	tr := NewInflight()

	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, map[string]string{}, nil)
	p.cfg.Inflight = tr
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		cfg = cfg.Clone()
		cfg.InsecureSkipVerify = true
		return tls.Dial("tcp", backendLn.Addr().String(), cfg)
	}

	_ = dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	// CONNECT is established and the tunnel idles in ReadRequest: nothing is
	// in flight. An empty read proves it directly.
	if open := tr.InFlight(); len(open) != 0 {
		t.Fatalf("an idle CONNECT tunnel tracks %v, want nothing — the oracles would block on pooled idle connections", open)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := tr.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle with an idle tunnel = %v, want nil", err)
	}
}
