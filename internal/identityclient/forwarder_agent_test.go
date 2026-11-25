package identityclient_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/identityclient"
)

// fakeSource is a TokenSource the tests drive: the held token, the error Token
// returns when none is held, and what Refresh does.
type fakeSource struct {
	mu       sync.Mutex
	cur      identityclient.WardenToken
	have     bool
	tokenErr error
	refresh  func(s *fakeSource) (identityclient.WardenToken, error)
	rotate   []func()

	refreshes atomic.Int64
}

func wtok(access string, exp time.Time) identityclient.WardenToken {
	return identityclient.WardenToken{AccessToken: access, Expiry: exp}
}

func newFakeSource(tok identityclient.WardenToken) *fakeSource {
	return &fakeSource{cur: tok, have: tok.AccessToken != ""}
}

func (s *fakeSource) Token(context.Context) (identityclient.WardenToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.have {
		return identityclient.WardenToken{}, s.tokenErr
	}
	return s.cur, nil
}

func (s *fakeSource) Refresh(ctx context.Context) (identityclient.WardenToken, error) {
	s.refreshes.Add(1)
	s.mu.Lock()
	fn := s.refresh
	s.mu.Unlock()
	if fn != nil {
		return fn(s)
	}
	return s.Token(ctx)
}

func (s *fakeSource) Current() (identityclient.WardenToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur, s.have
}

func (s *fakeSource) OnRotate(fn func()) {
	s.mu.Lock()
	s.rotate = append(s.rotate, fn)
	s.mu.Unlock()
}

// Rotate installs tok as the held token and runs the OnRotate callbacks, as
// WardenTokenSource does after an exchange.
func (s *fakeSource) Rotate(tok identityclient.WardenToken) {
	s.mu.Lock()
	s.cur, s.have = tok, true
	cbs := append([]func(){}, s.rotate...)
	s.mu.Unlock()
	for _, fn := range cbs {
		fn()
	}
}

// scriptedWorker is a worker whose answer depends on the token it was sent.
type scriptedWorker struct {
	ln    net.Listener
	dials atomic.Int64
	reply func(token string) string

	mu    sync.Mutex
	heads []string
}

func newScriptedWorker(t *testing.T, reply func(token string) string) *scriptedWorker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &scriptedWorker{ln: ln, reply: reply}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			w.dials.Add(1)
			go w.serve(c)
		}
	}()
	return w
}

func tokenInHead(head string) string {
	_, after, _ := strings.Cut(head, "Proxy-Authorization: Basic ")
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.SplitN(after, "\r\n", 2)[0]))
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(string(raw), "session:")
}

func (w *scriptedWorker) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	var head strings.Builder
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(l)
		if l == "\r\n" {
			break
		}
	}
	w.mu.Lock()
	w.heads = append(w.heads, head.String())
	w.mu.Unlock()
	reply := w.reply(tokenInHead(head.String()))
	_, _ = io.WriteString(c, reply)
	if strings.HasPrefix(reply, "HTTP/1.1 200") {
		_, _ = io.Copy(c, br)
	}
}

func (w *scriptedWorker) Tokens() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, h := range w.heads {
		out = append(out, tokenInHead(h))
	}
	return out
}

const reply407 = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"warden\"\r\nContent-Length: 0\r\n\r\n"

// srcRig is a forwarder over a TokenSource in front of a scripted worker.
type srcRig struct {
	*fwdRig
	sw  *scriptedWorker
	src *fakeSource
	clk *clocktest.Fake
	lw  *lockedWriter
}

// logSnapshot returns what the forwarder has logged so far.
func (a *srcRig) logSnapshot() string {
	a.lw.mu.Lock()
	defer a.lw.mu.Unlock()
	return a.logs.String()
}

// startAgentForwarder starts a Forwarder with Source src and a fake clock in
// front of a worker that answers reply(token). Clients need no credential.
func startAgentForwarder(t *testing.T, src *fakeSource, reply func(string) string, tweak func(*identityclient.Forwarder)) *srcRig {
	t.Helper()
	a := &srcRig{src: src, clk: clocktest.NewFake(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))}
	a.sw = newScriptedWorker(t, reply)
	r := &fwdRig{logs: &bytes.Buffer{}, done: make(chan error, 1)}
	a.fwdRig = r
	a.lw = &lockedWriter{w: r.logs}
	r.fwd = &identityclient.Forwarder{
		WorkerAddr: a.sw.ln.Addr().String(), Source: src, AllowAnonymousClients: true, Clock: a.clk,
		Log: slog.New(slog.NewTextHandler(a.lw, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if tweak != nil {
		tweak(r.fwd)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.done <- r.fwd.Serve(ctx, ln); close(r.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	return a
}

// tick advances the fake clock by d and waits until the drain loop has swept
// and armed its next timer again, so what it decided is visible.
func (a *srcRig) tick(t *testing.T, d time.Duration) {
	t.Helper()
	a.clk.Advance(d)
	waitFor(t, "the drain loop to re-arm", func() bool { return a.clk.PendingTimers() == 1 })
}

func reasonOf(head string) string {
	for _, l := range strings.Split(head, "\r\n") {
		if name, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(name, "X-Warden-Forwarder-Reason") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func echoWorker(string) string { return ok200 }

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func TestForwarderInjectsAndStrips(t *testing.T) {
	src := newFakeSource(wtok("warden.tok.AAA", t0.Add(15*time.Minute)))
	a := startAgentForwarder(t, src, echoWorker, nil)

	// The client sends its own Proxy-Authorization and other headers; none of
	// them reaches the worker, which gets exactly the injected one.
	req := connectReq("api.example.com:443", basicHeader("session", "client-own-token")+"X-Client: leak-me\r\nUser-Agent: curl\r\n")
	c, _, head := a.send(t, req)
	if statusOf(head) != 200 {
		t.Fatalf("status %d, head %q", statusOf(head), head)
	}
	_ = c.Close()
	want := "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n" +
		"Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("session:warden.tok.AAA")) + "\r\n\r\n"
	a.sw.mu.Lock()
	got := append([]string(nil), a.sw.heads...)
	a.sw.mu.Unlock()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("worker received %q, want %q", got, want)
	}

	// Any other method is 405 and nothing is dialled.
	dials := a.sw.dials.Load()
	_, _, head = a.send(t, "GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if statusOf(head) != 405 || !strings.Contains(head, "Allow: CONNECT") {
		t.Errorf("GET: head %q, want 405", head)
	}

	// Too many header lines and an oversized block are both 431.
	_, _, head = a.send(t, connectReq("a.example.com:443", strings.Repeat("X-A: b\r\n", 100)))
	if statusOf(head) != 431 {
		t.Errorf("101 header lines: head %q, want 431", head)
	}
	big := strings.Repeat("X-Pad: "+strings.Repeat("a", 1000)+"\r\n", 70)
	_, _, head = a.send(t, connectReq("a.example.com:443", big))
	if statusOf(head) != 431 {
		t.Errorf("oversized block: head %q, want 431", head)
	}
	// 100 lines (Host included) are fine.
	c, _, head = a.send(t, connectReq("a.example.com:443", strings.Repeat("X-A: b\r\n", 99)))
	if statusOf(head) != 200 {
		t.Errorf("100 header lines: head %q, want 200", head)
	}
	_ = c.Close()
	if n := a.sw.dials.Load(); n != dials+1 {
		t.Errorf("worker dials = %d, want %d (only the valid CONNECT reaches it)", n, dials+1)
	}
}

func TestForwarderOnlyDialsWorker(t *testing.T) {
	src := newFakeSource(wtok("warden.tok.AAA", t0.Add(15*time.Minute)))
	var mu sync.Mutex
	var dialed []string
	a := startAgentForwarder(t, src, echoWorker, func(f *identityclient.Forwarder) {
		f.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	})
	targets := []string{"a.example.com:443", "b.example.org:8443", "10.1.2.3:443", "[2001:db8::1]:443", "localhost:80"}
	for _, tg := range targets {
		c, _, head := a.send(t, connectReq(tg, ""))
		if statusOf(head) != 200 {
			t.Fatalf("%s: head %q", tg, head)
		}
		_ = c.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != len(targets) {
		t.Fatalf("%d dials for %d CONNECTs: %v", len(dialed), len(targets), dialed)
	}
	for _, d := range dialed {
		if d != a.sw.ln.Addr().String() {
			t.Errorf("dialled %q, want only the worker %q", d, a.sw.ln.Addr())
		}
	}
}

func TestForwarderRotationDrain(t *testing.T) {
	oldExp := t0.Add(15 * time.Minute)
	src := newFakeSource(wtok("warden.tok.OLD", oldExp))
	a := startAgentForwarder(t, src, echoWorker, nil)
	waitFor(t, "the drain loop to start", func() bool { return a.clk.PendingTimers() == 1 })

	c, br, head := a.send(t, connectReq("a.example.com:443", ""))
	if statusOf(head) != 200 {
		t.Fatalf("head %q", head)
	}
	echo := func(msg string) bool {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(c, msg+"\n"); err != nil {
			return false
		}
		got, err := br.ReadString('\n')
		return err == nil && got == msg+"\n"
	}
	closed := func() bool {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := br.ReadByte()
		var ne net.Error
		return !(errors.As(err, &ne) && ne.Timeout())
	}

	// No rotation: an idle tunnel is left alone however long it idles.
	a.tick(t, 30*time.Second)
	if !echo("idle-without-rotation") {
		t.Fatal("an idle tunnel was closed before any rotation")
	}

	// A rotation: the tunnel keeps streaming while it is active.
	src.Rotate(wtok("warden.tok.NEW", t0.Add(30*time.Minute)))
	waitFor(t, "the drain loop to re-arm", func() bool { return a.clk.PendingTimers() == 1 })
	for i := range 12 {
		a.tick(t, 500*time.Millisecond)
		if !echo("active-" + string(rune('a'+i))) {
			t.Fatalf("the old tunnel was closed at step %d while it was carrying bytes", i)
		}
	}

	// A CONNECT made after the rotation carries the new token.
	c2, _, head := a.send(t, connectReq("b.example.com:443", ""))
	if statusOf(head) != 200 {
		t.Fatalf("head %q", head)
	}
	defer func() { _ = c2.Close() }()
	if toks := a.sw.Tokens(); len(toks) != 2 || toks[0] != "warden.tok.OLD" || toks[1] != "warden.tok.NEW" {
		t.Fatalf("worker saw tokens %v, want OLD then NEW", toks)
	}

	// Idle now: closed once 2s have passed with no bytes, never earlier.
	idleSince := a.clk.Now()
	a.tick(t, 1900*time.Millisecond)
	if closed() {
		t.Fatal("the old tunnel was closed after 1.9s idle, want 2s")
	}
	for !closed() {
		a.tick(t, 250*time.Millisecond)
		if a.clk.Now().Sub(idleSince) > 5*time.Second {
			t.Fatal("the idle old tunnel was never closed")
		}
	}
	if idle := a.clk.Now().Sub(idleSince); idle < 2*time.Second {
		t.Errorf("the old tunnel was closed after %v idle, want at least 2s", idle)
	}
	// The tunnel made with the new token is not drained by the rotation.
	_ = c2.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := bufio.NewReader(c2).ReadByte(); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("the tunnel opened with the new token was closed: %v", err)
	}
}

func TestForwarderTunnelClosedAtTokenExp(t *testing.T) {
	exp := t0.Add(10 * time.Second)
	src := newFakeSource(wtok("warden.tok.SHORT", exp))
	a := startAgentForwarder(t, src, echoWorker, nil)
	waitFor(t, "the drain loop to start", func() bool { return a.clk.PendingTimers() == 1 })
	c, br, head := a.send(t, connectReq("a.example.com:443", ""))
	if statusOf(head) != 200 {
		t.Fatalf("head %q", head)
	}
	echo := func() bool {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(c, "x\n"); err != nil {
			return false
		}
		_, err := br.ReadString('\n')
		return err == nil
	}
	// Busy right up to exp, so only the exp can close it.
	for a.clk.Now().Before(exp.Add(-time.Second)) {
		a.tick(t, time.Second)
		if !echo() {
			t.Fatalf("closed at %v, before exp %v", a.clk.Now(), exp)
		}
	}
	a.tick(t, 2*time.Second)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := br.ReadByte(); err == nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("the tunnel stayed open past its token's exp: %v", err)
	}
}

func TestForwarderNoTokenFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		reason string
	}{
		"login required":      {identityclient.ErrLoginRequired, "login_required"},
		"issuer unreachable":  {identityclient.ErrIssuerUnreachable, "login_required"},
		"exchange denied":     {identityclient.ErrExchangeDenied{Code: "invalid_client"}, "exchange_denied"},
		"cp unreachable":      {identityclient.ErrCPUnreachable, "cp_unreachable"},
		"signer unavailable":  {identityclient.ErrUnavailable{RetryAfter: 5 * time.Second}, "cp_unreachable"},
		"rate limited":        {identityclient.ErrRateLimited{RetryAfter: time.Second}, "cp_unreachable"},
		"bad exchange answer": {identityclient.ErrBadExchangeResponse, "cp_unreachable"},
	} {
		t.Run(name, func(t *testing.T) {
			src := newFakeSource(identityclient.WardenToken{})
			src.tokenErr = tc.err
			a := startAgentForwarder(t, src, func(string) string { return reply407 }, nil)
			_, br, head := a.send(t, connectReq("a.example.com:443", ""))
			if statusOf(head) != 503 || reasonOf(head) != tc.reason {
				t.Fatalf("head %q, want 503 with reason %s", head, tc.reason)
			}
			if body, _ := io.ReadAll(br); !strings.Contains(string(body), tc.reason) || strings.Contains(string(body), "invalid_client") {
				t.Errorf("body %q", body)
			}
			if n := a.sw.dials.Load(); n != 0 {
				t.Fatalf("%d worker connections, want 0", n)
			}
			if src.refreshes.Load() != 0 {
				t.Error("a missing token must not be answered with a refresh")
			}
		})
	}

	// A worker 407 is relayed unchanged after exactly one retry.
	src := newFakeSource(wtok("warden.tok.AAA", t0.Add(15*time.Minute)))
	a := startAgentForwarder(t, src, func(string) string { return reply407 }, nil)
	_, br, head := a.send(t, connectReq("a.example.com:443", ""))
	if head != reply407 {
		t.Fatalf("relayed head %q, want the worker's 407 unchanged", head)
	}
	_, _ = io.Copy(io.Discard, br)
	if n, r := a.sw.dials.Load(), src.refreshes.Load(); n != 2 || r != 1 {
		t.Fatalf("worker connections = %d, refreshes = %d, want 2 and 1", n, r)
	}
}

func TestForwarderRetryOn407(t *testing.T) {
	const stale, fresh = "warden.tok.STALE", "warden.tok.FRESH"
	worker := func(tok string) string {
		if tok == fresh {
			return ok200
		}
		return reply407
	}
	t.Run("refresh yields a new token", func(t *testing.T) {
		src := newFakeSource(wtok(stale, t0.Add(15*time.Minute)))
		src.refresh = func(s *fakeSource) (identityclient.WardenToken, error) {
			tok := wtok(fresh, t0.Add(30*time.Minute))
			s.mu.Lock()
			s.cur = tok
			s.mu.Unlock()
			return tok, nil
		}
		a := startAgentForwarder(t, src, worker, nil)
		c, br, head := a.send(t, connectReq("a.example.com:443", ""))
		if statusOf(head) != 200 {
			t.Fatalf("head %q, want the retry's 200", head)
		}
		if toks := a.sw.Tokens(); len(toks) != 2 || toks[0] != stale || toks[1] != fresh {
			t.Fatalf("worker saw %v, want the stale then the fresh token", toks)
		}
		if _, err := io.WriteString(c, "hi\n"); err != nil {
			t.Fatal(err)
		}
		if got, _ := br.ReadString('\n'); got != "hi\n" {
			t.Errorf("echo through the retried tunnel = %q", got)
		}
		if a.src.refreshes.Load() != 1 {
			t.Errorf("%d refreshes, want 1", a.src.refreshes.Load())
		}
		logs := a.logSnapshot()
		for _, secret := range []string{stale, fresh} {
			if strings.Contains(logs, secret) {
				t.Errorf("a token appears in the logs: %q", secret)
			}
		}
	})
	t.Run("refresh fails with no valid token", func(t *testing.T) {
		src := newFakeSource(wtok(stale, t0.Add(15*time.Minute)))
		src.refresh = func(*fakeSource) (identityclient.WardenToken, error) {
			return identityclient.WardenToken{}, identityclient.ErrExchangeDenied{Code: "invalid_client"}
		}
		a := startAgentForwarder(t, src, worker, nil)
		_, _, head := a.send(t, connectReq("a.example.com:443", ""))
		if statusOf(head) != 407 || !strings.Contains(head, "Proxy-Authenticate") {
			t.Fatalf("head %q, want the worker's 407", head)
		}
		if n := a.sw.dials.Load(); n != 1 {
			t.Errorf("%d worker connections, want 1 (nothing to retry with)", n)
		}
	})
	t.Run("refresh error with a held token still retries once", func(t *testing.T) {
		src := newFakeSource(wtok(fresh, t0.Add(15*time.Minute)))
		src.refresh = func(s *fakeSource) (identityclient.WardenToken, error) {
			return s.cur, identityclient.ErrCPUnreachable
		}
		calls := 0
		a := startAgentForwarder(t, src, func(tok string) string {
			calls++ // serialised: one CONNECT at a time
			if calls == 1 {
				return reply407
			}
			return ok200
		}, nil)
		c, _, head := a.send(t, connectReq("a.example.com:443", ""))
		if statusOf(head) != 200 {
			t.Fatalf("head %q, want 200 from the retry", head)
		}
		_ = c.Close()
	})
	t.Run("a 403 is not retried", func(t *testing.T) {
		src := newFakeSource(wtok(stale, t0.Add(15*time.Minute)))
		a := startAgentForwarder(t, src, func(string) string { return "HTTP/1.1 403 Forbidden\r\n\r\n" }, nil)
		_, _, head := a.send(t, connectReq("a.example.com:443", ""))
		if statusOf(head) != 403 || a.sw.dials.Load() != 1 || src.refreshes.Load() != 0 {
			t.Errorf("head %q dials %d refreshes %d", head, a.sw.dials.Load(), src.refreshes.Load())
		}
	})
}

func TestForwarderOptionalClientCredential(t *testing.T) {
	// Without a credential and without AllowAnonymousClients Serve refuses.
	f := &identityclient.Forwarder{WorkerAddr: "w:1", Source: newFakeSource(identityclient.WardenToken{})}
	if err := f.Serve(context.Background(), nil); err == nil {
		t.Fatal("Serve accepted a forwarder with no client credential and no opt-in")
	}
	// With the opt-in a client needs nothing, and what it sends is not forwarded.
	src := newFakeSource(wtok("warden.tok.AAA", t0.Add(15*time.Minute)))
	a := startAgentForwarder(t, src, echoWorker, nil)
	c, _, head := a.send(t, connectReq("a.example.com:443", basicHeader("wx", "whatever")))
	if statusOf(head) != 200 {
		t.Fatalf("head %q", head)
	}
	_ = c.Close()
	a.sw.mu.Lock()
	defer a.sw.mu.Unlock()
	if len(a.sw.heads) != 1 || strings.Contains(a.sw.heads[0], base64.StdEncoding.EncodeToString([]byte("wx:whatever"))) {
		t.Errorf("the client's credential reached the worker: %q", a.sw.heads)
	}
}

func TestForwarderMaxTunnels(t *testing.T) {
	src := newFakeSource(wtok("warden.tok.AAA", t0.Add(15*time.Minute)))
	a := startAgentForwarder(t, src, echoWorker, func(f *identityclient.Forwarder) { f.MaxTunnels = 2 })
	c1, _, h1 := a.send(t, connectReq("a.example.com:443", ""))
	c2, _, h2 := a.send(t, connectReq("b.example.com:443", ""))
	if statusOf(h1) != 200 || statusOf(h2) != 200 {
		t.Fatalf("heads %q %q", h1, h2)
	}
	_, _, h3 := a.send(t, connectReq("c.example.com:443", ""))
	if statusOf(h3) != 503 || reasonOf(h3) != "tunnel_limit" {
		t.Fatalf("third CONNECT: head %q, want 503 tunnel_limit", h3)
	}
	if n := a.sw.dials.Load(); n != 2 {
		t.Errorf("%d worker connections, want 2", n)
	}
	// A slot is free again once a tunnel ends.
	_ = c1.Close()
	waitFor(t, "a free tunnel slot", func() bool {
		c, _, head := a.send(t, connectReq("d.example.com:443", ""))
		_ = c.Close()
		return statusOf(head) == 200
	})
	_ = c2.Close()
}

func TestForwarderTunnelLogs(t *testing.T) {
	src := newFakeSource(wtok("warden.tok.SECRET-TOKEN", t0.Add(15*time.Minute)))
	a := startAgentForwarder(t, src, echoWorker, nil)
	c, br, _ := a.send(t, connectReq("api.example.com:443", ""))
	_, _ = io.WriteString(c, "12345\n")
	_, _ = br.ReadString('\n')
	_ = c.Close()
	waitFor(t, "tunnel_close", func() bool { return strings.Contains(a.logSnapshot(), "tunnel_close") })
	logs := a.logSnapshot()
	fp := identityclient.Fingerprint("warden.tok.SECRET-TOKEN")
	for _, want := range []string{"tunnel_open", "tunnel_close", "target=api.example.com:443", "status=200", "bytes_up=6", "bytes_down=6", "duration=", "token_fp=" + fp} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
	for _, secret := range []string{"warden.tok.SECRET-TOKEN", base64.StdEncoding.EncodeToString([]byte("session:warden.tok.SECRET-TOKEN"))} {
		if strings.Contains(logs, secret) {
			t.Errorf("a token appears in the logs")
		}
	}
	src.Rotate(wtok("warden.tok.NEXT", t0.Add(30*time.Minute)))
	waitFor(t, "token_rotated", func() bool { return strings.Contains(a.logSnapshot(), "token_rotated") })
}
