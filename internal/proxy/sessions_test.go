package proxy

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// These tests cover W-P1-BLOCK-05: sessions that never pass a per-request check
// again (raw tunnels, idle keep-alive, h2, WebSocket) are cut when
// CloseBlockedSessions runs after a block lands, with one user_blocked deny
// event each, while a request that already arrived completes.

const cutWithin = time.Second

// waitBlockedEvents polls until the store holds n user_blocked events.
func waitBlockedEvents(t *testing.T, st *syncStore, n int) []analytics.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(blockedEvents(st)) < n && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	return blockedEvents(st)
}

// assertConnCut asserts a read on r fails (EOF or reset) within cutWithin.
func assertConnCut(t *testing.T, conn net.Conn, r io.Reader) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(cutWithin))
	if _, err := io.Copy(io.Discard, r); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("connection still open %v after the block applied", cutWithin)
		}
	}
}

// applyBlock is the long-poll sequence: replace the policy, then close sessions.
func (e *blockEnv) applyBlock(users ...config.BlockedUser) {
	e.block(users...)
	e.p.CloseBlockedSessions()
}

// rawTunnelEnv is a CA-less proxy whose dials return a pipe to a fake upstream
// that calls serve with its end.
type rawTunnelEnv struct {
	p     *Proxy
	store *syncStore
	m     *fakeMetrics
}

func newRawTunnelEnv(t *testing.T, serve func(net.Conn)) *rawTunnelEnv {
	t.Helper()
	v := fakes.NewVerifier()
	exp := time.Now().Add(time.Hour)
	v.Set("tok-u1", identity.Claims{Sub: "u1", Expiry: exp}, identity.StatusValid, "")
	v.Set("tok-u2", identity.Claims{Sub: "u2", Expiry: exp}, identity.StatusValid, "")
	e := &rawTunnelEnv{store: &syncStore{}, m: newFakeMetrics()}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "tunnel.test", Port: 443}}}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  e.store,
		Metrics:    e.m,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Identity:   IdentityConfig{Verifier: v, Mode: IdentityModeAttribute},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.dialFunc = func(string, string) (net.Conn, error) {
		c, up := net.Pipe()
		go func() {
			defer func() { _ = up.Close() }()
			serve(up)
		}()
		return c, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	waitForAddr(t, p)
	e.p = p
	return e
}

// tunnel opens a raw CONNECT tunnel as tok (or anonymous when "") and returns
// the conn and its reader positioned after the 200.
func (e *rawTunnelEnv) tunnel(t *testing.T, tok string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	auth := ""
	if tok != "" {
		auth = "Proxy-Authorization: " + basicAuth(tok) + "\r\n"
	}
	_, _ = io.WriteString(conn, "CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n"+auth+"\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	return conn, br
}

func replaceBlocked(p *Proxy, users ...config.BlockedUser) {
	p.cfg.Policy.Replace(config.Policy{
		Allowlist:    []config.AllowlistEntry{{Domain: "tunnel.test", Port: 443}},
		BlockedUsers: users,
	})
}

func TestBlockList_TunnelCut(t *testing.T) {
	e := newRawTunnelEnv(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	conn, br := e.tunnel(t, "tok-u1")
	replaceBlocked(e.p, config.BlockedUser{Sub: "u1"})
	e.p.CloseBlockedSessions()
	assertConnCut(t, conn, br)
	evs := waitBlockedEvents(t, e.store, 1)
	if len(evs) != 1 || evs[0].UserSub != "u1" || evs[0].Protocol != "tcp" || evs[0].Decision != "deny" || evs[0].Domain != "tunnel.test" {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
	// A second apply finds nothing left: still exactly one event.
	e.p.CloseBlockedSessions()
	if n := len(blockedEvents(e.store)); n != 1 {
		t.Errorf("user_blocked events = %d, want exactly 1", n)
	}
}

func TestBlockList_MidTransferTunnelCut(t *testing.T) {
	// A slow upstream that keeps streaming: the tunnel is mid-transfer.
	e := newRawTunnelEnv(t, func(c net.Conn) {
		for {
			if _, err := c.Write([]byte("chunk")); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	conn, br := e.tunnel(t, "tok-u1")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("no data before the block: %v", err)
	}
	replaceBlocked(e.p, config.BlockedUser{Sub: "u1"})
	start := time.Now()
	e.p.CloseBlockedSessions()
	assertConnCut(t, conn, br)
	if d := time.Since(start); d > cutWithin {
		t.Errorf("tunnel took %v to die", d)
	}
	if n := len(waitBlockedEvents(t, e.store, 1)); n != 1 {
		t.Errorf("user_blocked events = %d, want 1", n)
	}
}

func TestBlockList_IdleKeepAliveCut(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	c := e.h1("Proxy-Authorization: " + basicAuth("tok-u1") + "\r\n")
	if st := c.get(""); st != 200 {
		t.Fatalf("status = %d", st)
	}
	e.applyBlock(config.BlockedUser{Sub: "u1"})
	// No further request: the idle connection itself is closed.
	assertConnCut(t, c.tc, c.br)
	evs := waitBlockedEvents(t, e.store, 1)
	if len(evs) != 1 || evs[0].UserSub != "u1" || evs[0].Protocol != "https" {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
}

// A header identity on a connection with no CONNECT token registers the session
// on its first request.
func TestBlockList_HeaderIdentitySessionCut(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	c := e.h1("")
	if st := c.get("X-Warden-Identity: Bearer tok-u2\r\n"); st != 200 {
		t.Fatalf("status = %d", st)
	}
	e.applyBlock(config.BlockedUser{Email: "u2@corp.com"})
	assertConnCut(t, c.tc, c.br)
	if evs := waitBlockedEvents(t, e.store, 1); len(evs) != 1 || evs[0].UserSub != "u2" {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
}

func TestBlockList_H2Cut(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	cc := e.h2("Proxy-Authorization: " + basicAuth("tok-u1") + "\r\n")
	if st := h2Get(t, cc, nil); st != 200 {
		t.Fatalf("status = %d", st)
	}
	e.applyBlock(config.BlockedUser{Sub: "u1"})
	evs := waitBlockedEvents(t, e.store, 1)
	if len(evs) != 1 || evs[0].UserSub != "u1" || evs[0].Protocol != "http2" {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
	// The connection is gone: a new stream fails at the transport, it is not
	// answered by blockStage's 403 (which would add a second event).
	req, _ := http.NewRequest("GET", "https://"+idHost+"/x", nil)
	deadline := time.Now().Add(cutWithin)
	for {
		resp, err := cc.RoundTrip(req)
		if err != nil {
			break
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("h2 connection still serves streams after the cut")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(blockedEvents(e.store)); n != 1 {
		t.Errorf("user_blocked events = %d, want 1", n)
	}
}

func TestBlockList_WebSocketCut(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	_, _, caCert, caKey := generateTestCA(t)
	b := &wsBackend{}
	ln := startWSBackend(t, caCert, caKey, b)
	e.p.dialTLS = dialBackend(ln)
	conn, br, status := e.connect("Proxy-Authorization: " + basicAuth("tok-u1") + "\r\n")
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	tc := e.tlsOver(conn, br, "http/1.1")
	_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: "+idHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	cbr := bufio.NewReader(tc)
	resp, err := http.ReadResponse(cbr, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	e.applyBlock(config.BlockedUser{Sub: "u1"})
	assertConnCut(t, tc, cbr)
	evs := waitBlockedEvents(t, e.store, 1)
	if len(evs) != 1 || evs[0].UserSub != "u1" || evs[0].Protocol != "websocket" {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
}

// A request that arrived under the old policy completes and delivers its full
// response; the connection is closed right after it.
func TestBlockList_InFlightRequestCompletes(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.be.hold = make(chan struct{})
	e.be.arrived = make(chan struct{}, 1)
	e.be.echo = strings.Repeat("x", 4096)
	c := e.h1("Proxy-Authorization: " + basicAuth("tok-u1") + "\r\n")
	_, _ = io.WriteString(c.tc, "GET /x HTTP/1.1\r\nHost: "+idHost+"\r\n\r\n")
	select {
	case <-e.be.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the backend")
	}
	e.applyBlock(config.BlockedUser{Sub: "u1"})
	// The block is applied (deny event written) but the request is still served.
	if n := len(waitBlockedEvents(t, e.store, 1)); n != 1 {
		t.Fatalf("user_blocked events = %d, want 1", n)
	}
	close(e.be.hold)
	_ = c.tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatalf("in-flight response lost: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 || string(body) != e.be.echo+"ok" {
		t.Fatalf("response = %d, %d bytes, err %v; want 200 with the full body", resp.StatusCode, len(body), err)
	}
	// Then the session ends.
	assertConnCut(t, c.tc, c.br)
	if n := len(blockedEvents(e.store)); n != 1 {
		t.Errorf("user_blocked events = %d, want 1", n)
	}
}

func TestBlockList_OtherSessionsStay(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	u1 := e.h1("Proxy-Authorization: " + basicAuth("tok-u1") + "\r\n")
	u2 := e.h1("Proxy-Authorization: " + basicAuth("tok-u2") + "\r\n")
	anon := e.h1("")
	for _, c := range []*idH1{u1, u2, anon} {
		if st := c.get(""); st != 200 {
			t.Fatalf("status = %d", st)
		}
	}
	e.applyBlock(config.BlockedUser{Sub: "u1"})
	assertConnCut(t, u1.tc, u1.br)
	if st := u2.get(""); st != 200 {
		t.Errorf("other user's session: status = %d, want 200", st)
	}
	if st := anon.get(""); st != 200 {
		t.Errorf("anonymous session: status = %d, want 200", st)
	}
	if n := len(waitBlockedEvents(t, e.store, 1)); n != 1 {
		t.Errorf("user_blocked events = %d, want 1", n)
	}
}

func TestSessionRegistryRace(t *testing.T) {
	r := newSessionRegistry()
	var closed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s := r.newSession("tcp", "h", 443, true, closerFunc(func() error { closed.Add(1); return nil }))
				s.bind(connIdentity{Claims: identity.Claims{Sub: "u1", Email: "U1@Corp.com"}})
				s.addCloser(closerFunc(func() error { return nil }))
				s.beginRequest()
				_ = s.endRequest()
				s.release()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 400; j++ {
			r.takeBlocked(func(string) bool { return true }, func(string) bool { return true }, func(identity.Claims) bool { return true })
		}
	}()
	wg.Wait()
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// A session not interruptible and busy is only marked; it is cut by endRequest.
func TestSessionRegistryBusyDefersCut(t *testing.T) {
	r := newSessionRegistry()
	var closed atomic.Bool
	s := r.newSession("http1", "h", 443, false, closerFunc(func() error { closed.Store(true); return nil }))
	s.bind(connIdentity{Claims: identity.Claims{Sub: "u1"}})
	s.beginRequest()
	all := func(string) bool { return true }
	got := r.takeBlocked(all, all, func(identity.Claims) bool { return true })
	if len(got) != 1 || len(got[0].closers) != 0 {
		t.Fatalf("busy session: %+v, want one marked session with nothing to close yet", got)
	}
	if !s.endRequest() {
		t.Error("endRequest did not report the pending cut")
	}
	if s.upgrade("websocket", closerFunc(func() error { return nil })) {
		t.Error("upgrade of a cut session succeeded")
	}
	if again := r.takeBlocked(all, all, func(identity.Claims) bool { return true }); len(again) != 0 {
		t.Errorf("second take = %+v, want none", again)
	}
}

func TestBlocklistMetrics(t *testing.T) {
	e := newRawTunnelEnv(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	c1, r1 := e.tunnel(t, "tok-u1")
	c2, r2 := e.tunnel(t, "tok-u1")
	_, _ = e.tunnel(t, "tok-u2")
	replaceBlocked(e.p, config.BlockedUser{Sub: "u1"}, config.BlockedUser{Email: "gone@corp.com"})
	e.p.CloseBlockedSessions()
	assertConnCut(t, c1, r1)
	assertConnCut(t, c2, r2)
	e.m.mu.Lock()
	closed, entries := e.m.blocklistClosed, e.m.blocklistEntries
	e.m.mu.Unlock()
	if closed != 2 {
		t.Errorf("sessions closed = %d, want 2", closed)
	}
	if entries != 2 {
		t.Errorf("blocklist entries = %d, want 2", entries)
	}
	// The gauge follows the list down; nothing more is closed.
	replaceBlocked(e.p)
	e.p.CloseBlockedSessions()
	e.m.mu.Lock()
	closed, entries = e.m.blocklistClosed, e.m.blocklistEntries
	e.m.mu.Unlock()
	if closed != 2 || entries != 0 {
		t.Errorf("after unblock: closed = %d entries = %d, want 2 and 0", closed, entries)
	}
}

// With a CA configured (every worker with TLS termination) a CONNECT whose
// first byte is not a TLS hello is piped through handleTLS, not tunnel: it must
// register for a block-list cut all the same.
func TestBlockList_NonTLSPassthroughTunnelCut(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.p.dialFunc = func(string, string) (net.Conn, error) {
		c, up := net.Pipe()
		go func() {
			defer func() { _ = up.Close() }()
			_, _ = io.Copy(io.Discard, up)
		}()
		return c, nil
	}
	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT "+idHost+":443 HTTP/1.1\r\nHost: "+idHost+":443\r\nProxy-Authorization: "+basicAuth("tok-u1")+"\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	_, _ = io.WriteString(conn, "G") // not 0x16: passthrough
	waitAllowEvents(t, e.store, 1)
	e.applyBlock(config.BlockedUser{Sub: "u1"})
	assertConnCut(t, conn, br)
	evs := waitBlockedEvents(t, e.store, 1)
	if len(evs) != 1 || evs[0].UserSub != "u1" || evs[0].Protocol != "tcp" || evs[0].Domain != idHost {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
}

// waitAllowEvents waits until n allow events are recorded (the passthrough has
// dialled and is piping).
func waitAllowEvents(t *testing.T, st *syncStore, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := 0
		for _, ev := range st.snapshot() {
			if ev.Decision == "allow" {
				got++
			}
		}
		if got >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no allow event: %+v", st.snapshot())
}
