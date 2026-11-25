package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/mcp/ws"
)

// These tests cover W-P2-WBND-09: require-mode sessions are cut at token expiry
// and when a bundle apply breaks their binding. The identity clock AND the
// expiry loop's timer are one fake clock, so no test sleeps for token time.

const (
	expTTL  = 30 * time.Second
	expSkew = identity.DefaultClockSkew // the verifier-less holder default
)

type expEnv struct {
	*idEnv
	sv *bindVerifier
	fk *clocktest.Fake
}

// newExpiryEnv is newRequireEnv on a fake identity clock: tok-w-alice expires
// expTTL after start, tok-w-long an hour after. edit runs on the Config.
func newExpiryEnv(t *testing.T, edit func(*Config)) *expEnv {
	t.Helper()
	fk := clocktest.NewFake(time.Now())
	e := newIDEnvCfg(t, IdentityModeAttribute, func(c *Config) {
		c.IdentityClock = fk.Now
		c.IdentityTimer = func(d time.Duration) IdentityTimer { return fk.NewTimer(d) }
		if edit != nil {
			edit(c)
		}
	})
	sv := &bindVerifier{}
	sv.setKeys(t, 1, []string{"k1"}, reqActive("T1"))
	warden := func(sub string, ttl time.Duration) identity.Claims {
		c := wardenClaims(reqAgent, "T1")
		c.Sub, c.Email, c.Expiry = sub, sub+"@example.test", fk.Now().Add(ttl)
		return c
	}
	e.v.Set("tok-w-alice", warden("alice", expTTL), identity.StatusValid, "")
	e.v.Set("tok-w-long", warden("alice", time.Hour), identity.StatusValid, "")
	e.v.Set("tok-a-alice", idClaims("alice", fk.Now().Add(expTTL)), identity.StatusValid, "")
	e.p.SetIdentity(&reqVerifier{Verifier: e.v, snap: sv}, IdentityModeRequire)
	return &expEnv{idEnv: e, sv: sv, fk: fk}
}

// armed is how many sessions the expiry heap holds.
func (e *expEnv) armed() int {
	r := e.p.sessions
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.expiry)
}

// waitArmed waits for n armed sessions: a CONNECT's 200 is written before the
// tunnel registers.
func (e *expEnv) waitArmed(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.armed() != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions armed, want %d", e.armed(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// pollAdvance advances the fake clock by step until cond holds. One Advance
// alone is not enough: the expiry loop may compute its wait before the clock
// moves and arm its timer after, so it must be driven by condition.
func pollAdvance(t *testing.T, fk *clocktest.Fake, step time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", desc)
		}
		fk.Advance(step)
		time.Sleep(time.Millisecond)
	}
}

func (e *expEnv) expiredEvents() int {
	n := 0
	for _, ev := range e.denyEvents() {
		if ev.Reason == string(denyreason.IdentityExpired) {
			n++
		}
	}
	return n
}

// cutBy advances the clock by condition until an identity_expired event exists.
func (e *expEnv) cutBy(t *testing.T) {
	t.Helper()
	pollAdvance(t, e.fk, time.Second, "the identity_expired cut", func() bool { return e.expiredEvents() > 0 })
}

// rawPipe makes the upstream side of a raw tunnel: dials get one end of a pipe.
func (e *expEnv) rawPipe() (upstream chan net.Conn) {
	upstream = make(chan net.Conn, 4)
	e.setRaw(func() (net.Conn, error) {
		a, b := net.Pipe()
		upstream <- b
		return a, nil
	})
	return upstream
}

func readsEOF(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !isTimeout(err)
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestRequireSessionExpiry(t *testing.T) {
	t.Run("tunnel", func(t *testing.T) {
		e := newExpiryEnv(t, noCA)
		up := e.rawPipe()
		conn, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status %q", status)
		}
		e.waitArmed(t, 1)
		upstream := <-up

		// Past exp but inside skew the tunnel is still open: bytes flow.
		e.fk.Advance(expTTL + expSkew - time.Second)
		go func() { _, _ = conn.Write([]byte("x")) }()
		_ = upstream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := upstream.Read(make([]byte, 1)); err != nil {
			t.Fatalf("tunnel closed before exp+skew: %v", err)
		}
		if n := e.expiredEvents(); n != 0 {
			t.Fatalf("%d identity_expired events before exp+skew", n)
		}

		e.cutBy(t)
		if !readsEOF(conn) || !readsEOF(upstream) {
			t.Error("both legs must be closed after the cut")
		}
		e.waitDeny(t, denyreason.IdentityExpired, 1)
		if n := e.expiredEvents(); n != 1 {
			t.Errorf("%d identity_expired events, want exactly 1", n)
		}
		if got := e.m.blockedCount("identity_expired"); got != 1 {
			t.Errorf("blocked{identity_expired} = %d, want 1", got)
		}
		e.waitArmed(t, 0)
	})

	t.Run("keepalive", func(t *testing.T) {
		e := newExpiryEnv(t, nil)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if st := c.get(""); st != 200 {
			t.Fatalf("first request status %d, want 200", st)
		}
		e.waitArmed(t, 1)
		e.fk.Advance(expTTL - time.Second)
		if st := c.get(""); st != 200 {
			t.Fatalf("request before exp: status %d, want 200", st)
		}
		if n := e.expiredEvents(); n != 0 {
			t.Fatalf("%d events before exp", n)
		}
		// An idle keep-alive is cut at exp itself, with no skew grace.
		e.cutBy(t)
		_ = c.tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.br.ReadByte(); err == nil {
			t.Error("idle keep-alive still open after exp")
		}
		if n := e.expiredEvents(); n != 1 {
			t.Errorf("%d identity_expired events, want 1", n)
		}
		if got := e.m.blockedCount("identity_expired"); got != 1 {
			t.Errorf("blocked{identity_expired} = %d, want 1", got)
		}
		if n := e.be.requests(); n != 2 {
			t.Errorf("upstream saw %d requests, want 2", n)
		}
	})

	// A CONNECT the verifier admitted inside the skew window (past exp) must be
	// served, not cut on arrival: its keep-alive is cut one skew later.
	t.Run("keepalive_armed_inside_skew", func(t *testing.T) {
		e := newExpiryEnv(t, nil)
		e.fk.Advance(expTTL + 10*time.Second)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if st := c.get(""); st != 200 {
			t.Fatalf("request inside the skew: status %d, want 200", st)
		}
		e.waitArmed(t, 1)
		if st := c.get(""); st != 200 {
			t.Fatalf("second request inside the skew: status %d, want 200", st)
		}
		if n := e.expiredEvents(); n != 0 {
			t.Fatalf("%d events inside the skew", n)
		}
		e.cutBy(t)
		_ = c.tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.br.ReadByte(); err == nil {
			t.Error("keep-alive still open after exp+skew")
		}
	})

	t.Run("h2_goaway", func(t *testing.T) {
		inf := NewInflight()
		e := newExpiryEnv(t, func(c *Config) { c.Inflight = inf })
		conn, br, status := e.connect("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status %q", status)
		}
		tc := e.tlsOver(conn, br, "h2")
		fr := newRawH2(t, tc)
		fr.openStream(1, "POST", false) // in flight: the body is still to come
		e.waitArmed(t, 1)
		// GOAWAY names the last stream the server saw, so the stream must be in
		// flight server-side before the clock moves.
		for deadline := time.Now().Add(5 * time.Second); len(inf.InFlight()) != 1; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the stream never reached the proxy")
			}
		}

		e.fk.Advance(expTTL - time.Second)
		if fr.sawGoAway() {
			t.Fatal("GOAWAY before exp")
		}
		pollAdvance(t, e.fk, time.Second, "GOAWAY", fr.sawGoAway)
		if n := e.expiredEvents(); n != 1 {
			t.Errorf("%d identity_expired events, want 1", n)
		}
		// The in-flight stream still completes after GOAWAY.
		fr.endStream(1)
		if st := fr.waitStatus(t, 1); st != "200" {
			t.Errorf("in-flight stream status %q, want 200", st)
		}
		if !fr.waitClosed() {
			t.Error("connection must end once the in-flight stream finished")
		}
		if n := e.expiredEvents(); n != 1 {
			t.Errorf("%d identity_expired events after close, want still 1", n)
		}
	})

	t.Run("websocket", func(t *testing.T) {
		e := newExpiryEnv(t, nil)
		_, _, caCert, caKey := generateTestCA(t)
		b := &wsBackend{}
		ln := startWSBackend(t, caCert, caKey, b)
		e.p.dialTLS = dialBackend(ln)
		conn, br, status := e.connect("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status %q", status)
		}
		tc := e.tlsOver(conn, br, "http/1.1")
		_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: "+idHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
		cbr := bufio.NewReader(tc)
		resp, err := http.ReadResponse(cbr, nil)
		if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade: %v %v", resp, err)
		}
		e.waitArmed(t, 1)

		// A WebSocket gets the skew a tunnel gets: still open past exp.
		e.fk.Advance(expTTL + expSkew - time.Second)
		frame := ws.Frame{Fin: true, Opcode: ws.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hi")}
		if _, err := tc.Write(frameWire(frame)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-b.gotText:
		case <-time.After(5 * time.Second):
			t.Fatal("frame did not reach the backend before exp+skew")
		}
		if n := e.expiredEvents(); n != 0 {
			t.Fatalf("%d events before exp+skew", n)
		}
		e.cutBy(t)
		_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := cbr.ReadByte(); err == nil {
			t.Error("WebSocket still open after exp+skew")
		}
		if n := e.expiredEvents(); n != 1 {
			t.Errorf("%d identity_expired events, want 1", n)
		}
	})

	// The mid-tunnel case of a MITM-terminated tunnel: the next request on the
	// same TLS connection is refused after exp+skew, whichever of the cut or the
	// per-request recheck gets there first, and never reaches the upstream.
	t.Run("terminated_next_request_refused", func(t *testing.T) {
		e := newExpiryEnv(t, nil)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if st := c.get(""); st != 200 {
			t.Fatalf("first request status %d, want 200", st)
		}
		e.waitArmed(t, 1)
		e.fk.Advance(expTTL + expSkew + time.Second)
		_, _ = io.WriteString(c.tc, "GET /x HTTP/1.1\r\nHost: "+idHost+"\r\n\r\n")
		if resp, err := http.ReadResponse(c.br, nil); err == nil && resp.StatusCode == 200 {
			t.Error("a request after exp+skew was served")
		}
		e.waitDeny(t, denyreason.IdentityExpired, 1)
		if n := e.be.requests(); n != 1 {
			t.Errorf("upstream saw %d requests, want 1", n)
		}
	})
}

func TestRecheckClosesRevokedKey(t *testing.T) {
	setup := func(t *testing.T) (*expEnv, net.Conn, net.Conn) {
		e := newExpiryEnv(t, noCA)
		up := e.rawPipe()
		conn, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-w-long") + "\r\n")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status %q", status)
		}
		e.waitArmed(t, 1)
		return e, conn, <-up
	}
	logged := func(e *expEnv, want string) bool {
		return strings.Contains(e.logs.String(), "detail="+want)
	}

	t.Run("unchanged_bundle_keeps_session", func(t *testing.T) {
		e, conn, upstream := setup(t)
		e.sv.setKeys(t, 2, []string{"k1"}, reqActive("T1"))
		e.p.RecheckIdentitySessions()
		go func() { _, _ = conn.Write([]byte("x")) }()
		_ = upstream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := upstream.Read(make([]byte, 1)); err != nil {
			t.Fatalf("session closed by a recheck that still binds: %v", err)
		}
		if n := len(e.denyEvents()); n != 0 {
			t.Errorf("%d deny events, want 0", n)
		}
	})

	t.Run("unknown_kid", func(t *testing.T) {
		e, conn, upstream := setup(t)
		e.sv.setKeys(t, 2, []string{"k2"}, reqActive("T1")) // k1 left the JWKS
		e.p.RecheckIdentitySessions()
		if !readsEOF(conn) || !readsEOF(upstream) {
			t.Fatal("session survived the removal of its key id")
		}
		evs := e.waitDeny(t, denyreason.IdentityRequired, 1)
		if len(evs) != 1 || !logged(e, "unknown_kid") {
			t.Errorf("events %+v; want one identity_required with detail unknown_kid in the log", evs)
		}
		if got := e.m.blockedCount("identity_required"); got != 1 {
			t.Errorf("blocked{identity_required} = %d, want 1", got)
		}
		e.p.RecheckIdentitySessions() // idempotent: no second event
		if n := len(e.denyEvents()); n != 1 {
			t.Errorf("%d deny events after a second recheck, want 1", n)
		}
	})

	t.Run("agent_disabled", func(t *testing.T) {
		e, conn, _ := setup(t)
		e.sv.setKeys(t, 2, []string{"k1"}, map[string]identity.WardenAgent{reqAgent: {Active: false, JKT: jktSet("T1")}})
		e.p.RecheckIdentitySessions()
		if !readsEOF(conn) {
			t.Fatal("session survived its agent being disabled")
		}
		e.waitDeny(t, denyreason.IdentityRequired, 1)
		if !logged(e, "agent_disabled") {
			t.Errorf("log lacks detail agent_disabled:\n%s", e.logs.String())
		}
	})

	t.Run("key_removed", func(t *testing.T) {
		e, conn, _ := setup(t)
		e.sv.setKeys(t, 2, []string{"k1"}, reqActive("T2")) // agent key T1 no longer registered
		e.p.RecheckIdentitySessions()
		if !readsEOF(conn) {
			t.Fatal("session survived its agent key being removed")
		}
		e.waitDeny(t, denyreason.IdentityRequired, 1)
		if !logged(e, "cnf_mismatch") {
			t.Errorf("log lacks detail cnf_mismatch:\n%s", e.logs.String())
		}
	})
}

// TestAttributeSessionsNotRegistered: attribute-mode and anonymous sessions are
// never armed, so they stay open past token exp and see no change.
func TestAttributeSessionsNotRegistered(t *testing.T) {
	e := newExpiryEnv(t, noCA)
	e.p.SetIdentity(&reqVerifier{Verifier: e.v, snap: e.sv}, IdentityModeAttribute)
	up := e.rawPipe()
	conn, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-a-alice") + "\r\n")
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status %q", status)
	}
	anon, _, status := e.connect("")
	if !strings.Contains(status, "200") {
		t.Fatalf("anonymous CONNECT status %q", status)
	}
	upstream, anonUp := <-up, <-up
	if n := e.armed(); n != 0 {
		t.Fatalf("%d sessions armed in attribute mode, want 0", n)
	}
	// Far past exp and skew: the sessions carry on and no event is written.
	e.fk.Advance(expTTL + 10*expSkew)
	e.p.RecheckIdentitySessions()
	for _, pair := range [][2]net.Conn{{conn, upstream}, {anon, anonUp}} {
		go func(c net.Conn) { _, _ = c.Write([]byte("x")) }(pair[0])
		_ = pair[1].SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := pair[1].Read(make([]byte, 1)); err != nil {
			t.Fatalf("attribute-mode session closed past exp: %v", err)
		}
	}
	if n := len(e.denyEvents()); n != 0 {
		t.Errorf("%d deny events, want 0", n)
	}
}

// rawH2 is a minimal HTTP/2 client over an established TLS conn, so a test can
// see the GOAWAY frame and keep a stream open across it.
type rawH2 struct {
	t   *testing.T
	tc  *tls.Conn
	fr  *http2.Framer
	enc *hpack.Encoder
	buf *bufferedHPACK

	wmu    sync.Mutex // serializes writes: the Framer is not safe for concurrent use
	mu     sync.Mutex
	goaway bool
	status map[uint32]string
	closed chan struct{}
}

type bufferedHPACK struct{ b []byte }

func (w *bufferedHPACK) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }

func newRawH2(t *testing.T, tc *tls.Conn) *rawH2 {
	t.Helper()
	r := &rawH2{t: t, tc: tc, fr: http2.NewFramer(tc, tc), buf: &bufferedHPACK{}, status: map[uint32]string{}, closed: make(chan struct{})}
	r.enc = hpack.NewEncoder(r.buf)
	if _, err := io.WriteString(tc, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	if err := r.fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	go r.readLoop()
	return r
}

func (r *rawH2) readLoop() {
	defer close(r.closed)
	dec := hpack.NewDecoder(4096, nil)
	for {
		f, err := r.fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				r.wmu.Lock()
				_ = r.fr.WriteSettingsAck()
				r.wmu.Unlock()
			}
		case *http2.GoAwayFrame:
			r.mu.Lock()
			r.goaway = true
			r.mu.Unlock()
		case *http2.HeadersFrame:
			fields, _ := dec.DecodeFull(f.HeaderBlockFragment())
			for _, hf := range fields {
				if hf.Name == ":status" {
					r.mu.Lock()
					r.status[f.StreamID] = hf.Value
					r.mu.Unlock()
				}
			}
		}
	}
}

func (r *rawH2) openStream(id uint32, method string, endStream bool) {
	r.buf.b = r.buf.b[:0]
	for _, kv := range [][2]string{{":method", method}, {":scheme", "https"}, {":authority", idHost}, {":path", "/x"}} {
		_ = r.enc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]})
	}
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if err := r.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: r.buf.b, EndHeaders: true, EndStream: endStream}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawH2) endStream(id uint32) {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if err := r.fr.WriteData(id, true, nil); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawH2) sawGoAway() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.goaway
}

func (r *rawH2) waitStatus(t *testing.T, id uint32) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		s, ok := r.status[id]
		r.mu.Unlock()
		if ok {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no response on stream %d", id)
	return ""
}

func (r *rawH2) waitClosed() bool {
	select {
	case <-r.closed:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}
