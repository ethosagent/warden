package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	"github.com/ethosagent/warden/test/fakes"
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
	sv    *bindVerifier
	fk    *clocktest.Fake
	start time.Time // the fake clock when the env was built; tok-w-alice expires expTTL later
}

func (e *expEnv) exp() time.Time { return e.start.Add(expTTL) }

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
	return &expEnv{idEnv: e, sv: sv, fk: fk, start: fk.Now()}
}

// armed is how many sessions the expiry heap holds.
func (e *idEnv) armed() int {
	r := e.p.sessions
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.expiry)
}

// waitArmed waits for n armed sessions: a CONNECT's 200 is written before the
// tunnel registers.
func (e *idEnv) waitArmed(t *testing.T, n int) {
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
// moves and arm its timer after, so it must be driven by condition. After each
// step it gives the loop a short real moment to act, so a cut lands at the
// boundary the clock just crossed and not a step later.
func pollAdvance(t *testing.T, fk *clocktest.Fake, step time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", desc)
		}
		fk.Advance(step)
		for settle := time.Now().Add(100 * time.Millisecond); !cond() && time.Now().Before(settle); {
			time.Sleep(time.Millisecond)
		}
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

// cutBy advances the clock by condition until an identity_expired event exists
// and returns the fake time at which it was first seen.
func (e *expEnv) cutBy(t *testing.T) time.Time {
	t.Helper()
	return e.cutByNear(t, time.Time{})
}

// cutByNear is cutBy after moving the clock to 2s before near (zero: no move),
// so the polling steps cover only the boundary, not the whole token lifetime.
func (e *expEnv) cutByNear(t *testing.T, near time.Time) time.Time {
	t.Helper()
	if d := near.Add(-2 * time.Second).Sub(e.fk.Now()); !near.IsZero() && d > 0 {
		e.fk.Advance(d)
	}
	pollAdvance(t, e.fk, time.Second, "the identity_expired cut", func() bool { return e.expiredEvents() > 0 })
	return e.fk.Now()
}

// assertCutWithin fails when the cut was first seen later than limit+1s.
func assertCutWithin(t *testing.T, what string, at, limit time.Time) {
	t.Helper()
	if at.After(limit.Add(time.Second)) {
		t.Errorf("%s was cut %v after its limit, want within 1s", what, at.Sub(limit))
	}
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

		assertCutWithin(t, "the raw tunnel", e.cutBy(t), e.exp().Add(expSkew))
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
		assertCutWithin(t, "the idle keep-alive", e.cutBy(t), e.exp())
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
		assertCutWithin(t, "the late keep-alive", e.cutByNear(t, e.exp().Add(expSkew)), e.exp().Add(expSkew))
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
		// A new stream after GOAWAY is refused: the server never answers it.
		fr.openStream(3, "GET", true)
		fr.endStream(1)
		if st := fr.waitStatus(t, 1); st != "200" {
			t.Errorf("in-flight stream status %q, want 200", st)
		}
		if !fr.waitClosed() {
			t.Error("connection must end once the in-flight stream finished")
		}
		if st := fr.statusOf(3); st != "" {
			t.Errorf("a stream opened after GOAWAY got status %q, want none", st)
		}
		if n := e.expiredEvents(); n != 1 {
			t.Errorf("%d identity_expired events after close, want still 1", n)
		}
	})

	// A stream that never finishes is stopped at exp+skew: GOAWAY at exp, then a
	// forced close. One deny event, and a recheck after GOAWAY adds none.
	t.Run("h2_hard_stop", func(t *testing.T) {
		inf := NewInflight()
		e := newExpiryEnv(t, func(c *Config) { c.Inflight = inf })
		conn, br, status := e.connect("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status %q", status)
		}
		fr := newRawH2(t, e.tlsOver(conn, br, "h2"))
		fr.openStream(1, "POST", false) // never ended
		e.waitArmed(t, 1)
		for deadline := time.Now().Add(5 * time.Second); len(inf.InFlight()) != 1; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the stream never reached the proxy")
			}
		}
		pollAdvance(t, e.fk, time.Second, "GOAWAY", fr.sawGoAway)
		if fr.isClosed() {
			t.Fatal("the connection closed at GOAWAY with a stream in flight")
		}
		e.sv.setKeys(t, 2, []string{"k2"}, reqActive("T1"))
		e.p.RecheckIdentitySessions()
		e.fk.Advance(e.exp().Add(expSkew - 2*time.Second).Sub(e.fk.Now()))
		pollAdvance(t, e.fk, time.Second, "the hard stop", fr.isClosed)
		assertCutWithin(t, "the stuck h2 stream", e.fk.Now(), e.exp().Add(expSkew))
		if n := len(e.denyEvents()); n != 1 || e.expiredEvents() != 1 {
			t.Errorf("deny events %+v, want exactly one identity_expired", e.denyEvents())
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
		assertCutWithin(t, "the WebSocket", e.cutBy(t), e.exp().Add(expSkew))
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

func (r *rawH2) statusOf(id uint32) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status[id]
}

func (r *rawH2) isClosed() bool {
	select {
	case <-r.closed:
		return true
	default:
		return false
	}
}

func (r *rawH2) waitClosed() bool {
	select {
	case <-r.closed:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

// sseEnv is an expiry env whose upstream streams text/event-stream on demand: a
// request that stays busy (mid-response) for as long as the test wants.
func newSSEEnv(t *testing.T) (*expEnv, chan<- string) {
	t.Helper()
	ticks := make(chan string)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case m := <-ticks:
				_, _ = io.WriteString(w, "data: "+m+"\n\n")
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	}))
	t.Cleanup(func() { srv.CloseClientConnections(); srv.Close() })
	e := newExpiryEnv(t, nil)
	e.p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	}
	return e, ticks
}

// openSSE starts a streaming response on a keep-alive and returns its reader.
func openSSE(t *testing.T, e *expEnv, tok string) *bufio.Reader {
	t.Helper()
	c := e.h1("Proxy-Authorization: " + basicAuth(tok) + "\r\n")
	_, _ = io.WriteString(c.tc, "GET /sse HTTP/1.1\r\nHost: "+idHost+"\r\nAccept: text/event-stream\r\n\r\n")
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("SSE open: %v %v", resp, err)
	}
	return bufio.NewReader(resp.Body)
}

func readEvent(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	_, _ = r.ReadString('\n')
	return strings.TrimSpace(line), nil
}

// TestRequireBusySessionCut: an HTTP/1 session that is mid-response (an SSE
// relay) when its token expires is reported at exp and force-closed at exp+skew,
// so a stream cannot outlive the token; a revoked binding cuts it at once.
func TestRequireBusySessionCut(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		e, ticks := newSSEEnv(t)
		body := openSSE(t, e, "tok-w-alice")
		e.waitArmed(t, 1)
		send := func(m string) {
			t.Helper()
			select {
			case ticks <- m:
			case <-time.After(5 * time.Second):
				t.Fatal("the upstream stream is gone")
			}
			if got, err := readEvent(body); err != nil || got != "data: "+m {
				t.Fatalf("event %q: %q %v", m, got, err)
			}
		}
		send("one")
		// At exp the event is written, yet the stream keeps flowing until exp+skew.
		e.cutBy(t)
		send("two")
		if n := e.expiredEvents(); n != 1 {
			t.Fatalf("%d identity_expired events at exp, want 1", n)
		}
		e.fk.Advance(e.exp().Add(expSkew - 2*time.Second).Sub(e.fk.Now()))
		send("three") // still flowing just before exp+skew
		gone := make(chan struct{})
		go func() {
			defer close(gone)
			_, _ = io.Copy(io.Discard, body)
		}()
		pollAdvance(t, e.fk, time.Second, "the forced close", func() bool {
			select {
			case <-gone:
				return true
			default:
				return false
			}
		})
		assertCutWithin(t, "the busy stream", e.fk.Now(), e.exp().Add(expSkew))
		if n := e.expiredEvents(); n != 1 {
			t.Errorf("%d identity_expired events after the forced close, want still 1", n)
		}
	})

	t.Run("recheck", func(t *testing.T) {
		e, ticks := newSSEEnv(t)
		body := openSSE(t, e, "tok-w-long")
		e.waitArmed(t, 1)
		ticks <- "one"
		if _, err := readEvent(body); err != nil {
			t.Fatal(err)
		}
		e.sv.setKeys(t, 2, []string{"k2"}, reqActive("T1"))
		e.p.RecheckIdentitySessions()
		if _, err := readEvent(body); err == nil {
			t.Error("a busy stream survived the removal of its key")
		}
		evs := e.waitDeny(t, denyreason.IdentityRequired, 1)
		if evs[0].IdentityStatus != "invalid" || evs[0].IdentityReason != "unknown_kid" {
			t.Errorf("event identity = %s/%s, want invalid/unknown_kid", evs[0].IdentityStatus, evs[0].IdentityReason)
		}
		if got := e.m.identityCount("invalid", "unknown_kid"); got < 1 {
			t.Errorf("identity verify invalid/unknown_kid = %d, want the cut counted", got)
		}
	})
}

// TestRecheckSweepsUnarmedSessions: sessions opened before the agent moved to
// require carry no expiry. The next recheck arms the one holding a Warden token
// that still binds and cuts the others, so the flip leaves nothing behind.
func TestRecheckSweepsUnarmedSessions(t *testing.T) {
	e := newExpiryEnv(t, noCA)
	e.p.SetIdentity(&reqVerifier{Verifier: e.v, snap: e.sv}, IdentityModeAttribute)
	e.p.SetSessionTracking(true) // a managed worker tracks anonymous sessions too
	up := e.rawPipe()
	open := func(auth string) net.Conn {
		extra := ""
		if auth != "" {
			extra = "Proxy-Authorization: " + basicAuth(auth) + "\r\n"
		}
		conn, _, status := e.connect(extra)
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status %q", status)
		}
		return conn
	}
	good, idp, anon := open("tok-w-long"), open("tok-a-alice"), open("")
	for i := 0; i < 3; i++ {
		<-up
	}
	e.p.SetIdentity(&reqVerifier{Verifier: e.v, snap: e.sv}, IdentityModeRequire)
	e.p.RecheckIdentitySessions()
	if !readsEOF(idp) || !readsEOF(anon) {
		t.Fatal("an IdP-token or anonymous tunnel survived the flip to require")
	}
	e.waitArmed(t, 1) // the Warden-token tunnel is armed, not cut
	go func() { _, _ = good.Write([]byte("x")) }()
	evs := e.waitDeny(t, denyreason.IdentityRequired, 2)
	if len(evs) != 2 {
		t.Errorf("%d identity_required events, want 2 (idp, anonymous)", len(evs))
	}
	// Armed now: it is cut at exp+skew like any other.
	e.fk.Advance(time.Hour - time.Second) // tok-w-long expires after an hour
	pollAdvance(t, e.fk, time.Minute, "the swept tunnel's expiry", func() bool { return e.expiredEvents() > 0 })
	if !readsEOF(good) {
		t.Error("the swept Warden-token tunnel outlived its token")
	}
}

// TestRequireTransparentLeg: a transparent connection has no CONNECT, so require
// mode admits only a Warden token carried in X-Warden-Identity, arms the session
// from it, and refuses any non-HTTP traffic inside TLS without dialing.
func TestRequireTransparentLeg(t *testing.T) {
	fk := clocktest.NewFake(time.Now())
	sv := &bindVerifier{}
	sv.setKeys(t, 1, []string{"k1"}, map[string]identity.WardenAgent{"default": {Active: true, JKT: jktSet("T1")}})
	v := fakes.NewVerifier()
	claims := wardenClaims("default", "T1")
	claims.Expiry = fk.Now().Add(expTTL)
	v.Set("tok-w", claims, identity.StatusValid, "")
	_, _, caCert, caKey := generateTestCA(t)
	b := &wsBackend{}
	ln := startWSBackend(t, caCert, caKey, b)
	e := newTransparentEnv(t, transparentOpts{
		identity: IdentityConfig{Verifier: &reqVerifier{Verifier: v, snap: sv}, Mode: IdentityModeRequire},
		cfgEdit: func(c *Config) {
			c.IdentityClock = fk.Now
			c.IdentityTimer = func(d time.Duration) IdentityTimer { return fk.NewTimer(d) }
		},
	})
	e.p.dialTLS = dialBackend(ln)
	tlsDial := func() *tls.Conn {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(e.caPEM)
		tc, err := tls.Dial("tcp", e.tlsAddr(), &tls.Config{ServerName: invHost, RootCAs: pool})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tc.Close() })
		return tc
	}
	armed := func() int {
		e.p.sessions.mu.Lock()
		defer e.p.sessions.mu.Unlock()
		return len(e.p.sessions.expiry)
	}
	denies := func(reason string) int {
		n := 0
		for _, ev := range e.store.snapshot() {
			if ev.Decision == "deny" && ev.Reason == reason {
				n++
			}
		}
		return n
	}

	t.Run("websocket_armed_from_header", func(t *testing.T) {
		tc := tlsDial()
		_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: "+invHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			IdentityHeader+": Bearer tok-w\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
		cbr := bufio.NewReader(tc)
		resp, err := http.ReadResponse(cbr, nil)
		if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade: %v %v", resp, err)
		}
		for deadline := time.Now().Add(5 * time.Second); armed() != 1; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the header-only WebSocket was never armed")
			}
		}
		fk.Advance(expTTL + expSkew - 2*time.Second)
		pollAdvance(t, fk, time.Second, "the WebSocket cut", func() bool { return denies("identity_expired") > 0 })
		_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := cbr.ReadByte(); err == nil {
			t.Error("a header-only WebSocket outlived its token")
		}
	})

	t.Run("non_http_inside_tls_refused", func(t *testing.T) {
		before := e.tlsUpstreams.Load()
		tc := tlsDial()
		_, _ = tc.Write([]byte("\x00\x01\x02\x03 not http"))
		for deadline := time.Now().Add(5 * time.Second); denies("identity_required") < 1; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("no identity_required deny; events %+v", e.store.snapshot())
			}
		}
		if n := e.tlsUpstreams.Load() - before; n != 0 {
			t.Errorf("%d upstream dials for refused non-HTTP traffic", n)
		}
	})
}
