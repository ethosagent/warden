package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// These tests cover W-P2-AREG-05: while the bound agent is disabled every
// CONNECT, h1 request and h2 stream is refused with 403 agent_disabled in every
// identity mode, CloseAgentSessions cuts the sessions already open (anonymous
// ones too), and enabling the agent again restores traffic.

const agentDisabledWant = `{"error":"agent_disabled"}`

func agentDisabledEvents(st *syncStore) []analytics.Event {
	var out []analytics.Event
	for _, e := range st.snapshot() {
		if e.Reason == string(denyreason.AgentDisabled) && e.Decision == "deny" {
			out = append(out, e)
		}
	}
	return out
}

func waitAgentDisabledEvents(t *testing.T, st *syncStore, n int) []analytics.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(agentDisabledEvents(st)) < n && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	return agentDisabledEvents(st)
}

func assertAgentDisabledResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusForbidden || strings.TrimSpace(string(body)) != agentDisabledWant {
		t.Fatalf("response = %d %q, want 403 %s", resp.StatusCode, body, agentDisabledWant)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// TestAgentDisabledConnect: in every identity mode a disabled agent's CONNECT is
// answered 403 agent_disabled before identity resolution and any dial, with one
// deny event and one blocked count; enabling restores the tunnel.
func TestAgentDisabledConnect(t *testing.T) {
	for _, mode := range []IdentityMode{IdentityModeOff, IdentityModeAttribute, IdentityModeChallenge} {
		t.Run(string(mode), func(t *testing.T) {
			e := newBlockEnv(t, mode)
			e.p.SetAgentDisabled(true)

			// A valid token changes nothing: the switch runs before identity.
			conn, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-u1") + "\r\n")
			_ = conn.Close()
			if !strings.Contains(status, "403") {
				t.Fatalf("CONNECT status = %q, want 403", status)
			}
			conn2, err := net.Dial("tcp", e.p.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn2.Close() }()
			_ = conn2.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.WriteString(conn2, "CONNECT "+idHost+":443 HTTP/1.1\r\nHost: "+idHost+":443\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(conn2), nil)
			if err != nil {
				t.Fatal(err)
			}
			if !resp.Close {
				t.Error("response is not Connection: close")
			}
			assertAgentDisabledResponse(t, resp)
			if n := e.dials.Load(); n != 0 {
				t.Errorf("dials = %d, want 0", n)
			}
			evs := waitAgentDisabledEvents(t, e.store, 2)
			if len(evs) != 2 {
				t.Fatalf("events = %+v, want two agent_disabled denies", e.store.snapshot())
			}
			for _, ev := range evs {
				if ev.Protocol != "tcp" || ev.Domain != idHost || ev.Port != 443 {
					t.Errorf("event = %+v", ev)
				}
			}
			if n := e.m.blockedCount("agent_disabled"); n != 2 {
				t.Errorf("blocked{agent_disabled} = %d, want 2; %s", n, e.m.describe())
			}

			e.p.SetAgentDisabled(false)
			conn3, _, status3 := e.connect("Proxy-Authorization: " + basicAuth("tok-u1") + "\r\n")
			_ = conn3.Close()
			if !strings.Contains(status3, "200") {
				t.Errorf("CONNECT after enable = %q, want 200", status3)
			}
		})
	}
}

// TestAgentDisabledKeepAliveRequestDenied: an open keep-alive session is
// refused on its next request, never reaching the upstream, and works again
// after the agent is enabled on a new session.
func TestAgentDisabledKeepAliveRequestDenied(t *testing.T) {
	for _, mode := range []IdentityMode{IdentityModeOff, IdentityModeAttribute} {
		t.Run(string(mode), func(t *testing.T) {
			e := newBlockEnv(t, mode)
			c := e.h1("")
			if st := c.get(""); st != 200 {
				t.Fatalf("first request status = %d, want 200", st)
			}
			e.p.SetAgentDisabled(true)
			assertAgentDisabledResponse(t, c.getResp(""))
			if n := e.be.requests(); n != 1 {
				t.Errorf("upstream saw %d requests, want exactly 1", n)
			}
			evs := waitAgentDisabledEvents(t, e.store, 1)
			if len(evs) != 1 || evs[0].Protocol != "https" || evs[0].Method != "GET" {
				t.Errorf("events = %+v", e.store.snapshot())
			}
			// The session ended with the 403.
			_ = c.tc.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.br.ReadByte(); err == nil {
				t.Error("connection still open after an agent_disabled deny")
			}
			e.p.SetAgentDisabled(false)
			if st := e.h1("").get(""); st != 200 {
				t.Errorf("after enable status = %d, want 200", st)
			}
		})
	}
}

// TestAgentDisabledH2Stream: a stream on an open h2 connection gets a 403 on
// the stream and nothing reaches the upstream.
func TestAgentDisabledH2Stream(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	cc := e.h2("")
	if st := h2Get(t, cc, nil); st != 200 {
		t.Fatalf("first stream status = %d, want 200", st)
	}
	e.p.SetAgentDisabled(true)
	req, _ := http.NewRequest("GET", "https://"+idHost+"/x", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	assertAgentDisabledResponse(t, resp)
	if n := e.be.requests(); n != 1 {
		t.Errorf("upstream saw %d requests, want 1", n)
	}
	if evs := waitAgentDisabledEvents(t, e.store, 1); len(evs) != 1 || evs[0].Protocol != "http2" {
		t.Errorf("events = %+v", e.store.snapshot())
	}
}

// TestAgentDisabledCloseSessions: after the switch flips, CloseAgentSessions
// cuts an anonymous h1 session, an anonymous h2 connection and (with session
// tracking) an anonymous raw tunnel, writing one deny event for each.
func TestAgentDisabledCloseSessions(t *testing.T) {
	e := newBlockEnv(t, IdentityModeOff)
	e.p.SetSessionTracking(true)
	e.setRaw(func() (net.Conn, error) {
		c, up := net.Pipe()
		go func() { defer func() { _ = up.Close() }(); _, _ = io.Copy(io.Discard, up) }()
		return c, nil
	})

	h1 := e.h1("")
	if st := h1.get(""); st != 200 {
		t.Fatalf("h1 status = %d", st)
	}
	cc := e.h2("")
	if st := h2Get(t, cc, nil); st != 200 {
		t.Fatalf("h2 status = %d", st)
	}
	// A non-TLS byte after the 200 takes the opaque passthrough tunnel.
	tun, tbr, status := e.connect("")
	if !strings.Contains(status, "200") {
		t.Fatalf("tunnel CONNECT = %q", status)
	}
	_, _ = io.WriteString(tun, "G")
	deadline := time.Now().Add(5 * time.Second)
	for e.dials.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}

	e.p.SetAgentDisabled(true)
	e.p.CloseAgentSessions()

	assertConnCut(t, h1.tc, h1.br)
	assertConnCut(t, tun, tbr)
	evs := waitAgentDisabledEvents(t, e.store, 3)
	if len(evs) != 3 {
		t.Fatalf("events = %+v, want one per closed session", e.store.snapshot())
	}
	protos := map[string]int{}
	for _, ev := range evs {
		protos[ev.Protocol]++
	}
	if protos["https"] != 1 || protos["http2"] != 1 || protos["tcp"] != 1 {
		t.Errorf("event protocols = %v, want one each of https, http2, tcp", protos)
	}
	// A second cut finds nothing left.
	e.p.CloseAgentSessions()
	if n := len(agentDisabledEvents(e.store)); n != 3 {
		t.Errorf("agent_disabled events = %d after a second cut, want 3", n)
	}
}

// TestAgentDisabledAnonymousTunnelNeedsTracking pins the cost split: without
// session tracking an anonymous raw tunnel is not registered, so it is not cut.
func TestAgentDisabledAnonymousTunnelNeedsTracking(t *testing.T) {
	for _, track := range []bool{false, true} {
		e := newRawTunnelEnv(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
		e.p.SetSessionTracking(track)
		conn, br := e.tunnel(t, "")
		e.p.SetAgentDisabled(true)
		e.p.CloseAgentSessions()
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		_, err := br.ReadByte()
		ne, timedOut := err.(net.Error)
		timedOut = timedOut && ne.Timeout()
		if track && timedOut {
			t.Errorf("tracking on: the anonymous tunnel was not cut")
		}
		if !track && !timedOut {
			t.Errorf("tracking off: the anonymous tunnel was cut (%v); registration must stay free", err)
		}
	}
}

// TestAgentDisabledRefusesNewSessions: while the registry refuses sessions a
// session created after the cut (a connection that passed the per-connection
// check just before the flip) is closed at creation; allow lifts it.
func TestAgentDisabledRefusesNewSessions(t *testing.T) {
	r := newSessionRegistry()
	if cut := r.takeAll(); len(cut) != 0 {
		t.Fatalf("empty registry cut %d sessions", len(cut))
	}
	closed := 0
	s := r.newSession("tcp", "x.test", 443, true, closerFunc(func() error { closed++; return nil }))
	if closed != 1 {
		t.Fatalf("a session created while refusing was closed %d times, want 1", closed)
	}
	s.release()
	r.allow()
	s2 := r.newSession("tcp", "x.test", 443, true, closerFunc(func() error { closed++; return nil }))
	if closed != 1 {
		t.Fatalf("a session created after allow was closed (closed=%d)", closed)
	}
	s2.release()
}

// TestAgentDisabledIdentityHeldAfterCut: a session bound to an identity is cut
// by the agent switch too, and its event carries that identity.
func TestAgentDisabledIdentitySession(t *testing.T) {
	e := newRawTunnelEnv(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	conn, br := e.tunnel(t, "tok-u1")
	e.p.SetAgentDisabled(true)
	e.p.CloseAgentSessions()
	assertConnCut(t, conn, br)
	evs := waitAgentDisabledEvents(t, e.store, 1)
	if len(evs) != 1 || evs[0].UserSub != "u1" || evs[0].IdentityStatus != string(identity.StatusValid) {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
}

// TestAgentStageAllocs: the enabled-agent check on the hot path is one atomic
// load and allocates nothing.
func TestAgentStageAllocs(t *testing.T) {
	p := stageProxy(t, nil, IdentityModeOff, nil, nil)
	s := stageScope(connIdentity{})
	if n := testing.AllocsPerRun(1000, func() {
		if p.agentStage(s) {
			t.Fatal("denied while enabled")
		}
	}); n != 0 {
		t.Errorf("agentStage allocates %v per request, want 0", n)
	}
	if n := testing.AllocsPerRun(1000, func() {
		if p.connectAgentDisabled(io.Discard, "x.test", 443) {
			t.Fatal("denied while enabled")
		}
	}); n != 0 {
		t.Errorf("connectAgentDisabled allocates %v per CONNECT, want 0", n)
	}
}

// TestAgentDisabledTransparentMode: the transparent :443 floor refuses the
// connection before any handshake (one audited close), and the plain-HTTP
// floor answers through the shared request stage with 403 agent_disabled.
func TestAgentDisabledTransparentMode(t *testing.T) {
	e := newTransparentEnv(t, transparentOpts{})
	e.p.cfg.Policy.Replace(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: invHost}}})
	e.p.SetAgentDisabled(true)

	if tc, err := e.tlsDialSNI(invHost); err == nil {
		_ = tc.Close()
		t.Fatal("the TLS handshake succeeded for a disabled agent")
	}
	evs := waitAgentDisabledEvents(t, e.store, 1)
	if len(evs) != 1 || evs[0].Domain != invHost || evs[0].Protocol != "tcp" {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
	if n := len(e.backend.requests()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}

	e.p.SetAgentDisabled(false)
	req, _ := http.NewRequest(http.MethodGet, "https://"+invHost+"/ok", nil)
	if _, st, err := e.doH1(invHost, req); err != nil || st != 200 {
		t.Fatalf("after enable: status %d err %v", st, err)
	}
}

// rawTLSUpstream makes e's TLS dial return a TLS conn to an in-memory server
// that swallows what it is sent: an upstream for non-HTTP bytes.
func rawTLSUpstream(e *idEnv) {
	e.p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		e.dials.Add(1)
		cc, sc := net.Pipe()
		go func() {
			srv := tls.Server(sc, e.be.srv.TLS)
			defer func() { _ = srv.Close() }()
			if srv.Handshake() == nil {
				_, _ = io.Copy(io.Discard, srv)
			}
		}()
		tc := tls.Client(cc, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
		return tc, tc.Handshake()
	}
}

// openRawTLS opens a CONNECT, handshakes TLS and sends bytes that are neither
// HTTP nor h2, so the worker forwards them raw; it waits for the upstream dial.
func openRawTLS(t *testing.T, e *idEnv, connectExtra string) *tls.Conn {
	t.Helper()
	conn, br, status := e.connect(connectExtra)
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT = %q", status)
	}
	tc := e.tlsOver(conn, br)
	_, _ = io.WriteString(tc, "\x01\x02\x03\x04 not http at all\n")
	deadline := time.Now().Add(5 * time.Second)
	for e.dials.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if e.dials.Load() < 1 {
		t.Fatal("the raw TLS upstream was never dialed")
	}
	return tc
}

// TestAgentDisabledCutsRawTLS: a raw TLS forward (non-HTTP bytes inside a
// terminated CONNECT) is registered, so the agent cut closes it, and so does
// the block-list cut (same registry).
func TestAgentDisabledCutsRawTLS(t *testing.T) {
	t.Run("agent", func(t *testing.T) {
		e := newBlockEnv(t, IdentityModeOff)
		e.p.SetSessionTracking(true)
		rawTLSUpstream(e.idEnv)
		tc := openRawTLS(t, e.idEnv, "")
		e.p.SetAgentDisabled(true)
		e.p.CloseAgentSessions()
		assertConnCut(t, tc.NetConn(), tc)
		evs := waitAgentDisabledEvents(t, e.store, 1)
		if len(evs) != 1 || evs[0].Domain != idHost {
			t.Fatalf("events = %+v", e.store.snapshot())
		}
	})
	t.Run("blocklist", func(t *testing.T) {
		e := newBlockEnv(t, IdentityModeAttribute)
		rawTLSUpstream(e.idEnv)
		tc := openRawTLS(t, e.idEnv, "Proxy-Authorization: "+basicAuth("tok-u1")+"\r\n")
		e.applyBlock(config.BlockedUser{Sub: "u1"})
		assertConnCut(t, tc.NetConn(), tc)
		if n := len(waitBlockedEvents(t, e.store, 1)); n != 1 {
			t.Fatalf("user_blocked events = %d, want 1", n)
		}
	})
}

// TestAgentDisabledCutsBusyRequest: a request in flight on an HTTP/1 session
// (a long upload or download) is cut at once by the agent switch, unlike the
// block-list cut which lets it finish.
func TestAgentDisabledCutsBusyRequest(t *testing.T) {
	e := newBlockEnv(t, IdentityModeOff)
	e.be.hold = make(chan struct{})
	e.be.arrived = make(chan struct{}, 1)
	defer close(e.be.hold)
	c := e.h1("")
	_, _ = io.WriteString(c.tc, "GET /x HTTP/1.1\r\nHost: "+idHost+"\r\n\r\n")
	select {
	case <-e.be.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the backend")
	}
	e.p.SetAgentDisabled(true)
	e.p.CloseAgentSessions()
	assertConnCut(t, c.tc.NetConn(), c.br)
	if n := len(waitAgentDisabledEvents(t, e.store, 1)); n != 1 {
		t.Fatalf("agent_disabled events = %d, want 1", n)
	}
}

// TestAgentDisabledRefusedSessionNeverDials: a tunnel whose session the
// registry refused at creation (it passed the CONNECT check just before the
// flip) is closed with a deny event and no upstream dial.
func TestAgentDisabledRefusedSessionNeverDials(t *testing.T) {
	e := newRawTunnelEnv(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	e.p.SetSessionTracking(true)
	e.p.sessions.refuseNew() // the flag itself is still off: the race window
	var dials int
	inner := e.p.dialFunc
	e.p.dialFunc = func(a, b string) (net.Conn, error) { dials++; return inner(a, b) }
	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\n")
	_, _ = io.Copy(io.Discard, conn)
	if evs := waitAgentDisabledEvents(t, e.store, 1); len(evs) != 1 {
		t.Fatalf("events = %+v", e.store.snapshot())
	}
	if dials != 0 {
		t.Errorf("dials = %d, want 0", dials)
	}
}
