package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/test/fakes"
)

// These tests cover W-P2-WBND-03: require mode on CONNECT and on terminated
// traffic. The verifier is the fake one plus a Warden snapshot a test swaps, so
// the real proxy stages run the real binding check against it.

// reqVerifier serves fixed per-token results (fakes.Verifier) and a snapshot.
type reqVerifier struct {
	*fakes.Verifier
	snap *bindVerifier
}

func (r *reqVerifier) Snapshot() *identity.WardenSnapshot { return r.snap.Snapshot() }

const reqAgent = "agent" // newIDEnvCfg binds the proxy to this agent

func reqActive(k ...string) map[string]identity.WardenAgent {
	return map[string]identity.WardenAgent{
		reqAgent:  {Active: true, JKT: jktSet(k...)},
		"agent-A": {Active: true, JKT: jktSet(k...)},
	}
}

// newRequireEnv is a forward-mode proxy with a CA in require mode. Tokens:
// tok-w-alice / tok-w-bob are Warden tokens for the bound agent (alice's expires
// in 30s), tok-w-other is alice's token minted for agent-A, tok-idp is a valid
// IdP token.
func newRequireEnv(t *testing.T) (*idEnv, *bindVerifier) {
	t.Helper()
	e := newIDEnvCfg(t, IdentityModeAttribute, nil)
	sv := &bindVerifier{}
	sv.setKeys(t, 1, []string{"k1"}, reqActive("T1"))
	warden := func(sub, act string, ttl time.Duration) identity.Claims {
		c := wardenClaims(act, "T1")
		c.Sub, c.Email, c.Expiry = sub, sub+"@example.test", e.clk.now().Add(ttl)
		return c
	}
	e.v.Set("tok-w-alice", warden("alice", reqAgent, 30*time.Second), identity.StatusValid, "")
	e.v.Set("tok-w-long", warden("alice", reqAgent, time.Hour), identity.StatusValid, "")
	e.v.Set("tok-w-bob", warden("bob", reqAgent, time.Hour), identity.StatusValid, "")
	e.v.Set("tok-w-other", warden("alice", "agent-A", time.Hour), identity.StatusValid, "")
	idp := idClaims("alice", e.clk.now().Add(time.Hour))
	idp.TokenType = identity.TokenIdP
	e.v.Set("tok-idp", idp, identity.StatusValid, "")
	e.p.SetIdentity(&reqVerifier{Verifier: e.v, snap: sv}, IdentityModeRequire)
	return e, sv
}

// rawConnect sends one CONNECT (host idHost) with the given Proxy-Authorization
// header value ("" for none) and returns the reply with its body.
func rawConnect(t *testing.T, e *idEnv, auth string) (*http.Response, string) {
	t.Helper()
	conn, err := dialRaw(e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	req := "CONNECT " + idHost + ":443 HTTP/1.1\r\nHost: " + idHost + ":443\r\n"
	if auth != "" {
		req += "Proxy-Authorization: " + auth + "\r\n"
	}
	_, _ = io.WriteString(conn, req+"\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

// assertNo401 fails when a response is a 401 or carries WWW-Authenticate.
func assertNo401(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode == http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("response is a 401 or carries WWW-Authenticate: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestIdentityRequireMode(t *testing.T) {
	t.Run("connect_no_token", func(t *testing.T) {
		e, _ := newRequireEnv(t)
		resp, b := rawConnect(t, e, "")
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status %d, want 407", resp.StatusCode)
		}
		if resp.Header.Get("Proxy-Authenticate") != `Basic realm="warden"` || resp.Header.Get("Content-Type") != "application/json" || !resp.Close {
			t.Errorf("headers %v close=%v", resp.Header, resp.Close)
		}
		assertNo401(t, resp)
		var body map[string]any
		if err := json.Unmarshal([]byte(b), &body); err != nil || body["error"] != "identity_required" || body["reason"] != "none" || len(body) != 2 {
			t.Errorf("body = %s (%v), want exactly error identity_required and reason none (no sign_in)", b, err)
		}
		if n := e.dials.Load(); n != 0 {
			t.Errorf("%d dials", n)
		}
		evs := e.waitDeny(t, "identity_required", 1)
		if len(evs) != 1 || evs[0].Domain != idHost || evs[0].IdentityStatus != "none" {
			t.Errorf("events = %+v", evs)
		}
		if got := e.m.blockedCount("identity_required"); got != 1 {
			t.Errorf("blocked{identity_required} = %d, want 1", got)
		}
		if got := e.m.requestCount("deny", "tcp"); got != 1 {
			t.Errorf("requests{deny,tcp} = %d, want 1", got)
		}
	})

	t.Run("connect_dex_token", func(t *testing.T) {
		e, _ := newRequireEnv(t)
		resp, b := rawConnect(t, e, basicAuth("tok-idp"))
		if resp.StatusCode != http.StatusProxyAuthRequired || !strings.Contains(b, `"reason":"unbound_token"`) {
			t.Fatalf("status %d body %s, want 407 unbound_token", resp.StatusCode, b)
		}
		if n := e.dials.Load(); n != 0 {
			t.Errorf("%d dials", n)
		}
		if got := e.m.identityTypeCount("invalid", "unbound_token", "idp"); got != 1 {
			t.Errorf("verify{invalid,unbound_token,idp} = %d, want 1; %s", got, e.m.describe())
		}
		evs := e.waitDeny(t, "identity_required", 1)
		if evs[0].IdentityStatus != "invalid" || evs[0].IdentityReason != "unbound_token" || evs[0].UserSub != "" {
			t.Errorf("event = %+v", evs[0])
		}
	})

	t.Run("connect_refusals", func(t *testing.T) {
		e, sv := newRequireEnv(t)
		for _, tc := range []struct{ name, auth, reason string }{
			{"other agent", basicAuth("tok-w-other"), "agent_mismatch"},
			{"bad signature", basicAuth("tok-bad"), "bad_signature"},
			{"expired", basicAuth("tok-expired"), "expired"},
			{"verifier down", basicAuth("tok-down"), "jwks_unavailable"},
			{"malformed", "Basic !!!", "malformed"},
		} {
			resp, b := rawConnect(t, e, tc.auth)
			if resp.StatusCode != 407 || !strings.Contains(b, `"reason":"`+tc.reason+`"`) {
				t.Errorf("%s: status %d body %s, want 407 reason %s", tc.name, resp.StatusCode, b, tc.reason)
			}
		}
		// No snapshot yet (before the first verified bundle): fail closed.
		sv.snap.Store(nil)
		resp, b := rawConnect(t, e, basicAuth("tok-w-long"))
		if resp.StatusCode != 407 || !strings.Contains(b, `"reason":"agent_unregistered"`) {
			t.Errorf("no snapshot: status %d body %s, want 407 agent_unregistered", resp.StatusCode, b)
		}
		if n := e.dials.Load(); n != 0 {
			t.Errorf("%d dials", n)
		}
	})

	t.Run("connect_bound_token_passes", func(t *testing.T) {
		e, _ := newRequireEnv(t)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-long") + "\r\n")
		if st := c.get(""); st != 200 {
			t.Fatalf("bound token: status %d, want the upstream's 200", st)
		}
		// The same header identity as the CONNECT is not a conflict.
		if st := c.get("X-Warden-Identity: Bearer tok-w-long\r\n"); st != 200 {
			t.Fatalf("same identity in the header: status %d, want 200", st)
		}
	})

	t.Run("conflict", func(t *testing.T) {
		for name, hdr := range map[string]string{
			"other sub":   "Bearer tok-w-bob",
			"other agent": "Bearer tok-w-other", // same sub, minted for agent-A (fails binding)
			"idp token":   "Bearer tok-idp",
		} {
			t.Run(name, func(t *testing.T) {
				e, _ := newRequireEnv(t)
				c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-long") + "\r\n")
				resp, body := readH1(t, c, "X-Warden-Identity: "+hdr+"\r\n")
				if resp.StatusCode != 403 || body != `{"error":"identity_conflict"}` || !resp.Close {
					t.Fatalf("status %d body %q close %v, want 403 identity_conflict with Connection: close", resp.StatusCode, body, resp.Close)
				}
				assertNo401(t, resp)
				e.waitDeny(t, "identity_conflict", 1)
				if got := e.m.blockedCount("identity_conflict"); got != 1 {
					t.Errorf("blocked{identity_conflict} = %d, want 1", got)
				}
			})
		}
	})

	t.Run("expired_http", func(t *testing.T) {
		e, _ := newRequireEnv(t)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if st := c.get(""); st != 200 {
			t.Fatalf("before exp: %d", st)
		}
		e.clk.advance(30*time.Second + identity.DefaultClockSkew + time.Second)
		resp, body := readH1(t, c, "")
		if resp.StatusCode != 403 || body != `{"error":"identity_expired"}` || !resp.Close {
			t.Fatalf("status %d body %q close %v, want 403 identity_expired with Connection: close", resp.StatusCode, body, resp.Close)
		}
		assertNo401(t, resp)
		if got := e.m.blockedCount("identity_expired"); got != 1 {
			t.Errorf("blocked{identity_expired} = %d, want 1", got)
		}
	})

	t.Run("h2_stream", func(t *testing.T) {
		e, _ := newRequireEnv(t)
		cc := e.h2("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		if st := h2Get(t, cc, nil); st != 200 {
			t.Fatalf("before exp: %d", st)
		}
		// A second subject on one stream, then the expiry, each a 403 on the stream.
		for _, tc := range []struct {
			name, want string
			hdr        map[string]string
			advance    time.Duration
		}{
			{"conflict", "identity_conflict", map[string]string{IdentityHeader: "Bearer tok-w-bob"}, 0},
			{"expired", "identity_expired", nil, 30*time.Second + identity.DefaultClockSkew + time.Second},
		} {
			e.clk.advance(tc.advance)
			req, _ := http.NewRequest("GET", "https://"+idHost+"/x", nil)
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 403 || string(b) != `{"error":"`+tc.want+`"}` {
				t.Errorf("%s: status %d body %q, want 403 %s on the stream", tc.name, resp.StatusCode, b, tc.want)
			}
			assertNo401(t, resp)
		}
	})

	t.Run("ws_upgrade", func(t *testing.T) {
		e, _ := newRequireEnv(t)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-alice") + "\r\n")
		e.clk.advance(30*time.Second + identity.DefaultClockSkew + time.Second)
		resp, body := readH1(t, c, "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
		if resp.StatusCode != 403 || body != `{"error":"identity_expired"}` {
			t.Fatalf("status %d body %q, want 403 identity_expired instead of 101", resp.StatusCode, body)
		}
		assertNo401(t, resp)
	})

	t.Run("mcp_http", func(t *testing.T) {
		e, sv := newRequireEnv(t)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-long") + "\r\n")
		// The agent is disabled by a new bundle: the next MCP request is a plain
		// JSON 403, never a JSON-RPC error body and never a 401.
		sv.setKeys(t, 2, []string{"k1"}, map[string]identity.WardenAgent{reqAgent: {Active: false, JKT: jktSet("T1")}})
		const rpc = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
		_, _ = io.WriteString(c.tc, "POST /mcp HTTP/1.1\r\nHost: "+idHost+"\r\nContent-Type: application/json\r\nContent-Length: "+
			strconv.Itoa(len(rpc))+"\r\n\r\n"+rpc)
		resp, err := http.ReadResponse(c.br, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 403 || string(b) != `{"error":"identity_required"}` || !resp.Close {
			t.Fatalf("status %d body %q close %v, want 403 identity_required", resp.StatusCode, b, resp.Close)
		}
		if strings.Contains(string(b), "jsonrpc") {
			t.Error("a JSON-RPC body was written")
		}
		assertNo401(t, resp)
	})

	t.Run("rebind_ends_tunnel", func(t *testing.T) {
		for name, change := range map[string]func(*bindVerifier, testing.TB){
			"key removed":   func(v *bindVerifier, tb testing.TB) { v.setKeys(tb, 2, []string{"k1"}, reqActive("T2")) },
			"agent removed": func(v *bindVerifier, tb testing.TB) { v.setKeys(tb, 2, []string{"k1"}, nil) },
			"signing key":   func(v *bindVerifier, tb testing.TB) { v.setKeys(tb, 2, nil, reqActive("T1")) },
		} {
			t.Run(name, func(t *testing.T) {
				e, sv := newRequireEnv(t)
				c := e.h1("Proxy-Authorization: " + basicAuth("tok-w-long") + "\r\n")
				if st := c.get(""); st != 200 {
					t.Fatalf("before the bundle changes: %d", st)
				}
				change(sv, t)
				resp, body := readH1(t, c, "")
				if resp.StatusCode != 403 || body != `{"error":"identity_required"}` || !resp.Close {
					t.Fatalf("status %d body %q close %v, want 403 identity_required", resp.StatusCode, body, resp.Close)
				}
			})
		}
	})

	// A tunnel opened under attribute or challenge mode with a valid IdP token
	// must not survive the flip to require: it is refused as unbound.
	t.Run("mode_flip_idp_tunnel", func(t *testing.T) {
		for _, start := range []IdentityMode{IdentityModeAttribute, IdentityModeChallenge} {
			t.Run(string(start), func(t *testing.T) {
				e := newIDEnvCfg(t, start, nil)
				idp := idClaims("alice", e.clk.now().Add(time.Hour))
				idp.TokenType = identity.TokenIdP
				e.v.Set("tok-idp", idp, identity.StatusValid, "")
				c := e.h1("Proxy-Authorization: " + basicAuth("tok-idp") + "\r\n")
				if st := c.get(""); st != 200 {
					t.Fatalf("under %s: status %d, want 200", start, st)
				}
				hits := e.be.requests()
				sv := &bindVerifier{}
				sv.setKeys(t, 1, []string{"k1"}, reqActive("T1"))
				e.p.SetIdentity(&reqVerifier{Verifier: e.v, snap: sv}, IdentityModeRequire)
				resp, body := readH1(t, c, "")
				if resp.StatusCode != 403 || body != `{"error":"identity_required"}` || !resp.Close {
					t.Fatalf("after the flip: status %d body %q close %v, want 403 identity_required with Connection: close", resp.StatusCode, body, resp.Close)
				}
				assertNo401(t, resp)
				if got := e.be.requests(); got != hits {
					t.Errorf("%d upstream requests after the flip, want 0", got-hits)
				}
			})
		}
	})

	t.Run("no_connect_identity", func(t *testing.T) {
		// A request with no CONNECT identity (a transparent leg) and no header
		// proves nothing: refused, not served anonymously.
		e, _ := newRequireEnv(t)
		s := stageScope(connIdentity{})
		rec := &sinkRecorder{}
		s.out = rec
		e.p.captureIdentityHeader(s)
		if !e.p.identityStage(s) || rec.status != 403 || rec.body != identityRequiredBody {
			t.Fatalf("ended=%v answer %d %q, want 403 identity_required", s.idStatus, rec.status, rec.body)
		}
		// A valid bound Warden token in the header alone is enough.
		s = stageScope(connIdentity{}, "Bearer tok-w-long")
		s.out = &sinkRecorder{}
		e.p.captureIdentityHeader(s)
		if e.p.identityStage(s) || s.subject == nil || s.subject.Sub != "alice" || s.subject.AgentID != reqAgent {
			t.Fatalf("header-only bound token: status %s subject %+v", s.idStatus, s.subject)
		}
	})

	t.Run("block_list_still_runs", func(t *testing.T) {
		// Identity passing does not skip the block list: it runs after.
		e, _ := newRequireEnv(t)
		e.p.cfg.Policy.Replace(config.Policy{
			Allowlist:    []config.AllowlistEntry{{Domain: idHost, Port: 443}},
			BlockedUsers: []config.BlockedUser{{Sub: "alice"}},
		})
		resp, _ := rawConnect(t, e, basicAuth("tok-w-long"))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want the block list's 403 (not the 407: identity passed)", resp.StatusCode)
		}
		e.waitDeny(t, "user_blocked", 1)
	})
}

// TestIdentityAttributeModeUnchanged: attribute mode forwards an invalid token
// when policy allows, with identity_status invalid recorded, and an IdP token is
// not turned away as unbound.
func TestIdentityAttributeModeUnchanged(t *testing.T) {
	e := newIDEnv(t, IdentityModeAttribute)
	c := e.h1("Proxy-Authorization: " + basicAuth("tok-bad") + "\r\n")
	if st := c.get(""); st != 200 {
		t.Fatalf("invalid token in attribute mode: status %d, want it forwarded", st)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		found := false
		for _, ev := range e.store.snapshot() {
			if ev.Decision == "allow" && ev.IdentityStatus == "invalid" && ev.IdentityReason == "bad_signature" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no allow event with identity_status invalid: %+v", e.store.snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := e.m.blockedCount("identity_required"); got != 0 {
		t.Errorf("attribute mode blocked %d requests for identity_required", got)
	}
	c2 := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
	if st := c2.get(""); st != 200 {
		t.Fatalf("valid token: %d", st)
	}
}
