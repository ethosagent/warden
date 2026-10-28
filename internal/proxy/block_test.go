package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// These tests cover W-P1-BLOCK-02: the block list held by policy.Evaluator is
// enforced at CONNECT and by blockStage on every request (h1 keep-alive, h2,
// gRPC, WebSocket upgrade, transparent), from the claims of any token the worker
// parsed. The verifier is fakes.Verifier; blocking is applied by Replace on the
// live evaluator, exactly as a long-poll update does.

const blockedWant = `{"error":"user_blocked"}`

// blockEnv is an idEnv with extra tokens and a dial counter.
type blockEnv struct {
	*idEnv
	dials atomic.Int64
}

func newBlockEnv(t *testing.T, mode IdentityMode) *blockEnv {
	t.Helper()
	e := &blockEnv{idEnv: newIDEnv(t, mode)}
	exp := e.clk.now().Add(time.Hour)
	e.v.Set("tok-u1", identity.Claims{Sub: "u1", Expiry: exp}, identity.StatusValid, "")
	e.v.Set("tok-u2", identity.Claims{Sub: "u2", Email: "u2@corp.com", Expiry: exp}, identity.StatusValid, "")
	e.v.Set("tok-alice-corp", identity.Claims{Sub: "alice-corp", Email: "alice@corp.com", Expiry: exp}, identity.StatusValid, "")
	inner := e.p.dialTLS
	e.p.dialTLS = func(n, a string, c *tls.Config) (*tls.Conn, error) {
		e.dials.Add(1)
		return inner(n, a, c)
	}
	return e
}

// block replaces the live policy with the test allowlist plus users.
func (e *blockEnv) block(users ...config.BlockedUser) {
	e.p.cfg.Policy.Replace(config.Policy{
		Allowlist:    []config.AllowlistEntry{{Domain: idHost, Port: 443}},
		BlockedUsers: users,
	})
}

// assertBlockedResponse asserts a user_blocked 403 JSON response.
func assertBlockedResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if string(body) != blockedWant {
		t.Errorf("body = %q, want %q", body, blockedWant)
	}
	if !json.Valid(body) {
		t.Errorf("body is not valid JSON: %q", body)
	}
	if resp.ContentLength != int64(len(blockedWant)) {
		t.Errorf("Content-Length = %d, want %d", resp.ContentLength, len(blockedWant))
	}
}

func blockedEvents(st *syncStore) []analytics.Event {
	var out []analytics.Event
	for _, ev := range st.snapshot() {
		if ev.Reason == "user_blocked" {
			out = append(out, ev)
		}
	}
	return out
}

func (c *idH1) getResp(extra string) *http.Response {
	c.t.Helper()
	_, _ = io.WriteString(c.tc, "GET /x HTTP/1.1\r\nHost: "+idHost+"\r\n"+extra+"\r\n")
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		c.t.Fatalf("read response: %v", err)
	}
	return resp
}

func TestBlockList_ConnectDenied(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.block(config.BlockedUser{Sub: "u1"})

	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT "+idHost+":443 HTTP/1.1\r\nHost: "+idHost+":443\r\nProxy-Authorization: "+basicAuth("tok-u1")+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedResponse(t, resp)
	if !resp.Close {
		t.Error("response is not Connection: close")
	}
	if n := e.dials.Load(); n != 0 {
		t.Errorf("dials = %d, want 0", n)
	}
	evs := waitEvents(t, e.store, 1)
	if len(evs) != 1 {
		t.Fatalf("events = %+v, want exactly one", evs)
	}
	ev := evs[0]
	if ev.Reason != "user_blocked" || ev.Decision != "deny" || ev.UserSub != "u1" || ev.Protocol != "tcp" ||
		ev.IdentityStatus != string(identity.StatusValid) || ev.Domain != idHost || ev.Port != 443 {
		t.Errorf("event = %+v", ev)
	}
	if n := e.m.blockedCount("user_blocked"); n != 1 {
		t.Errorf("blocked{user_blocked} = %d, want 1; %s", n, e.m.describe())
	}
	if n := e.m.requestCount("deny", "tcp"); n != 1 {
		t.Errorf("deny/tcp requests = %d, want 1", n)
	}
	if strings.Contains(e.logs.String(), "tok-u1") {
		t.Error("the token reached the logs")
	}
}

// A raw tunnel (no CA) is gated at CONNECT too, before any dial.
func TestBlockList_ConnectDeniedRawTunnel(t *testing.T) {
	v := fakes.NewVerifier()
	v.Set("tok-u1", identity.Claims{Sub: "u1", Expiry: time.Now().Add(time.Hour)}, identity.StatusValid, "")
	store := &syncStore{}
	pol := policy.NewEvaluator(config.Policy{
		Allowlist:    []config.AllowlistEntry{{Domain: "tunnel.test", Port: 443}},
		BlockedUsers: []config.BlockedUser{{Sub: "u1"}},
	})
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     pol,
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Identity:   IdentityConfig{Verifier: v, Mode: IdentityModeAttribute},
	})
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int64
	p.dialFunc = func(string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, io.EOF
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	waitForAddr(t, p)

	connect := func(auth string) *http.Response {
		conn, err := net.Dial("tcp", p.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.WriteString(conn, "CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n"+auth+"\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	assertBlockedResponse(t, connect("Proxy-Authorization: "+basicAuth("tok-u1")+"\r\n"))
	if n := dials.Load(); n != 0 {
		t.Errorf("dials = %d, want 0", n)
	}
	if evs := blockedEvents(store); len(evs) != 1 || evs[0].UserSub != "u1" {
		t.Errorf("events = %+v", store.snapshot())
	}
	// Control: the same tunnel without a token is admitted (the dial is attempted).
	resp := connect("")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("token-less CONNECT status = %d, want 200", resp.StatusCode)
	}
}

func TestBlockList_KeepAliveCut(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice-corp") + "\r\n")
	if st := c.get(""); st != 200 {
		t.Fatalf("first request status = %d, want 200", st)
	}
	// An admin blocks alice by email, in another case, on the live evaluator.
	e.block(config.BlockedUser{Email: "ALICE@corp.com"})
	assertBlockedResponse(t, c.getResp(""))
	if n := e.be.requests(); n != 1 {
		t.Errorf("upstream saw %d requests, want exactly 1", n)
	}
	evs := blockedEvents(e.store)
	if len(evs) != 1 || evs[0].UserSub != "alice-corp" || evs[0].UserEmail != "alice@corp.com" || evs[0].Protocol != "https" {
		t.Errorf("user_blocked events = %+v", evs)
	}
	// The session ended: the proxy closed the connection after the 403.
	_ = c.tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.br.ReadByte(); err == nil {
		t.Error("connection still open after a user_blocked deny")
	}
	// Unblocking lets a new session through.
	e.block()
	if st := e.h1("Proxy-Authorization: " + basicAuth("tok-alice-corp") + "\r\n").get(""); st != 200 {
		t.Errorf("after unblock status = %d, want 200", st)
	}
}

func TestBlockList_ExpiredTokenDenied(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.block(config.BlockedUser{Sub: "mallory"})
	t.Run("header", func(t *testing.T) {
		assertBlockedResponse(t, e.h1("").getResp("X-Warden-Identity: Bearer tok-expired\r\n"))
	})
	t.Run("connect", func(t *testing.T) {
		conn, br, status := e.connect("Proxy-Authorization: " + basicAuth("tok-expired") + "\r\n")
		_ = conn
		_ = br
		if !strings.Contains(status, "403") {
			t.Errorf("CONNECT status = %q, want 403", status)
		}
	})
	if n := e.be.requests(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	for _, ev := range blockedEvents(e.store) {
		// Unverified claims reach the deny check, never storage.
		if ev.UserSub != "" || ev.IdentityStatus != string(identity.StatusExpired) {
			t.Errorf("event = %+v, want no user fields and identity_status expired", ev)
		}
	}
	if len(blockedEvents(e.store)) != 2 {
		t.Errorf("events = %+v, want two user_blocked", e.store.snapshot())
	}
}

func TestBlockList_BadSignatureDenied(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.block(config.BlockedUser{Sub: "mallory"})
	assertBlockedResponse(t, e.h1("").getResp("X-Warden-Identity: Bearer tok-bad\r\n"))
	if n := e.be.requests(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	evs := blockedEvents(e.store)
	if len(evs) != 1 || evs[0].IdentityStatus != string(identity.StatusInvalid) || evs[0].UserSub != "" {
		t.Errorf("events = %+v", e.store.snapshot())
	}
}

func TestBlockList_OtherUsersUnaffected(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.block(config.BlockedUser{Sub: "u1"}, config.BlockedUser{Sub: "mallory"})
	if st := e.h1("Proxy-Authorization: " + basicAuth("tok-u2") + "\r\n").get(""); st != 200 {
		t.Errorf("u2 via CONNECT status = %d, want 200", st)
	}
	if st := e.h1("").get("X-Warden-Identity: Bearer tok-u2\r\n"); st != 200 {
		t.Errorf("u2 via header status = %d, want 200", st)
	}
	if st := e.h1("").get(""); st != 200 {
		t.Errorf("token-less status = %d, want 200 (attribute mode does not match)", st)
	}
	// A token the verifier cannot read yields no claims and is not matched.
	if st := e.h1("").get("X-Warden-Identity: Bearer tok-down\r\n"); st != 200 {
		t.Errorf("unverified status = %d, want 200", st)
	}
	if n := e.be.requests(); n != 4 {
		t.Errorf("upstream saw %d requests, want 4", n)
	}
	if evs := blockedEvents(e.store); len(evs) != 0 {
		t.Errorf("unexpected user_blocked events: %+v", evs)
	}
}

// A blocked user cannot hide behind a second token: a CONNECT/header conflict
// is matched on both claims sets. The CONNECT user is refused at CONNECT; the
// header user is refused per request.
func TestBlockList_ConflictStillDenied(t *testing.T) {
	t.Run("connect user", func(t *testing.T) {
		e := newBlockEnv(t, IdentityModeAttribute)
		e.block(config.BlockedUser{Sub: "bob"})
		_, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-bob") + "\r\n")
		if !strings.Contains(status, "403") {
			t.Errorf("CONNECT status = %q, want 403", status)
		}
	})
	t.Run("connect user blocked after CONNECT", func(t *testing.T) {
		e := newBlockEnv(t, IdentityModeAttribute)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-bob") + "\r\n")
		e.block(config.BlockedUser{Sub: "bob"})
		assertBlockedResponse(t, c.getResp("X-Warden-Identity: Bearer tok-alice\r\n"))
		if n := e.be.requests(); n != 0 {
			t.Errorf("upstream saw %d requests, want 0", n)
		}
	})
	t.Run("header user", func(t *testing.T) {
		e := newBlockEnv(t, IdentityModeAttribute)
		e.block(config.BlockedUser{Sub: "alice"})
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-bob") + "\r\n")
		assertBlockedResponse(t, c.getResp("X-Warden-Identity: Bearer tok-alice\r\n"))
		if n := e.be.requests(); n != 0 {
			t.Errorf("upstream saw %d requests, want 0", n)
		}
		if evs := blockedEvents(e.store); len(evs) != 1 || evs[0].IdentityStatus != string(identity.StatusConflict) {
			t.Errorf("events = %+v", e.store.snapshot())
		}
	})
}

// With identity off no token is parsed, so there are no claims to match.
func TestBlockList_IdentityOffNotMatched(t *testing.T) {
	e := newBlockEnv(t, IdentityModeOff)
	e.block(config.BlockedUser{Sub: "alice"})
	if st := e.h1("").get("X-Warden-Identity: Bearer tok-alice\r\n"); st != 200 {
		t.Errorf("status = %d, want 200", st)
	}
}

func TestBlockList_H2StreamDenied(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	cc := e.h2("Proxy-Authorization: " + basicAuth("tok-u1") + "\r\n")
	if st := h2Get(t, cc, nil); st != 200 {
		t.Fatalf("first stream status = %d, want 200", st)
	}
	e.block(config.BlockedUser{Sub: "u1"})
	req, _ := http.NewRequest("GET", "https://"+idHost+"/x", nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedResponse(t, resp)
	if n := e.be.requests(); n != 1 {
		t.Errorf("upstream saw %d requests, want 1", n)
	}
	evs := blockedEvents(e.store)
	if len(evs) != 1 || evs[0].UserSub != "u1" {
		t.Errorf("events = %+v", e.store.snapshot())
	}
}

func TestBlockList_GRPCStreamDenied(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.block(config.BlockedUser{Sub: "u1"})
	cc := e.h2("")
	req, _ := http.NewRequest("POST", "https://"+idHost+"/pkg.Svc/M", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("X-Warden-Identity", "Bearer tok-u1")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	assertBlockedResponse(t, resp)
	if n := e.be.requests(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
	if evs := blockedEvents(e.store); len(evs) != 1 || evs[0].UserSub != "u1" {
		t.Errorf("events = %+v", e.store.snapshot())
	}
}

func TestBlockList_WebSocketUpgradeDenied(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.block(config.BlockedUser{Sub: "u1"})
	_, _, caCert, caKey := generateTestCA(t)
	b := &wsBackend{reqHeaders: make(chan string, 1)}
	ln := startWSBackend(t, caCert, caKey, b)
	inner := dialBackend(ln)
	var wsDials atomic.Int64
	e.p.dialTLS = func(n, a string, c *tls.Config) (*tls.Conn, error) {
		wsDials.Add(1)
		return inner(n, a, c)
	}
	conn, br, status := e.connect("")
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	tc := e.tlsOver(conn, br, "http/1.1")
	_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: "+idHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"X-Warden-Identity: Bearer tok-u1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("blocked user got a 101")
	}
	assertBlockedResponse(t, resp)
	if n := wsDials.Load(); n != 0 {
		t.Errorf("upstream dials = %d, want 0", n)
	}
	select {
	case raw := <-b.reqHeaders:
		t.Errorf("the backend saw an upgrade request:\n%s", raw)
	default:
	}
}

func TestBlockList_TransparentMode(t *testing.T) {
	v := fakes.NewVerifier()
	v.Set("tok-alice", idClaims("alice", time.Now().Add(time.Hour)), identity.StatusValid, "")
	e := newTransparentEnv(t, transparentOpts{identity: IdentityConfig{Verifier: v, Mode: IdentityModeAttribute}})
	e.p.cfg.Policy.Replace(config.Policy{
		Allowlist:    []config.AllowlistEntry{{Domain: invHost}},
		BlockedUsers: []config.BlockedUser{{Sub: "alice"}},
	})

	// No identity: forwarded (documented gap: there is no CONNECT, so only the header can attribute).
	req, _ := http.NewRequest(http.MethodGet, "https://"+invHost+"/plain", nil)
	if _, st, err := e.doH1(invHost, req); err != nil || st != 200 {
		t.Fatalf("no identity: status %d err %v", st, err)
	}
	// Proxy-Authorization is never consulted in transparent mode.
	req, _ = http.NewRequest(http.MethodGet, "https://"+invHost+"/plain", nil)
	req.Header.Set("Proxy-Authorization", basicAuth("tok-alice"))
	if _, st, err := e.doH1(invHost, req); err != nil || st != 200 {
		t.Fatalf("proxy-authorization only: status %d err %v", st, err)
	}
	// A blocked X-Warden-Identity is denied.
	req, _ = http.NewRequest(http.MethodGet, "https://"+invHost+"/plain", nil)
	req.Header.Set(IdentityHeader, "Bearer tok-alice")
	out, st, err := e.doH1(invHost, req)
	if err != nil || st != 403 {
		t.Fatalf("blocked header: status %d err %v", st, err)
	}
	if !strings.Contains(out, blockedWant) {
		t.Errorf("response = %q, want the user_blocked JSON body", out)
	}
	evs := blockedEvents(e.store)
	if len(evs) != 1 || evs[0].UserSub != "alice" {
		t.Errorf("events = %+v", e.store.snapshot())
	}
}

// blockStage is the first policy gate: a blocked user is refused before the
// constraint check, so the event names user_blocked even for a request policy
// would also have denied.
func TestBlockList_BeforePolicyGates(t *testing.T) {
	e := newBlockEnv(t, IdentityModeAttribute)
	e.p.cfg.Policy.Replace(config.Policy{
		Allowlist:    []config.AllowlistEntry{{Domain: idHost, Port: 443, Methods: []string{"POST"}}},
		BlockedUsers: []config.BlockedUser{{Sub: "u1"}},
	})
	assertBlockedResponse(t, e.h1("").getResp("X-Warden-Identity: Bearer tok-u1\r\n"))
	if evs := blockedEvents(e.store); len(evs) != 1 {
		t.Errorf("events = %+v, want one user_blocked", e.store.snapshot())
	}
	// An unblocked user gets the ordinary constraint deny.
	if st := e.h1("").get("X-Warden-Identity: Bearer tok-u2\r\n"); st != 403 {
		t.Errorf("u2 status = %d, want the constraint 403", st)
	}
	if n := len(blockedEvents(e.store)); n != 1 {
		t.Errorf("user_blocked events = %d, want still 1", n)
	}
}

func TestBlockStageAllocs(t *testing.T) {
	p := stageProxy(t, fakes.NewVerifier(), IdentityModeAttribute, nil, nil)
	users := make([]config.BlockedUser, 0, 5000)
	for i := 0; i < 5000; i++ {
		users = append(users, config.BlockedUser{Sub: "sub-" + strings.Repeat("x", i%7) + string(rune('a'+i%26))})
	}
	p.cfg.Policy.Replace(config.Policy{BlockedUsers: users})
	s := stageScope(connIdentity{})
	s.idClaims = identity.Claims{Sub: "other", Email: "other@corp.com"}
	if n := testing.AllocsPerRun(1000, func() {
		if p.blockStage(s) {
			t.Fatal("blocked")
		}
	}); n != 0 {
		t.Errorf("blockStage allocates %v per request, want 0", n)
	}
}

func BenchmarkBlockStage(b *testing.B) {
	p := stageProxy(b, fakes.NewVerifier(), IdentityModeAttribute, nil, nil)
	users := make([]config.BlockedUser, 0, 5000)
	for i := 0; i < 5000; i++ {
		users = append(users, config.BlockedUser{Sub: "sub-" + strings.Repeat("x", i%7) + string(rune('a'+i%26))})
	}
	p.cfg.Policy.Replace(config.Policy{BlockedUsers: users})
	s := stageScope(connIdentity{})
	s.idClaims = identity.Claims{Sub: "other", Email: "other@corp.com"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.blockStage(s)
	}
}
