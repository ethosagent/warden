package controlplane

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/test/fakes"
)

const (
	rigClientID     = "warden-console"
	rigClientSecret = "rig-client-secret"
)

// rig is a control plane in oidc mode in front of the issuer fake. The browser
// is played by the test: it calls the control plane's handler directly and the
// IdP over HTTP, and relays the cookies and redirects by hand.
type rig struct {
	t     *testing.T
	idp   *fakes.OIDCIssuer
	srv   *Server
	h     http.Handler
	clk   *fakeClock
	db    *cpstate.DB
	logs  *bytes.Buffer
	redir string
}

type rigOpts struct {
	redirect string
	// publicIssuer makes the fake present this issuer and be reached only
	// through internalIssuerURL.
	publicIssuer string
	noInternal   bool
	idpDown      bool
	noStart      bool
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	clk := newFakeClock()
	var iopts []fakes.IssuerOption
	iopts = append(iopts, fakes.WithIssuerClock(clk.Now))
	if o.publicIssuer != "" {
		iopts = append(iopts, fakes.WithPublicIssuer(o.publicIssuer))
	}
	idp := fakes.NewOIDCIssuer(t, iopts...)
	idp.RegisterClient(rigClientID, rigClientSecret)
	if o.idpDown {
		idp.Stop()
	}
	if o.redirect == "" {
		o.redirect = "http://127.0.0.1:7070/auth/callback"
	}
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"),
		append(SessionMigrations(), OIDCPendingMigrations()...))
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cc := config.ConsoleConfig{
		Auth: config.ConsoleAuthOIDC,
		OIDC: config.ConsoleOIDC{
			Issuer: idp.Issuer(), ClientID: rigClientID, ClientSecretEnv: "UNUSED",
			RedirectURL: o.redirect, Scopes: config.DefaultConsoleScopes(),
		},
		Roles:   config.ConsoleRoles{Admin: []string{"admins"}, Viewer: []string{"staff"}},
		Session: config.ConsoleSession{Idle: time.Hour, Absolute: 12 * time.Hour},
	}
	// The fake speaks plain http, which the http-issuer rule allows only with
	// internalIssuerURL set (the development profile).
	if !o.noInternal {
		cc.OIDC.InternalIssuerURL = idp.URL()
	}
	logs := &bytes.Buffer{}
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "a.example"), State: db, Console: cc,
		ClientSecret: rigClientSecret, Now: clk.Now,
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if srv.auth == nil {
		t.Fatal("auth service not built")
	}
	srv.auth.backoffMin, srv.auth.backoffMax = 10*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if !o.noStart {
		srv.Start(ctx)
	}
	return &rig{t: t, idp: idp, srv: srv, h: srv.Handler(), clk: clk, db: db, logs: logs, redir: o.redirect}
}

// ready waits for discovery to succeed.
func (r *rig) ready() {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := r.srv.auth.ready(); ok {
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatal("oidc discovery never succeeded")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *rig) serve(method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// flow is the state of one browser login attempt, up to the callback request.
type flow struct {
	loginRec    *httptest.ResponseRecorder
	loginCookie *http.Cookie
	callback    string // path and query the IdP redirected the browser to
}

// start performs /auth/login and the IdP leg, stopping before the callback.
func (r *rig) start(next string) flow {
	r.t.Helper()
	target := "/auth/login"
	if next != "" {
		target += "?next=" + url.QueryEscape(next)
	}
	rec := r.serve(http.MethodGet, target)
	if rec.Code != http.StatusFound {
		r.t.Fatalf("/auth/login = %d, want 302: %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		r.t.Fatal(err)
	}
	// The browser could reach the public issuer; the test cannot, so it goes
	// straight to the fake's listener.
	if loc.Host != r.idp.Addr() {
		loc.Scheme, loc.Host = "http", r.idp.Addr()
	}
	loc.Path = strings.TrimPrefix(loc.Path, pathOf(r.idp.Issuer()))
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, loc.String(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		r.t.Fatalf("idp authorize: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		r.t.Fatalf("idp authorize = %d, want 302", resp.StatusCode)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		r.t.Fatal(err)
	}
	return flow{loginRec: rec, loginCookie: cookieNamed(rec, r.srv.auth.loginCookieName), callback: cb.RequestURI()}
}

func pathOf(raw string) string {
	u, _ := url.Parse(raw)
	return u.Path
}

// finish sends the callback with the login cookie plus extras.
func (r *rig) finish(f flow, extra ...*http.Cookie) *httptest.ResponseRecorder {
	r.t.Helper()
	cookies := extra
	if f.loginCookie != nil {
		cookies = append([]*http.Cookie{{Name: f.loginCookie.Name, Value: f.loginCookie.Value}}, extra...)
	}
	return r.serve(http.MethodGet, f.callback, cookies...)
}

func (r *rig) sessionRows() int {
	r.t.Helper()
	var n int
	if err := r.db.SQL().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *rig) pendingRows() int {
	r.t.Helper()
	var n int
	if err := r.db.SQL().QueryRow(`SELECT COUNT(*) FROM oidc_pending`).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func wantRedirect(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func adminLogin(idp *fakes.OIDCIssuer) {
	idp.SetLogin(fakes.Valid("alice", "alice@example.com", "admins"))
}

func TestOIDCLoginEndToEnd(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.ready()
	adminLogin(r.idp)

	f := r.start("/dashboard/fleet?tab=1")
	req := r.idp.AuthRequests()
	if len(req) != 1 {
		t.Fatalf("idp saw %d authorize requests, want 1", len(req))
	}
	a := req[0]
	if a.ClientID != rigClientID || a.ChallengeMethod != "S256" || a.Challenge == "" || a.Nonce == "" || a.State == "" ||
		a.RedirectURI != r.redir || strings.Contains(a.Scope, "offline_access") {
		t.Fatalf("authorize request wrong: %+v", a)
	}
	if f.loginCookie == nil || !f.loginCookie.HttpOnly || f.loginCookie.SameSite != http.SameSiteLaxMode || f.loginCookie.MaxAge != 600 {
		t.Fatalf("login cookie flags wrong: %+v", f.loginCookie)
	}
	var verifier string
	if err := r.db.SQL().QueryRow(`SELECT verifier FROM oidc_pending`).Scan(&verifier); err != nil || verifier == "" {
		t.Fatalf("pending verifier: %q %v", verifier, err)
	}
	code := mustQuery(t, f.callback, "code")

	rec := r.finish(f)
	wantRedirect(t, rec, "/dashboard/fleet?tab=1")
	sc := cookieNamed(rec, "warden_console")
	if sc == nil || sc.Value == "" || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" {
		t.Fatalf("session cookie wrong: %+v", sc)
	}
	var iss, sub string
	if err := r.db.SQL().QueryRow(`SELECT iss, sub FROM sessions`).Scan(&iss, &sub); err != nil {
		t.Fatalf("no sessions row: %v", err)
	}
	if iss != r.idp.Issuer() || sub != "alice" {
		t.Fatalf("session row = (%q, %q)", iss, sub)
	}
	if lc := cookieNamed(rec, "warden_login"); lc == nil || lc.MaxAge >= 0 {
		t.Fatalf("login cookie not cleared: %+v", lc)
	}
	if r.pendingRows() != 0 {
		t.Fatal("pending row not consumed")
	}
	if _, live, _ := r.srv.sessions.Lookup(context.Background(), sc.Value); !live {
		t.Fatal("issued cookie does not name a live session")
	}

	out := r.logs.String()
	if !strings.Contains(out, `"msg":"console_login"`) || !strings.Contains(out, `"result":"ok"`) || !strings.Contains(out, `"sub":"alice"`) {
		t.Fatalf("no console_login success line: %s", out)
	}
	for name, secret := range map[string]string{
		"code": code, "verifier": verifier, "nonce": a.Nonce, "state": a.State, "session id": sc.Value,
		"jwt": "eyJ", "access token": "fake-access-token", "client secret": rigClientSecret,
	} {
		if strings.Contains(out, secret) {
			t.Errorf("logs leak the %s", name)
		}
	}
}

func mustQuery(t *testing.T, requestURI, key string) string {
	t.Helper()
	u, err := url.Parse(requestURI)
	if err != nil {
		t.Fatal(err)
	}
	v := u.Query().Get(key)
	if v == "" {
		t.Fatalf("no %s in %s", key, requestURI)
	}
	return v
}

func TestOIDCCallbackRejects(t *testing.T) {
	tests := []struct {
		name string
		want string
		// setup runs before login; mutate edits the callback request.
		setup  func(*rig)
		mutate func(*rig, *flow) []*http.Cookie
	}{
		{name: "nonce mismatch", want: "nonce_mismatch", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithNonce("not-the-nonce"))
		}},
		{name: "missing nonce", want: "nonce_mismatch", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithoutClaim("nonce"))
		}},
		{name: "aud is another client only", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithAud("agent-harness"))
		}},
		{name: "two auds, azp is the other client", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithAud(rigClientID, "agent-harness"), fakes.WithAZP("agent-harness"))
		}},
		{name: "two auds, azp absent", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithAud(rigClientID, "agent-harness"), fakes.WithoutClaim("azp"))
		}},
		{name: "expired", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.Expired())
		}},
		{name: "alg none", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithAlg("none"))
		}},
		{name: "alg HS256", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithAlg("HS256"))
		}},
		{name: "wrong signing key", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithUnpublishedKey())
		}},
		{name: "wrong issuer", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithIss("http://other.example"))
		}},
		{name: "no subject", want: "token_invalid", setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithSub(""))
		}},
		{name: "idp error", want: "idp_error", setup: func(r *rig) { r.idp.FailAuthorize("access_denied") }},
		{name: "token endpoint fails", want: "exchange_failed", setup: func(r *rig) { r.idp.SetTokenStatus(500) }},
		{name: "code replayed at the idp", want: "exchange_failed", mutate: func(r *rig, f *flow) []*http.Cookie {
			// Spend the code first; the control plane's own exchange then fails.
			form := url.Values{"grant_type": {"authorization_code"}, "code": {mustQuery(t, f.callback, "code")}}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, r.idp.URL()+"/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(rigClientID, rigClientSecret)
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
			return nil
		}},
		{name: "no login cookie", want: "state_invalid", mutate: func(_ *rig, f *flow) []*http.Cookie {
			f.loginCookie = nil
			return nil
		}},
		{name: "another browser's login cookie", want: "state_invalid", mutate: func(_ *rig, f *flow) []*http.Cookie {
			f.loginCookie = &http.Cookie{Name: f.loginCookie.Name, Value: "someone-else"}
			return nil
		}},
		{name: "unknown state", want: "state_invalid", mutate: func(_ *rig, f *flow) []*http.Cookie {
			f.callback = "/auth/callback?code=x&state=forged"
			return nil
		}},
		{name: "missing state", want: "state_invalid", mutate: func(_ *rig, f *flow) []*http.Cookie {
			f.callback = "/auth/callback?code=x"
			return nil
		}},
		{name: "expired state", want: "state_invalid", mutate: func(r *rig, _ *flow) []*http.Cookie {
			r.clk.Advance(11 * time.Minute)
			return nil
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, rigOpts{})
			r.ready()
			if tc.setup != nil {
				tc.setup(r)
			} else {
				adminLogin(r.idp)
			}
			f := r.start("")
			var extra []*http.Cookie
			if tc.mutate != nil {
				extra = tc.mutate(r, &f)
			}
			rec := r.finish(f, extra...)
			wantRedirect(t, rec, "/dashboard/?login_error="+tc.want)
			if n := r.sessionRows(); n != 0 {
				t.Fatalf("%d sessions rows exist after a rejected login", n)
			}
			if cookieNamed(rec, "warden_console") != nil {
				t.Fatal("a session cookie was set on a rejected login")
			}
			if strings.Contains(rec.Body.String(), "refused") || strings.Contains(rec.Header().Get("Location"), "refused") {
				t.Fatal("IdP error text echoed to the browser")
			}
			if !strings.Contains(r.logs.String(), `"result":"failed"`) || !strings.Contains(r.logs.String(), `"reason":"`+tc.want+`"`) {
				t.Fatalf("no failed console_login line with reason %s: %s", tc.want, r.logs)
			}
		})
	}

	t.Run("replayed state", func(t *testing.T) {
		r := newRig(t, rigOpts{})
		r.ready()
		adminLogin(r.idp)
		f := r.start("")
		wantRedirect(t, r.finish(f), "/dashboard/")
		if r.sessionRows() != 1 {
			t.Fatal("first callback made no session")
		}
		wantRedirect(t, r.finish(f), "/dashboard/?login_error=state_invalid")
		if r.sessionRows() != 1 {
			t.Fatal("a replayed callback made a second session")
		}
	})
}

func TestOIDCLoginNoRole(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.ready()
	r.idp.SetLogin(fakes.Valid("mallory", "m@example.com", "strangers"))
	rec := r.finish(r.start(""))
	wantRedirect(t, rec, "/dashboard/?login_error=no_role")
	if r.sessionRows() != 0 || cookieNamed(rec, "warden_console") != nil {
		t.Fatal("a session was created for a user with no role")
	}
}

func TestOIDCLoginManyGroupsKeepsRole(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.ready()
	groups := []string{"staff"}
	for i := 0; i < 100; i++ {
		groups = append(groups, fmt.Sprintf("g%03d", i))
	}
	// "staff" sorts after 100 other groups: past the worker's 64-entry cap, inside
	// the console's 256.
	r.idp.SetLogin(fakes.Valid("dave", "d@example.com", groups...))
	wantRedirect(t, r.finish(r.start("")), "/dashboard/")
	if r.sessionRows() != 1 {
		t.Fatal("no session for a user whose role group is past the 64th")
	}
}

func TestOIDCLoginNextIsRelative(t *testing.T) {
	for next, want := range map[string]string{
		"https://evil.example":              "/dashboard/",
		"//evil.example":                    "/dashboard/",
		"//evil.example/dashboard/":         "/dashboard/",
		"/dashboard//evil.example":          "/dashboard/",
		`/dashboard/\evil.example`:          "/dashboard/",
		"/dashboard/../central/secrets":     "/dashboard/",
		"/evil":                             "/dashboard/",
		"javascript:alert(1)":               "/dashboard/",
		"/dashboard/\r\nSet-Cookie: x=y":    "/dashboard/",
		"/dashboard/a%2F%2Fb":               "/dashboard/",
		"/dashboard/a%2f%2fb":               "/dashboard/",
		"/dashboard/a%5Cb":                  "/dashboard/",
		"/dashboard/%2e%2e/central/secrets": "/dashboard/",
		"/dashboard/a%0d%0ab":               "/dashboard/",
		"":                                  "/dashboard/",
		"/dashboard/alerts":                 "/dashboard/alerts",
		"/dashboard/?tab=policy":            "/dashboard/?tab=policy",
	} {
		t.Run(next, func(t *testing.T) {
			r := newRig(t, rigOpts{})
			r.ready()
			adminLogin(r.idp)
			wantRedirect(t, r.finish(r.start(next)), want)
		})
	}
}

func TestOIDCSessionFixation(t *testing.T) {
	r := newRig(t, rigOpts{redirect: "https://cp.example/auth/callback"})
	r.ready()
	adminLogin(r.idp)
	oldID, _, err := r.srv.sessions.Create(context.Background(), testSessionInput())
	if err != nil {
		t.Fatal(err)
	}
	f := r.start("")
	if f.loginCookie == nil || f.loginCookie.Name != "__Host-warden_login" || !f.loginCookie.Secure {
		t.Fatalf("https login cookie wrong: %+v", f.loginCookie)
	}
	rec := r.finish(f, &http.Cookie{Name: "__Host-warden_console", Value: oldID})
	wantRedirect(t, rec, "/dashboard/")
	sc := cookieNamed(rec, "__Host-warden_console")
	if sc == nil {
		t.Fatal("no session cookie")
	}
	if sc.Value == "" || sc.Value == oldID {
		t.Fatalf("new cookie value %q equals the one the request carried", sc.Value)
	}
	if !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" {
		t.Fatalf("session cookie flags wrong: %+v", sc)
	}
	if _, live, _ := r.srv.sessions.Lookup(context.Background(), oldID); live {
		t.Fatal("the old session row survived the login")
	}
	if _, live, _ := r.srv.sessions.Lookup(context.Background(), sc.Value); !live {
		t.Fatal("the new session is not live")
	}
	if r.sessionRows() != 1 {
		t.Fatalf("%d session rows, want 1", r.sessionRows())
	}

	// A planted session id with no login attempt behind it creates nothing.
	rec = r.serve(http.MethodGet, "/auth/callback?code=x&state=y", &http.Cookie{Name: "__Host-warden_console", Value: "attacker-chosen"})
	wantRedirect(t, rec, "/dashboard/?login_error=state_invalid")
	if c := cookieNamed(rec, "__Host-warden_console"); c != nil {
		t.Fatalf("a failed callback set a session cookie: %+v", c)
	}
}

func TestOIDCLoginIdPDownAtStart(t *testing.T) {
	r := newRig(t, rigOpts{idpDown: true})
	adminLogin(r.idp)

	if rec := r.serve(http.MethodGet, "/policy"); rec.Code != http.StatusOK {
		t.Fatalf("/policy = %d with the IdP down, want 200", rec.Code)
	}
	for _, path := range []string{"/auth/login", "/auth/callback?code=x&state=y"} {
		rec := r.serve(http.MethodGet, path)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"idp_unavailable"`) {
			t.Fatalf("%s = %d %s, want 503 idp_unavailable", path, rec.Code, rec.Body)
		}
	}
	r.idp.Start()
	r.ready()
	wantRedirect(t, r.finish(r.start("")), "/dashboard/")
	if r.sessionRows() != 1 {
		t.Fatal("no session after the IdP came up")
	}
}

func TestOIDCLoginInternalIssuer(t *testing.T) {
	const public = "http://localhost:5556/dex"
	t.Run("reaches the internal origin", func(t *testing.T) {
		r := newRig(t, rigOpts{publicIssuer: public})
		r.ready()
		adminLogin(r.idp)
		f := r.start("")
		loc := r.idp.AuthRequests()
		if len(loc) != 1 {
			t.Fatalf("idp saw %d authorize requests", len(loc))
		}
		if got := f.loginRec.Header().Get("Location"); !strings.HasPrefix(got, public+"/auth?") {
			t.Fatalf("authorize redirect %q does not use the public issuer", got)
		}
		wantRedirect(t, r.finish(f), "/dashboard/")
		var iss string
		if err := r.db.SQL().QueryRow(`SELECT iss FROM sessions`).Scan(&iss); err != nil || iss != public {
			t.Fatalf("session iss = %q, %v; want %q", iss, err, public)
		}
		if r.idp.DiscoveryRequests() == 0 || r.idp.JWKSRequests() == 0 || r.idp.TokenRequests() != 1 {
			t.Fatalf("fake saw discovery=%d jwks=%d token=%d", r.idp.DiscoveryRequests(), r.idp.JWKSRequests(), r.idp.TokenRequests())
		}
	})
	t.Run("without internalIssuerURL login is unavailable", func(t *testing.T) {
		r := newRig(t, rigOpts{publicIssuer: public, noInternal: true})
		rec := r.serve(http.MethodGet, "/auth/login")
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"idp_unavailable"`) {
			t.Fatalf("/auth/login = %d %s, want 503 idp_unavailable", rec.Code, rec.Body)
		}
	})
}

func TestOIDCRoutesOnlyInOIDCMode(t *testing.T) {
	db := openSessionDB(t)
	for name, cfg := range map[string]Config{
		"none":          {State: db},
		"oidc no state": {Console: config.ConsoleConfig{Auth: config.ConsoleAuthOIDC, OIDC: config.ConsoleOIDC{RedirectURL: testRedirectHTTPS}}},
	} {
		cfg.PolicyPath = writePolicyFile(t, "a.example")
		h := New(cfg).Handler()
		for _, path := range []string{"/auth/login", "/auth/callback"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s: %s = %d, want 404", name, path, rec.Code)
			}
		}
	}
}

func TestOIDCRoutesRejectOtherMethods(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.ready()
	for _, path := range []string{"/auth/login", "/auth/callback"} {
		if rec := r.serve(http.MethodPost, path); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, rec.Code)
		}
	}
}

func TestOIDCPendingCapAndSweep(t *testing.T) {
	r := newRig(t, rigOpts{noStart: true})
	r.srv.auth.endpoints.Store(&oidc.Endpoints{AuthURL: "http://idp.example/auth", TokenURL: "http://idp.example/token"})
	// Fill to the cap in one statement, then one more login must be refused.
	if _, err := r.db.SQL().Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
		INSERT INTO oidc_pending SELECT 'h' || i, 'n', 'v', '/dashboard/', 'b', ? FROM n`,
		pendingCap, r.clk.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	rec := r.serve(http.MethodGet, "/auth/login")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "login_busy") {
		t.Fatalf("login at the cap = %d %s, want 503 login_busy", rec.Code, rec.Body)
	}
	if r.pendingRows() != pendingCap {
		t.Fatalf("rows = %d, want %d", r.pendingRows(), pendingCap)
	}
	r.clk.Advance(2 * time.Hour)
	n, err := r.srv.auth.pending.Sweep(context.Background())
	if err != nil || n != pendingCap || r.pendingRows() != 0 {
		t.Fatalf("sweep removed %d (%v), %d rows left", n, err, r.pendingRows())
	}
}

func TestOIDCPendingTakeIsSingleUse(t *testing.T) {
	r := newRig(t, rigOpts{noStart: true})
	ps := r.srv.auth.pending
	ctx := context.Background()
	if err := ps.Put(ctx, pendingLogin{StateHash: "s1", Nonce: "n", Verifier: "v", Next: "/dashboard/", BrowserHash: "b"}); err != nil {
		t.Fatal(err)
	}
	if p, ok, err := ps.Take(ctx, "s1"); err != nil || !ok || p.Nonce != "n" || p.Verifier != "v" {
		t.Fatalf("first take = %+v %v %v", p, ok, err)
	}
	if _, ok, _ := ps.Take(ctx, "s1"); ok {
		t.Fatal("a state was taken twice")
	}
}
