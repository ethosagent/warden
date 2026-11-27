package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/internal/webauth"
	"github.com/ethosagent/warden/internal/webauth/webauthtest"
	"github.com/ethosagent/warden/test/fakes"
)

// The consent portal's sign-in (W-P3-CSIG-02), driven through the real OIDC
// flow against the issuer fake. The rig runs the console too (same IdP, its
// own client), so a console state can be replayed on the portal callback.

const (
	portalClientID     = config.DefaultConsentClientID
	portalClientSecret = "portal-rig-secret"
	portalRefreshToken = "rt-portal-rig-refresh-token-value"
	portalRedirect     = "https://cp.example/portal/callback"
	portalCookie       = "__Host-warden_portal"
	portalLoginCookie  = "__Host-warden_portal_login"
)

type portalRig struct {
	t    *testing.T
	idp  *webauthtest.FakeOIDC
	srv  *Server
	h    http.Handler
	clk  *fakeClock
	db   *cpstate.DB
	logs *syncBuf
}

type portalRigOpts struct {
	allowedGroups []string
	noIdPLink     bool
	idpDown       bool
	noConsent     bool
	noState       bool
	links         portal.LinkWriter
	// userStore is consent.store (Config.UserStore); nil gets a fresh
	// fakes.MemorySecretStore, so the real LinkStore stores the IdP link.
	userStore secrets.SecretStore
	// offboarding is consent.offboarding (zero: off).
	offboarding config.ConsentOffboarding
}

func newPortalRig(t *testing.T, o portalRigOpts) *portalRig {
	t.Helper()
	clk := newFakeClock()
	idp := webauthtest.NewFakeOIDC(t, webauthtest.Options{
		ClientID: rigClientID, ClientSecret: rigClientSecret, Now: clk.Now, Down: o.idpDown,
	})
	idp.RegisterClient(portalClientID, portalClientSecret)
	idp.SetRefreshToken(portalRefreshToken)
	var db *cpstate.DB
	if !o.noState {
		var err error
		db, err = cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), StateMigrations())
		if err != nil {
			t.Fatalf("cpstate.Open: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
	}
	cc := config.ConsoleConfig{
		Auth: config.ConsoleAuthOIDC,
		OIDC: config.ConsoleOIDC{
			Issuer: idp.Issuer(), ClientID: rigClientID, ClientSecretEnv: "UNUSED",
			RedirectURL: "http://127.0.0.1:7070/auth/callback", Scopes: config.DefaultConsoleScopes(),
			InternalIssuerURL: idp.URL(),
		},
		Roles:   config.ConsoleRoles{Admin: []string{"admins"}, Viewer: []string{"staff"}},
		Session: config.ConsoleSession{Idle: time.Hour, Absolute: 12 * time.Hour},
	}
	var consent *config.ConsentConfig
	if !o.noConsent {
		consent = &config.ConsentConfig{
			Enabled: true,
			OIDC: config.ConsentOIDC{
				Issuer: idp.Issuer(), ClientID: portalClientID, ClientSecretEnv: "UNUSED",
				RedirectURL: portalRedirect, InternalIssuerURL: idp.URL(),
			},
			AllowedGroups: o.allowedGroups,
			Session:       config.ConsentSession{Idle: config.DefaultConsentIdle, Absolute: config.DefaultConsentAbsolute},
			IdPLink:       config.ConsentIdPLink{Enabled: !o.noIdPLink, RefreshLifetime: config.DefaultConsentRefreshLifetime},
			Offboarding:   o.offboarding,
		}
	}
	logs := &syncBuf{}
	userStore := o.userStore
	if userStore == nil {
		userStore = fakes.NewMemorySecretStore()
	}
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "a.example"), State: db, Console: cc, Consent: consent, UserStore: userStore,
		ClientSecret: rigClientSecret, ConsentClientSecret: portalClientSecret, Now: clk.Now,
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if srv.portal != nil && srv.portal.provider != nil {
		srv.portal.provider.SetBackoff(10*time.Millisecond, 20*time.Millisecond)
		if o.links != nil {
			srv.portal.links = o.links
		}
	}
	if srv.auth != nil && srv.auth.provider != nil {
		srv.auth.provider.SetBackoff(10*time.Millisecond, 20*time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.Start(ctx)
	return &portalRig{t: t, idp: idp, srv: srv, h: srv.Handler(), clk: clk, db: db, logs: logs}
}

func (r *portalRig) ready() {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !r.srv.portal.ready() || !r.srv.auth.ready() {
		if time.Now().After(deadline) {
			r.t.Fatal("oidc discovery never succeeded")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *portalRig) serve(method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

// start performs /portal/login (with next) and the IdP leg.
func (r *portalRig) start(next string) flow {
	r.t.Helper()
	target := "/portal/login"
	if next != "" {
		target += "?next=" + url.QueryEscape(next)
	}
	rec := r.serve(http.MethodGet, target)
	if rec.Code != http.StatusFound {
		r.t.Fatalf("/portal/login = %d, want 302: %s", rec.Code, rec.Body)
	}
	callback := r.idp.Authorize(r.t, rec.Header().Get("Location"))
	return flow{loginRec: rec, loginCookie: cookieNamed(rec, portalLoginCookie), callback: callback}
}

func (r *portalRig) finish(f flow, extra ...*http.Cookie) *httptest.ResponseRecorder {
	r.t.Helper()
	cookies := extra
	if f.loginCookie != nil {
		cookies = append([]*http.Cookie{{Name: f.loginCookie.Name, Value: f.loginCookie.Value}}, extra...)
	}
	return r.serve(http.MethodGet, f.callback, cookies...)
}

func (r *portalRig) count(table string) int {
	r.t.Helper()
	var n int
	if err := r.db.SQL().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// login runs a full portal login and returns the session cookie.
func (r *portalRig) login(next string) *http.Cookie {
	r.t.Helper()
	res := r.finish(r.start(next))
	sc := cookieNamed(res, portalCookie)
	if res.Code != http.StatusFound || sc == nil {
		r.t.Fatalf("portal login = %d (cookie %v): %s", res.Code, sc, res.Body)
	}
	return &http.Cookie{Name: sc.Name, Value: sc.Value}
}

// signedIn reports whether GET /portal sees a live session for email.
func (r *portalRig) signedIn(c *http.Cookie, email string) bool {
	r.t.Helper()
	rec := r.serve(http.MethodGet, "/portal", c)
	if rec.Code != http.StatusOK {
		r.t.Fatalf("GET /portal = %d", rec.Code)
	}
	return strings.Contains(rec.Body.String(), "Signed in as <strong>"+email+"</strong>")
}

func TestPortalLoginEndToEnd(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com", "staff"))

	f := r.start("/portal/connect/abc")
	loc, err := url.Parse(f.loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("client_id") != portalClientID || q.Get("redirect_uri") != portalRedirect ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatalf("authorize query = %v", q)
	}
	if got := q.Get("scope"); got != "openid email profile groups offline_access" {
		t.Fatalf("scope = %q", got)
	}
	lc := f.loginCookie
	if lc == nil || !lc.Secure || !lc.HttpOnly || lc.SameSite != http.SameSiteLaxMode || lc.Path != "/" {
		t.Fatalf("binding cookie = %+v, want %s Secure HttpOnly Lax", lc, portalLoginCookie)
	}
	var purpose string
	if err := r.db.SQL().QueryRow(`SELECT purpose FROM oidc_pending`).Scan(&purpose); err != nil || purpose != webauth.PurposePortal {
		t.Fatalf("pending purpose = %q (%v), want portal", purpose, err)
	}

	res := r.finish(f)
	wantRedirect(t, res, "/portal/connect/abc")
	sc := cookieNamed(res, portalCookie)
	if sc == nil || !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" ||
		sc.MaxAge != int(config.DefaultConsentAbsolute.Seconds()) || len(sc.Value) < 43 {
		t.Fatalf("session cookie = %+v", sc)
	}
	if c := cookieNamed(res, portalLoginCookie); c == nil || c.MaxAge >= 0 {
		t.Fatalf("binding cookie not cleared: %+v", c)
	}
	var iss, sub, email, idHash string
	if err := r.db.SQL().QueryRow(`SELECT iss, sub, email, id_hash FROM portal_sessions`).Scan(&iss, &sub, &email, &idHash); err != nil {
		t.Fatal(err)
	}
	if iss != r.idp.Issuer() || sub != "pat" || email != "pat@example.com" || idHash != webauth.HashID(sc.Value) {
		t.Fatalf("portal_sessions row = (%s, %s, %s, %s)", iss, sub, email, idHash)
	}
	if r.count("sessions") != 0 {
		t.Fatal("a portal login created a console session")
	}
	if !r.signedIn(&http.Cookie{Name: sc.Name, Value: sc.Value}, "pat@example.com") {
		t.Fatal("GET /portal does not see the new session")
	}
	// A second login mints a fresh id and drops the session the browser held.
	again := r.finish(r.start(""), &http.Cookie{Name: sc.Name, Value: sc.Value})
	wantRedirect(t, again, portal.Home)
	if nc := cookieNamed(again, portalCookie); nc == nil || nc.Value == sc.Value || r.count("portal_sessions") != 1 {
		t.Fatalf("re-login reused or kept the old session (rows %d)", r.count("portal_sessions"))
	}
}

func TestPortalLoginWithoutIdPLink(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{noIdPLink: true})
	r.ready()
	r.idp.SetRefreshToken("")
	f := r.start("")
	loc, _ := url.Parse(f.loginRec.Header().Get("Location"))
	if got := loc.Query().Get("scope"); got != "openid email profile groups" {
		t.Fatalf("scope = %q, want no offline_access", got)
	}
	wantRedirect(t, r.finish(f), portal.Home)
	if r.count("portal_sessions") != 1 {
		t.Fatal("no session without the IdP link")
	}
}

func TestPortalCallbackRejects(t *testing.T) {
	cases := []struct {
		name string
		code string
		run  func(r *portalRig) *httptest.ResponseRecorder
	}{
		{"unknown state", webauth.CodeStateInvalid, func(r *portalRig) *httptest.ResponseRecorder {
			f := r.start("")
			return r.serve(http.MethodGet, "/portal/callback?state=nope&code=x", &http.Cookie{Name: f.loginCookie.Name, Value: f.loginCookie.Value})
		}},
		{"missing binding cookie", webauth.CodeStateInvalid, func(r *portalRig) *httptest.ResponseRecorder {
			f := r.start("")
			return r.serve(http.MethodGet, f.callback)
		}},
		{"mismatched binding cookie", webauth.CodeStateInvalid, func(r *portalRig) *httptest.ResponseRecorder {
			f := r.start("")
			return r.serve(http.MethodGet, f.callback, &http.Cookie{Name: portalLoginCookie, Value: "someone-else"})
		}},
		{"console state", webauth.CodeStateInvalid, func(r *portalRig) *httptest.ResponseRecorder {
			rec := r.serve(http.MethodGet, "/auth/login")
			if rec.Code != http.StatusFound {
				r.t.Fatalf("/auth/login = %d", rec.Code)
			}
			cb := r.idp.Authorize(r.t, rec.Header().Get("Location"))
			cbURL, _ := url.Parse(cb)
			lc := cookieNamed(rec, r.srv.auth.loginCookieName)
			res := r.serve(http.MethodGet, "/portal/callback?"+cbURL.RawQuery,
				&http.Cookie{Name: lc.Name, Value: lc.Value}, &http.Cookie{Name: portalLoginCookie, Value: lc.Value})
			// The console's row is left for the console callback.
			if n := r.count("oidc_pending"); n != 1 {
				r.t.Fatalf("console pending rows = %d, want 1 (untouched)", n)
			}
			return res
		}},
		{"mismatched nonce", webauth.CodeNonceMismatch, func(r *portalRig) *httptest.ResponseRecorder {
			r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"), fakes.WithNonce("not-the-nonce"))
			return r.finish(r.start(""))
		}},
		{"console audience only", webauth.CodeTokenInvalid, func(r *portalRig) *httptest.ResponseRecorder {
			r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"), fakes.WithAud(rigClientID), fakes.WithAZP(rigClientID))
			return r.finish(r.start(""))
		}},
		{"alg HS256", webauth.CodeTokenInvalid, func(r *portalRig) *httptest.ResponseRecorder {
			r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"), fakes.WithHS256([]byte(portalClientSecret)))
			return r.finish(r.start(""))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newPortalRig(t, portalRigOpts{})
			r.ready()
			res := c.run(r)
			wantRedirect(t, res, "/portal?login_error="+c.code)
			if cookieNamed(res, portalCookie) != nil || r.count("portal_sessions") != 0 || r.count("sessions") != 0 {
				t.Fatal("a rejected callback created a session")
			}
		})
	}
	t.Run("replayed state", func(t *testing.T) {
		r := newPortalRig(t, portalRigOpts{})
		r.ready()
		f := r.start("")
		wantRedirect(t, r.finish(f), portal.Home)
		res := r.finish(f)
		wantRedirect(t, res, "/portal?login_error="+webauth.CodeStateInvalid)
		if cookieNamed(res, portalCookie) != nil || r.count("portal_sessions") != 1 {
			t.Fatalf("a replayed state created a session (rows %d)", r.count("portal_sessions"))
		}
	})
	t.Run("portal state on the console callback", func(t *testing.T) {
		r := newPortalRig(t, portalRigOpts{})
		r.ready()
		f := r.start("")
		cbURL, _ := url.Parse(f.callback)
		res := r.serve(http.MethodGet, "/auth/callback?"+cbURL.RawQuery,
			&http.Cookie{Name: r.srv.auth.loginCookieName, Value: f.loginCookie.Value})
		wantRedirect(t, res, "/dashboard/?login_error="+webauth.CodeStateInvalid)
		if r.count("sessions") != 0 || r.count("portal_sessions") != 0 {
			t.Fatal("a portal state signed in to the console")
		}
	})
}

func TestPortalNextRedirect(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	for _, next := range []string{"https://evil.example", "//evil.example", "/dashboard/", "/portal/../dashboard/", `/portal\evil`, "/connectx"} {
		wantRedirect(t, r.finish(r.start(next)), portal.Home)
	}
	for _, next := range []string{"/portal/connect/abc", "/connect/github?x=1"} {
		wantRedirect(t, r.finish(r.start(next)), next)
	}
}

func TestPortalSessionExpiry(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		r := newPortalRig(t, portalRigOpts{})
		r.ready()
		c := r.login("")
		r.clk.Advance(29 * time.Minute)
		if !r.signedIn(c, fakes.DefaultLoginSub+"@example.com") {
			t.Fatal("session dead before the idle limit")
		}
		r.clk.Advance(30*time.Minute + time.Second)
		if r.signedIn(c, fakes.DefaultLoginSub+"@example.com") {
			t.Fatal("session idle for 30m01s still authenticates")
		}
	})
	t.Run("absolute", func(t *testing.T) {
		r := newPortalRig(t, portalRigOpts{})
		r.ready()
		c := r.login("")
		email := fakes.DefaultLoginSub + "@example.com"
		for elapsed := time.Duration(0); elapsed < 7*time.Hour+59*time.Minute; {
			step := min(20*time.Minute, 7*time.Hour+59*time.Minute-elapsed)
			r.clk.Advance(step)
			elapsed += step
			if !r.signedIn(c, email) {
				t.Fatalf("active session dead after %s", elapsed)
			}
		}
		r.clk.Advance(2 * time.Minute)
		if r.signedIn(c, email) {
			t.Fatal("active session still authenticates after 8h01m")
		}
		if n := r.count("portal_sessions"); n != 0 {
			t.Fatalf("expired row kept: %d", n)
		}
	})
}

type fakeLinkWriter struct {
	mu    sync.Mutex
	links []portal.Link
	err   error
}

func (f *fakeLinkWriter) StoreLink(_ context.Context, l portal.Link) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.links = append(f.links, l)
	return nil
}

func TestPortalAdmission(t *testing.T) {
	for _, c := range []struct {
		name  string
		entry BlockEntry
	}{
		{"blocked sub", BlockEntry{Sub: "pat"}},
		{"blocked email", BlockEntry{Email: "PAT@example.com"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newPortalRig(t, portalRigOpts{})
			r.ready()
			r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
			blockAdd(t, r.srv, c.entry)
			res := r.finish(r.start(""))
			wantRedirect(t, res, "/portal?login_error="+portal.CodeBlocked)
			if cookieNamed(res, portalCookie) != nil || r.count("portal_sessions") != 0 {
				t.Fatal("a blocked principal got a portal session")
			}
		})
	}
	t.Run("blocking a signed-in user hides the session", func(t *testing.T) {
		r := newPortalRig(t, portalRigOpts{})
		r.ready()
		r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
		c := r.login("")
		blockAdd(t, r.srv, BlockEntry{Sub: "pat"})
		if r.signedIn(c, "pat@example.com") {
			t.Fatal("a blocked principal's portal session still authenticates")
		}
	})
	t.Run("outside allowedGroups", func(t *testing.T) {
		r := newPortalRig(t, portalRigOpts{allowedGroups: []string{"employees"}})
		r.ready()
		r.idp.SetLogin(fakes.Valid("pat", "pat@example.com", "contractors"))
		res := r.finish(r.start(""))
		wantRedirect(t, res, "/portal?login_error="+portal.CodeNotAllowed)
		if r.count("portal_sessions") != 0 {
			t.Fatal("a user outside allowedGroups got a session")
		}
		r.idp.SetLogin(fakes.Valid("pat", "pat@example.com", "contractors", "employees"))
		wantRedirect(t, r.finish(r.start("")), portal.Home)
		if r.count("portal_sessions") != 1 {
			t.Fatal("a member of an allowed group got no session")
		}
	})
	t.Run("no refresh token", func(t *testing.T) {
		links := &fakeLinkWriter{}
		r := newPortalRig(t, portalRigOpts{links: links})
		r.ready()
		r.idp.SetRefreshToken("")
		res := r.finish(r.start(""))
		if res.Code != http.StatusBadGateway || errBody(t, res) != portal.CodeOfflineAccessNotGranted {
			t.Fatalf("callback = %d %s, want 502 offline_access_not_granted", res.Code, res.Body)
		}
		if cookieNamed(res, portalCookie) != nil || r.count("portal_sessions") != 0 || len(links.links) != 0 {
			t.Fatal("a login without a refresh token wrote something")
		}
	})
	t.Run("link writer", func(t *testing.T) {
		links := &fakeLinkWriter{}
		r := newPortalRig(t, portalRigOpts{links: links})
		r.ready()
		r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
		r.login("")
		if len(links.links) != 1 || links.links[0] != (portal.Link{Iss: r.idp.Issuer(), Sub: "pat", Email: "pat@example.com", EmailVerified: true, RefreshToken: portalRefreshToken}) {
			t.Fatalf("links = %v", links.links)
		}
		links.err = errors.New("store down")
		res := r.finish(r.start(""))
		if res.Code != http.StatusServiceUnavailable || errBody(t, res) != portalSecretStoreUnavailable {
			t.Fatalf("callback = %d %s, want 503 secret_store_unavailable", res.Code, res.Body)
		}
		if cookieNamed(res, portalCookie) != nil || r.count("portal_sessions") != 1 {
			t.Fatal("a failed link store created a session")
		}
	})
}

func TestPortalIdPDown(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{idpDown: true})
	for _, path := range []string{"/portal/login", "/portal/callback?state=x&code=y"} {
		rec := r.serve(http.MethodGet, path)
		if rec.Code != http.StatusServiceUnavailable || errBody(t, rec) != loginIDPUnavailable {
			t.Fatalf("%s with the IdP down = %d %s, want 503 idp_unavailable", path, rec.Code, rec.Body)
		}
	}
	if rec := r.serve(http.MethodGet, "/policy"); rec.Code != http.StatusOK {
		t.Fatalf("/policy with the IdP down = %d, want 200", rec.Code)
	}
	if r.count("oidc_pending") != 0 {
		t.Fatal("a login with the IdP down stored a pending row")
	}

	// Once the IdP is back, a full login logs nothing secret.
	r.idp.Start()
	r.ready()
	f := r.start("")
	var verifier, nonce string
	if err := r.db.SQL().QueryRow(`SELECT verifier, nonce FROM oidc_pending`).Scan(&verifier, &nonce); err != nil {
		t.Fatal(err)
	}
	cb, _ := url.Parse(f.callback)
	code, state := cb.Query().Get("code"), cb.Query().Get("state")
	res := r.finish(f)
	sc := cookieNamed(res, portalCookie)
	if sc == nil {
		t.Fatalf("no session after the IdP recovered: %d %s", res.Code, res.Body)
	}
	logs := r.logs.String()
	if !strings.Contains(logs, `"msg":"portal_login"`) || !strings.Contains(logs, `"result":"ok"`) || !strings.Contains(logs, `"duration_ms"`) {
		t.Fatalf("no portal_login line in logs:\n%s", logs)
	}
	for name, secret := range map[string]string{
		"code": code, "state": state, "verifier": verifier, "nonce": nonce, "session id": sc.Value,
		"binding cookie": f.loginCookie.Value, "refresh token": portalRefreshToken, "client secret": portalClientSecret,
	} {
		if secret == "" || strings.Contains(logs, secret) {
			t.Errorf("logs contain the %s (or it is empty)", name)
		}
	}
	// A raw ID token is a JWS: base64url JSON starting {"... = eyJ.
	if strings.Contains(logs, "eyJ") {
		t.Error("logs contain what looks like a raw ID token")
	}
}

func TestPortalNotMounted(t *testing.T) {
	for name, o := range map[string]portalRigOpts{
		"no consent block": {noConsent: true},
		"no state db":      {noState: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newPortalRig(t, o)
			if r.srv.portal != nil {
				t.Fatal("portal built")
			}
			for _, path := range []string{"/portal/login", "/portal/callback", "/portal"} {
				if rec := r.serve(http.MethodGet, path); rec.Code != http.StatusNotFound {
					t.Errorf("%s = %d, want 404", path, rec.Code)
				}
			}
			if rec := r.serve(http.MethodGet, "/policy"); rec.Code != http.StatusOK {
				t.Fatalf("/policy = %d", rec.Code)
			}
		})
	}
}

func TestPortalRoutePaths(t *testing.T) {
	if portalLoginPath != portal.LoginPath || portalCallbackPath != portal.CallbackPath || portalHomePath != portal.Home ||
		portal.CallbackPath != config.ConsentCallbackPath {
		t.Fatal("the portal mux patterns drifted from the portal package's paths")
	}
}

func TestPortalHomeStub(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	rec := r.serve(http.MethodGet, "/portal?login_error=blocked")
	body := rec.Body.String()
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(body, `href="/portal/login"`) ||
		!strings.Contains(body, "blocked from the portal") {
		t.Fatalf("signed-out stub = %s %q", rec.Header().Get("Cache-Control"), body)
	}
	// An unknown login_error is never echoed.
	if rec := r.serve(http.MethodGet, "/portal?login_error=%3Cscript%3E"); strings.Contains(rec.Body.String(), "script") {
		t.Fatal("the stub echoed login_error")
	}
	r.idp.SetLogin(fakes.Valid("pat", "<pat>@example.com"))
	c := r.login("")
	body = r.serve(http.MethodGet, "/portal", c).Body.String()
	if !strings.Contains(body, "&lt;pat&gt;@example.com") || strings.Contains(body, "<pat>") ||
		!strings.Contains(body, `value="`+webauth.CSRFToken([]byte(c.Value), portal.CSRFLabel)+`"`) {
		t.Fatalf("signed-in stub = %q", body)
	}
	if rec := r.serve(http.MethodPost, "/portal", c); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /portal = %d", rec.Code)
	}
}

func TestPortalLoginAudited(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	rec := &fakeRecorder{}
	r.srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	r.h = r.srv.Handler()
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	c := r.login("")
	// The IdP link (on by default) adds its own row (W-P3-CSIG-03).
	linked := rowsByAction(rec, actionIdPLinked)
	logins := rowsByAction(rec, actionPortalLogin)
	if len(linked) != 1 || len(logins) != 1 {
		t.Fatalf("rows: %d %s, %d %s, want one each", len(linked), actionIdPLinked, len(logins), actionPortalLogin)
	}
	row := logins[0]
	if row.Action != actionPortalLogin || row.Target != targetPortalSession || row.Outcome != adminaudit.OutcomeOK ||
		row.Actor != (adminaudit.Actor{Sub: "pat", Email: "pat@example.com"}) || row.TargetRef != shortHash(webauth.HashID(c.Value)) {
		t.Fatalf("login row = %+v", row)
	}
	blockAdd(t, r.srv, BlockEntry{Sub: "pat"})
	wantRedirect(t, r.finish(r.start("")), "/portal?login_error=blocked")
	rows := rowsByAction(rec, actionPortalLoginFailed)
	if len(rows) != 1 || rows[0].Outcome != adminaudit.OutcomeDenied || rows[0].Details[detailReason] != portal.CodeBlocked {
		t.Fatalf("failed rows = %+v", rows)
	}
}

// TestRestoreClearsPortalSessions: a restored state DB keeps no portal (or
// console) session and no pending login, so cookies issued before the backup
// stop working.
func TestRestoreClearsPortalSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db, err := cpstate.Open(context.Background(), path, StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now
	if _, _, err := NewPortalSessionStore(db.SQL(), time.Hour, 8*time.Hour, now).Create(context.Background(), webauth.SessionInput{Iss: "i", Sub: "s"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewSessionStore(db.SQL(), time.Hour, 8*time.Hour, now).Create(context.Background(), SessionInput{Iss: "i", Sub: "s", AuthMethod: "oidc"}); err != nil {
		t.Fatal(err)
	}
	if err := webauth.NewPendingStore(db.SQL(), now).Put(context.Background(), webauth.Pending{StateHash: "h", Purpose: webauth.PurposePortal, Nonce: "n", Verifier: "v", Next: "/portal", BrowserHash: "b"}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := prepareRestoredState(context.Background(), path, false, nil); err != nil {
		t.Fatal(err)
	}
	db, err = cpstate.Open(context.Background(), path, StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, tbl := range []string{"portal_sessions", "sessions", "oidc_pending"} {
		var n int
		if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s after restore = %d rows (%v), want 0", tbl, n, err)
		}
	}
}

// TestPortalBlockListUnloaded: while no block list has loaded the portal
// cannot tell who is blocked, so login, callback and existing sessions all
// fail closed.
func TestPortalBlockListUnloaded(t *testing.T) {
	links := &fakeLinkWriter{}
	r := newPortalRig(t, portalRigOpts{links: links})
	r.ready()
	c := r.login("")
	links.links = nil
	f := r.start("") // state stored while the list was loaded
	r.srv.blocks.snap.Store(nil)

	if rec := r.serve(http.MethodGet, "/portal/login"); rec.Code != http.StatusServiceUnavailable || errBody(t, rec) != loginBlockUnavailable {
		t.Fatalf("/portal/login = %d %s, want 503 block_list_unavailable", rec.Code, rec.Body)
	}
	res := r.finish(f)
	if res.Code != http.StatusServiceUnavailable || errBody(t, res) != loginBlockUnavailable {
		t.Fatalf("callback = %d %s, want 503 block_list_unavailable", res.Code, res.Body)
	}
	if cookieNamed(res, portalCookie) != nil || r.count("portal_sessions") != 1 || len(links.links) != 0 {
		t.Fatalf("an unloaded block list let a login write (rows %d, links %d)", r.count("portal_sessions"), len(links.links))
	}
	if r.count("oidc_pending") != 0 {
		t.Fatal("the callback did not consume its state")
	}
	if r.signedIn(c, fakes.DefaultLoginSub+"@example.com") {
		t.Fatal("an existing session authenticates while no block list has loaded")
	}
}

// TestPortalSessionStoreFailure: a failed portal_sessions insert is 503
// session_store_unavailable, not a login_error redirect.
func TestPortalSessionStoreFailure(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	f := r.start("")
	if _, err := r.db.SQL().Exec(`DROP TABLE portal_sessions`); err != nil {
		t.Fatal(err)
	}
	res := r.finish(f)
	if res.Code != http.StatusServiceUnavailable || errBody(t, res) != portalSessionStoreUnavailable || cookieNamed(res, portalCookie) != nil {
		t.Fatalf("callback = %d %s, want 503 session_store_unavailable and no cookie", res.Code, res.Body)
	}
	if !strings.Contains(r.logs.String(), `"reason":"session_store_failed"`) {
		t.Fatal("no session_store_failed log line")
	}
}

// tokenEchoErr is a store error that (wrongly) carries what it was given.
type tokenEchoErr struct{ tok string }

func (e tokenEchoErr) Error() string { return "put failed for " + e.tok }

// TestPortalLinkErrorNotLogged: a LinkWriter error is logged by type only.
func TestPortalLinkErrorNotLogged(t *testing.T) {
	links := &fakeLinkWriter{err: tokenEchoErr{tok: portalRefreshToken}}
	r := newPortalRig(t, portalRigOpts{links: links})
	r.ready()
	if res := r.finish(r.start("")); res.Code != http.StatusServiceUnavailable {
		t.Fatalf("callback = %d, want 503", res.Code)
	}
	logs := r.logs.String()
	if strings.Contains(logs, portalRefreshToken) {
		t.Fatal("the logs hold the refresh token from the link error")
	}
	if !strings.Contains(logs, `"reason":"idp_link_row_failed"`) {
		t.Fatalf("link failure not logged by its classified reason:\n%s", logs)
	}
}

// TestPortalLoginFailedOwnBudget: portal.login_failed rows have their own
// per-address limit, so a portal flood leaves the console's budget intact.
func TestPortalLoginFailedOwnBudget(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	rec := &fakeRecorder{}
	r.srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	req := httptest.NewRequest(http.MethodGet, "/portal/callback", nil)
	for range loginFailedPerMinute + 5 {
		r.srv.recordPortalLogin(req, portalLoginResult{reason: portal.CodeBlocked, consumed: true, status: http.StatusFound})
	}
	if n := len(rowsByAction(rec, actionPortalLoginFailed)); n != loginFailedPerMinute {
		t.Fatalf("portal.login_failed rows = %d, want the cap %d", n, loginFailedPerMinute)
	}
	if n := r.srv.audit.portalLoginFailedDropped.Load(); n != 5 {
		t.Fatalf("portal dropped = %d, want 5", n)
	}
	r.srv.recordLogin(req, loginResult{reason: loginNoRole, consumed: true})
	if n := len(rowsByAction(rec, actionLoginFailed)); n != 1 || r.srv.audit.loginFailedDropped.Load() != 0 {
		t.Fatalf("console auth.login_failed rows = %d after a portal flood, want 1", n)
	}
}
