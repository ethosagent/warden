package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// testConsoleRoles maps one group onto each role.
var testConsoleRoles = config.ConsoleRoles{
	Admin: []string{"warden-admins"}, Editor: []string{"warden-editors"}, Viewer: []string{"warden-viewers"},
}

// newOIDCServer builds a control plane in console.auth oidc with a state DB, so
// sessions and the /auth routes are on. issuer may be empty.
func newOIDCServer(t *testing.T, issuer string) (*Server, http.Handler) {
	t.Helper()
	cc := config.ConsoleConfig{
		Auth:    config.ConsoleAuthOIDC,
		OIDC:    config.ConsoleOIDC{Issuer: issuer, RedirectURL: testRedirectHTTPS},
		Roles:   testConsoleRoles,
		Session: config.ConsoleSession{Idle: time.Hour, Absolute: 12 * time.Hour},
	}
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: openSessionDB(t), Console: cc})
	if srv.sessions == nil {
		t.Fatal("oidc mode with a state db must enable sessions")
	}
	return srv, srv.Handler()
}

// login stands in for /auth/login (W-P1-SSO-03): it mints a session directly.
func login(t *testing.T, srv *Server, groups ...string) (string, Session) {
	t.Helper()
	in := testSessionInput()
	in.Groups = groups
	raw, sess, err := srv.sessions.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return raw, sess
}

// authReq sends method path with the session cookie (when raw is set) and the
// CSRF header (when csrf is set).
func authReq(h http.Handler, srv *Server, method, path, raw, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if raw != "" {
		req.AddCookie(&http.Cookie{Name: srv.sessionCookie.Name, Value: raw})
	}
	if csrf != "" {
		req.Header.Set(CSRFHeader, csrf)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthMe(t *testing.T) {
	srv, h := newOIDCServer(t, "")
	for _, tc := range []struct{ group, role string }{
		{"warden-viewers", "viewer"}, {"warden-editors", "editor"}, {"warden-admins", "admin"},
	} {
		t.Run(tc.role, func(t *testing.T) {
			raw, sess := login(t, srv, tc.group)
			rec := authReq(h, srv, http.MethodGet, "/auth/me", raw, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /auth/me: %d %s", rec.Code, rec.Body.String())
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q", ct)
			}
			var got map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v (%s)", err, rec.Body.String())
			}
			want := map[string]string{
				"sub": "u1", "email": "u1@example.com", "role": tc.role, "authMethod": "oidc",
				"csrf": CSRFToken(raw), "expiresAt": sess.ExpiresAt.UTC().Format(time.RFC3339),
			}
			if len(got) != len(want) {
				t.Errorf("fields = %v, want exactly %v", got, want)
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			if strings.Contains(rec.Body.String(), raw) {
				t.Error("response leaks the raw session id")
			}
		})
	}
	t.Run("no role", func(t *testing.T) {
		raw, _ := login(t, srv, "someone-else")
		rec := authReq(h, srv, http.MethodGet, "/auth/me", raw, "")
		var got map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusOK || got["role"] != "none" {
			t.Fatalf("unmapped groups: %d role=%q, want 200 none", rec.Code, got["role"])
		}
	})
	t.Run("no session", func(t *testing.T) {
		for _, raw := range []string{"", "not-a-session"} {
			rec := authReq(h, srv, http.MethodGet, "/auth/me", raw, "")
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("cookie %q: %d, want 401", raw, rec.Code)
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("401 Cache-Control = %q, want no-store", cc)
			}
		}
	})
	t.Run("expired session", func(t *testing.T) {
		clk := newFakeClock()
		srv.sessions.now = clk.Now
		t.Cleanup(func() { srv.sessions.now = time.Now })
		raw, _ := login(t, srv, "warden-admins")
		clk.Advance(2 * time.Hour)
		if rec := authReq(h, srv, http.MethodGet, "/auth/me", raw, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("idle-expired session: %d, want 401", rec.Code)
		}
	})
	t.Run("method", func(t *testing.T) {
		raw, _ := login(t, srv, "warden-admins")
		rec := authReq(h, srv, http.MethodPost, "/auth/me", raw, CSRFToken(raw))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST /auth/me: %d, want 405", rec.Code)
		}
	})
	t.Run("none mode", func(t *testing.T) {
		none := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken}).Handler()
		for _, p := range []string{"/auth/me", "/auth/logout"} {
			for _, m := range []string{http.MethodGet, http.MethodPost} {
				req := httptest.NewRequest(m, p, nil)
				req.Header.Set("Authorization", "Bearer "+dashTestToken) // the shared token opens nothing here
				rec := httptest.NewRecorder()
				none.ServeHTTP(rec, req)
				if rec.Code != http.StatusNotFound {
					t.Errorf("none mode %s %s: %d, want 404", m, p, rec.Code)
				}
			}
		}
	})
	t.Run("oidc without state db", func(t *testing.T) {
		cc := config.ConsoleConfig{Auth: config.ConsoleAuthOIDC, OIDC: config.ConsoleOIDC{RedirectURL: testRedirectHTTPS}}
		nostate := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, Console: cc}).Handler()
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			p := map[string]string{http.MethodGet: "/auth/me", http.MethodPost: "/auth/logout"}[m]
			rec := httptest.NewRecorder()
			nostate.ServeHTTP(rec, httptest.NewRequest(m, p, nil))
			// Not 404: the UI must not fall back to the bearer prompt in oidc mode.
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s %s with sessions off: %d, want 503", m, p, rec.Code)
			}
		}
	})
}

func TestLogout(t *testing.T) {
	srv, h := newOIDCServer(t, "")
	raw, _ := login(t, srv, "warden-editors")

	// Without CSRF: 403 from the session middleware, and the session lives on.
	for _, csrf := range []string{"", "deadbeef", CSRFToken(raw + "x")} {
		rec := authReq(h, srv, http.MethodPost, "/auth/logout", raw, csrf)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("logout with csrf %q: %d, want 403", csrf, rec.Code)
		}
		if sc := rec.Header().Get("Set-Cookie"); sc != "" {
			t.Fatalf("refused logout set a cookie: %q", sc)
		}
	}
	if rec := authReq(h, srv, http.MethodGet, "/auth/me", raw, ""); rec.Code != http.StatusOK {
		t.Fatalf("session after refused logout: %d, want 200", rec.Code)
	}

	// Wrong method.
	if rec := authReq(h, srv, http.MethodGet, "/auth/logout", raw, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /auth/logout: %d, want 405", rec.Code)
	}

	// With CSRF: 204, the cookie is cleared and the old cookie no longer works.
	rec := authReq(h, srv, http.MethodPost, "/auth/logout", raw, CSRFToken(raw))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s, want 204", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("logout Cache-Control = %q, want no-store", cc)
	}
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != srv.sessionCookie.Name || cleared[0].MaxAge >= 0 || cleared[0].Value != "" {
		t.Fatalf("logout cookies = %+v, want one clearing %s", cleared, srv.sessionCookie.Name)
	}
	if rec := authReq(h, srv, http.MethodGet, "/auth/me", raw, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old cookie after logout: %d, want 401", rec.Code)
	}
	if _, ok, _ := srv.sessions.Lookup(context.Background(), raw); ok {
		t.Fatal("session row survived logout")
	}

	// Logout with no live session is idempotent: 204 and a clearing cookie.
	for _, c := range []string{"", raw} {
		rec := authReq(h, srv, http.MethodPost, "/auth/logout", c, "")
		if rec.Code != http.StatusNoContent || len(rec.Result().Cookies()) != 1 {
			t.Errorf("logout without a live session (cookie %t): %d %v", c != "", rec.Code, rec.Result().Cookies())
		}
	}

	// Another user's session is untouched by this logout.
	other, _ := login(t, srv, "warden-admins")
	mine, _ := login(t, srv, "warden-admins")
	if rec := authReq(h, srv, http.MethodPost, "/auth/logout", mine, CSRFToken(mine)); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := authReq(h, srv, http.MethodGet, "/auth/me", other, ""); rec.Code != http.StatusOK {
		t.Fatalf("other session after a logout: %d, want 200", rec.Code)
	}
}

// fakeIdP is an IdP that counts every request and remembers the browsers it
// has signed in (its own session cookie). Its /authorize answers with a code
// when the browser has an IdP session and with a password prompt otherwise.
type fakeIdP struct {
	srv      *httptest.Server
	requests atomic.Int64
	mu       sync.Mutex
	sessions map[string]bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{sessions: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.URL.Path != "/authorize" {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if c, err := r.Cookie("idp_session"); err == nil && f.sessions[c.Value] {
			_, _ = w.Write([]byte("code"))
			return
		}
		_, _ = w.Write([]byte("password prompt"))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// signIn records an IdP session for the browser whose IdP cookie is id.
func (f *fakeIdP) signIn(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[id] = true
}

// authorize is what a later /auth/login does at the IdP.
func (f *fakeIdP) authorize(t *testing.T, idpCookie string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/authorize", nil)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: idpCookie})
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLogoutIsLocal(t *testing.T) {
	idp := newFakeIdP(t)
	srv, h := newOIDCServer(t, idp.srv.URL)
	idp.signIn("browser-1")
	raw, _ := login(t, srv, "warden-admins")
	before := idp.requests.Load()

	rec := authReq(h, srv, http.MethodPost, "/auth/logout", raw, CSRFToken(raw))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if n := idp.requests.Load() - before; n != 0 {
		t.Fatalf("logout made %d requests to the IdP, want 0", n)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("logout Location = %q, want none (no RP-initiated logout)", loc)
	}
	for k, vs := range rec.Header() {
		for _, v := range vs {
			if strings.Contains(v, "id_token_hint") {
				t.Fatalf("header %s carries id_token_hint", k)
			}
		}
	}
	if strings.Contains(rec.Body.String(), "id_token_hint") {
		t.Fatal("body carries id_token_hint")
	}
	// The IdP-side session is untouched: the next sign-in completes without a
	// password prompt.
	if got := idp.authorize(t, "browser-1"); got != "code" {
		t.Fatalf("IdP after Warden logout answered %q, want a code without a prompt", got)
	}
}

// TestAuthRoutesStoreErrors: a store failure after the middleware resolved the
// session answers a fixed 500 and, for logout, keeps the cookie.
func TestAuthRoutesStoreErrors(t *testing.T) {
	srv, h := newOIDCServer(t, "")
	raw, _ := login(t, srv, "warden-admins")
	// The middleware keeps the working reader; the handlers see a broken store.
	broken := openSessionDB(t)
	_ = broken.Close()
	srv.sessions = NewSessionStore(broken.SQL(), time.Hour, 12*time.Hour, nil)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/auth/me"}, {http.MethodPost, "/auth/logout"},
	} {
		rec := authReq(h, srv, tc.method, tc.path, raw, CSRFToken(raw))
		if rec.Code != http.StatusInternalServerError || strings.TrimSpace(rec.Body.String()) != `{"error":"session store error"}` {
			t.Errorf("%s %s: %d %q, want 500 session store error", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s %s set a cookie on failure", tc.method, tc.path)
		}
	}
}
