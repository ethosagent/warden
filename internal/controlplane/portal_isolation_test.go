package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/internal/webauth"
	"github.com/ethosagent/warden/test/fakes"
)

// Console isolation (W-P3-CSIG-04): a portal session opens no console or
// /central route, and no console credential opens a portal route.

var templateSegment = regexp.MustCompile(`\{[^}]+\}`)

// concretePath turns a route template or subtree pattern into a request path.
func concretePath(p string) string {
	p = templateSegment.ReplaceAllString(p, "x")
	if strings.HasSuffix(p, "/") {
		p += "x"
	}
	return p
}

// consoleSession creates a console session for sub in group and returns its
// cookie.
func (r *portalRig) consoleSession(sub, group string) *http.Cookie {
	r.t.Helper()
	raw, _, err := r.srv.sessions.Create(context.Background(), SessionInput{
		Iss: r.idp.Issuer(), Sub: sub, Email: sub + "@example.com", Groups: []string{group}, AuthMethod: "oidc",
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return &http.Cookie{Name: r.srv.sessionCookie.Name, Value: raw}
}

func TestPortalConsoleIsolation(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{secretStore: secrets.NewEchoStore(), token: dashTestToken, allRoutes: true})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com", "admins"))
	pc := r.login("")
	// The portal session is live: the isolation below is not an expired cookie.
	decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", pc))

	t.Run("portal cookie opens no console route", func(t *testing.T) {
		// Every /dashboard/api/* route of the authz table and every /central/*
		// and /auth/me route of the control plane's own table, with the portal
		// cookie, the portal's CSRF token and the portal's Origin.
		type route struct{ method, path string }
		var routes []route
		for k := range authzTable() {
			if strings.HasPrefix(k.Path, "/dashboard/api/") {
				routes = append(routes, route{k.Method, k.Path})
			}
		}
		for k := range cpRouteTable() {
			if strings.HasPrefix(k.Path, "/central/") || k.Path == "/auth/me" {
				routes = append(routes, route{k.Method, k.Path})
			}
		}
		sort.Slice(routes, func(i, j int) bool { return routes[i].path+routes[i].method < routes[j].path+routes[j].method })
		if len(routes) < 50 {
			t.Fatalf("walked only %d routes; the tables look wrong", len(routes))
		}
		hdr := map[string]string{CSRFHeader: portalCSRF(pc), "Origin": portalOrigin, "Content-Type": "application/json"}
		for _, rt := range routes {
			path := concretePath(rt.path)
			// The same portal session id pasted into the console cookie name is
			// no console session either.
			pasted := &http.Cookie{Name: r.srv.sessionCookie.Name, Value: pc.Value}
			for name, c := range map[string]*http.Cookie{"portal cookie": pc, "portal id as console cookie": pasted} {
				rec := r.portalReq(rt.method, path, "{}", hdr, c)
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("%s %s with the %s = %d %s, want 401", rt.method, path, name, rec.Code, strings.TrimSpace(rec.Body.String()))
				}
			}
		}
	})

	t.Run("no console credential opens a portal route", func(t *testing.T) {
		admin := r.consoleSession("admin", "admins")
		// The console session is live: it opens the console.
		if rec := r.serve(http.MethodGet, "/dashboard/api/policy", admin); rec.Code != http.StatusOK {
			t.Fatalf("console admin GET /dashboard/api/policy = %d", rec.Code)
		}
		consoleCSRF := webauth.CSRFToken([]byte(admin.Value), csrfLabel)
		cases := map[string]struct {
			hdr     map[string]string
			cookies []*http.Cookie
		}{
			"console admin session":       {cookies: []*http.Cookie{admin}},
			"console id as portal cookie": {cookies: []*http.Cookie{{Name: portalCookie, Value: admin.Value}}},
			"WARDEN_CP_TOKEN bearer":      {hdr: map[string]string{"Authorization": "Bearer " + dashTestToken}},
			"worker token bearer":         {hdr: map[string]string{"Authorization": "Bearer wtk_" + strings.Repeat("a", 40)}},
			"wak_ API key":                {hdr: map[string]string{"Authorization": "Bearer wak_" + strings.Repeat("b", 40)}},
			"portal id as console cookie": {cookies: []*http.Cookie{{Name: r.srv.sessionCookie.Name, Value: pc.Value}}},
		}
		for name, tc := range cases {
			if rec := r.portalReq(http.MethodGet, "/portal/api/me", "", tc.hdr, tc.cookies...); rec.Code != http.StatusUnauthorized {
				t.Errorf("GET /portal/api/me with %s = %d, want 401", name, rec.Code)
			}
			hdr := map[string]string{CSRFHeader: consoleCSRF}
			for k, v := range tc.hdr {
				hdr[k] = v
			}
			if rec := r.portalReq(http.MethodPost, "/portal/logout", "", hdr, tc.cookies...); rec.Code != http.StatusUnauthorized {
				t.Errorf("POST /portal/logout with %s = %d, want 401", name, rec.Code)
			}
			// A browser page load is sent to the portal sign-in, not let in.
			if rec := r.portalReq(http.MethodGet, "/portal/connect/abc", "", tc.hdr, tc.cookies...); rec.Code != http.StatusFound {
				t.Errorf("GET /portal/connect/abc with %s = %d, want 302 to sign-in", name, rec.Code)
			}
		}
		// The stub page sees no portal user for a console session.
		if body := r.serve(http.MethodGet, "/portal", admin).Body.String(); strings.Contains(body, "Signed in as") {
			t.Fatal("the portal stub accepted a console session")
		}
	})
}

// countingPortalStore counts every call the portal middleware makes.
type countingPortalStore struct {
	portalSessionBackend
	mu    sync.Mutex
	calls int
}

func (c *countingPortalStore) hit() { c.mu.Lock(); c.calls++; c.mu.Unlock() }
func (c *countingPortalStore) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}
func (c *countingPortalStore) Lookup(ctx context.Context, raw string) (webauth.Session, bool, error) {
	c.hit()
	return c.portalSessionBackend.Lookup(ctx, raw)
}
func (c *countingPortalStore) Touch(ctx context.Context, raw string) (bool, error) {
	c.hit()
	return c.portalSessionBackend.Touch(ctx, raw)
}
func (c *countingPortalStore) Delete(ctx context.Context, raw string) error {
	c.hit()
	return c.portalSessionBackend.Delete(ctx, raw)
}
func (c *countingPortalStore) DeleteBySub(ctx context.Context, sub string) (int, error) {
	c.hit()
	return c.portalSessionBackend.DeleteBySub(ctx, sub)
}
func (c *countingPortalStore) DeleteByEmail(ctx context.Context, email string) (int, error) {
	c.hit()
	return c.portalSessionBackend.DeleteByEmail(ctx, email)
}
func (c *countingPortalStore) Now() time.Time { c.hit(); return c.portalSessionBackend.Now() }

func TestPortalNotOnWorkerRoutes(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{token: dashTestToken})
	r.ready()
	pc := r.login("")
	fake := &countingPortalStore{portalSessionBackend: r.srv.portal.store}
	r.srv.portal.store = fake
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/policy"},
		{http.MethodPost, "/control/heartbeat"},
		{http.MethodPost, "/central/ingest"},
		{http.MethodGet, "/healthz"},
		{http.MethodGet, "/readyz"},
	} {
		req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(`{}`))
		req.AddCookie(pc)
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		r.h.ServeHTTP(httptest.NewRecorder(), req)
		if n := fake.count(); n != 0 {
			t.Fatalf("%s %s with a portal cookie called the portal store %d times", rt.method, rt.path, n)
		}
	}
	// The console routes never read it either.
	r.serve(http.MethodGet, "/dashboard/api/policy", pc)
	r.serve(http.MethodGet, "/auth/me", pc)
	if n := fake.count(); n != 0 {
		t.Fatalf("a console route called the portal store %d times", n)
	}
	decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", pc))
	if fake.count() == 0 {
		t.Fatal("a portal request must reach the portal store")
	}
}

func TestPortalSessionRevocation(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()

	t.Run("blocking the sub ends the session at once", func(t *testing.T) {
		r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
		c := r.login("")
		decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", c))
		blockAdd(t, r.srv, BlockEntry{Sub: "pat"})
		var n int
		if err := r.db.SQL().QueryRow(`SELECT COUNT(*) FROM portal_sessions WHERE sub = 'pat'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("pat's portal sessions after the block = %d (%v), want 0", n, err)
		}
		if rec := r.serve(http.MethodGet, "/portal/api/me", c); rec.Code != http.StatusUnauthorized {
			t.Fatalf("me after the block = %d, want 401", rec.Code)
		}
		if !strings.Contains(r.logs.String(), `"msg":"portal_session_revoked","by_sub":"oidc:admin","target_sub":"pat","count":1`) {
			t.Fatal("no portal_session_revoked line for the block")
		}
	})

	t.Run("blocking the email ends the session", func(t *testing.T) {
		r.idp.SetLogin(fakes.Valid("quinn", "quinn@example.com"))
		c := r.login("")
		blockAdd(t, r.srv, BlockEntry{Email: "Quinn@Example.com"})
		if rec := r.serve(http.MethodGet, "/portal/api/me", c); rec.Code != http.StatusUnauthorized {
			t.Fatalf("me after the email block = %d, want 401", rec.Code)
		}
	})

	t.Run("admin revoke by sub and by handle", func(t *testing.T) {
		r.idp.SetLogin(fakes.Valid("sam", "sam@example.com"))
		sam := r.login("")
		r.idp.SetLogin(fakes.Valid("lee", "lee@example.com"))
		lee := r.login("")
		admin := r.consoleSession("root", "admins")
		viewer := r.consoleSession("vic", "staff")
		ccsrf := func(c *http.Cookie) map[string]string {
			return map[string]string{CSRFHeader: webauth.CSRFToken([]byte(c.Value), csrfLabel)}
		}

		// Admin only, for both GET and DELETE.
		if rec := r.serve(http.MethodGet, sessionsPath+"?kind=portal", viewer); rec.Code != http.StatusForbidden {
			t.Fatalf("viewer list portal sessions = %d, want 403", rec.Code)
		}
		if rec := r.portalReq(http.MethodDelete, sessionsPath+"?kind=portal&sub=sam", "", ccsrf(viewer), viewer); rec.Code != http.StatusForbidden {
			t.Fatalf("viewer revoke portal sessions = %d, want 403", rec.Code)
		}
		if rec := r.serve(http.MethodGet, sessionsPath+"?kind=portal", sam); rec.Code != http.StatusUnauthorized {
			t.Fatalf("a portal session listing sessions = %d, want 401", rec.Code)
		}
		if rec := r.serve(http.MethodGet, sessionsPath+"?kind=bogus", admin); rec.Code != http.StatusBadRequest {
			t.Fatalf("kind=bogus = %d, want 400", rec.Code)
		}

		rec := r.serve(http.MethodGet, sessionsPath+"?kind=portal", admin)
		if rec.Code != http.StatusOK {
			t.Fatalf("admin list = %d %s", rec.Code, rec.Body)
		}
		body := rec.Body.String()
		if strings.Contains(body, sam.Value) || strings.Contains(body, lee.Value) || strings.Contains(body, portalCSRF(sam)) {
			t.Fatal("the portal session list leaks a session id or CSRF token")
		}
		var rows []sessionView
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		bySub := map[string]sessionView{}
		for _, v := range rows {
			bySub[v.Sub] = v
		}
		if v := bySub["sam"]; v.Kind != sessionKindPortal || v.Handle != webauth.HashID(sam.Value) || v.Email != "sam@example.com" || v.Iss != r.idp.Issuer() {
			t.Fatalf("sam's row = %+v", v)
		}
		if _, ok := bySub["root"]; ok {
			t.Fatal("kind=portal listed a console session")
		}
		// The default kind still lists console sessions only.
		if out, _ := listSessionsVia(t, r, admin, ""); len(out) == 0 || out["sam"] {
			t.Fatalf("console list = %v", out)
		}

		rec = r.portalReq(http.MethodDelete, sessionsPath+"?kind=portal&sub=sam", "", ccsrf(admin), admin)
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"revoked":1}` {
			t.Fatalf("revoke sam = %d %s", rec.Code, rec.Body)
		}
		if rec := r.serve(http.MethodGet, "/portal/api/me", sam); rec.Code != http.StatusUnauthorized {
			t.Fatalf("sam after revoke = %d, want 401", rec.Code)
		}
		decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", lee))
		// The console admin session is untouched by a portal revoke.
		if rec := r.serve(http.MethodGet, "/dashboard/api/policy", admin); rec.Code != http.StatusOK {
			t.Fatal("a portal revoke ended a console session")
		}

		h := webauth.HashID(lee.Value)
		if rec := r.portalReq(http.MethodDelete, sessionsPath+"?kind=portal&handle="+h, "", ccsrf(admin), admin); rec.Code != http.StatusOK {
			t.Fatalf("revoke lee by handle = %d %s", rec.Code, rec.Body)
		}
		if rec := r.serve(http.MethodGet, "/portal/api/me", lee); rec.Code != http.StatusUnauthorized {
			t.Fatalf("lee after revoke = %d, want 401", rec.Code)
		}
		if rec := r.portalReq(http.MethodDelete, sessionsPath+"?kind=portal&handle="+h, "", ccsrf(admin), admin); rec.Code != http.StatusNotFound {
			t.Fatalf("second revoke = %d, want 404", rec.Code)
		}
		if rec := r.portalReq(http.MethodDelete, sessionsPath+"?kind=portal&sub=sam", "", nil, admin); rec.Code != http.StatusForbidden {
			t.Fatalf("revoke without console csrf = %d, want 403", rec.Code)
		}
		logs := r.logs.String()
		if !strings.Contains(logs, `"msg":"portal_session_revoked","by_sub":"root","target_sub":"sam","count":1`) ||
			strings.Contains(logs, sam.Value) || strings.Contains(logs, lee.Value) {
			t.Fatal("portal_session_revoked line missing or holds a session id")
		}
	})
}

// listSessionsVia lists ?kind=<kind> sessions and returns the set of subs.
func listSessionsVia(t *testing.T, r *portalRig, c *http.Cookie, kind string) (map[string]bool, string) {
	t.Helper()
	target := sessionsPath
	if kind != "" {
		target += "?kind=" + kind
	}
	rec := r.serve(http.MethodGet, target, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", target, rec.Code)
	}
	var rows []sessionView
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, v := range rows {
		out[v.Sub] = true
	}
	return out, rec.Body.String()
}
