package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/internal/webauth"
	"github.com/ethosagent/warden/test/fakes"
)

// The portal session middleware, CSRF, me and logout (W-P3-CSIG-04).

const portalOrigin = "https://cp.example"

// portalReq sends one request with the given cookies, headers and body.
func (r *portalRig) portalReq(method, target, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

func portalCSRF(c *http.Cookie) string { return webauth.CSRFToken([]byte(c.Value), portal.CSRFLabel) }

// probeBehind serves requireSession around a handler that answers 200 with
// the Principal's sub, and records the urlencoded form it saw.
func (r *portalRig) probeBehind() http.Handler {
	return r.srv.portal.requireSession(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p, ok := portal.PrincipalFrom(req.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		if _, ok := PrincipalFrom(req.Context()); ok {
			http.Error(w, "a console principal reached a portal handler", http.StatusInternalServerError)
			return
		}
		// No console credential reaches a portal handler.
		if req.Header.Get("Authorization") != "" {
			http.Error(w, "the Authorization header reached a portal handler", http.StatusInternalServerError)
			return
		}
		if _, err := req.Cookie(r.srv.sessionCookie.Name); err == nil {
			http.Error(w, "the console cookie reached a portal handler", http.StatusInternalServerError)
			return
		}
		if _, err := req.Cookie(portalCookie); err != nil {
			http.Error(w, "the portal cookie was dropped", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, p.Sub+"|"+req.PostFormValue("provider"))
	}))
}

func TestPortalCSRF(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	c := r.login("")
	h := r.probeBehind()
	tok := portalCSRF(c)
	form := "application/x-www-form-urlencoded"
	do := func(method, body string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/connect/start", strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for name, tc := range map[string]struct {
		body string
		hdr  map[string]string
	}{
		"no token":               {hdr: map[string]string{"Content-Type": "application/json"}},
		"wrong token":            {hdr: map[string]string{CSRFHeader: strings.Repeat("0", 64)}},
		"console-derived token":  {hdr: map[string]string{CSRFHeader: webauth.CSRFToken([]byte(c.Value), csrfLabel)}},
		"foreign origin":         {hdr: map[string]string{CSRFHeader: tok, "Origin": "https://evil.example"}},
		"foreign origin on form": {body: "csrf=" + tok, hdr: map[string]string{"Content-Type": form, "Origin": "https://evil.example"}},
		"wrong form field":       {body: "csrf=nope", hdr: map[string]string{"Content-Type": form}},
		"form field on json":     {body: "csrf=" + tok, hdr: map[string]string{"Content-Type": "application/json"}},
		"form field in query":    {hdr: map[string]string{"Content-Type": form}},
	} {
		t.Run(name, func(t *testing.T) {
			method := http.MethodPost
			rec := do(method, tc.body, tc.hdr)
			if name == "form field in query" {
				req := httptest.NewRequest(method, "/connect/start?csrf="+tok, nil)
				req.Header.Set("Content-Type", form)
				req.AddCookie(c)
				rec = httptest.NewRecorder()
				h.ServeHTTP(rec, req)
			}
			if rec.Code != http.StatusForbidden || errBody(t, rec) != portal.CodeCSRF {
				t.Fatalf("= %d %s, want 403 csrf", rec.Code, rec.Body)
			}
		})
	}
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if rec := do(m, "", nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s without a token = %d, want 403", m, rec.Code)
		}
	}
	// The right token passes as the header (with or without the portal's own
	// Origin) and as the csrf field of a urlencoded post.
	if rec := do(http.MethodPost, "", map[string]string{CSRFHeader: tok}); rec.Code != http.StatusOK || rec.Body.String() != "pat|" {
		t.Fatalf("header token = %d %q", rec.Code, rec.Body)
	}
	if rec := do(http.MethodPost, "", map[string]string{CSRFHeader: tok, "Origin": portalOrigin}); rec.Code != http.StatusOK {
		t.Fatalf("header token + own origin = %d", rec.Code)
	}
	if rec := do(http.MethodPost, "csrf="+url.QueryEscape(tok)+"&provider=google", map[string]string{"Content-Type": form}); rec.Code != http.StatusOK || rec.Body.String() != "pat|google" {
		t.Fatalf("form token = %d %q, want 200 and the form still readable", rec.Code, rec.Body)
	}
	// A bearer and a console cookie sent alongside are stripped before the
	// handler runs (the probe fails on either); other cookies are kept.
	req := httptest.NewRequest(http.MethodPost, "/connect/start", nil)
	req.Header.Set(CSRFHeader, tok)
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	req.AddCookie(c)
	req.AddCookie(&http.Cookie{Name: r.srv.sessionCookie.Name, Value: "console-id"})
	req.AddCookie(&http.Cookie{Name: "__Host-warden_connect", Value: "keep"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("request with a bearer and a console cookie = %d %s", rec.Code, rec.Body)
	}
	if req.Header.Get("Authorization") == "" {
		t.Fatal("the caller's request was mutated")
	}
	// Safe methods need no token.
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if rec := do(m, "", map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", m, rec.Code)
		}
	}
	// A token for another portal session does not validate this one.
	r.idp.SetLogin(fakes.Valid("sam", "sam@example.com"))
	other := r.login("")
	if rec := do(http.MethodPost, "", map[string]string{CSRFHeader: portalCSRF(other)}); rec.Code != http.StatusForbidden {
		t.Fatalf("another session's token = %d, want 403", rec.Code)
	}
	// An oversized body is cut off by the cap, never parsed whole.
	big := "csrf=" + tok + "&x=" + strings.Repeat("a", portalMaxBody)
	if rec := do(http.MethodPost, big, map[string]string{"Content-Type": form}); rec.Code == http.StatusOK {
		t.Fatalf("an oversized form body passed: %d", rec.Code)
	}
	logs := r.logs.String()
	if !strings.Contains(logs, `"msg":"portal_csrf_denied"`) {
		t.Fatal("no portal_csrf_denied log line")
	}
	if strings.Contains(logs, tok) || strings.Contains(logs, c.Value) {
		t.Fatal("the logs hold the CSRF token or the session id")
	}
}

// fakeLinks is an IdP link store: StoreLink records, LinkStatus reports.
type fakeLinks struct {
	mu      sync.Mutex
	links   map[string]portal.Link
	due     time.Time
	readErr error
}

func (f *fakeLinks) StoreLink(_ context.Context, l portal.Link) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.links == nil {
		f.links = map[string]portal.Link{}
	}
	f.links[l.Iss+"\x00"+l.Sub] = l
	return nil
}

func (f *fakeLinks) LinkStatus(_ context.Context, iss, sub string) (portal.LinkStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return portal.LinkStatus{}, f.readErr
	}
	if _, ok := f.links[iss+"\x00"+sub]; !ok {
		return portal.LinkStatus{Status: portal.LinkMissing}, nil
	}
	return portal.LinkStatus{Status: portal.LinkLinked, RelinkDueAt: f.due}, nil
}

func (f *fakeLinks) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.links)
}

func decodeMe(t *testing.T, rec *httptest.ResponseRecorder) portalMe {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /portal/api/me = %d %s", rec.Code, rec.Body)
	}
	var me portalMe
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	return me
}

func TestPortalMe(t *testing.T) {
	due := time.Unix(1_900_000_000, 0).UTC()
	links := &fakeLinks{due: due}
	r := newPortalRig(t, portalRigOpts{links: links, linkStatus: links})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	c := r.login("")
	rec := r.serve(http.MethodGet, "/portal/api/me", c)
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("headers = %v", rec.Header())
	}
	me := decodeMe(t, rec)
	if me.Sub != "pat" || me.Email != "pat@example.com" || me.CSRF != portalCSRF(c) ||
		me.Link != (portalLink{Status: portal.LinkLinked, RelinkDueAt: due.Format(time.RFC3339)}) {
		t.Fatalf("me = %+v", me)
	}
	if exp, err := time.Parse(time.RFC3339, me.ExpiresAt); err != nil || exp.IsZero() {
		t.Fatalf("expiresAt = %q", me.ExpiresAt)
	}
	if strings.Contains(rec.Body.String(), c.Value) || strings.Contains(rec.Body.String(), portalRefreshToken) {
		t.Fatal("me leaks the session id or the refresh token")
	}
	links.readErr = errors.New("idp_links down")
	if me := decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", c)); me.Link != (portalLink{Status: portal.LinkUnknown}) {
		t.Fatalf("link on a read error = %+v, want unknown", me.Link)
	}
	// No reader wired: unknown; the IdP link off: disabled.
	r.srv.portal.linkStatus = nil
	if me := decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", c)); me.Link.Status != portal.LinkUnknown {
		t.Fatalf("link with no reader = %+v", me.Link)
	}
	r.srv.portal.cfg.IdPLink.Enabled = false
	if me := decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", c)); me.Link.Status != portal.LinkDisabled {
		t.Fatalf("link with idpLink off = %+v", me.Link)
	}
	if rec := r.portalReq(http.MethodPost, "/portal/api/me", "", map[string]string{CSRFHeader: portalCSRF(c)}, c); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST me = %d, want 405", rec.Code)
	}
	if rec := r.serve(http.MethodGet, "/portal/api/me"); rec.Code != http.StatusUnauthorized || errBody(t, rec) != portal.CodeUnauthenticated {
		t.Fatalf("signed-out me = %d %s, want 401", rec.Code, rec.Body)
	}
}

func TestPortalLogout(t *testing.T) {
	links := &fakeLinks{}
	r := newPortalRig(t, portalRigOpts{links: links, linkStatus: links})
	audit := &fakeRecorder{}
	r.srv.enableAdminAudit(audit, audit.probe, fakeMAC)
	r.h = r.srv.Handler()
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	c := r.login("")
	decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", c))

	// Without the CSRF token logout is refused and the session lives on.
	if rec := r.portalReq(http.MethodPost, "/portal/logout", "", nil, c); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without csrf = %d, want 403", rec.Code)
	}
	decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", c))
	if rec := r.serve(http.MethodGet, "/portal/logout", c); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout = %d, want 405", rec.Code)
	}

	rec := r.portalReq(http.MethodPost, "/portal/logout", "", map[string]string{CSRFHeader: portalCSRF(c), "Origin": portalOrigin}, c)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %s, want 204", rec.Code, rec.Body)
	}
	if cl := cookieNamed(rec, portalCookie); cl == nil || cl.MaxAge >= 0 || cl.Value != "" {
		t.Fatalf("logout did not clear the cookie: %+v", cl)
	}
	if rec := r.serve(http.MethodGet, "/portal/api/me", c); rec.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d, want 401", rec.Code)
	}
	if r.count("portal_sessions") != 0 {
		t.Fatal("the portal session row survived logout")
	}
	// The IdP link and its stored token stay: logout ends the session only.
	if links.count() != 1 || links.links[r.idp.Issuer()+"\x00pat"].RefreshToken != portalRefreshToken {
		t.Fatalf("logout touched the IdP link: %+v", links.links)
	}
	if st, _ := links.LinkStatus(context.Background(), r.idp.Issuer(), "pat"); st.Status != portal.LinkLinked {
		t.Fatalf("link status after logout = %+v", st)
	}
	if rows := rowsByAction(audit, actionPortalLogout); len(rows) != 1 || rows[0].Actor.Sub != "pat" ||
		rows[0].TargetRef != shortHash(webauth.HashID(c.Value)) || rows[0].Outcome != adminaudit.OutcomeOK {
		t.Fatalf("portal.logout rows = %+v", rows)
	}

	// The stub's sign-out form (csrf field) lands back on /portal.
	c = r.login("")
	rec = r.portalReq(http.MethodPost, "/portal/logout", "csrf="+portalCSRF(c), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, c)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != portal.Home || r.count("portal_sessions") != 0 {
		t.Fatalf("form logout = %d to %q (rows %d), want 303 to /portal and no row", rec.Code, rec.Header().Get("Location"), r.count("portal_sessions"))
	}
	if !strings.Contains(r.logs.String(), `"msg":"portal_logout"`) || strings.Contains(r.logs.String(), c.Value) {
		t.Fatal("no portal_logout line, or it holds the session id")
	}
}

func TestPortalRedirectToLogin(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	rec := r.serve(http.MethodGet, "/portal/connect/abc")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/portal/login?next=%2Fportal%2Fconnect%2Fabc" {
		t.Fatalf("signed-out GET = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := r.serve(http.MethodGet, "/portal/connect/abc?x=1"); rec.Header().Get("Location") != "/portal/login?next=%2Fportal%2Fconnect%2Fabc%3Fx%3D1" {
		t.Fatalf("query not kept in next: %q", rec.Header().Get("Location"))
	}
	// An escaped path round-trips as sent, not decoded.
	if rec := r.serve(http.MethodGet, "/portal/connect/a%2Fb"); rec.Header().Get("Location") != "/portal/login?next=%2Fportal%2Fconnect%2Fa%252Fb" {
		t.Fatalf("escaped path in next = %q", rec.Header().Get("Location"))
	}
	if rec := r.serve(http.MethodHead, "/portal/connect/abc"); rec.Code != http.StatusFound {
		t.Fatalf("signed-out HEAD = %d, want 302", rec.Code)
	}
	// API calls and writes get 401, never a redirect.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/portal/api/me"},
		{http.MethodGet, "/portal/api/connections"},
		{http.MethodPost, "/portal/logout"},
		{http.MethodPost, "/portal/connect/abc"},
	} {
		if rec := r.serve(tc.method, tc.path); rec.Code != http.StatusUnauthorized || errBody(t, rec) != portal.CodeUnauthenticated {
			t.Fatalf("signed-out %s %s = %d %s, want 401", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
	// The login follows next back to the page.
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	res := r.finish(r.start(loc.Query().Get("next")))
	wantRedirect(t, res, "/portal/connect/abc")
	c := cookieNamed(res, portalCookie)
	// Signed in, an unknown portal path is 404 (later tickets mount pages there).
	if rec := r.serve(http.MethodGet, "/portal/connect/abc", &http.Cookie{Name: c.Name, Value: c.Value}); rec.Code != http.StatusNotFound {
		t.Fatalf("signed-in unknown path = %d, want 404", rec.Code)
	}
	// An expired or unknown cookie is signed out.
	if rec := r.serve(http.MethodGet, "/portal/connect/abc", &http.Cookie{Name: portalCookie, Value: "forged"}); rec.Code != http.StatusFound {
		t.Fatalf("forged cookie = %d, want 302", rec.Code)
	}
}

// TestPortalBlockedSession: a session whose principal the snapshot names is
// refused 403 user_blocked and deleted, even when the Add-path revoke did not
// run (here it is unset), so the next request is 401.
func TestPortalBlockedSession(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	c := r.login("")
	r.srv.blocks.SetPortalSessionRevoker(nil)
	blockAdd(t, r.srv, BlockEntry{Email: "PAT@example.com"})
	if r.count("portal_sessions") != 1 {
		t.Fatal("the revoker was unset but the session went")
	}
	rec := r.serve(http.MethodGet, "/portal/api/me", c)
	if rec.Code != http.StatusForbidden || errBody(t, rec) != portal.CodeUserBlocked {
		t.Fatalf("blocked me = %d %s, want 403 user_blocked", rec.Code, rec.Body)
	}
	if r.count("portal_sessions") != 0 {
		t.Fatal("the blocked principal's portal session was not deleted")
	}
	if rec := r.serve(http.MethodGet, "/portal/api/me", c); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after the block = %d, want 401", rec.Code)
	}
	if !strings.Contains(r.logs.String(), `"msg":"portal_session_revoked","by_sub":"system:blocklist","target_sub":"pat","count":1`) {
		t.Fatalf("no portal_session_revoked line: %s", r.logs.String())
	}
}

// TestPortalMiddlewareFailsClosed: no loaded block list or a failing session
// store gives 503, never a session.
func TestPortalMiddlewareFailsClosed(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	c := r.login("")
	r.srv.blocks.snap.Store(nil)
	if rec := r.serve(http.MethodGet, "/portal/api/me", c); rec.Code != http.StatusServiceUnavailable || errBody(t, rec) != loginBlockUnavailable {
		t.Fatalf("me without a block list = %d %s, want 503 block_list_unavailable", rec.Code, rec.Body)
	}
	r.srv.blocks.refreshSnapshot(context.Background())
	decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", c))
	if _, err := r.db.SQL().Exec(`DROP TABLE portal_sessions`); err != nil {
		t.Fatal(err)
	}
	if rec := r.serve(http.MethodGet, "/portal/api/me", c); rec.Code != http.StatusServiceUnavailable || errBody(t, rec) != portalSessionUnavailable {
		t.Fatalf("me with a failing store = %d %s, want 503", rec.Code, rec.Body)
	}
}

func TestPortalSessionRoutesNotMounted(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{noConsent: true})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/portal/api/me"},
		{http.MethodPost, "/portal/logout"},
		{http.MethodGet, "/portal/connect/abc"},
		{http.MethodGet, "/portal/anything"},
	} {
		if rec := r.serve(tc.method, tc.path); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s with consent off = %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
	if portalMePath != portal.MePath || portalLogoutPath != portal.LogoutPath || !strings.HasPrefix(portal.MePath, portal.APIPrefix) {
		t.Fatal("the portal session mux patterns drifted from the portal package's paths")
	}
}

// TestPortalBlockWatchRevokes: a block another process writes (the offline
// CLI, through its own BlockStore) ends portal sessions when the watch sees it.
func TestPortalBlockWatchRevokes(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
	c := r.login("")
	other := NewBlockStore(r.db, BlockStoreOptions{})
	if _, err := other.Add(context.Background(), BlockEntry{Sub: "pat"}, "cli:test"); err != nil {
		t.Fatal(err)
	}
	r.srv.blocks.watchChanged(context.Background())
	if n := r.count("portal_sessions"); n != 0 {
		t.Fatalf("portal_sessions after the watched block = %d, want 0", n)
	}
	if rec := r.serve(http.MethodGet, "/portal/api/me", c); rec.Code != http.StatusUnauthorized {
		t.Fatalf("me after the watched block = %d, want 401", rec.Code)
	}
	if !strings.Contains(r.logs.String(), `"msg":"portal_session_revoked","by_sub":"system:blocklist_watch","target_sub":"pat","count":1`) {
		t.Fatalf("no watch portal_session_revoked line: %s", r.logs.String())
	}
}

// TestPortalBlockedNonASCIIEmail: a block on a non-ASCII email, in another
// case than the session's, is still denied on the next portal request from
// the snapshot alone (the Add-path revoke is unset here).
func TestPortalBlockedNonASCIIEmail(t *testing.T) {
	r := newPortalRig(t, portalRigOpts{})
	r.ready()
	r.idp.SetLogin(fakes.Valid("zoe", "Zoë@Exämple.com"))
	c := r.login("")
	decodeMe(t, r.serve(http.MethodGet, "/portal/api/me", c))
	r.srv.blocks.SetPortalSessionRevoker(nil)
	blockAdd(t, r.srv, BlockEntry{Email: "ZOË@EXÄMPLE.COM"})
	if r.count("portal_sessions") != 1 {
		t.Fatal("the revoker was unset but the session went")
	}
	if rec := r.serve(http.MethodGet, "/portal/api/me", c); rec.Code != http.StatusForbidden || errBody(t, rec) != portal.CodeUserBlocked {
		t.Fatalf("me for a blocked non-ASCII email = %d %s, want 403 user_blocked", rec.Code, rec.Body)
	}
	if r.count("portal_sessions") != 0 {
		t.Fatal("the blocked principal's portal session was not deleted")
	}
}
