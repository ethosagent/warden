package oauthbrokerhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/oauthbroker"
	oauthbrokerhttp "github.com/ethosagent/warden/internal/oauthbroker/http"
	"github.com/ethosagent/warden/internal/portal"
)

type fakeStarter struct {
	calls []oauthbroker.StartRequest
	res   oauthbroker.StartResult
	err   error
}

func (f *fakeStarter) Start(_ context.Context, r oauthbroker.StartRequest) (oauthbroker.StartResult, error) {
	f.calls = append(f.calls, r)
	return f.res, f.err
}

func newHandler(f *fakeStarter) http.Handler {
	return oauthbrokerhttp.New(oauthbrokerhttp.Config{
		Broker: f, Cookie: oauthbrokerhttp.Cookie{Name: "__Host-warden_connect", Secure: true},
	}).Start()
}

func post(h http.Handler, body string, signedIn bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/connect/start?provider=evil", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if signedIn {
		r = r.WithContext(portal.WithPrincipal(r.Context(), portal.Principal{Iss: "https://idp", Sub: "alice", Email: "a@example.com"}))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestConnectStartHTTP: a POST starts a flow from the session principal and the
// body's fields only, answers 303 with the provider URL, the binding cookie and
// no-store, no-referrer headers.
func TestConnectStartHTTP(t *testing.T) {
	f := &fakeStarter{res: oauthbroker.StartResult{
		RedirectURL: "https://accounts.google.com/o/oauth2/v2/auth?state=s", BrowserToken: "tok", CookieMaxAge: 10 * time.Minute,
	}}
	w := post(newHandler(f), url.Values{"provider": {"google"}, "scopes": {"drive.readonly, openid"}, "pending": {"p1"}}.Encode(), true)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != f.res.RedirectURL {
		t.Fatalf("status %d Location %q", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers = %v", w.Header())
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != "__Host-warden_connect" || c[0].Value != "tok" || !c[0].Secure || !c[0].HttpOnly ||
		c[0].SameSite != http.SameSiteLaxMode || c[0].Path != "/" || c[0].MaxAge != 600 || c[0].Domain != "" {
		t.Errorf("cookie = %+v", c)
	}
	if len(f.calls) != 1 {
		t.Fatalf("Start called %d times", len(f.calls))
	}
	got := f.calls[0]
	if got.Iss != "https://idp" || got.Sub != "alice" || got.Provider != "google" || got.PendingID != "p1" ||
		strings.Join(got.Scopes, "|") != "drive.readonly|openid" || got.HasCeiling {
		t.Errorf("request = %+v (the query string's provider=evil must not count; no ceiling comes from a form)", got)
	}
	// No session principal: refused before Start.
	if w := post(newHandler(f), "provider=google", false); w.Code != http.StatusUnauthorized || len(f.calls) != 1 {
		t.Errorf("no principal: %d, %d calls", w.Code, len(f.calls))
	}
}

// TestConnectStartHTTPGet: a GET changes nothing and sends the browser to the
// pending's landing page or the portal; the id is never reflected unvetted.
func TestConnectStartHTTPGet(t *testing.T) {
	f := &fakeStarter{}
	h := newHandler(f)
	for _, tc := range []struct{ target, want string }{
		{"/connect/start", "/portal"},
		{"/connect/start?pending=abc-_123", "/portal/connect/abc-_123"},
		{"/connect/start?pending=../../evil", "/portal"},
		{"/connect/start?pending=" + strings.Repeat("a", 65), "/portal"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.target, nil))
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != tc.want || len(w.Result().Cookies()) != 0 {
			t.Errorf("GET %s = %d %q, want 303 %q with no cookie", tc.target, w.Code, w.Header().Get("Location"), tc.want)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("a GET reached Start")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/connect/start", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") == "" {
		t.Errorf("PUT = %d", w.Code)
	}
}

// TestConnectStartHTTPErrors: each refusal maps to its status and a fixed body.
func TestConnectStartHTTPErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		body   string
		header string
	}{
		{&oauthbroker.StartError{Code: oauthbroker.CodeScopeNotAllowed, Scopes: []string{"a", "b"}}, 400, `{"detail":["a","b"],"error":"scope_not_allowed"}`, ""},
		{&oauthbroker.StartError{Code: oauthbroker.CodeUserBlocked}, 403, `{"error":"user_blocked"}`, ""},
		{&oauthbroker.StartError{Code: oauthbroker.CodePendingNotFound}, 404, `{"error":"pending_not_found"}`, ""},
		{&oauthbroker.StartError{Code: oauthbroker.CodeUnknownProvider}, 404, `{"error":"unknown_provider"}`, ""},
		{&oauthbroker.StartError{Code: oauthbroker.CodePendingNotActive}, 409, `{"error":"pending_not_active"}`, ""},
		{&oauthbroker.StartError{Code: oauthbroker.CodeInvalidRequest}, 400, `{"error":"invalid_request"}`, ""},
		{&oauthbroker.StartError{Code: oauthbroker.CodeRateLimited, RetryAfter: 1500 * time.Millisecond}, 429, `{"error":"rate_limited"}`, "2"},
		{&oauthbroker.StartError{Code: oauthbroker.CodeTooManyAttempts}, 429, `{"error":"too_many_attempts"}`, "600"},
		{&oauthbroker.StartError{Code: oauthbroker.CodeBlockListUnavailable}, 503, `{"error":"block_list_unavailable"}`, ""},
		{&oauthbroker.StartError{Code: oauthbroker.CodeStoreUnavailable}, 503, `{"error":"store_unavailable"}`, ""},
		{context.DeadlineExceeded, 500, `{"error":"internal"}`, ""},
	} {
		w := post(newHandler(&fakeStarter{err: tc.err}), "provider=google", true)
		if w.Code != tc.status || strings.TrimSpace(w.Body.String()) != tc.body || w.Header().Get("Retry-After") != tc.header {
			t.Errorf("%v: %d %q Retry-After %q, want %d %q %q", tc.err, w.Code, w.Body.String(), w.Header().Get("Retry-After"), tc.status, tc.body, tc.header)
		}
		if len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" {
			t.Errorf("%v: a refusal set a cookie or redirect", tc.err)
		}
	}
}
