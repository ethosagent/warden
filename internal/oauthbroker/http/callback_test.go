package oauthbrokerhttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/oauthbroker"
	oauthbrokerhttp "github.com/ethosagent/warden/internal/oauthbroker/http"
	"github.com/ethosagent/warden/internal/portal"
)

type fakeCallbacker struct {
	calls []oauthbroker.CallbackRequest
	res   oauthbroker.CallbackResult
	err   error
}

func (f *fakeCallbacker) Callback(_ context.Context, r oauthbroker.CallbackRequest) (oauthbroker.CallbackResult, error) {
	f.calls = append(f.calls, r)
	return f.res, f.err
}

func callbackHandler(f *fakeCallbacker) http.Handler {
	return oauthbrokerhttp.New(oauthbrokerhttp.Config{
		Callback: f, Cookie: oauthbrokerhttp.Cookie{Name: "__Host-warden_connect", Secure: true},
	}).Callback()
}

func get(h http.Handler, target string, signedIn bool, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "__Host-warden_connect", Value: cookie})
	}
	if signedIn {
		r = r.WithContext(portal.WithPrincipal(r.Context(), portal.Principal{Iss: "https://idp", Sub: "alice", Email: "a@example.com"}))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestConnectCallbackHTTP: the handler passes the session principal, the query's
// state, code and error and the cookie to the broker, ignores error_description
// and a user-supplied provider or sub, clears the cookie, and sends a finished
// callback to a fixed internal path.
func TestConnectCallbackHTTP(t *testing.T) {
	cases := map[string]struct {
		res  oauthbroker.CallbackResult
		want string
	}{
		"granted with pending": {oauthbroker.CallbackResult{Result: "granted", Provider: "google", PendingID: "p_1-x"}, "/portal/connect/p_1-x?result=granted"},
		"denied with pending":  {oauthbroker.CallbackResult{Result: "denied", Reason: "access_denied", Provider: "google", PendingID: "p1"}, "/portal/connect/p1?reason=access_denied&result=denied"},
		"granted portal":       {oauthbroker.CallbackResult{Result: "granted", Provider: "google"}, "/portal?connected=google"},
		"denied portal":        {oauthbroker.CallbackResult{Result: "denied", Reason: "insufficient_scope", Provider: "github"}, "/portal?connect_denied=github&reason=insufficient_scope"},
		"hostile id escaped":   {oauthbroker.CallbackResult{Result: "granted", Provider: "google", PendingID: "../x?y"}, "/portal/connect/..%2Fx%3Fy?result=granted"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeCallbacker{res: c.res}
			w := get(callbackHandler(f), "/connect/callback?state=S&code=C&error=&error_description=EVIL&sub=mallory&provider=evil", true, "cookie-value")
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != c.want {
				t.Fatalf("status %d Location %q, want 303 %q", w.Code, w.Header().Get("Location"), c.want)
			}
			if len(f.calls) != 1 {
				t.Fatalf("calls = %d", len(f.calls))
			}
			got := f.calls[0]
			if got.Iss != "https://idp" || got.Sub != "alice" || got.Email != "a@example.com" ||
				got.State != "S" || got.Code != "C" || got.ProviderError != "" || got.BrowserToken != "cookie-value" {
				t.Fatalf("request = %+v", got)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Errorf("headers = %v", w.Header())
			}
			cs := w.Result().Cookies()
			if len(cs) != 1 || cs[0].Name != "__Host-warden_connect" || cs[0].MaxAge >= 0 || !cs[0].Secure || !cs[0].HttpOnly {
				t.Fatalf("cookies = %+v, want the connect cookie cleared", cs)
			}
		})
	}
}

// TestConnectCallbackHTTPErrors: each broker refusal is a generic page with the
// broker's status, a fixed message and no provider text, state or code.
func TestConnectCallbackHTTPErrors(t *testing.T) {
	for _, code := range []string{
		oauthbroker.CodeStateInvalid, oauthbroker.CodeSessionMismatch, oauthbroker.CodeUserBlocked, oauthbroker.CodeBlockListUnavailable,
		oauthbroker.CodeAuditUnavailable, oauthbroker.CodeExchangeFailed, oauthbroker.CodeProviderUnreachable, oauthbroker.CodeScopeExceeded,
		oauthbroker.CodeSecretStoreDown, oauthbroker.CodeProviderConfig, oauthbroker.CodeInternal,
	} {
		t.Run(code, func(t *testing.T) {
			f := &fakeCallbacker{err: &oauthbroker.CallbackError{Code: code}}
			w := get(callbackHandler(f), "/connect/callback?state=SECRETSTATE&code=SECRETCODE&error_description=PROVIDERTEXT", true, "c")
			want := (&oauthbroker.CallbackError{Code: code}).Status()
			if w.Code != want {
				t.Fatalf("status %d, want %d", w.Code, want)
			}
			body := w.Body.String()
			for _, leak := range []string{"SECRETSTATE", "SECRETCODE", "PROVIDERTEXT"} {
				if strings.Contains(body, leak) {
					t.Fatalf("page leaks %s", leak)
				}
			}
			if !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(body, "Reference: "+code) ||
				!strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
				t.Errorf("page = %q headers %v", body, w.Header())
			}
		})
	}
	// A non-CallbackError is a bare 500.
	f := &fakeCallbacker{err: errors.New("db password is hunter2")}
	w := get(callbackHandler(f), "/connect/callback?state=S&code=C", true, "c")
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "hunter2") {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
}

// TestConnectCallbackHTTPGuards: no principal is 401 without a broker call, a
// non-GET is 405, an oversized state or code never reaches the broker, and a
// handler without a callbacker is 404.
func TestConnectCallbackHTTPGuards(t *testing.T) {
	f := &fakeCallbacker{}
	h := callbackHandler(f)
	if w := get(h, "/connect/callback?state=S&code=C", false, "c"); w.Code != http.StatusUnauthorized || len(f.calls) != 0 {
		t.Fatalf("no session = %d, %d calls", w.Code, len(f.calls))
	}
	r := httptest.NewRequest(http.MethodPost, "/connect/callback", nil)
	r = r.WithContext(portal.WithPrincipal(r.Context(), portal.Principal{Iss: "i", Sub: "s"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" || len(f.calls) != 0 {
		t.Fatalf("POST = %d", w.Code)
	}
	for _, target := range []string{
		"/connect/callback?state=" + strings.Repeat("a", 257) + "&code=C",
		"/connect/callback?state=S&code=" + strings.Repeat("a", 2049),
		"/connect/callback?state=S&error=" + strings.Repeat("a", 129),
	} {
		if w := get(h, target, true, "c"); w.Code != http.StatusBadRequest || len(f.calls) != 0 {
			t.Fatalf("%.60s = %d, %d calls", target, w.Code, len(f.calls))
		}
	}
	none := oauthbrokerhttp.New(oauthbrokerhttp.Config{}).Callback()
	if w := get(none, "/connect/callback", true, ""); w.Code != http.StatusNotFound {
		t.Fatalf("no callbacker = %d", w.Code)
	}
}

// TestConnectCallbackHTTPNoReferrer: every callback response, redirect or page,
// is no-store and no-referrer (the URL it was reached by carries the code).
func TestConnectCallbackHTTPNoReferrer(t *testing.T) {
	check := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: headers = %v", name, w.Header())
		}
	}
	ok := &fakeCallbacker{res: oauthbroker.CallbackResult{Result: "granted", Provider: "google"}}
	check("redirect", get(callbackHandler(ok), "/connect/callback?state=S&code=C", true, "c"))
	bad := &fakeCallbacker{err: &oauthbroker.CallbackError{Code: oauthbroker.CodeStateInvalid}}
	check("error page", get(callbackHandler(bad), "/connect/callback?state=S&code=C", true, "c"))
	check("no session", get(callbackHandler(ok), "/connect/callback?state=S&code=C", false, "c"))
	check("oversized", get(callbackHandler(ok), "/connect/callback?state="+strings.Repeat("a", 300), true, "c"))
	w := httptest.NewRecorder()
	oauthbrokerhttp.WriteErrorPage(w, http.StatusUnauthorized, portal.CodeUnauthenticated)
	check("exported page", w)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Sign in") {
		t.Errorf("exported page = %d %q", w.Code, w.Body)
	}
}
