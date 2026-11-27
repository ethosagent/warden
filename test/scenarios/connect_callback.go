package scenarios

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The connect callback scenario (W-P3-BRKR-04): a real control plane with the
// OAuth broker, consent.store on the in-memory AWS account and a fake OAuth
// provider on loopback. A signed-in portal user starts a flow, the fake plays
// the provider (checking the PKCE verifier and the client secret), and the
// callback stores the token at warden-cp/users/<userKey>/google in the account
// while the cpstate file holds no token bytes. A callback from another portal
// user, from another browser, with a replayed or expired state, after the user
// denied consent, with a scope the cap does not allow, or while consent.store
// is down stores nothing usable, and the logs never hold a code, state,
// verifier, token or client secret. Observed only through the control plane's
// HTTP surface, its state database, the AWS account and its logs.

func connectCallbackOpts() []harness.Option { return []harness.Option{harness.WithOAuthProviderFake()} }

type ccFlow struct {
	callback string // the redirect target the fake provider produced (path and query)
	state    string
	code     string
	cookie   *http.Cookie
	userKey  string
}

type ccUser struct {
	b    *harness.Browser
	csrf string
}

func ccSignIn(t *testing.T, h *harness.H, sub string) ccUser {
	t.Helper()
	b, _ := portalSignIn(t, h, fakes.Valid(sub, sub+"@example.com"))
	_, me := portalMe(t, b)
	csrf, _ := me["csrf"].(string)
	if len(csrf) != 64 {
		t.Fatalf("portal csrf = %q", csrf)
	}
	return ccUser{b: b, csrf: csrf}
}

// ccStart starts a flow for u and plays the browser at the fake provider; with
// deny the provider answers access_denied.
func ccStart(t *testing.T, h *harness.H, u ccUser, scopes string, deny bool) ccFlow {
	t.Helper()
	known := map[string]bool{}
	for _, a := range h.ConnectAttempts() {
		known[a.StateHash] = true
	}
	resp, body := connectPost(t, u.b, u.csrf, url.Values{"provider": {"google"}, "scopes": {scopes}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /connect/start = %d %s", resp.StatusCode, body)
	}
	cb, err := h.OAuthProvider().Authorize(resp.Header.Get("Location"), deny)
	if err != nil {
		t.Fatal(err)
	}
	cu, err := url.Parse(cb)
	if err != nil {
		t.Fatal(err)
	}
	f := ccFlow{callback: cu.RequestURI(), state: cu.Query().Get("state"), code: cu.Query().Get("code"), cookie: cookieIn(resp, connectCookie)}
	if f.cookie == nil {
		t.Fatal("no connect cookie on the start response")
	}
	for _, a := range h.ConnectAttempts() {
		if !known[a.StateHash] {
			f.userKey = a.UserKey
		}
	}
	if f.userKey == "" {
		t.Fatal("no new connect attempt")
	}
	return f
}

// ccCallback sends the callback from u's browser; extraCookie adds another
// browser's connect cookie to the request.
func ccCallback(t *testing.T, u ccUser, target string, extraCookie *http.Cookie) (*http.Response, string) {
	t.Helper()
	hdr := http.Header{}
	if extraCookie != nil {
		hdr.Set("Cookie", extraCookie.Name+"="+extraCookie.Value)
	}
	return consoleDo(t, u.b, http.MethodGet, target, hdr)
}

func ccKey(userKey string) string {
	k, err := secrets.UserGrantKey(userKey, "google")
	if err != nil {
		panic(err)
	}
	return "warden-cp/" + k
}

func connectCallback(t *testing.T, h *harness.H) {
	prov := h.OAuthProvider()
	aws := h.UserStoreAWS()
	dana := ccSignIn(t, h, "dana")
	erin := ccSignIn(t, h, "erin")

	// 1. Another portal user holding the cookie value completes dana's flow:
	// 403 before any code exchange, nothing stored, no grant row.
	f1 := ccStart(t, h, dana, "drive.readonly", false)
	resp, body := ccCallback(t, erin, f1.callback, f1.cookie)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "session_mismatch") {
		t.Fatalf("callback from another portal user = %d %s", resp.StatusCode, body)
	}
	if n := prov.TokenRequests(); n != 0 {
		t.Fatalf("the provider's token endpoint got %d requests for a refused callback", n)
	}
	if aws.Has(ccKey(f1.userKey)) || len(h.OAuthGrants()) != 0 {
		t.Fatal("a refused callback stored a token or a grant")
	}

	// 2. The right user in another browser (no connect cookie): state_invalid.
	f2 := ccStart(t, h, dana, "drive.readonly", false)
	other := ccSignIn(t, h, "dana")
	if resp, body := ccCallback(t, other, f2.callback, nil); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "state_invalid") {
		t.Fatalf("callback without the connect cookie = %d %s", resp.StatusCode, body)
	}
	if prov.TokenRequests() != 0 || aws.Has(ccKey(f2.userKey)) {
		t.Fatal("a callback from another browser reached the provider or stored a token")
	}

	// 3. The real flow: 303 to the portal, the token in consent.store with the
	// fake's access token and the active grant's id, no token bytes in cpstate.
	f3 := ccStart(t, h, dana, "drive.readonly", false)
	resp, body = ccCallback(t, dana, f3.callback, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/portal?connected=google" {
		t.Fatalf("callback = %d %q %s, want 303 /portal?connected=google", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	if cc := cookieIn(resp, connectCookie); cc == nil || cc.MaxAge >= 0 {
		t.Errorf("the connect cookie was not cleared: %+v", cc)
	}
	stored, err := aws.GetSecretValue(ccKey(f3.userKey))
	if err != nil {
		t.Fatalf("no token at %s: %v", ccKey(f3.userKey), err)
	}
	grants := h.OAuthGrants()
	if len(grants) != 1 || grants[0].State != "active" || grants[0].UserKey != f3.userKey || len(grants[0].Scopes) != 1 || grants[0].Scopes[0] != "drive.readonly" {
		t.Fatalf("grants = %+v", grants)
	}
	for _, want := range []string{prov.AccessToken(1), prov.RefreshToken(1), `"grant_id":"` + grants[0].GrantID + `"`, `"v":1`} {
		if !strings.Contains(stored, want) {
			t.Errorf("stored record lacks %s", want)
		}
	}
	for name, secret := range map[string]string{"access token": prov.AccessToken(1), "refresh token": prov.RefreshToken(1)} {
		if h.StateFilesContain(secret) {
			t.Errorf("the cpstate file holds the %s", name)
		}
	}

	// 4. Replaying the used state: state_invalid, no second exchange.
	if resp, body := ccCallback(t, dana, f3.callback, f3.cookie); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "state_invalid") {
		t.Fatalf("replay = %d %s", resp.StatusCode, body)
	}
	if prov.TokenRequests() != 1 {
		t.Fatalf("token requests = %d after a replay, want 1", prov.TokenRequests())
	}

	// 5. A reconnect whose response has no refresh token keeps the stored one.
	prov.OmitRefreshToken(true)
	f5 := ccStart(t, h, dana, "drive.readonly", false)
	if resp, body := ccCallback(t, dana, f5.callback, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("reconnect = %d %s", resp.StatusCode, body)
	}
	prov.OmitRefreshToken(false)
	stored, err = aws.GetSecretValue(ccKey(f5.userKey))
	if err != nil || !strings.Contains(stored, prov.AccessToken(2)) || !strings.Contains(stored, prov.RefreshToken(1)) || strings.Contains(stored, prov.AccessToken(1)) {
		t.Fatalf("after a reconnect without a refresh token: %v %s", err, redactedRecord(stored))
	}
	if g := h.OAuthGrants(); len(g) != 1 || g[0].State != "active" || g[0].GrantID == grants[0].GrantID {
		t.Fatalf("grants after the reconnect = %+v", g)
	}

	// 6. The user refusing consent at the provider: no exchange, nothing stored.
	gwen := ccSignIn(t, h, "gwen")
	f6 := ccStart(t, h, gwen, "drive.readonly", true)
	before := prov.TokenRequests()
	resp, _ = ccCallback(t, gwen, f6.callback, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/portal?connect_denied=google&reason=access_denied" {
		t.Fatalf("denied consent = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if prov.TokenRequests() != before || aws.Has(ccKey(f6.userKey)) {
		t.Fatal("a refusal at the provider ran an exchange or stored a token")
	}

	// 7. A provider that widens the grant past the cap: nothing stored, no grant.
	prov.GrantScopes("drive.readonly gmail.send")
	f7 := ccStart(t, h, gwen, "drive.readonly", false)
	resp, body = ccCallback(t, gwen, f7.callback, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "scope_exceeded") {
		t.Fatalf("widened scope = %d %s", resp.StatusCode, body)
	}
	prov.ClearGrantScopes()
	if aws.Has(ccKey(f7.userKey)) {
		t.Fatal("a token granted past the cap was stored")
	}
	for _, g := range h.OAuthGrants() {
		if g.UserKey == f7.userKey {
			t.Fatalf("a grant row exists for the refused scope: %+v", g)
		}
	}

	// 8. The user is blocked between start and callback: the portal refuses the
	// request before the broker (403 user_blocked), the provider is not called.
	frank := ccSignIn(t, h, "frank")
	f8 := ccStart(t, h, frank, "drive.readonly", false)
	admin, acsrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	if resp, body := blockAPIDo(t, admin, acsrf, http.MethodPost, "/dashboard/api/blocked-users", `{"sub":"frank"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("block frank = %d %s", resp.StatusCode, body)
	}
	before = prov.TokenRequests()
	if resp, _ := ccCallback(t, frank, f8.callback, nil); resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a blocked user's callback was accepted")
	}
	if prov.TokenRequests() != before || aws.Has(ccKey(f8.userKey)) {
		t.Fatal("a blocked user's callback reached the provider or stored a token")
	}

	// 9. consent.store down: 503 secret_store_unavailable, the grant stays
	// connecting, and the reconciler then revokes it with no key behind.
	hank := ccSignIn(t, h, "hank")
	f9 := ccStart(t, h, hank, "drive.readonly", false)
	aws.SetDown(errors.New("consent.store unreachable"))
	resp, body = ccCallback(t, hank, f9.callback, nil)
	aws.SetDown(nil)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "secret_store_unavailable") {
		t.Fatalf("callback with the store down = %d %s", resp.StatusCode, body)
	}
	if st := grantState(h, f9.userKey); st != "connecting" {
		t.Fatalf("grant after the failed write = %q, want connecting", st)
	}
	h.Eventually("the reconciler revokes the stuck grant", func() bool {
		h.Clock().Advance(time.Minute)
		return grantState(h, f9.userKey) == "revoked"
	})
	if aws.Has(ccKey(f9.userKey)) {
		t.Fatal("a key exists for the revoked grant")
	}

	// 10. An attempt older than its 10 minutes is state_invalid.
	ivy := ccSignIn(t, h, "ivy")
	f10 := ccStart(t, h, ivy, "drive.readonly", false)
	h.Clock().Advance(11 * time.Minute)
	before = prov.TokenRequests()
	if resp, body := ccCallback(t, ivy, f10.callback, nil); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "state_invalid") {
		t.Fatalf("expired attempt = %d %s", resp.StatusCode, body)
	}
	if prov.TokenRequests() != before {
		t.Fatal("an expired attempt reached the provider")
	}

	// 11. No code, state, verifier, token or client secret in the logs; the
	// connect line carries the consent schema.
	logs := h.Logs()
	if !strings.Contains(logs, `"msg":"connect"`) || !strings.Contains(logs, `"schema":"warden.consent.v1"`) {
		t.Error("no connect log line with schema warden.consent.v1")
	}
	leaks := map[string]string{"client secret": fakes.OAuthDefaultSecret}
	for i := 1; i <= prov.Issued(); i++ {
		leaks["access token"] = prov.AccessToken(i)
		leaks["refresh token"] = prov.RefreshToken(i)
		for name, s := range leaks {
			if strings.Contains(logs, s) {
				t.Errorf("the logs hold the %s", name)
			}
		}
	}
	for _, f := range []ccFlow{f1, f2, f3, f5, f6, f7, f8, f9, f10} {
		for name, s := range map[string]string{"state": f.state, "code": f.code, "connect cookie": f.cookie.Value} {
			if s != "" && strings.Contains(logs, s) {
				t.Errorf("the logs hold a %s", name)
			}
		}
	}
	for _, form := range prov.TokenForms() {
		if v := form.Get("code_verifier"); v != "" && strings.Contains(logs, v) {
			t.Error("the logs hold a PKCE verifier")
		}
	}
}

func grantState(h *harness.H, userKey string) string {
	for _, g := range h.OAuthGrants() {
		if g.UserKey == userKey {
			return g.State
		}
	}
	return ""
}

// redactedRecord keeps a failure message free of token values.
func redactedRecord(s string) string {
	if s == "" {
		return "(empty)"
	}
	return fmt.Sprintf("(token record, %d bytes)", len(s))
}
