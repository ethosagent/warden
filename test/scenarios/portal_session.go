package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The portal session scenario (W-P3-CSIG-04): with a real control plane and
// the issuer fake, a signed-in portal user reads /portal/api/me and its CSRF
// token; the same portal cookie opens no console route; a console admin
// session opens no portal route; a logout without the token or with a foreign
// Origin is refused; a logout with it ends the session; an admin lists and
// revokes portal sessions; and blocking a signed-in user ends their portal
// session at once. Observed only through the control plane's HTTP surface,
// its state database and its logs.

// portalSignIn runs one portal login for login in a new browser and returns
// the browser and its portal session cookie value.
func portalSignIn(t *testing.T, h *harness.H, login fakes.MintOption) (*harness.Browser, string) {
	t.Helper()
	idp := h.Issuer()
	idp.SetLogin(login)
	idp.SetRefreshToken(portalRefreshToken)
	b := h.ConsoleBrowser()
	h.Eventually("the portal has discovered the issuer", func() bool {
		resp, _ := consoleDo(t, b, http.MethodGet, "/portal/callback", nil)
		return resp.StatusCode != http.StatusServiceUnavailable
	})
	resp, _ := consoleDo(t, b, http.MethodGet, "/portal/login", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/portal/login = %d, want 302", resp.StatusCode)
	}
	resp, _ = consoleDo(t, b, http.MethodGet, portalIdPLeg(t, h, resp.Header.Get("Location")), nil)
	sc := cookieIn(resp, portalSessionCookie)
	if resp.StatusCode != http.StatusFound || sc == nil {
		t.Fatalf("/portal/callback = %d, session cookie %v", resp.StatusCode, sc != nil)
	}
	return b, sc.Value
}

// portalMe reads /portal/api/me and returns its status and body.
func portalMe(t *testing.T, b *harness.Browser) (int, map[string]any) {
	t.Helper()
	resp, body := consoleDo(t, b, http.MethodGet, "/portal/api/me", nil)
	var me map[string]any
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &me); err != nil {
			t.Fatalf("/portal/api/me body %q: %v", body, err)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("/portal/api/me is cacheable")
		}
	}
	return resp.StatusCode, me
}

func portalSession(t *testing.T, h *harness.H) {
	pb, sid := portalSignIn(t, h, fakes.Valid("dana", "dana@example.com", harness.ConsoleAdminGroup))
	code, me := portalMe(t, pb)
	csrf, _ := me["csrf"].(string)
	if code != http.StatusOK || me["sub"] != "dana" || me["email"] != "dana@example.com" || len(csrf) != 64 {
		t.Fatalf("/portal/api/me = %d %v", code, me)
	}

	// 1. The portal cookie opens no console route, even for a user in the
	// console admin group, and even with the portal's own CSRF token.
	hdr := http.Header{"X-Warden-Csrf": {csrf}}
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/policy"},
		{http.MethodGet, "/dashboard/api/sessions"},
		{http.MethodPost, "/dashboard/api/blocked-users"},
		{http.MethodGet, "/auth/me"},
	} {
		if resp, _ := consoleDo(t, pb, rt.method, rt.path, hdr); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s with the portal cookie = %d, want 401", rt.method, rt.path, resp.StatusCode)
		}
	}

	// 2. A console admin session opens no portal route.
	admin, acsrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	if code, _ := portalMe(t, admin); code != http.StatusUnauthorized {
		t.Fatalf("/portal/api/me with a console session = %d, want 401", code)
	}

	// 3. The admin sees dana's portal session, value-free.
	resp, body := blockAPIDo(t, admin, acsrf, http.MethodGet, "/dashboard/api/sessions?kind=portal", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"sub":"dana"`) || !strings.Contains(body, `"kind":"portal"`) ||
		strings.Contains(body, sid) || strings.Contains(body, csrf) {
		t.Fatalf("GET sessions?kind=portal = %d %s", resp.StatusCode, body)
	}

	// 4. Logout is CSRF- and Origin-checked, then ends the session only.
	if resp, body := consoleDo(t, pb, http.MethodPost, "/portal/logout", nil); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, `"csrf"`) {
		t.Fatalf("logout without csrf = %d %s, want 403 csrf", resp.StatusCode, body)
	}
	foreign := http.Header{"X-Warden-Csrf": {csrf}, "Origin": {"https://evil.example"}}
	if resp, _ := consoleDo(t, pb, http.MethodPost, "/portal/logout", foreign); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout with a foreign Origin = %d, want 403", resp.StatusCode)
	}
	if resp, _ := consoleDo(t, pb, http.MethodPost, "/portal/logout", hdr); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", resp.StatusCode)
	}
	if code, _ := portalMe(t, pb); code != http.StatusUnauthorized {
		t.Fatalf("/portal/api/me after logout = %d, want 401", code)
	}
	if rows := h.PortalSessions(); len(rows) != 0 {
		t.Fatalf("portal_sessions after logout = %+v", rows)
	}

	// 5. Blocking a signed-in user ends their portal session at once.
	eb, _ := portalSignIn(t, h, fakes.Valid("erin", "erin@example.com"))
	if code, _ := portalMe(t, eb); code != http.StatusOK {
		t.Fatalf("erin /portal/api/me = %d", code)
	}
	if resp, body := blockAPIDo(t, admin, acsrf, http.MethodPost, "/dashboard/api/blocked-users", `{"sub":"erin"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("block erin = %d %s", resp.StatusCode, body)
	}
	if rows := h.PortalSessions(); len(rows) != 0 {
		t.Fatalf("portal_sessions after the block = %+v, want none", rows)
	}
	if code, _ := portalMe(t, eb); code != http.StatusUnauthorized {
		t.Fatalf("erin after the block = %d, want 401", code)
	}

	// 6. An admin revoke by sub ends a portal session too.
	fb, _ := portalSignIn(t, h, fakes.Valid("finn", "finn@example.com"))
	if resp, body := blockAPIDo(t, admin, acsrf, http.MethodDelete, "/dashboard/api/sessions?kind=portal&sub=finn", ""); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"revoked":1`) {
		t.Fatalf("revoke finn = %d %s", resp.StatusCode, body)
	}
	if code, _ := portalMe(t, fb); code != http.StatusUnauthorized {
		t.Fatalf("finn after the revoke = %d, want 401", code)
	}
	if resp, _ := consoleDo(t, admin, http.MethodGet, "/auth/me", nil); resp.StatusCode != http.StatusOK {
		t.Fatal("a portal revoke ended the admin's console session")
	}

	logs := h.Logs()
	for _, msg := range []string{"portal_logout", "portal_csrf_denied", "portal_session_revoked"} {
		if !strings.Contains(logs, `"msg":"`+msg+`"`) {
			t.Errorf("no %s log line", msg)
		}
	}
	if strings.Contains(logs, sid) || strings.Contains(logs, csrf) {
		t.Fatal("the logs hold a portal session id or CSRF token")
	}
}
