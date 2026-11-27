package scenarios

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The consent portal sign-in scenario (W-P3-CSIG-02): a real control plane
// with console.auth oidc and an enabled consent block, the in-process issuer
// fake playing both the console and the warden-portal client, and a browser
// that follows /portal/login, the issuer and /portal/callback. It proves,
// through the control plane's HTTP surface, its state database and its logs
// only, that a portal login creates a portal_sessions row (not a console
// session) behind a __Host-warden_portal cookie, that a login without a
// refresh token creates nothing, and that no log line holds the refresh token.

func portalOpts() []harness.Option { return []harness.Option{harness.WithConsent()} }

const (
	portalSessionCookie = "__Host-warden_portal"
	portalLoginCookie   = "__Host-warden_portal_login"
	portalRefreshToken  = "rt-harness-portal-refresh-token"
)

// portalIdPLeg follows the issuer's authorize redirect and returns the
// callback URL it sends the browser back to.
func portalIdPLeg(t *testing.T, h *harness.H, authURL string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatalf("issuer authorize: %v", err)
	}
	_ = resp.Body.Close()
	cb := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(cb, h.ConsoleURL()+"/portal/callback?") {
		t.Fatalf("issuer answered %d, Location %q", resp.StatusCode, cb)
	}
	return cb
}

func portalLogin(t *testing.T, h *harness.H) {
	idp := h.Issuer()
	idp.SetLogin(fakes.Valid("dana", "dana@example.com"))
	idp.SetRefreshToken(portalRefreshToken)
	b := h.ConsoleBrowser()

	h.Eventually("the portal has discovered the issuer", func() bool {
		resp, _ := consoleDo(t, b, http.MethodGet, "/portal/callback", nil)
		return resp.StatusCode != http.StatusServiceUnavailable
	})

	// 1. /portal/login redirects to the issuer as the portal client, asking for
	// offline_access, and binds the attempt with the portal's own cookie.
	resp, _ := consoleDo(t, b, http.MethodGet, "/portal/login?next=/portal/connect/abc", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/portal/login = %d, want 302", resp.StatusCode)
	}
	authURL := resp.Header.Get("Location")
	q := mustParse(t, authURL).Query()
	if q.Get("client_id") != harness.PortalClientID || q.Get("scope") != "openid email profile groups offline_access" ||
		q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		t.Fatalf("authorize query = %v", q)
	}
	if lc := cookieIn(resp, portalLoginCookie); lc == nil || !lc.Secure || !lc.HttpOnly || lc.SameSite != http.SameSiteLaxMode {
		t.Fatalf("portal login cookie flags wrong: %+v", lc)
	}

	// 2. The callback creates a portal session and lands on next.
	resp, _ = consoleDo(t, b, http.MethodGet, portalIdPLeg(t, h, authURL), nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/portal/connect/abc" {
		t.Fatalf("/portal/callback = %d to %q, want 302 to /portal/connect/abc", resp.StatusCode, resp.Header.Get("Location"))
	}
	sc := cookieIn(resp, portalSessionCookie)
	if sc == nil || !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" {
		t.Fatalf("portal session cookie flags wrong: %+v", sc)
	}
	rows := h.PortalSessions()
	if len(rows) != 1 || rows[0].Sub != "dana" || rows[0].Iss != idp.Issuer() || rows[0].Email != "dana@example.com" {
		t.Fatalf("portal_sessions = %+v, want one row for dana at the issuer", rows)
	}
	if n := len(h.ConsoleSessions()); n != 0 {
		t.Fatalf("a portal login created %d console sessions", n)
	}
	_, body := consoleDo(t, b, http.MethodGet, "/portal", nil)
	if !strings.Contains(body, "Signed in as <strong>dana@example.com</strong>") {
		t.Fatalf("/portal does not show the signed-in user: %q", body)
	}

	// 3. Without a refresh token (offline_access not granted) nothing is written.
	idp.SetRefreshToken("")
	resp, _ = consoleDo(t, b, http.MethodGet, "/portal/login", nil)
	resp, body = consoleDo(t, b, http.MethodGet, portalIdPLeg(t, h, resp.Header.Get("Location")), nil)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "offline_access_not_granted") {
		t.Fatalf("callback without a refresh token = %d %q, want 502 offline_access_not_granted", resp.StatusCode, body)
	}
	if n := len(h.PortalSessions()); n != 1 {
		t.Fatalf("portal_sessions = %d rows after a refused login, want 1", n)
	}

	logs := h.Logs()
	if !strings.Contains(logs, `"msg":"portal_login"`) || !strings.Contains(logs, `"reason":"offline_access_not_granted"`) {
		t.Fatal("no portal_login log lines")
	}
	if strings.Contains(logs, portalRefreshToken) || strings.Contains(logs, sc.Value) {
		t.Fatal("the logs hold the refresh token or the portal session id")
	}
}
