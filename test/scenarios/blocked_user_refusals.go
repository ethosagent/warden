package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The blocked-user refusal scenario (W-P3-OFFB-06): a real control plane with
// consent, the OAuth broker, consent.store and admin audit. A portal user with
// a session and a connect flow in flight is blocked by an admin. Their portal
// session and connect callback then get no answer (signed out), a fresh portal
// login is refused with login_error=blocked, and nothing is written: no new
// portal session, no grant, no consent.store key, no request to the provider.
// The refused login leaves its admin audit row with reason blocked and no
// token, and an unblocked user is unaffected. Observed only through the
// control plane's HTTP surface, its state database, the AWS account and the
// admin audit table.

func blockedUserRefusalsOpts() []harness.Option {
	return append(connectCallbackOpts(), harness.WithAdminAudit())
}

func blockedUserRefusals(t *testing.T, h *harness.H) {
	prov := h.OAuthProvider()
	aws := h.UserStoreAWS()
	dana := ccSignIn(t, h, "dana")
	erin := ccSignIn(t, h, "erin")
	f := ccStart(t, h, dana, "drive.readonly", false)

	baseline := struct{ sessions, grants, attempts int }{len(h.PortalSessions()), len(h.OAuthGrants()), len(h.ConnectAttempts())}

	admin, acsrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	if resp, body := blockAPIDo(t, admin, acsrf, http.MethodPost, "/dashboard/api/blocked-users", `{"sub":"dana"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("block dana = %d %s", resp.StatusCode, body)
	}

	// 1. The open session and the flow in flight are refused.
	if code, _ := portalMe(t, dana.b); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Fatalf("/portal/api/me for a blocked user = %d, want 401 or 403", code)
	}
	if resp, _ := ccCallback(t, dana, f.callback, nil); resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusOK {
		t.Fatalf("a blocked user's callback = %d, want a refusal", resp.StatusCode)
	}
	if prov.TokenRequests() != 0 {
		t.Fatalf("the provider got %d token requests for a blocked user", prov.TokenRequests())
	}

	// 2. A fresh portal login (the IdP account still works) is refused.
	h.Issuer().SetLogin(fakes.Valid("dana", "dana@example.com"))
	h.Issuer().SetRefreshToken(portalRefreshToken)
	b := h.ConsoleBrowser()
	resp, _ := consoleDo(t, b, http.MethodGet, "/portal/login", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/portal/login = %d, want 302", resp.StatusCode)
	}
	resp, _ = consoleDo(t, b, http.MethodGet, portalIdPLeg(t, h, resp.Header.Get("Location")), nil)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || loc != "/portal?login_error=blocked" {
		t.Fatalf("blocked /portal/callback = %d to %q, want 302 to /portal?login_error=blocked", resp.StatusCode, loc)
	}
	if cookieIn(resp, portalSessionCookie) != nil {
		t.Fatal("a blocked login got a portal session cookie")
	}

	// 3. Nothing was written.
	if got := len(h.PortalSessions()); got > baseline.sessions {
		t.Fatalf("portal_sessions grew from %d to %d", baseline.sessions, got)
	}
	if got := len(h.OAuthGrants()); got != baseline.grants {
		t.Fatalf("oauth_grants grew from %d to %d", baseline.grants, got)
	}
	if got := len(h.ConnectAttempts()); got != baseline.attempts {
		t.Fatalf("connect_attempts changed from %d to %d", baseline.attempts, got)
	}
	if aws.Has(ccKey(f.userKey)) {
		t.Fatal("a blocked user has a token in consent.store")
	}

	// 4. The refused login is audited with its reason and no secret.
	var denied int
	for _, row := range h.AdminAuditRows() {
		if row.Action == "portal.login_failed" && row.Sub == "dana" {
			denied++
			if row.Outcome != "denied" || !strings.Contains(row.Details, `"reason":"blocked"`) {
				t.Fatalf("login_failed row = %+v", row)
			}
			if strings.Contains(row.Details, portalRefreshToken) {
				t.Fatal("the audit row holds the refresh token")
			}
		}
	}
	if denied != 1 {
		t.Fatalf("portal.login_failed rows for the blocked user = %d, want 1", denied)
	}

	// 5. An unblocked user is unaffected.
	if code, me := portalMe(t, erin.b); code != http.StatusOK || me["sub"] != "erin" {
		t.Fatalf("/portal/api/me for an unblocked user = %d %v", code, me)
	}
}
