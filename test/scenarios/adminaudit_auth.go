package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Login and logout events (W-P1-AAUD-07): with admin audit on, the console's
// OIDC callback and logout record their own signed rows.

// adminAuditRecordsLoginLogout: a sign-in is one auth.login row for the
// verified user and role, a user with no matching role is one
// auth.login_failed row (reason no_role) and gets no session, and a logout is
// one auth.logout row for the session's user. No row or log line carries the
// session cookie or the CSRF token.
func adminAuditRecordsLoginLogout(t *testing.T, h *harness.H) {
	b, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	var session string
	for _, c := range b.Cookies() {
		if c.Name == consoleSessionCookie {
			session = c.Value
		}
	}

	_, resp := consoleCallback(t, h, fakes.Valid("nobody", "nobody@example.com", "strangers"))
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasSuffix(loc, "login_error=no_role") {
		t.Fatalf("no-role callback = %d %q, want a no_role redirect", resp.StatusCode, loc)
	}
	if cookieIn(resp, consoleSessionCookie) != nil {
		t.Fatal("a user with no role got a session cookie")
	}

	if resp, body := consoleDo(t, b, http.MethodPost, "/auth/logout", http.Header{controlplane.CSRFHeader: {csrf}}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d %s, want 204", resp.StatusCode, body)
	}
	if resp, _ := consoleDo(t, b, http.MethodGet, "/auth/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/auth/me after logout = %d, want 401", resp.StatusCode)
	}

	rows := h.AdminAuditRows()
	if len(rows) != 4 {
		t.Fatalf("admin_audit = %+v, want genesis, login, failed login and logout", rows)
	}
	login, failed, logout := rows[1], rows[2], rows[3]
	if login.Action != "auth.login" || login.Target != "session" || login.Outcome != adminaudit.OutcomeOK ||
		login.AuthMethod != adminaudit.AuthMethodOIDC || login.HTTPStatus != http.StatusFound ||
		login.Sub != "ada" || login.Email != "ada@example.com" || login.ActorRole != "admin" ||
		login.Details != `{"role":"admin"}` || login.TargetRef == "" {
		t.Fatalf("login row = %+v", login)
	}
	if failed.Action != "auth.login_failed" || failed.Outcome != adminaudit.OutcomeDenied ||
		failed.Details != `{"reason":"no_role"}` || failed.Sub != "nobody" || failed.TargetRef != "" {
		t.Fatalf("failed login row = %+v", failed)
	}
	if logout.Action != "auth.logout" || logout.Outcome != adminaudit.OutcomeOK || logout.HTTPStatus != http.StatusNoContent ||
		logout.Sub != "ada" || logout.ActorRole != "admin" || logout.TargetRef != login.TargetRef {
		t.Fatalf("logout row = %+v (login target_ref %q)", logout, login.TargetRef)
	}
	for _, r := range rows[1:] {
		if r.RequestID == "" || r.ClientIP == "" {
			t.Errorf("%s row: request_id %q, client_ip %q", r.Action, r.RequestID, r.ClientIP)
		}
	}

	logs := h.Logs()
	for _, secret := range []string{session, csrf} {
		if secret == "" {
			t.Fatal("no session cookie in the browser")
		}
		if strings.Contains(logs, secret) {
			t.Fatal("a session cookie or CSRF token reached the logs")
		}
		for _, r := range rows {
			if strings.Contains(r.Details+r.TargetRef+r.RequestID, secret) {
				t.Fatalf("a session cookie or CSRF token is in the %s row", r.Action)
			}
		}
	}
}
