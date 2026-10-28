package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/test/harness"
)

// The break-glass login (W-P1-OPS1-08): POST /auth/breakglass on a real
// control plane with console.breakGlass enabled and admin audit on. Every
// attempt is loud (one signed row, one ERROR line, one Finding) and the
// credentials appear nowhere.

func breakGlassOpts() []harness.Option {
	return []harness.Option{harness.WithConsoleOIDC(), harness.WithAdminAudit(), harness.WithBreakGlass()}
}

var jsonHeader = http.Header{"Content-Type": {"application/json"}}

func breakGlassPost(t *testing.T, b *harness.Browser, user, password string) (*http.Response, string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": user, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := b.DoBody(http.MethodPost, "/auth/breakglass", jsonHeader, body)
	if err != nil {
		t.Fatalf("POST /auth/breakglass: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(out)
}

// breakGlassLogin: a wrong password is 401 and a right one opens a Secure
// admin session that ends at its absolute TTL on the control plane's clock;
// each attempt is one signed row and one ERROR line, the Finding is reported
// in the alert store, and
// neither credential is in any row or log.
func breakGlassLogin(t *testing.T, h *harness.H) {
	b := h.ConsoleBrowser()
	if resp, _ := consoleDo(t, b, http.MethodGet, "/auth/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/auth/me before login = %d, want 401", resp.StatusCode)
	}

	resp, body := breakGlassPost(t, b, harness.BreakGlassUsername, "not the password at all")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"invalid_credentials"`) {
		t.Fatalf("wrong password = %d %s, want 401 invalid_credentials", resp.StatusCode, body)
	}
	wrongUserResp, wrongUserBody := breakGlassPost(t, b, "somebody-else", harness.BreakGlassPassword)
	if wrongUserResp.StatusCode != http.StatusUnauthorized || wrongUserBody != body {
		t.Fatalf("wrong username = %d %s, want the same 401 body as a wrong password", wrongUserResp.StatusCode, wrongUserBody)
	}
	if cookieIn(resp, consoleSessionCookie) != nil {
		t.Fatal("a failed login set a session cookie")
	}

	resp, body = breakGlassPost(t, b, harness.BreakGlassUsername, harness.BreakGlassPassword)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) || !strings.Contains(body, `"expiresAt"`) {
		t.Fatalf("login = %d %s, want 200 ok", resp.StatusCode, body)
	}
	sc := cookieIn(resp, consoleSessionCookie)
	if sc == nil || !sc.Secure || !sc.HttpOnly || sc.MaxAge != int(time.Hour.Seconds()) {
		t.Fatalf("session cookie = %+v, want Secure HttpOnly with a 1h lifetime", sc)
	}

	resp, body = consoleDo(t, b, http.MethodGet, "/auth/me", nil)
	var me map[string]string
	if err := json.Unmarshal([]byte(body), &me); err != nil || resp.StatusCode != http.StatusOK ||
		me["role"] != "admin" || me["authMethod"] != "breakglass" || me["sub"] != "breakglass:"+harness.BreakGlassUsername {
		t.Fatalf("/auth/me = %d %s, want an admin break-glass session", resp.StatusCode, body)
	}
	if rows := h.ConsoleSessions(); len(rows) != 1 || rows[0].Sub != "breakglass:"+harness.BreakGlassUsername {
		t.Fatalf("sessions table = %+v, want one break-glass row", rows)
	}

	rows := h.AdminAuditRows()
	if len(rows) != 4 {
		t.Fatalf("admin_audit = %+v, want genesis and three break-glass rows", rows)
	}
	for i, want := range []struct{ outcome, sub string }{
		{adminaudit.OutcomeDenied, "breakglass:" + harness.BreakGlassUsername},
		{adminaudit.OutcomeDenied, "breakglass:unknown"},
		{adminaudit.OutcomeOK, "breakglass:" + harness.BreakGlassUsername},
	} {
		r := rows[i+1]
		if r.Action != "auth.breakglass" || r.AuthMethod != adminaudit.AuthMethodBreakglass || r.Outcome != want.outcome ||
			r.Sub != want.sub || r.ClientIP == "" {
			t.Fatalf("row %d = %+v, want %+v", i+1, r, want)
		}
	}

	logs := h.Logs()
	if n := strings.Count(logs, `"msg":"breakglass_login"`); n != 3 {
		t.Fatalf("breakglass_login lines = %d, want 3", n)
	}

	// The Findings reach the alert store: one critical alert for the login, and
	// the two failures aggregated into one high alert by count.
	h.Eventually("the break-glass Findings are in the alert store", func() bool {
		var failure, success bool
		for _, a := range h.Alerts() {
			switch {
			case a.DedupKey == "breakglass_login:failure":
				failure = a.Severity == integration.SevHigh && a.Count == 2
			case strings.HasPrefix(a.DedupKey, "breakglass_login:success:"):
				success = a.Severity == integration.SevCritical && a.Count == 1 &&
					strings.TrimPrefix(a.DedupKey, "breakglass_login:success:") == shortSessionHash(logs)
			}
		}
		return failure && success
	})
	for _, secret := range []string{harness.BreakGlassPassword, "not the password at all", "somebody-else", sc.Value} {
		if strings.Contains(logs, secret) {
			t.Fatalf("a credential or the session id reached the logs: %q", secret)
		}
		for _, r := range rows {
			if strings.Contains(r.Details+r.TargetRef+r.Sub+r.Email, secret) {
				t.Fatalf("a credential or the session id is in the %s row", r.Action)
			}
		}
	}

	// The session ends at its absolute TTL, by the control plane's clock.
	h.Clock().Advance(time.Hour + time.Minute)
	if resp, _ := consoleDo(t, b, http.MethodGet, "/auth/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/auth/me after the TTL = %d, want 401", resp.StatusCode)
	}
}

// breakGlassRateLimit: five failures from one address lock it out for the
// window, even with the right password, and the window passing opens it again.
func breakGlassRateLimit(t *testing.T, h *harness.H) {
	b := h.ConsoleBrowser()
	for i := 0; i < 5; i++ {
		if resp, _ := breakGlassPost(t, b, harness.BreakGlassUsername, "wrong password "+strings.Repeat("x", i)); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401", i+1, resp.StatusCode)
		}
	}
	resp, body := breakGlassPost(t, b, harness.BreakGlassUsername, harness.BreakGlassPassword)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, `"rate_limited"`) || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("6th attempt = %d %s, want 429 rate_limited with Retry-After", resp.StatusCode, body)
	}
	if cookieIn(resp, consoleSessionCookie) != nil || len(h.ConsoleSessions()) != 0 {
		t.Fatal("a rate-limited attempt created a session")
	}
	h.Clock().Advance(16 * time.Minute)
	if resp, body := breakGlassPost(t, b, harness.BreakGlassUsername, harness.BreakGlassPassword); resp.StatusCode != http.StatusOK {
		t.Fatalf("after the window = %d %s, want 200", resp.StatusCode, body)
	}
}

// breakGlassDisabled: with console.breakGlass absent the route is a 404 and
// nothing is audited.
func breakGlassDisabled(t *testing.T, h *harness.H) {
	b := h.ConsoleBrowser()
	resp, _ := breakGlassPost(t, b, "anyone", "anything")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /auth/breakglass = %d, want 404", resp.StatusCode)
	}
	if rows := h.AdminAuditRows(); len(rows) != 1 {
		t.Fatalf("admin_audit = %+v, want only genesis", rows)
	}
}

// shortSessionHash is the session hash prefix the success log line carries.
func shortSessionHash(logs string) string {
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `"msg":"breakglass_login"`) && strings.Contains(line, `"outcome":"ok"`) {
			var rec struct {
				Session string `json:"session"`
			}
			if json.Unmarshal([]byte(line), &rec) == nil {
				return rec.Session
			}
		}
	}
	return ""
}
