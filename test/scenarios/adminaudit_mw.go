package scenarios

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The admin audit middleware (W-P1-AAUD-02): with console.adminAudit enabled
// the control plane writes one signed row per admin change, naming who made
// it, and none for worker traffic or unauthenticated attempts.

func adminAuditBearerOpts() []harness.Option {
	return []harness.Option{harness.WithAdminAudit(), harness.WithControlPlaneAdminToken()}
}

// adminAuditRecordsBearerWrite: in console.auth none a dashboard write with the
// CP admin bearer is recorded as actor cp-admin-token (auth_method bearer);
// a wrong bearer, the worker token, heartbeats, ingest and policy pulls write
// nothing.
func adminAuditRecordsBearerWrite(t *testing.T, h *harness.H) {
	cp := h.CP()
	admin, worker := h.ControlPlaneAdminToken(), cp.Token()

	code, policy, err := cp.Do(http.MethodGet, "/dashboard/api/policy", "", nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/policy = %d, %v", code, err)
	}
	for _, bearer := range []string{"wrong-token", worker, ""} {
		if code, _, err := cp.Do(http.MethodPut, "/dashboard/api/policy", bearer, []byte(policy)); err != nil || code != http.StatusUnauthorized {
			t.Fatalf("PUT /dashboard/api/policy without the admin bearer = %d, %v; want 401", code, err)
		}
	}
	for range 5 {
		if code, _, err := cp.Do(http.MethodPost, "/control/heartbeat", worker, []byte(`{"policyETag":""}`)); err != nil || code != http.StatusNoContent {
			t.Fatalf("heartbeat = %d, %v", code, err)
		}
		if _, _, err := cp.Do(http.MethodPost, "/central/ingest", worker, []byte(`{"events":[]}`)); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}
	if rows := h.AdminAuditRows(); len(rows) != 1 {
		t.Fatalf("admin_audit = %+v, want only genesis before the admin write", rows)
	}

	// Write the policy back twice: the second write changes nothing, so its
	// row hashes the same state before and after, chained to the first.
	for range 2 {
		if code, body, err := cp.Do(http.MethodPut, "/dashboard/api/policy", admin, []byte(policy)); err != nil || code != http.StatusOK {
			t.Fatalf("PUT /dashboard/api/policy with the admin bearer = %d %q, %v", code, body, err)
		}
	}
	rows := h.AdminAuditRows()
	if len(rows) != 3 {
		t.Fatalf("admin_audit = %+v, want genesis and two writes", rows)
	}
	for _, r := range rows[1:] {
		if r.Action != "policy.write" || r.Target != "policy" || r.Outcome != adminaudit.OutcomeOK || r.HTTPStatus != http.StatusOK ||
			r.AuthMethod != adminaudit.AuthMethodBearer || r.Sub != "cp-admin-token" || r.ActorRole != "admin" {
			t.Fatalf("write row = %+v", r)
		}
		if !strings.HasPrefix(r.TargetRef, "policy@") || r.RequestID == "" || !strings.HasPrefix(r.BeforeHash, adminaudit.StateHashPrefix) {
			t.Errorf("target_ref %q, request_id %q, before_hash %q", r.TargetRef, r.RequestID, r.BeforeHash)
		}
	}
	if rows[2].BeforeHash != rows[1].AfterHash || rows[2].BeforeHash != rows[2].AfterHash {
		t.Errorf("state hashes do not chain: %q -> %q, then %q -> %q", rows[1].BeforeHash, rows[1].AfterHash, rows[2].BeforeHash, rows[2].AfterHash)
	}

	// Workers are unaffected.
	h.Upstream("api.example.com")
	if status, _ := get(t, h, "https://api.example.com/v1/models", nil); status != http.StatusOK {
		t.Fatalf("allowed request = %d, want 200", status)
	}
	logs := h.Logs()
	if strings.Contains(logs, admin) || strings.Contains(logs, worker) {
		t.Fatal("a control-plane token value reached the logs")
	}
}

func adminAuditOIDCOpts() []harness.Option {
	return []harness.Option{harness.WithConsoleOIDC(), harness.WithAdminAudit()}
}

// adminAuditRecordsViewerDenied: in console.auth oidc a viewer's write is
// refused with 403 and recorded as denied for that viewer; a write with no
// session is refused with 401 and recorded nowhere.
func adminAuditRecordsViewerDenied(t *testing.T, h *harness.H) {
	b, csrf := consoleLogin(t, h, fakes.Valid("vera", "vera@example.com", harness.ConsoleViewerGroup))
	resp, body := consoleDo(t, b, http.MethodPost, "/dashboard/api/policy", http.Header{controlplane.CSRFHeader: {csrf}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /dashboard/api/policy = %d %s, want 403", resp.StatusCode, body)
	}
	if resp, _ := consoleDo(t, h.ConsoleBrowser(), http.MethodPost, "/dashboard/api/policy", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /dashboard/api/policy with no session = %d, want 401", resp.StatusCode)
	}
	rows := h.AdminAuditRows()
	if len(rows) != 2 {
		t.Fatalf("admin_audit = %+v, want genesis and one denied write", rows)
	}
	r := rows[1]
	if r.Action != "policy.write" || r.Outcome != adminaudit.OutcomeDenied || r.HTTPStatus != http.StatusForbidden ||
		r.AuthMethod != adminaudit.AuthMethodOIDC || r.ActorRole != "viewer" || r.Sub != "vera" {
		t.Fatalf("denied row = %+v", r)
	}
	if r.BeforeHash == "" || r.BeforeHash != r.AfterHash {
		t.Errorf("denied row hashes %q -> %q, want equal", r.BeforeHash, r.AfterHash)
	}
}

// consoleLogin signs a user in through the issuer fake and returns the
// browser holding the session and the session's CSRF token.
func consoleLogin(t *testing.T, h *harness.H, login fakes.MintOption) (*harness.Browser, string) {
	t.Helper()
	h.Issuer().SetLogin(login)
	b := h.ConsoleBrowser()
	h.Eventually("the control plane has discovered the issuer", func() bool {
		resp, _ := consoleDo(t, b, http.MethodGet, "/auth/callback", nil)
		return resp.StatusCode != http.StatusServiceUnavailable
	})
	resp, _ := consoleDo(t, b, http.MethodGet, "/auth/login?next=/dashboard/", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/auth/login = %d, want 302", resp.StatusCode)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, resp.Header.Get("Location"), nil)
	if err != nil {
		t.Fatal(err)
	}
	idpResp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatalf("issuer authorize: %v", err)
	}
	_ = idpResp.Body.Close()
	resp, _ = consoleDo(t, b, http.MethodGet, idpResp.Header.Get("Location"), nil)
	sc := cookieIn(resp, consoleSessionCookie)
	if resp.StatusCode != http.StatusFound || sc == nil {
		t.Fatalf("/auth/callback = %d, session cookie %v", resp.StatusCode, sc != nil)
	}
	return b, controlplane.CSRFToken(sc.Value)
}
