package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The block-list admin API scenarios (W-P1-BLOCK-11): an admin adds and
// removes entries over /dashboard/api/blocked-users, the served policy follows,
// every change is audited, a viewer is refused, and an admin cannot remove the
// block that matches their own identity.

const blockAPIReason = "reason-text-for-block-api-scenario"

type blockAPIEntry struct {
	ID        string `json:"id"`
	Sub       string `json:"sub"`
	Email     string `json:"email"`
	CreatedBy string `json:"createdBy"`
	Hint      string `json:"hint"`
}

func blockAPIBearerOpts() []harness.Option {
	return []harness.Option{harness.WithAdminAudit(), harness.WithControlPlaneAdminToken()}
}

func servedBlocked(t *testing.T, h *harness.H) []config.BlockedUser {
	t.Helper()
	var p struct {
		BlockedUsers []config.BlockedUser `json:"blockedUsers"`
	}
	if err := h.CP().GetJSON("/policy", &p); err != nil {
		t.Fatalf("GET /policy: %v", err)
	}
	return p.BlockedUsers
}

// blockAPIBearer: in console.auth none an admin-bearer POST blocks an email,
// the control plane serves it (without the reason) to workers, the write is
// audited with differing state hashes, a write with no bearer is refused and
// leaves no row, and a DELETE unblocks.
func blockAPIBearer(t *testing.T, h *harness.H) {
	cp := h.CP()
	admin := h.ControlPlaneAdminToken()
	const path = "/dashboard/api/blocked-users"
	body := []byte(`{"email":"Alice@Corp.com","reason":"` + blockAPIReason + `"}`)

	if code, _, err := cp.Do(http.MethodPost, path, "", body); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("POST without a bearer = %d, %v; want 401", code, err)
	}
	if rows := h.AdminAuditRows(); len(rows) != 1 {
		t.Fatalf("admin_audit = %+v, want only genesis after a refused write", rows)
	}

	code, resp, err := cp.Do(http.MethodPost, path, admin, body)
	if err != nil || code != http.StatusCreated {
		t.Fatalf("POST = %d %q, %v; want 201", code, resp, err)
	}
	var created blockAPIEntry
	decodeInto(t, "POST", resp, &created)
	if created.ID == "" || created.Email != "alice@corp.com" || created.Hint == "" || created.CreatedBy != "cp-admin-token" {
		t.Fatalf("POST body = %+v, want id, lowercase email, a hint, created_by cp-admin-token", created)
	}
	h.Eventually("the control plane serves the block", func() bool {
		got := servedBlocked(t, h)
		return len(got) == 1 && got[0] == config.BlockedUser{Email: "alice@corp.com"}
	})
	if code, served, err := cp.Do(http.MethodGet, "/policy", cp.Token(), nil); err != nil || code != http.StatusOK || strings.Contains(served, blockAPIReason) {
		t.Errorf("GET /policy = %d, %v; want 200 without the reason", code, err)
	}

	code, list, err := cp.Do(http.MethodGet, path, admin, nil)
	var envelope struct {
		Entries []blockAPIEntry `json:"entries"`
	}
	decodeInto(t, "GET", list, &envelope)
	if err != nil || code != http.StatusOK || len(envelope.Entries) != 1 || envelope.Entries[0].ID != created.ID {
		t.Fatalf("GET = %d %q, %v; want the entry in an envelope", code, list, err)
	}

	if code, _, err := cp.Do(http.MethodDelete, path+"/"+created.ID, admin, nil); err != nil || code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, %v; want 204", code, err)
	}
	h.Eventually("the control plane stops serving the block", func() bool { return len(servedBlocked(t, h)) == 0 })

	rows := h.AdminAuditRows()
	if len(rows) != 3 {
		t.Fatalf("admin_audit = %+v, want genesis, add and remove", rows)
	}
	for i, action := range []string{"blocked_users.add", "blocked_users.remove"} {
		r := rows[i+1]
		if r.Action != action || r.Target != "blocked_users" || r.Outcome != adminaudit.OutcomeOK || r.Sub != "cp-admin-token" ||
			r.TargetRef != "block:"+created.ID || r.BeforeHash == r.AfterHash || r.BeforeHash == "" {
			t.Fatalf("%s row = %+v", action, r)
		}
	}
	var details map[string]string
	decodeInto(t, "details", rows[1].Details, &details)
	if details["has_email"] != "true" || details["has_sub"] != "false" {
		t.Errorf("add details = %v, want has_email true, has_sub false", details)
	}
	for _, r := range rows {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), blockAPIReason) || strings.Contains(string(b), "alice@corp.com") {
			t.Errorf("an audit row carries a block value: %s", b)
		}
	}
	if logs := h.Logs(); strings.Contains(logs, blockAPIReason) || strings.Contains(logs, admin) {
		t.Error("a log line carries the reason or the admin token")
	}
}

func blockAPIOIDCOpts() []harness.Option {
	return []harness.Option{harness.WithConsoleOIDC(), harness.WithAdminAudit()}
}

// blockAPIRoles: in console.auth oidc a viewer's POST is refused and recorded
// as denied; an admin blocks an entry; an admin deleting the entry that matches
// their own email gets 403 self_unblock_forbidden and the entry stays; another
// admin may delete it.
func blockAPIRoles(t *testing.T, h *harness.H) {
	const path = "/dashboard/api/blocked-users"
	viewer, vcsrf := consoleLogin(t, h, fakes.Valid("vera", "vera@example.com", harness.ConsoleViewerGroup))
	resp, body := blockAPIDo(t, viewer, vcsrf, http.MethodPost, path, `{"email":"x@corp.com"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST = %d %s, want 403", resp.StatusCode, body)
	}
	if resp, _ := blockAPIDo(t, viewer, vcsrf, http.MethodGet, path, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer GET = %d, want 403", resp.StatusCode)
	}

	ada, acsrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	resp, body = blockAPIDo(t, ada, acsrf, http.MethodPost, path, `{"email":"ADA@example.com","reason":"`+blockAPIReason+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin POST = %d %s, want 201", resp.StatusCode, body)
	}
	var own blockAPIEntry
	decodeInto(t, "POST", body, &own)
	if own.CreatedBy != "oidc:ada" {
		t.Errorf("created_by = %q, want oidc:ada", own.CreatedBy)
	}

	resp, body = blockAPIDo(t, ada, acsrf, http.MethodDelete, path+"/"+own.ID, "")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "self_unblock_forbidden") {
		t.Fatalf("self DELETE = %d %s, want 403 self_unblock_forbidden", resp.StatusCode, body)
	}
	if got := servedBlocked(t, h); len(got) != 1 || got[0].Email != "ada@example.com" {
		t.Fatalf("served blockedUsers = %+v after the refused self-unblock, want ada's entry", got)
	}

	ben, bcsrf := consoleLogin(t, h, fakes.Valid("ben", "ben@example.com", harness.ConsoleAdminGroup))
	if resp, body := blockAPIDo(t, ben, bcsrf, http.MethodDelete, path+"/"+own.ID, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("another admin DELETE = %d %s, want 204", resp.StatusCode, body)
	}
	h.Eventually("the control plane stops serving the block", func() bool { return len(servedBlocked(t, h)) == 0 })

	var denied, ok, selfDenied int
	for _, r := range h.AdminAuditRows() {
		switch {
		case r.Action == "blocked_users.add" && r.Outcome == adminaudit.OutcomeDenied && r.Sub == "vera":
			denied++
		case r.Action == "blocked_users.add" && r.Outcome == adminaudit.OutcomeOK && r.Sub == "ada":
			ok++
		case r.Action == "blocked_users.remove" && r.Outcome != adminaudit.OutcomeOK && r.Sub == "ada":
			selfDenied++
		}
	}
	if denied != 1 || ok != 1 || selfDenied != 1 {
		t.Errorf("audit rows: viewer denied %d, admin add %d, self-unblock refused %d; want 1 each: %+v", denied, ok, selfDenied, h.AdminAuditRows())
	}
	if strings.Contains(h.Logs(), blockAPIReason) {
		t.Error("a log line carries the reason")
	}
}

func blockAPIDo(t *testing.T, b *harness.Browser, csrf, method, target, body string) (*http.Response, string) {
	t.Helper()
	hdr := http.Header{}
	if method != http.MethodGet {
		hdr.Set(controlplane.CSRFHeader, csrf)
	}
	var payload []byte
	if body != "" {
		payload = []byte(body)
	}
	resp, err := b.DoBody(method, target, hdr, payload)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp, string(out)
}
