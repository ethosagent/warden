package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The admin audit log in the dashboard (W-P1-AAUD-03): the control plane
// serves the chain through /dashboard/api/admin-audit (list), .../verify and
// .../pubkey. Reading and verifying write nothing to the chain; a control
// plane with admin audit off serves none of it.

type adminAuditListBody struct {
	Entries []struct {
		Seq        int64  `json:"seq"`
		Action     string `json:"action"`
		ActorSub   string `json:"actorSub"`
		ActorEmail string `json:"actorEmail"`
		KeyID      string `json:"keyId"`
		EntryHash  string `json:"entryHash"`
	} `json:"entries"`
	NextCursor int64 `json:"nextCursor"`
}

type adminAuditVerifyBody struct {
	OK          bool   `json:"ok"`
	Checked     int    `json:"checked"`
	FirstBadSeq int64  `json:"firstBadSeq"`
	HeadSeq     int64  `json:"headSeq"`
	HeadHash    string `json:"headHash"`
}

type adminAuditPubKeyBody struct {
	Alg  string `json:"alg"`
	Keys []struct {
		KeyID     string `json:"keyId"`
		PublicKey string `json:"publicKey"`
		FirstSeq  int64  `json:"firstSeq"`
	} `json:"keys"`
}

func decodeInto(t *testing.T, what, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("%s: %v in %q", what, err, body)
	}
}

// adminAuditDashboardBearer: in console.auth none, after one admin-bearer
// policy write the list shows it newest first for cp-admin-token, the pubkey
// route names the key_id the rows carry, verify needs the admin bearer and
// reports the whole chain intact, and none of it adds a row.
func adminAuditDashboardBearer(t *testing.T, h *harness.H) {
	cp := h.CP()
	admin := h.ControlPlaneAdminToken()
	code, policy, err := cp.Do(http.MethodGet, "/dashboard/api/policy", "", nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/policy = %d, %v", code, err)
	}
	if code, body, err := cp.Do(http.MethodPut, "/dashboard/api/policy", admin, []byte(policy)); err != nil || code != http.StatusOK {
		t.Fatalf("PUT /dashboard/api/policy = %d %q, %v", code, body, err)
	}
	rows := h.AdminAuditRows()
	if len(rows) != 2 {
		t.Fatalf("admin_audit = %+v, want genesis and the write", rows)
	}

	code, body, err := cp.Do(http.MethodGet, "/dashboard/api/admin-audit?limit=50", "", nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/admin-audit = %d %q, %v", code, body, err)
	}
	var list adminAuditListBody
	decodeInto(t, "list", body, &list)
	if len(list.Entries) != 2 || list.Entries[0].Seq != 2 || list.Entries[1].Seq != 1 || list.NextCursor != 0 {
		t.Fatalf("list = %+v, want seq 2 then 1 and no next page", list)
	}
	if e := list.Entries[0]; e.Action != "policy.write" || e.ActorSub != "cp-admin-token" || e.KeyID != rows[1].KeyID || len(e.EntryHash) != 64 {
		t.Fatalf("newest entry = %+v", e)
	}
	if strings.Contains(body, "ignature") {
		t.Error("the list exposes signatures")
	}

	code, body, err = cp.Do(http.MethodGet, "/dashboard/api/admin-audit/pubkey", "", nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("GET pubkey = %d %q, %v", code, body, err)
	}
	var keys adminAuditPubKeyBody
	decodeInto(t, "pubkey", body, &keys)
	if keys.Alg != "ed25519" || len(keys.Keys) != 1 || keys.Keys[0].KeyID != rows[0].KeyID || keys.Keys[0].FirstSeq != 1 || keys.Keys[0].PublicKey == "" {
		t.Fatalf("pubkey = %+v, want the genesis key %s", keys, rows[0].KeyID)
	}

	for _, bearer := range []string{"", cp.Token()} {
		if code, _, err := cp.Do(http.MethodPost, "/dashboard/api/admin-audit/verify", bearer, nil); err != nil || code != http.StatusUnauthorized {
			t.Fatalf("verify without the admin bearer = %d, %v; want 401", code, err)
		}
	}
	code, body, err = cp.Do(http.MethodPost, "/dashboard/api/admin-audit/verify", admin, nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("verify = %d %q, %v", code, body, err)
	}
	var res adminAuditVerifyBody
	decodeInto(t, "verify", body, &res)
	if !res.OK || res.Checked != 2 || res.HeadSeq != 2 || res.FirstBadSeq != 0 || res.HeadHash != list.Entries[0].EntryHash {
		t.Fatalf("verify = %+v, want ok over 2 rows ending at the newest entry", res)
	}
	if n := len(h.AdminAuditRows()); n != 2 {
		t.Fatalf("admin_audit has %d rows after reads and verify, want 2", n)
	}
	if strings.Contains(h.Logs(), admin) {
		t.Fatal("the admin token reached the logs")
	}
}

// adminAuditDashboardRoles: in oidc mode a viewer may read the public keys but
// gets 403 on the list and verify; an admin reads and verifies the chain.
func adminAuditDashboardRoles(t *testing.T, h *harness.H) {
	viewer, vcsrf := consoleLogin(t, h, fakes.Valid("vera", "vera@example.com", harness.ConsoleViewerGroup))
	if resp, body := consoleDo(t, viewer, http.MethodGet, "/dashboard/api/admin-audit/pubkey", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer pubkey = %d %s, want 200", resp.StatusCode, body)
	}
	if resp, _ := consoleDo(t, viewer, http.MethodGet, "/dashboard/api/admin-audit", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer list = %d, want 403", resp.StatusCode)
	}
	if resp, _ := consoleDo(t, viewer, http.MethodPost, "/dashboard/api/admin-audit/verify", http.Header{controlplane.CSRFHeader: {vcsrf}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer verify = %d, want 403", resp.StatusCode)
	}

	admin, acsrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	resp, body := consoleDo(t, admin, http.MethodGet, "/dashboard/api/admin-audit", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin list = %d %s", resp.StatusCode, body)
	}
	var list adminAuditListBody
	decodeInto(t, "list", body, &list)
	if len(list.Entries) == 0 || list.Entries[len(list.Entries)-1].Seq != 1 {
		t.Fatalf("admin list = %+v, want entries down to genesis", list)
	}
	resp, body = consoleDo(t, admin, http.MethodPost, "/dashboard/api/admin-audit/verify", http.Header{controlplane.CSRFHeader: {acsrf}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin verify = %d %s", resp.StatusCode, body)
	}
	var res adminAuditVerifyBody
	decodeInto(t, "verify", body, &res)
	if !res.OK || int64(res.Checked) != res.HeadSeq {
		t.Fatalf("admin verify = %+v, want the whole chain ok", res)
	}
	// Viewer reads and refusals on read-only routes write nothing.
	for _, r := range h.AdminAuditRows() {
		if strings.HasPrefix(r.Action, "adminaudit.") {
			t.Fatalf("a read of the admin log was chained: %+v", r)
		}
	}
}

// adminAuditDashboardDisabled: with admin audit off the three routes are 404,
// so the dashboard hides the Admin log tab.
func adminAuditDashboardDisabled(t *testing.T, h *harness.H) {
	cp := h.CP()
	admin := h.ControlPlaneAdminToken()
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/admin-audit"},
		{http.MethodPost, "/dashboard/api/admin-audit/verify"},
		{http.MethodGet, "/dashboard/api/admin-audit/pubkey"},
	} {
		if code, body, err := cp.Do(c.method, c.path, admin, nil); err != nil || code != http.StatusNotFound {
			t.Errorf("%s %s = %d %q, %v; want 404", c.method, c.path, code, body, err)
		}
	}
}
