package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/test/harness"
)

// The admin audit gate (W-P1-AAUD-05): with console.adminAudit.enabled the
// control plane creates its audit keys in the state dir, writes the genesis
// entry before serving, and logs the key_id and public key, never key
// material. Workers keep pulling policy as before.

func adminAuditOpts() []harness.Option { return []harness.Option{harness.WithAdminAudit()} }

func adminAuditEnabledGenesis(t *testing.T, h *harness.H) {
	// The worker still gets its policy and allows traffic: audit is CP-local.
	h.Upstream("api.example.com")
	if status, _ := get(t, h, "https://api.example.com/v1/models", nil); status != http.StatusOK {
		t.Fatalf("allowed request = %d, want 200", status)
	}

	rows := h.AdminAuditRows()
	if len(rows) != 1 || rows[0].Action != adminaudit.ActionGenesis || rows[0].AuthMethod != adminaudit.AuthMethodSystem {
		t.Fatalf("admin_audit = %+v, want exactly the genesis entry", rows)
	}
	for _, f := range []string{adminaudit.DefaultKeyFileName, adminaudit.HMACKeyFileName} {
		if !h.AdminAuditStateFile(f) {
			t.Errorf("%s not created in the state dir", f)
		}
	}

	logs := h.Logs()
	if strings.Contains(logs, "PRIVATE KEY") {
		t.Error("logs contain PEM key material")
	}
	var found bool
	for _, line := range strings.Split(logs, "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "admin audit enabled" {
			continue
		}
		found = true
		if rec["key_id"] != rows[0].KeyID {
			t.Errorf("logged key_id = %v, want the genesis key_id %s", rec["key_id"], rows[0].KeyID)
		}
		if pk, _ := rec["public_key"].(string); pk == "" {
			t.Error("startup line has no public_key")
		}
	}
	if !found {
		t.Error("no `admin audit enabled` startup line")
	}
}

// The admin audit anchor (W-P1-AAUD-06): with admin audit enabled the control
// plane logs the chain head as a warden.admin.v1 admin_audit.checkpoint line at
// startup and again every 5 minutes on its clock, so an off-host copy of the
// logs detects deletion of the newest rows. The harness's goroutine-leak check
// at cleanup proves the checkpoint loop stops with the control plane.
func adminAuditCheckpoint(t *testing.T, h *harness.H) {
	rows := h.AdminAuditRows()
	if len(rows) != 1 {
		t.Fatalf("admin_audit = %+v, want exactly the genesis entry", rows)
	}
	checkpoints := func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(h.Logs(), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "admin_audit.checkpoint" {
				out = append(out, rec)
			}
		}
		return out
	}
	h.Eventually("the startup admin_audit.checkpoint line", func() bool { return len(checkpoints()) == 1 })
	h.Clock().Advance(adminaudit.DefaultCheckpointInterval)
	h.Eventually("a checkpoint line after 5 minutes", func() bool { return len(checkpoints()) == 2 })

	for _, c := range checkpoints() {
		if c["schema"] != adminaudit.SchemaV1 || c["head_seq"] != float64(rows[0].Seq) || c["key_id"] != rows[0].KeyID {
			t.Errorf("checkpoint line = %v, want schema %s, head_seq %d, key_id %s",
				c, adminaudit.SchemaV1, rows[0].Seq, rows[0].KeyID)
		}
	}
}
