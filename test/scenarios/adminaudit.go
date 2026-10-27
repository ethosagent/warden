package scenarios

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
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

// adminAuditOfflineVerify (W-P1-AAUD-04): the control plane verifies the
// chain's newest rows at startup and logs the result; the offline verifier
// and exporter read the same state dir read-only while the control plane runs
// (no key file, no audit row), and the export verifies with no database.
func adminAuditOfflineVerify(t *testing.T, h *harness.H) {
	var verified map[string]any
	for _, line := range strings.Split(h.Logs(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "admin audit chain verified" {
			verified = rec
		}
		if rec["msg"] == "admin audit chain verification failed" {
			t.Fatalf("startup verification failed on a fresh chain: %v", rec)
		}
	}
	if verified == nil || verified["checked"] != float64(1) || verified["head_seq"] != float64(1) {
		t.Fatalf("startup verify line = %v, want checked=1 head_seq=1", verified)
	}

	ctx := context.Background()
	st, closeFn, err := adminaudit.OpenReadOnly(ctx, h.AdminAuditStateDir(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("OpenReadOnly on the live state dir: %v", err)
	}
	defer func() { _ = closeFn() }()
	res, err := st.VerifyAll(ctx, adminaudit.VerifyOptions{})
	if err != nil || !res.OK || res.Checked != 1 {
		t.Fatalf("offline VerifyAll = %+v, %v", res, err)
	}
	out := filepath.Join(t.TempDir(), "admin-audit.jsonl")
	if _, err := st.ExportFile(ctx, out, adminaudit.ExportOptions{}); err != nil {
		t.Fatalf("ExportFile: %v", err)
	}
	anchor := &adminaudit.Anchor{Seq: res.HeadSeq, Hash: res.HeadHash}
	if vr, err := adminaudit.VerifyExport(out, adminaudit.VerifyExportOptions{Anchor: anchor}); err != nil || !vr.OK {
		t.Fatalf("VerifyExport = %+v, %v", vr, err)
	}
	if rows := h.AdminAuditRows(); len(rows) != 1 {
		t.Errorf("admin_audit has %d rows after offline verify and export, want 1 (they write nothing)", len(rows))
	}
}
