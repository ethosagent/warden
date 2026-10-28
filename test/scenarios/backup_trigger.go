package scenarios

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The on-demand backup trigger (W-P1-OPS1-11): POST /dashboard/api/backup is an
// audited admin action. A viewer is refused (and the refusal recorded); an
// admin gets 202 and a further complete set appears; a control plane without
// --backup-dir answers 404. In-process only (it reads the CP's backup dir).

func backupTriggerOpts() []harness.Option {
	return []harness.Option{harness.WithConsoleOIDC(), harness.WithAdminAudit(), harness.WithBackup()}
}

func backupTriggerAdmin(t *testing.T, h *harness.H) {
	dir := h.BackupDir()
	h.Eventually("the startup backup set", func() bool { return len(completeSets(t, dir)) == 1 })
	startup := completeSets(t, dir)[0]

	viewer, vcsrf := consoleLogin(t, h, fakes.Valid("vera", "vera@example.com", harness.ConsoleViewerGroup))
	resp, body := consoleDo(t, viewer, http.MethodPost, "/dashboard/api/backup", http.Header{controlplane.CSRFHeader: {vcsrf}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /dashboard/api/backup = %d %s, want 403", resp.StatusCode, body)
	}
	if n := len(completeSets(t, dir)); n != 1 {
		t.Fatalf("%d sets after a refused request, want 1", n)
	}

	admin, acsrf := consoleLogin(t, h, fakes.Valid("alice", "alice@example.com", harness.ConsoleAdminGroup))
	resp, body = consoleDo(t, admin, http.MethodPost, "/dashboard/api/backup", http.Header{controlplane.CSRFHeader: {acsrf}})
	if resp.StatusCode != http.StatusAccepted || strings.TrimSpace(body) != `{"started":true}` {
		t.Fatalf("admin POST /dashboard/api/backup = %d %s, want 202 {\"started\":true}", resp.StatusCode, body)
	}
	h.Eventually("the on-demand backup set", func() bool { return len(completeSets(t, dir)) == 2 })
	var fresh string
	for _, s := range completeSets(t, dir) {
		if s != startup {
			fresh = s
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, fresh, controlplane.BackupManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m controlplane.BackupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != controlplane.BackupFormat || len(m.Files) == 0 {
		t.Errorf("on-demand manifest = %+v", m)
	}

	// One denied row for the viewer and one ok row for the admin.
	var denied, ok []harness.AdminAuditRow
	for _, r := range h.AdminAuditRows() {
		if r.Action != "backup.run" {
			continue
		}
		if r.Outcome == adminaudit.OutcomeOK {
			ok = append(ok, r)
		} else {
			denied = append(denied, r)
		}
	}
	if len(denied) != 1 || denied[0].Outcome != adminaudit.OutcomeDenied || denied[0].ActorRole != "viewer" || denied[0].Sub != "vera" {
		t.Errorf("denied backup.run rows = %+v", denied)
	}
	if len(ok) != 1 || ok[0].Target != "backup" || ok[0].TargetRef != "backup" || ok[0].ActorRole != "admin" ||
		ok[0].Sub != "alice" || ok[0].HTTPStatus != http.StatusAccepted {
		t.Errorf("ok backup.run rows = %+v", ok)
	}
	if m.AuditKeyFingerprint == "" {
		t.Error("manifest has no audit key fingerprint with admin audit on")
	}
}

func backupTriggerDisabledOpts() []harness.Option {
	return []harness.Option{harness.WithControlPlaneAdminToken()}
}

// backupTriggerDisabled: a control plane started without --backup-dir serves
// no backup route, even to a holder of the admin bearer.
func backupTriggerDisabled(t *testing.T, h *harness.H) {
	code, body, err := h.CP().Do(http.MethodPost, "/dashboard/api/backup", h.ControlPlaneAdminToken(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusNotFound {
		t.Fatalf("POST /dashboard/api/backup with backups off = %d %s, want 404", code, body)
	}
}
