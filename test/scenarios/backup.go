package scenarios

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/harness"
)

// Scheduled backups (W-P1-OPS1-06): a control plane started with --backup-dir
// writes a complete set at startup without delaying /policy, writes the next
// one when the fake clock passes the interval, keeps only the newest sets, and
// never copies a key file. In-process only (it reads the CP's backup dir).

func backupOpts() []harness.Option {
	return []harness.Option{harness.WithBackup()}
}

// completeSets lists the set directories (those holding manifest.json), newest
// first, and fails on any visible directory that is not complete.
func completeSets(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read backup dir: %v", err)
	}
	var sets []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.Name(), controlplane.BackupManifestName)); err != nil {
			t.Fatalf("set %s is visible without a manifest", e.Name())
		}
		sets = append(sets, e.Name())
	}
	slices.Sort(sets)
	slices.Reverse(sets)
	return sets
}

func backupScheduled(t *testing.T, h *harness.H) {
	dir := h.BackupDir()

	// The startup backup appears, while workers keep pulling policy.
	h.Eventually("the startup backup set", func() bool { return len(completeSets(t, dir)) == 1 })
	var pulled struct {
		Allowlist []any `json:"allowlist"`
	}
	if err := h.CP().GetJSON("/policy", &pulled); err != nil || len(pulled.Allowlist) == 0 {
		t.Fatalf("GET /policy with backups on: %v (allowlist %d)", err, len(pulled.Allowlist))
	}

	first := completeSets(t, dir)[0]
	setDir := filepath.Join(dir, first)
	raw, err := os.ReadFile(filepath.Join(setDir, controlplane.BackupManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m controlplane.BackupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != controlplane.BackupFormat || m.WardenVersion != "harness" || m.SchemaVersion < 1 {
		t.Errorf("manifest = %+v", m)
	}
	if strings.Contains(string(raw), "audit_key_fingerprint") {
		t.Error("manifest has an audit key fingerprint with admin audit off")
	}
	var names []string
	for _, f := range m.Files {
		names = append(names, f.Name)
		b, err := os.ReadFile(filepath.Join(setDir, f.Name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 || int64(len(b)) != f.Size {
			t.Errorf("%s does not match its manifest entry", f.Name)
		}
	}
	if want := []string{"warden-cp.db", "warden-alerts.db", "config.yaml"}; !slices.Equal(names, want) {
		t.Errorf("files = %v, want %v", names, want)
	}
	if len(m.Skipped) != 1 || m.Skipped[0].Name != "warden-fleet.db" {
		t.Errorf("skipped = %+v, want the memory fleet store", m.Skipped)
	}
	if !slices.Contains(m.NotIncluded, "cp-audit.key") {
		t.Errorf("not_included = %v", m.NotIncluded)
	}
	if fi, err := os.Stat(setDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("set dir mode = %v, %v; want 0700", fi, err)
	}
	ents, _ := os.ReadDir(setDir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".key") {
			t.Errorf("a key file %s is in the set", e.Name())
		}
		if info, _ := e.Info(); info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", e.Name(), info.Mode().Perm())
		}
	}

	// Past the interval the next set is written; retention keeps the newest two.
	seen := map[string]bool{first: true}
	h.Eventually("two more sets past the interval", func() bool {
		sets := completeSets(t, dir)
		if len(sets) > harness.BackupKeep {
			t.Fatalf("%d sets kept, want at most %d: %v", len(sets), harness.BackupKeep, sets)
		}
		for _, s := range sets {
			seen[s] = true
		}
		if len(seen) >= 3 {
			return true
		}
		h.Clock().Advance(harness.BackupInterval + time.Hour)
		return false
	})
	if sets := completeSets(t, dir); len(sets) != harness.BackupKeep || slices.Contains(sets, first) {
		t.Errorf("sets after pruning = %v, want the newest %d without %s", sets, harness.BackupKeep, first)
	}

	logs := h.Logs()
	if !strings.Contains(logs, `"msg":"cp_backup"`) || !strings.Contains(logs, `"outcome":"ok"`) {
		t.Error("no cp_backup success lines in the control plane log")
	}
}
