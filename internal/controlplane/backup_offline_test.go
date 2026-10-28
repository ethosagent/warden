package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethosagent/warden/internal/cpstate"
)

func TestRunOfflineBackup(t *testing.T) {
	state := t.TempDir()
	db, err := cpstate.Open(context.Background(), filepath.Join(state, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("policy:\n  allowlist: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backups := filepath.Join(t.TempDir(), "backups")
	cfg := BackupConfig{Dir: backups, Include: []string{BackupCP, BackupAlerts, BackupConfigKey, BackupFleet}, Keep: 1}

	// Older complete sets beyond Keep survive: a one-off run never prunes.
	for _, n := range []string{"20250101T000000Z", "20250102T000000Z", "20250103T000000Z"} {
		if err := os.MkdirAll(filepath.Join(backups, n), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(backups, n, BackupManifestName), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	res, err := RunOfflineBackup(context.Background(), OfflineBackupParams{StateDir: state, Backup: cfg, Version: "v-test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.WardenVersion != "v-test" || res.Manifest.AuditKeyFingerprint != "" {
		t.Errorf("manifest = %+v", res.Manifest)
	}
	// The alert and fleet databases do not exist: skipped, not created.
	if len(res.Manifest.Skipped) != 2 {
		t.Errorf("skipped = %+v, want alerts and fleet", res.Manifest.Skipped)
	}
	for _, f := range []string{"warden-alerts.db", "warden-fleet.db"} {
		if _, err := os.Stat(filepath.Join(state, f)); err == nil {
			t.Errorf("%s was created in the state dir", f)
		}
	}
	sets, _ := listBackupSets(backups)
	if len(sets) != 4 {
		t.Errorf("%d sets after the run, want the 3 old ones and the new one", len(sets))
	}

	// The copy opens as a CP database.
	copyDB, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(res.Path, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatalf("the backed-up database does not open: %v", err)
	}
	_ = copyDB.Close()
}

func TestRunOfflineBackup_Refusals(t *testing.T) {
	state := t.TempDir()
	cfg := BackupConfig{Dir: filepath.Join(t.TempDir(), "b"), Interval: DefaultBackupInterval, Keep: 1, Include: DefaultBackupInclude}

	if _, err := RunOfflineBackup(context.Background(), OfflineBackupParams{StateDir: state, Backup: BackupConfig{}}); err == nil {
		t.Error("no --backup-dir was accepted")
	}
	if _, err := RunOfflineBackup(context.Background(), OfflineBackupParams{StateDir: filepath.Join(state, "missing"), Backup: cfg}); err == nil {
		t.Error("a missing state dir was accepted")
	}
	release, err := cpstate.AcquireDirLock(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	if _, err := RunOfflineBackup(context.Background(), OfflineBackupParams{StateDir: state, Backup: cfg}); !errors.Is(err, ErrControlPlaneRunning) {
		t.Errorf("locked state dir: err = %v, want ErrControlPlaneRunning", err)
	}
}
