//go:build unix

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
)

// stoppedStateDir boots a control plane on a fresh state dir and stops it, so
// the directory holds what a real CP leaves behind.
func stoppedStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	_, stop := startLockCP(t, dir)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestControlPlaneBackupCmd(t *testing.T) {
	t.Run("stopped writes a complete set", func(t *testing.T) {
		state := stoppedStateDir(t)
		backups := filepath.Join(t.TempDir(), "backups")
		stdout, stderr, code := runWarden(t, "control-plane", "backup", "--state-dir", state, "--backup-dir", backups)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		setDir := strings.TrimSpace(stdout)
		if filepath.Dir(setDir) != backups {
			t.Fatalf("printed %q, want a set directory under %s", setDir, backups)
		}
		raw, err := os.ReadFile(filepath.Join(setDir, controlplane.BackupManifestName))
		if err != nil {
			t.Fatalf("no manifest: %v", err)
		}
		var m controlplane.BackupManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, f := range m.Files {
			names = append(names, f.Name)
			b, err := os.ReadFile(filepath.Join(setDir, f.Name))
			if err != nil {
				t.Fatalf("manifest lists %s: %v", f.Name, err)
			}
			sum := sha256.Sum256(b)
			if hex.EncodeToString(sum[:]) != f.SHA256 || int64(len(b)) != f.Size {
				t.Errorf("%s does not match its manifest entry", f.Name)
			}
		}
		for _, want := range []string{"warden-cp.db", "config.yaml"} {
			if !slices.Contains(names, want) {
				t.Errorf("files = %v, missing %s", names, want)
			}
		}
		if m.Format != controlplane.BackupFormat || m.SchemaVersion < 1 || m.AuditKeyFingerprint != "" {
			t.Errorf("manifest = %+v", m)
		}
		// The lock is released: a second run works, into its own set.
		if _, stderr, code := runWarden(t, "control-plane", "backup", "--state-dir", state, "--backup-dir", backups); code != 0 {
			t.Fatalf("second run exit %d: %s", code, stderr)
		}
	})

	t.Run("a running control plane is refused", func(t *testing.T) {
		state := filepath.Join(t.TempDir(), "state")
		_, stop := startLockCP(t, state)
		defer func() { _ = stop() }()
		backups := filepath.Join(t.TempDir(), "backups")
		stdout, stderr, code := runWarden(t, "control-plane", "backup", "--state-dir", state, "--backup-dir", backups)
		if code == 0 || !strings.Contains(stderr, "control plane is running") {
			t.Fatalf("exit %d, stderr %q, want non-zero naming 'control plane is running'", code, stderr)
		}
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("printed %q on refusal", stdout)
		}
		if _, err := os.Stat(backups); err == nil {
			t.Error("the refused run created the backup dir")
		}
	})

	t.Run("usage errors", func(t *testing.T) {
		state := stoppedStateDir(t)
		for _, c := range []struct {
			name string
			args []string
			want string
		}{
			{"no state dir", []string{"--backup-dir", t.TempDir()}, "--state-dir"},
			{"no backup dir", []string{"--state-dir", state}, "--backup-dir"},
			{"backup dir inside state dir", []string{"--state-dir", state, "--backup-dir", filepath.Join(state, "b")}, "--backup-dir"},
			{"bad include", []string{"--state-dir", state, "--backup-dir", t.TempDir(), "--backup-include", "nope"}, "--backup-include"},
		} {
			_, stderr, code := runWarden(t, append([]string{"control-plane", "backup"}, c.args...)...)
			if code != exitAuditUsage || !strings.Contains(stderr, c.want) {
				t.Errorf("%s: exit %d, stderr %q, want %d naming %s", c.name, code, stderr, exitAuditUsage, c.want)
			}
		}
	})

	t.Run("a state dir with no database is an error and creates none", func(t *testing.T) {
		state := t.TempDir()
		_, stderr, code := runWarden(t, "control-plane", "backup", "--state-dir", state, "--backup-dir", filepath.Join(t.TempDir(), "b"))
		if code != 1 || stderr == "" {
			t.Fatalf("exit %d, stderr %q, want 1", code, stderr)
		}
		if _, err := os.Stat(filepath.Join(state, "warden-cp.db")); err == nil {
			t.Error("the command created warden-cp.db")
		}
	})
}
