package scenarios

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// The verified restore (W-P1-OPS1-04): a backup set the running control plane
// wrote is restored into an empty state dir (its databases open with the full
// migration list and the served config is the set's); a restore aimed at the
// running control plane's own state dir is refused with "control plane is
// running" and leaves no staging behind; a set with one flipped byte is refused
// with "manifest mismatch" and writes nothing. In-process only (it reads the
// control plane's backup dir and holds its state-dir lock).

func restoreOpts() []harness.Option {
	return []harness.Option{harness.WithBackup()}
}

func restoreVerified(t *testing.T, h *harness.H) {
	dir := h.BackupDir()
	h.Eventually("the startup backup set", func() bool { return len(completeSets(t, dir)) == 1 })
	set := filepath.Join(dir, completeSets(t, dir)[0])
	ctx := context.Background()

	// The control plane holds the state dir: refused, nothing written.
	_, err := controlplane.RunRestore(ctx, controlplane.RestoreParams{From: set, StateDir: h.StateDir(), Force: true})
	if !errors.Is(err, controlplane.ErrRestoreRunning) || !strings.Contains(err.Error(), "control plane is running") {
		t.Fatalf("restore into the running control plane's state dir = %v, want 'control plane is running'", err)
	}
	ents, err := os.ReadDir(h.StateDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".restore-") || strings.HasPrefix(e.Name(), "pre-restore-") {
			t.Errorf("the refused restore left %s in the running control plane's state dir", e.Name())
		}
	}

	// A flipped byte: refused, the empty target stays empty.
	bad := filepath.Join(t.TempDir(), "set")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(set)
	for _, e := range files {
		b, err := os.ReadFile(filepath.Join(set, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() == "warden-cp.db" {
			b[len(b)/2] ^= 0xff
		}
		if err := os.WriteFile(filepath.Join(bad, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	empty := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.RunRestore(ctx, controlplane.RestoreParams{From: bad, StateDir: empty}); !errors.Is(err, controlplane.ErrRestoreManifest) ||
		!strings.Contains(err.Error(), "manifest mismatch: warden-cp.db") {
		t.Fatalf("restore of a tampered set = %v, want 'manifest mismatch: warden-cp.db'", err)
	}
	left, _ := os.ReadDir(empty)
	for _, e := range left {
		if e.Name() != cpstate.LockFileName {
			t.Errorf("the refused restore left %s in the target", e.Name())
		}
	}

	// The intact set restores into the empty dir.
	res, err := controlplane.RunRestore(ctx, controlplane.RestoreParams{From: set, StateDir: empty})
	if err != nil {
		t.Fatalf("restore of the control plane's backup set: %v", err)
	}
	if res.WardenVersion != "harness" || res.PreRestoreDir != "" {
		t.Errorf("restore result = %+v", res)
	}
	db, err := cpstate.OpenReadOnly(ctx, filepath.Join(empty, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("the restored warden-cp.db does not open: %v", err)
	}
	_ = db.Close()
	want, err := os.ReadFile(filepath.Join(set, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(empty, "config.yaml"))
	if err != nil || string(got) != string(want) {
		t.Errorf("restored config.yaml differs from the set's: %v", err)
	}
}
