//go:build unix

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
)

// keysRestoreFix seeds a keys-enabled control plane's state dir and takes a
// backup set of it: what a restore after disk loss starts from.
func keysRestoreFix(t *testing.T) (set, keyFile string) {
	t.Helper()
	src := seedStateDir(t, keysCLIConfig)
	keyFile = adminaudit.DefaultKeyPath(src)
	stdout, stderr, code := runWarden(t, "control-plane", "backup", "--state-dir", src,
		"--backup-dir", filepath.Join(t.TempDir(), "backups"))
	if code != 0 {
		t.Fatalf("backup exit %d: %s", code, stderr)
	}
	return strings.TrimSpace(stdout), keyFile
}

// TestKeysRestoreHint: a backup set never contains the key store — the
// manifest lists it under not_included — so restoring a keys-enabled control
// plane leaves signing keys with no material, and the restore says so and
// prints the keys reset hint that recovers it.
func TestKeysRestoreHint(t *testing.T) {
	set, keyFile := keysRestoreFix(t)

	if m := readManifest(t, set); !slices.Contains(m.NotIncluded, "signing key material") {
		t.Errorf("not_included = %v, want the signing key material", m.NotIncluded)
	}

	// A rebuilt host: a fresh state dir with only the admin audit keys restored.
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{keyFile, adminaudit.DefaultHMACKeyPath(keyFile)} {
		b, err := os.ReadFile(k)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(state, filepath.Base(k)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	stdout, stderr, code := restoreCLI(t, set, state)
	if code != 0 {
		t.Fatalf("restore exit %d: %s", code, stderr)
	}
	for _, want := range []string{"token", "bundle", "keys reset", filepath.Join(state, "keys")} {
		if !strings.Contains(stderr, want) {
			t.Errorf("restore stderr lacks %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stdout+stderr, "PRIVATE") {
		t.Errorf("restore output leaks private material:\n%s%s", stdout, stderr)
	}

	// The hint's command is the way out: resetting each purpose regenerates
	// its keys in the restored dir, and the purposes sign again.
	for _, p := range []string{"token", "bundle"} {
		if _, resetErr, c := runWarden(t, "control-plane", "keys", "reset", "--purpose", p, "--yes",
			"--state-dir", state, "--config", writeTempConfig(t, keysCLIConfig)); c != 0 {
			t.Fatalf("keys reset %s exit %d: %s", p, c, resetErr)
		}
	}
	if _, exportErr, c := runWarden(t, "control-plane", "keys", "export", "--purpose", "token", "--state-dir", state); c != 0 {
		t.Fatalf("token export after the reset exit %d: %s", c, exportErr)
	}
}
