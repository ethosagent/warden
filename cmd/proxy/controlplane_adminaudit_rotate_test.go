//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/audit"
)

// auditKeyID loads the signing key at path and returns its key_id.
func auditKeyID(t *testing.T, path string) string {
	t.Helper()
	s, err := audit.LoadOrCreateSigner(path)
	if err != nil {
		t.Fatalf("load key %s: %v", path, err)
	}
	return audit.KeyID(s.PubKey())
}

// TestAdminAuditRotateKeyLocked: with the control plane holding the state-dir
// lock, rotate-key exits 1 saying the control plane is running and leaves the
// key file byte-for-byte unchanged; once the control plane has stopped, the
// same command rotates the key and `admin-audit verify` stays ok on the
// rotated chain.
func TestAdminAuditRotateKeyLocked(t *testing.T) {
	dir := seedAuditStateDir(t, 2)
	keyFile := adminaudit.DefaultKeyPath(dir)
	oldID := auditKeyID(t, keyFile)
	before, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	_, stop := startLockCPWithConfig(t, dir, minimalConfig+auditConfig)
	_, stderr, code := runWarden(t, "control-plane", "admin-audit", "rotate-key", "--state-dir", dir)
	if code != exitAuditFailed {
		t.Fatalf("rotate-key while the control plane runs exit = %d, want 1 (stderr %q)", code, stderr)
	}
	if !strings.Contains(stderr, "control plane is running") {
		t.Errorf("stderr %q does not say the control plane is running", stderr)
	}
	after, rerr := os.ReadFile(keyFile)
	if rerr != nil || !bytes.Equal(before, after) {
		t.Errorf("the refused rotation changed the key file (%v)", rerr)
	}
	if err := stop(); err != nil {
		t.Fatalf("control plane shutdown: %v", err)
	}

	stdout, stderr, code := runWarden(t, "control-plane", "admin-audit", "rotate-key", "--state-dir", dir)
	if code != 0 {
		t.Fatalf("rotate-key exit = %d, %s", code, stderr)
	}
	var res adminaudit.RotateKeyResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("rotate-key output %q is not JSON: %v", stdout, err)
	}
	if res.OldKeyID != oldID || res.NewKeyID == "" || res.NewKeyID == oldID || res.RetiredPath == "" || res.Recovered {
		t.Fatalf("rotate-key result = %+v, want %s rotated over, not recovered", res, oldID)
	}
	if got := auditKeyID(t, keyFile); got != res.NewKeyID {
		t.Errorf("key file now holds %s, want %s", got, res.NewKeyID)
	}
	if _, serr := os.Stat(res.RetiredPath); serr != nil {
		t.Errorf("retired key: %v", serr)
	}
	if _, stderr, code := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir); code != 0 {
		t.Errorf("admin-audit verify after the rotation exit = %d (%s), want 0", code, stderr)
	}
}

// TestAdminAuditRotateKeyUsage: usage and I/O errors exit 2 and print no
// result, and a missing key file is never created.
func TestAdminAuditRotateKeyUsage(t *testing.T) {
	dir := seedAuditStateDir(t, 1)
	empty := t.TempDir()
	missing := filepath.Join(dir, "nope.key")
	for name, args := range map[string][]string{
		"no state dir": {"control-plane", "admin-audit", "rotate-key"},
		"bad flag":     {"control-plane", "admin-audit", "rotate-key", "--state-dir", dir, "--nope"},
		"positional":   {"control-plane", "admin-audit", "rotate-key", "--state-dir", dir, "x"},
		"missing key":  {"control-plane", "admin-audit", "rotate-key", "--state-dir", dir, "--admin-audit-key-file", missing},
		"no database":  {"control-plane", "admin-audit", "rotate-key", "--state-dir", empty},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, code := runWarden(t, args...)
			if code != exitAuditUsage {
				t.Errorf("exit = %d, want 2 (stderr %q)", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
		})
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("a refused rotation created the missing key file")
	}
	if _, err := os.Stat(filepath.Join(empty, adminaudit.StateDBFileName)); err == nil {
		t.Error("rotate-key created a database")
	}
}
