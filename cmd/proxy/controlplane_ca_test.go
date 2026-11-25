//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/workerca"
)

// runCA runs `warden control-plane ca ...` and returns stdout, stderr, error.
func runCA(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var so, se bytes.Buffer
	root.SetOut(&so)
	root.SetErr(&se)
	root.SetArgs(append([]string{"control-plane", "ca"}, args...))
	root.SetContext(context.Background())
	err := root.Execute()
	return so.String(), se.String(), err
}

// TestControlPlaneCAInit: init with the file key source creates 0600 key
// files and a chain, refuses a second run without --force, and leaves nothing
// of the key under --state-dir.
func TestControlPlaneCAInit(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ca")
	state := t.TempDir()
	args := []string{"init", "--out-dir", out, "--trust-domain", "warden.local", "--key-source", "file", "--state-dir", state}
	_, stderr, err := runCA(t, args...)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(stderr, "root.key") {
		t.Errorf("no offline warning on stderr: %q", stderr)
	}
	for _, name := range []string{"root.key", "intermediate.key"} {
		if fi, err := os.Stat(filepath.Join(out, name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: err=%v mode=%v", name, err, fi)
		}
	}
	chain, err := os.ReadFile(filepath.Join(out, "intermediate-chain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if certs, err := workerca.ParseCertsPEM(chain); err != nil || len(certs) != 2 {
		t.Fatalf("chain: %v", err)
	}
	if _, _, err := runCA(t, args...); err == nil {
		t.Fatal("second init without --force succeeded")
	}
	if _, _, err := runCA(t, append(args, "--force")...); err != nil {
		t.Fatalf("init --force: %v", err)
	}
	// Scan the state dir for the intermediate key's DER (any file at any depth).
	keyPEM, _ := os.ReadFile(filepath.Join(out, "intermediate.key"))
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("intermediate.key is not PEM")
	}
	_ = filepath.WalkDir(state, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(p); len(b) > 0 && (bytes.Contains(b, block.Bytes) || bytes.Contains(b, keyPEM)) {
			t.Errorf("key material found in %s", p)
		}
		return nil
	})
}

func TestControlPlaneCAUsage(t *testing.T) {
	if _, _, err := runCA(t); err == nil {
		t.Error("ca without a subcommand succeeded")
	}
	if _, _, err := runCA(t, "init", "--out-dir", t.TempDir()); err == nil {
		t.Error("init without --trust-domain succeeded")
	}
	if _, _, err := runCA(t, "init", "--out-dir", t.TempDir(), "--trust-domain", "Bad Domain", "--key-source", "file"); err == nil {
		t.Error("init with a bad trust domain succeeded")
	}
	stdout, _, err := runCA(t, "csr", "--key-source", "file", "--key-file", filepath.Join(t.TempDir(), "k.pem"))
	if err != nil || !strings.Contains(stdout, "BEGIN CERTIFICATE REQUEST") {
		t.Errorf("csr: %v %q", err, stdout)
	}
}

// TestResolveWorkerCAStartup: a control plane whose workerCA block is invalid
// for its keys setup exits with an error naming the key before it listens.
func TestResolveWorkerCAStartup(t *testing.T) {
	chain := filepath.Join(t.TempDir(), "chain.pem")
	if err := os.WriteFile(chain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeTempConfig(t, minimalConfig+"workerCA:\n  enabled: true\n  trustDomain: warden.local\n  certFile: "+chain+"\n")
	err := executeRoot(t, "control-plane", "--config", cfg, "--listen", "127.0.0.1:0", "--analytics-provider", "memory", "--state-dir", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "workerCA.keySource") {
		t.Fatalf("err = %v, want one naming workerCA.keySource", err)
	}
}
