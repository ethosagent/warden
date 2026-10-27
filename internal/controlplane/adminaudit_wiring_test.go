package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// writeAuditPolicy writes a policy file with a console.adminAudit block
// (enabled may be "" for no block at all).
func writeAuditPolicy(t *testing.T, enabled string) string {
	t.Helper()
	path := writePolicyFile(t, "api.openai.com")
	if enabled == "" {
		return path
	}
	body := readFile(t, path) + "console:\n  adminAudit:\n    enabled: " + enabled + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runCP boots Run with p until OnReady, fetches /policy, then shuts it down.
// It returns the /policy body and everything Run logged.
func runCP(t *testing.T, p Params) (policy []byte, logs string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	p.OnReady = func(a string) { ready <- a }
	if p.ListenAddr == "" && p.Listener == nil {
		p.ListenAddr = "127.0.0.1:0"
	}
	if p.AnalyticsProvider == "" {
		p.AnalyticsProvider = "memory"
	}
	var out syncBuffer
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, &out, p) }()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("Run returned before OnReady: %v\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}
	resp, err := http.Get("http://" + addr + "/policy")
	if err != nil {
		t.Fatalf("GET /policy: %v", err)
	}
	policy, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run = %v", err)
	}
	return policy, out.String()
}

// bootErr runs Run expecting a boot error, and checks it closed the listener
// (so nothing was ever served).
func bootErr(t *testing.T, p Params) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tcp, ok := ln.(*net.TCPListener); ok {
		_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))
	}
	p.Listener = ln
	p.AnalyticsProvider = "memory"
	p.OnReady = func(string) { t.Error("Run reached OnReady; want a boot error before listening") }
	err = Run(context.Background(), &bytes.Buffer{}, p)
	if err == nil {
		t.Fatal("Run = nil, want a boot error")
	}
	if _, aerr := ln.Accept(); !errors.Is(aerr, net.ErrClosed) {
		t.Errorf("Accept after failed boot = %v, want net.ErrClosed", aerr)
	}
	return err
}

func auditRows(t *testing.T, stateDir string) int {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow("SELECT count(*) FROM admin_audit").Scan(&n); err != nil {
		t.Fatalf("count admin_audit: %v", err)
	}
	return n
}

func assertNoKeyFiles(t *testing.T, dir string) {
	t.Helper()
	for _, f := range []string{adminaudit.DefaultKeyFileName, adminaudit.HMACKeyFileName} {
		if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists in %s with admin audit disabled (stat err %v)", f, dir, err)
		}
	}
}

// TestAdminAuditDisabledCreatesNothing: with console.adminAudit.enabled false
// (explicitly, or no block at all), with or without --state-dir, no key file
// exists after startup, admin_audit has zero rows, Config.AdminAudit is nil
// and /policy is byte-identical to a CP without the block.
func TestAdminAuditDisabledCreatesNothing(t *testing.T) {
	baseState := filepath.Join(t.TempDir(), "state")
	base, _ := runCP(t, Params{ConfigPath: writeAuditPolicy(t, ""), StateDir: baseState})

	for _, enabled := range []string{"", "false"} {
		t.Run("enabled="+enabled+"/state-dir", func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			got, logs := runCP(t, Params{ConfigPath: writeAuditPolicy(t, enabled), StateDir: stateDir})
			assertNoKeyFiles(t, stateDir)
			if n := auditRows(t, stateDir); n != 0 {
				t.Errorf("admin_audit rows = %d, want 0", n)
			}
			if !bytes.Equal(got, base) {
				t.Errorf("/policy differs from a CP without the block:\n got %s\nwant %s", got, base)
			}
			if strings.Contains(logs, "admin audit") {
				t.Errorf("disabled CP logged about admin audit:\n%s", logs)
			}
		})
		t.Run("enabled="+enabled+"/no-state-dir", func(t *testing.T) {
			cfg := writeAuditPolicy(t, enabled)
			got, _ := runCP(t, Params{ConfigPath: cfg})
			assertNoKeyFiles(t, filepath.Dir(cfg))
			assertNoKeyFiles(t, ".")
			if !bytes.Equal(got, base) {
				t.Errorf("/policy differs from a CP without the block:\n got %s\nwant %s", got, base)
			}
		})
	}
}

// TestAdminAuditToggleOffKeepsMigrations: enable, disable, restart: the
// adminaudit migration stays registered, so the downgrade guard never trips,
// and the rows written while enabled are kept untouched.
func TestAdminAuditToggleOffKeepsMigrations(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	runCP(t, Params{ConfigPath: writeAuditPolicy(t, "true"), StateDir: stateDir})
	if n := auditRows(t, stateDir); n != 1 {
		t.Fatalf("rows after the enabled start = %d, want 1 (genesis)", n)
	}
	runCP(t, Params{ConfigPath: writeAuditPolicy(t, "false"), StateDir: stateDir})
	runCP(t, Params{ConfigPath: writeAuditPolicy(t, ""), StateDir: stateDir})
	if n := auditRows(t, stateDir); n != 1 {
		t.Errorf("rows after disabled restarts = %d, want 1", n)
	}
	// And back on with the same key: the chain continues.
	runCP(t, Params{ConfigPath: writeAuditPolicy(t, "true"), StateDir: stateDir})
	if n := auditRows(t, stateDir); n != 1 {
		t.Errorf("rows after re-enabling = %d, want 1", n)
	}
}

// TestAdminAuditNeedsStateDir: enabled without --state-dir exits before
// listening with the actionable error.
func TestAdminAuditNeedsStateDir(t *testing.T) {
	cfg := writeAuditPolicy(t, "true")
	err := bootErr(t, Params{ConfigPath: cfg})
	if !strings.Contains(err.Error(), "control-plane: console.adminAudit.enabled needs --state-dir") {
		t.Errorf("Run err = %v, want the needs --state-dir error", err)
	}
	assertNoKeyFiles(t, filepath.Dir(cfg))
}

// TestAdminAuditNewSegmentNeedsEnabled: the rotation flag on a CP with audit
// disabled is a startup error, never silently ignored.
func TestAdminAuditNewSegmentNeedsEnabled(t *testing.T) {
	err := bootErr(t, Params{
		ConfigPath:           writeAuditPolicy(t, ""),
		StateDir:             filepath.Join(t.TempDir(), "state"),
		AdminAuditNewSegment: "0123456789abcdef",
	})
	if !strings.Contains(err.Error(), "--admin-audit-new-segment") || !strings.Contains(err.Error(), "console.adminAudit.enabled") {
		t.Errorf("Run err = %v, want one naming the flag and the config key", err)
	}
}

// TestAdminAuditEnabledWiresStore: an enabled start creates both key files in
// the state dir, writes genesis, and logs key_id and the public key.
func TestAdminAuditEnabledWiresStore(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	_, logs := runCP(t, Params{ConfigPath: writeAuditPolicy(t, "true"), StateDir: stateDir})
	keyFile := filepath.Join(stateDir, adminaudit.DefaultKeyFileName)
	signer, err := audit.LoadOrCreateSigner(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, adminaudit.HMACKeyFileName)); err != nil {
		t.Errorf("HMAC key file: %v", err)
	}
	for _, want := range []string{"admin audit enabled", audit.KeyID(signer.PubKey()), base64.StdEncoding.EncodeToString(signer.PubKey())} {
		if !strings.Contains(logs, want) {
			t.Errorf("startup log missing %q:\n%s", want, logs)
		}
	}
	if n := auditRows(t, stateDir); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

// TestAdminAuditCustomKeyFile: --admin-audit-key-file moves the signing key
// (and the HMAC key beside it) out of the state dir.
func TestAdminAuditCustomKeyFile(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	keyDir := t.TempDir()
	keyFile := filepath.Join(keyDir, "audit.pem")
	runCP(t, Params{ConfigPath: writeAuditPolicy(t, "true"), StateDir: stateDir, AdminAuditKeyFile: keyFile})
	for _, f := range []string{keyFile, filepath.Join(keyDir, adminaudit.HMACKeyFileName)} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("key file %s: %v", f, err)
		}
	}
	assertNoKeyFiles(t, stateDir)
}

// TestCheckKeyMissingFile (CP): a state dir with rows whose key file was
// removed stops startup naming the expected key_id and the flag, and never
// creates a replacement key.
func TestCheckKeyMissingFile(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeAuditPolicy(t, "true")
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	keyFile := filepath.Join(stateDir, adminaudit.DefaultKeyFileName)
	signer, err := audit.LoadOrCreateSigner(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	err = bootErr(t, Params{ConfigPath: cfg, StateDir: stateDir})
	for _, want := range []string{audit.KeyID(signer.PubKey()), adminaudit.KeyFileFlag} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Run err = %v, want it to name %q", err, want)
		}
	}
	if _, serr := os.Stat(keyFile); !errors.Is(serr, os.ErrNotExist) {
		t.Error("the CP minted a replacement key while rows exist")
	}
	if n := auditRows(t, stateDir); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

// TestCheckKeyMismatch (CP): a different key at --admin-audit-key-file stops
// startup naming the chain's key_id and the flag; with
// --admin-audit-new-segment set to the new key_id it starts and rotates.
func TestCheckKeyMismatch(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeAuditPolicy(t, "true")
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	old, err := audit.LoadOrCreateSigner(filepath.Join(stateDir, adminaudit.DefaultKeyFileName))
	if err != nil {
		t.Fatal(err)
	}

	newDir := t.TempDir()
	newKey := filepath.Join(newDir, "new.pem")
	signer, err := audit.LoadOrCreateSigner(newKey)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := os.ReadFile(filepath.Join(stateDir, adminaudit.HMACKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, adminaudit.HMACKeyFileName), hk, 0o600); err != nil {
		t.Fatal(err)
	}
	err = bootErr(t, Params{ConfigPath: cfg, StateDir: stateDir, AdminAuditKeyFile: newKey})
	for _, want := range []string{audit.KeyID(old.PubKey()), adminaudit.KeyFileFlag} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Run err = %v, want it to name %q", err, want)
		}
	}
	err = bootErr(t, Params{ConfigPath: cfg, StateDir: stateDir, AdminAuditKeyFile: newKey, AdminAuditNewSegment: audit.KeyID(old.PubKey())})
	if !errors.Is(err, adminaudit.ErrNewSegmentKeyID) {
		t.Errorf("Run with a new-segment value that is not the loaded key = %v, want ErrNewSegmentKeyID", err)
	}
	if n := auditRows(t, stateDir); n != 1 {
		t.Fatalf("rows after refused starts = %d, want 1", n)
	}
	newID := audit.KeyID(signer.PubKey())
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir, AdminAuditKeyFile: newKey, AdminAuditNewSegment: newID})
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir, AdminAuditKeyFile: newKey, AdminAuditNewSegment: newID})
	if n := auditRows(t, stateDir); n != 2 {
		t.Errorf("rows after rotation and a restart with the flag = %d, want 2", n)
	}
}

// TestAdminAuditStartupLogsNoKeyMaterial: nothing the CP logs at startup holds
// the private key, its PEM or the HMAC key, in any common encoding.
func TestAdminAuditStartupLogsNoKeyMaterial(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeAuditPolicy(t, "true")
	_, first := runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	_, second := runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	logs := first + second

	pemBytes, err := os.ReadFile(filepath.Join(stateDir, adminaudit.DefaultKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	hk, err := os.ReadFile(filepath.Join(stateDir, adminaudit.HMACKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	var pemBody string
	for _, line := range strings.Split(string(pemBytes), "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") {
			pemBody += line
		}
	}
	forbidden := map[string]string{
		"PEM header":     "PRIVATE KEY",
		"PEM body":       pemBody,
		"HMAC raw":       string(hk),
		"HMAC hex":       hex.EncodeToString(hk),
		"HMAC base64":    base64.StdEncoding.EncodeToString(hk),
		"HMAC base64url": base64.RawURLEncoding.EncodeToString(hk),
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		t.Fatal("key file is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("key file holds %T, want ed25519", parsed)
	}
	forbidden["private seed hex"] = hex.EncodeToString(priv.Seed())
	forbidden["private seed base64"] = base64.StdEncoding.EncodeToString(priv.Seed())
	forbidden["private key base64"] = base64.StdEncoding.EncodeToString(priv)
	if len(pemBody) > 24 {
		forbidden["PEM body prefix"] = pemBody[:24]
	}
	for name, s := range forbidden {
		if s != "" && strings.Contains(logs, s) {
			t.Errorf("startup logs contain the %s", name)
		}
	}
	if !strings.Contains(logs, "admin audit enabled") {
		t.Fatalf("expected the admin audit startup line; logs:\n%s", logs)
	}
}
