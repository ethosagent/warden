package controlplane

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/fakes"
)

// writeKeysPolicy writes a policy file followed by extra top-level YAML.
func writeKeysPolicy(t *testing.T, extra string) string {
	t.Helper()
	path := writePolicyFile(t, "api.openai.com")
	if err := os.WriteFile(path, []byte(readFile(t, path)+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const keysEnabledYAML = "keys:\n  enabled: true\n"

type recFindings struct {
	mu sync.Mutex
	fs []integration.Finding
}

func (r *recFindings) PublishFinding(f integration.Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fs = append(r.fs, f)
}

func (r *recFindings) byRule(rule string) []integration.Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []integration.Finding
	for _, f := range r.fs {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

// keyRows reads the signing_keys rows of a stopped control plane's state dir.
func keyRows(t *testing.T, stateDir string) []keys.Record {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT kid, purpose, state FROM signing_keys ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []keys.Record
	for rows.Next() {
		var r keys.Record
		var st string
		if err := rows.Scan(&r.KID, &r.Purpose, &st); err != nil {
			t.Fatal(err)
		}
		r.State = keys.State(st)
		out = append(out, r)
	}
	return out
}

func signingKeysTable(t *testing.T, stateDir string) bool {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'signing_keys'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// TestKeysDisabledCreatesNothing: with keys absent from the config (the
// default) there is no keys directory and no signing_keys table.
func TestKeysDisabledCreatesNothing(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	runCP(t, Params{ConfigPath: writeKeysPolicy(t, ""), StateDir: stateDir})
	if _, err := os.Stat(filepath.Join(stateDir, "keys")); !os.IsNotExist(err) {
		t.Errorf("keys directory exists with keys disabled: %v", err)
	}
	if signingKeysTable(t, stateDir) {
		t.Error("signing_keys table exists with keys disabled")
	}
	// An explicit enabled: false is the same.
	stateDir = filepath.Join(t.TempDir(), "state")
	runCP(t, Params{ConfigPath: writeKeysPolicy(t, "keys:\n  enabled: false\n"), StateDir: stateDir})
	if signingKeysTable(t, stateDir) {
		t.Error("signing_keys table exists with keys.enabled false")
	}
}

func TestKeysEnabledNeedsStateDir(t *testing.T) {
	err := bootErr(t, Params{ConfigPath: writeKeysPolicy(t, keysEnabledYAML)})
	if !strings.Contains(err.Error(), "keys.enabled") || !strings.Contains(err.Error(), "--state-dir") {
		t.Errorf("error = %v, want it to name keys.enabled and --state-dir", err)
	}
}

func TestKeysBadConfigRefusesStart(t *testing.T) {
	for _, block := range []string{
		"keys:\n  enabled: true\n  store:\n    backend: echo\n",
		"keys:\n  enabled: true\n  bundle:\n    alg: ES256\n",
	} {
		err := bootErr(t, Params{ConfigPath: writeKeysPolicy(t, block), StateDir: filepath.Join(t.TempDir(), "s")})
		if !strings.Contains(err.Error(), "keys.") {
			t.Errorf("error for %q = %v, want it to name the field", block, err)
		}
	}
}

// TestKeysEnabledCreatesAndKeepsKeys: the file backend creates an active and a
// next key per purpose, the admin audit trail records each generation, a
// restart keeps the kids, and turning keys off again still opens the database.
func TestKeysEnabledCreatesAndKeepsKeys(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeKeysPolicy(t, keysEnabledYAML+"console:\n  adminAudit:\n    enabled: true\n")
	_, logs := runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	first := keyRows(t, stateDir)
	if len(first) != 4 {
		t.Fatalf("rows = %+v, want 4", first)
	}
	files, _ := filepath.Glob(filepath.Join(stateDir, "keys", "*", "*.pem"))
	if len(files) != 4 {
		t.Errorf("key files = %v, want 4", files)
	}
	for _, f := range files {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
		pem := readFile(t, f)
		if strings.Contains(logs, strings.TrimSpace(strings.Split(pem, "\n")[1])) {
			t.Errorf("PEM body of %s reached the logs", f)
		}
	}
	if !strings.Contains(logs, "keys_loaded") {
		t.Errorf("no keys_loaded log line:\n%s", logs)
	}

	// The audit trail has one keys.generated entry per key, from the system.
	ctx := context.Background()
	db, err := cpstate.OpenReadOnly(ctx, filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	items, err := adminaudit.NewStore(db, adminaudit.Options{}).List(ctx, adminaudit.Filter{Action: keys.ActionGenerated}, 50, 0)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 {
		t.Fatalf("keys.generated entries = %d, want 4", len(items))
	}
	kids := map[string]bool{}
	for _, r := range first {
		kids[r.KID] = true
	}
	for _, it := range items {
		if it.AuthMethod != adminaudit.AuthMethodSystem || !strings.HasPrefix(it.Target, "keys:") ||
			!strings.HasPrefix(it.TargetRef, "kid:") || !kids[strings.TrimPrefix(it.TargetRef, "kid:")] {
			t.Errorf("audit entry = %+v", it)
		}
	}

	// Restart: same kids, no new rows, no new audit entries.
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir})
	second := keyRows(t, stateDir)
	if len(second) != len(first) {
		t.Fatalf("restart rows %d -> %d", len(first), len(second))
	}
	for i := range first {
		if first[i].KID != second[i].KID || first[i].State != second[i].State {
			t.Errorf("row %d changed: %+v -> %+v", i, first[i], second[i])
		}
	}

	// Keys switched off: the file holds signing_keys/0001, the guard knows it.
	runCP(t, Params{ConfigPath: writeKeysPolicy(t, "console:\n  adminAudit:\n    enabled: true\n"), StateDir: stateDir})
	if got := keyRows(t, stateDir); len(got) != len(first) {
		t.Errorf("disabling keys changed rows: %d", len(got))
	}
}

// TestKeysBackendDownAtStartup: with rows in the database and a key store that
// cannot be read, the control plane still starts and serves /policy and
// /healthz, signing returns ErrNoActiveKey, no row or key is created, a
// signing_key_unavailable Finding is published, and signing works once the
// store recovers — without a restart.
func TestKeysBackendDownAtStartup(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeKeysPolicy(t, keysEnabledYAML)
	store := fakes.NewFakeKeyStore()
	runCP(t, Params{ConfigPath: cfg, StateDir: stateDir, KeyStore: store})
	rowsBefore := keyRows(t, stateDir)
	if len(rowsBefore) != 4 {
		t.Fatalf("setup rows = %d", len(rowsBefore))
	}

	store.SetDown(errors.New("secret backend unreachable"))
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	findings := &recFindings{}
	mgrCh := make(chan *keys.Manager, 1)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		errCh <- Run(ctx, &out, Params{
			ConfigPath: cfg, StateDir: stateDir, KeyStore: store, Clock: clk, Findings: findings,
			ListenAddr: "127.0.0.1:0", AnalyticsProvider: "memory",
			OnReady:    func(a string) { ready <- a },
			KeysReady: func(m *keys.Manager) { mgrCh <- m },
		})
	}()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cancel()
			if err := <-errCh; err != nil {
				t.Errorf("Run = %v", err)
			}
		}
	}
	defer stop()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		stopped = true
		t.Fatalf("Run returned with the key store down: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}
	mgr := <-mgrCh
	for _, path := range []string{"/policy", "/healthz"} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s with the key store down = %d, want 200", path, resp.StatusCode)
		}
	}
	if _, err := mgr.KeySet().Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("Active with the store down = %v, want ErrNoActiveKey", err)
	}
	if mgr.Ready() {
		t.Error("Ready() = true with the store down")
	}
	got := findings.byRule(keys.AlertSigningKeyUnavailable)
	if len(got) != 2 {
		t.Fatalf("signing_key_unavailable findings = %d, want one per purpose", len(got))
	}
	for _, f := range got {
		if !strings.HasPrefix(f.DedupKey, keys.AlertSigningKeyUnavailable+":") || strings.Contains(string(f.Evidence), "PRIVATE KEY") {
			t.Errorf("finding = %+v", f)
		}
	}

	// Recovery without a restart: the retry loop picks the store up.
	store.SetDown(nil)
	deadline := time.Now().Add(10 * time.Second)
	for !mgr.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("signing did not recover after the store came back")
		}
		if clk.PendingTimers() > 0 {
			clk.Advance(time.Minute)
		}
		time.Sleep(5 * time.Millisecond)
	}
	sg, err := mgr.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sg.Sign(context.Background(), []byte("a.b")); err != nil {
		t.Errorf("Sign after recovery: %v", err)
	}
	stop()

	rowsAfter := keyRows(t, stateDir)
	if len(rowsAfter) != len(rowsBefore) {
		t.Errorf("outage and recovery changed rows: %d -> %d", len(rowsBefore), len(rowsAfter))
	}
	for i := range rowsBefore {
		if rowsBefore[i].KID != rowsAfter[i].KID {
			t.Errorf("row %d kid changed", i)
		}
	}
}

func TestKeysFindingMapping(t *testing.T) {
	f := keysFinding(keys.Alert{Rule: keys.AlertSigningKeyUnavailable, Purpose: keys.PurposeBundle, Detail: strings.Repeat("x", 500)}, time.Unix(5, 0))
	if f.DedupKey != "signing_key_unavailable:bundle" || f.RuleID != keys.AlertSigningKeyUnavailable {
		t.Errorf("finding = %+v", f)
	}
	if len(string(f.Evidence)) > keysEvidenceMax+64 {
		t.Errorf("evidence not bounded: %d bytes", len(string(f.Evidence)))
	}
}
