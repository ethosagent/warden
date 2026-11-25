//go:build unix

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
)

// Staged bundle key rotation through the CLI (W-P2-SBND-07).

const bundleAPIKey = "wak_test_not_a_real_key"

// stagedStateDir boots a keys-enabled control plane on a fresh state dir once
// (it creates the keys) and stops it, as the CLI works on a stopped one too.
func bundleStateDir(t *testing.T) string {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	_, stop := startKeysCP(t, stateDir)
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	return stateDir
}

// backdateStage moves the staged key's publish_at back, the way waiting out
// keys.bundle.prepublish would (the CLI runs on the real clock).
func backdateStage(t *testing.T, stateDir string) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.SQL().Exec(`UPDATE signing_keys SET publish_at = publish_at - 7200 WHERE purpose = 'bundle' AND state = 'next'`); err != nil {
		t.Fatal(err)
	}
}

// fleetServer plays the control plane's GET /dashboard/api/workers.
func fleetServer(t *testing.T, workers []dashboard.WorkerView) (url string, calls *atomic.Int32) {
	t.Helper()
	calls = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/dashboard/api/workers" || r.Header.Get("Authorization") != "Bearer "+bundleAPIKey {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(workers)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, calls
}

func pinnedWorker(id string, online bool, kids ...string) dashboard.WorkerView {
	return dashboard.WorkerView{ProxyID: id, Online: online, Caps: []string{config.CapBundleV1}, PinnedKIDs: kids}
}

func apiKeyFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(bundleAPIKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// auditRowsWithOp returns the details of the keys.rotate_requested rows whose
// op detail is op.
func auditRowsWithOp(t *testing.T, stateDir, op string) []map[string]string {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT details_json FROM admin_audit WHERE action = 'keys.rotate_requested' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var d map[string]string
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			t.Fatal(err)
		}
		if d["op"] == op {
			out = append(out, d)
		}
	}
	return out
}

// TestKeysRotateBundleStage: --stage marks the next key staged, names both
// kids, writes one audit row, and a second --stage changes nothing and writes
// no second row. The export then lists both keys, public members only.
func TestKeysRotateBundleStage(t *testing.T) {
	stateDir := bundleStateDir(t)
	before := keyStates(t, stateDir, "bundle")
	active, next := stateKid(before, "active"), stateKid(before, "next")

	stdout, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--stage", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("stage exit = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, active) || !strings.Contains(stdout, next) {
		t.Errorf("stage output %q does not name both kids", stdout)
	}
	if !strings.Contains(stderr, next) {
		t.Errorf("stage did not log the kids involved:\n%s", stderr)
	}
	if after := keyStates(t, stateDir, "bundle"); after[active] != "active" || after[next] != "next" {
		t.Errorf("bundle rows after the stage = %v, want the same states (staging only adds a signature)", after)
	}
	rows := auditRowsWithOp(t, stateDir, "stage")
	if len(rows) != 1 || rows[0]["kid"] != active || rows[0]["next_kid"] != next {
		t.Fatalf("stage audit rows = %v, want one naming %s and %s", rows, active, next)
	}

	stdout, _, code = runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--stage", "--state-dir", stateDir)
	if code != 0 || !strings.Contains(stdout, "already staged") {
		t.Errorf("second stage = %d %q, want a no-op", code, stdout)
	}
	if n := len(auditRowsWithOp(t, stateDir, "stage")); n != 1 {
		t.Errorf("stage audit rows = %d after a repeat, want 1", n)
	}
}

// TestKeysRotateBundleActivateGate: --activate refuses and names the worker
// that lacks the next kid in pinnedKids; nothing changes; with --force it goes
// on and writes ONE audit row carrying the missing proxy id. Unpinned and
// offline workers do not block.
func TestKeysRotateBundleActivateGate(t *testing.T) {
	stateDir := bundleStateDir(t)
	bs := keyStates(t, stateDir, "bundle")
	old, next := stateKid(bs, "active"), stateKid(bs, "next")
	url, _ := fleetServer(t, []dashboard.WorkerView{
		pinnedWorker("w-both", true, old, next),
		pinnedWorker("w-old-only", true, old),
		{ProxyID: "w-legacy", Online: true, Caps: []string{"grouppolicy/v1"}}, // heartbeated, no bundle/v1: applies the legacy wire
		{ProxyID: "w-fresh", Online: true},                                    // polled, no heartbeat yet: pins unknown
		pinnedWorker("w-offline", false, old),
	})
	keyFile := apiKeyFile(t)
	activate := func(extra ...string) (string, string, int) {
		args := append([]string{"control-plane", "keys", "rotate", "--purpose", "bundle", "--activate",
			"--state-dir", stateDir, "--admin-url", url, "--api-key-file", keyFile}, extra...)
		return runWarden(t, args...)
	}

	// Not staged yet: refused before the fleet is even asked.
	if _, stderr, code := activate(); code == 0 || !strings.Contains(stderr, "not staged") {
		t.Fatalf("unstaged activate = %d %q, want a not-staged refusal", code, stderr)
	}
	if _, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--stage", "--state-dir", stateDir); code != 0 {
		t.Fatalf("stage: %q", stderr)
	}
	backdateStage(t, stateDir)

	_, stderr, code := activate()
	if code == 0 {
		t.Fatal("activate with a worker lacking the next kid succeeded")
	}
	if !strings.Contains(stderr, "w-old-only") || !strings.Contains(stderr, "w-fresh") || !strings.Contains(stderr, "no heartbeat yet") {
		t.Errorf("refusal %q does not name the worker lacking the kid and the one with no heartbeat yet", stderr)
	}
	_, refusal, _ := strings.Cut(stderr, "keys: refusing")
	for _, innocent := range []string{"w-both", "w-legacy", "w-offline"} {
		if strings.Contains(refusal, innocent) {
			t.Errorf("refusal %q names %s, which does not block", refusal, innocent)
		}
	}
	if !strings.Contains(stderr, "w-offline") {
		t.Errorf("stderr %q has no warning for the offline worker lacking the kid", stderr)
	}
	if strings.Contains(stderr, bundleAPIKey) {
		t.Errorf("refusal leaks the API key: %q", stderr)
	}
	if after := keyStates(t, stateDir, "bundle"); after[old] != "active" || after[next] != "next" {
		t.Fatalf("a refused activation changed the rows: %v", after)
	}
	if n := len(auditRowsWithOp(t, stateDir, "activate")); n != 0 {
		t.Errorf("a refused activation wrote %d audit rows", n)
	}

	stdout, stderr, code := activate("--force")
	if code != 0 {
		t.Fatalf("forced activate exit = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, next) || !strings.Contains(stderr, "w-old-only") || !strings.Contains(stderr, "w-offline") {
		t.Errorf("forced output %q / %q should name the new key, the overridden worker and the offline warning", stdout, stderr)
	}
	after := keyStates(t, stateDir, "bundle")
	if after[next] != "active" || after[old] != "retired" {
		t.Fatalf("bundle rows after the forced activation = %v, want %s active and %s retired", after, next, old)
	}
	rows := auditRowsWithOp(t, stateDir, "activate")
	if len(rows) != 1 {
		t.Fatalf("forced activate audit rows = %v, want exactly one", rows)
	}
	if r := rows[0]; r["forced"] != "true" || r["missing"] != "w-fresh,w-old-only" || r["kid"] != next || r["previous_kid"] != old ||
		r["offline_missing"] != "w-offline" {
		t.Errorf("forced activate row = %v, want forced, the missing proxy id, both kids and the offline worker", r)
	}
	// The old key stays published for its overlap, so the exported pin set
	// still lists it while the new key signs.
	stdout, _, code = runWarden(t, "control-plane", "keys", "export", "--purpose", "bundle", "--state-dir", stateDir)
	got := extractJWKSKids(t, stdout)
	if code != 0 || !sliceHas(got, old) || !sliceHas(got, next) {
		t.Errorf("export after the activation = %v, want the old key (overlap) and the new key", got)
	}
}

// TestKeysRotateBundleActivateAllPinned: with every online worker reporting the
// next kid the activation needs no --force and its audit row carries no
// override.
func TestKeysRotateBundleActivateAllPinned(t *testing.T) {
	stateDir := bundleStateDir(t)
	bs := keyStates(t, stateDir, "bundle")
	old, next := stateKid(bs, "active"), stateKid(bs, "next")
	url, calls := fleetServer(t, []dashboard.WorkerView{pinnedWorker("w1", true, old, next), pinnedWorker("w2", true, next)})
	if _, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--stage", "--state-dir", stateDir); code != 0 {
		t.Fatalf("stage: %q", stderr)
	}
	backdateStage(t, stateDir)
	t.Setenv("WARDEN_API_KEY", bundleAPIKey)
	_, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--activate",
		"--state-dir", stateDir, "--admin-url", url)
	if code != 0 {
		t.Fatalf("activate exit = %d, stderr %q", code, stderr)
	}
	if calls.Load() != 1 {
		t.Errorf("the fleet was asked %d times, want 1", calls.Load())
	}
	rows := auditRowsWithOp(t, stateDir, "activate")
	if len(rows) != 1 || rows[0]["forced"] != "" || rows[0]["missing"] != "" {
		t.Fatalf("activate audit rows = %v, want one without an override", rows)
	}
}

// TestKeysRotateBundleActivateUnreadablePins: a gate that cannot read the pins
// fails closed, whatever the reason; --force overrides and the row says the pins
// were unverified.
func TestKeysRotateBundleActivateUnreadablePins(t *testing.T) {
	stateDir := bundleStateDir(t)
	if _, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--stage", "--state-dir", stateDir); code != 0 {
		t.Fatalf("stage: %q", stderr)
	}
	backdateStage(t, stateDir)
	bs := keyStates(t, stateDir, "bundle")
	old, next := stateKid(bs, "active"), stateKid(bs, "next")

	// No admin URL at all.
	t.Setenv("WARDEN_API_KEY", "")
	_, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--activate", "--state-dir", stateDir)
	if code == 0 || !strings.Contains(stderr, "--admin-url") {
		t.Fatalf("activate without an admin URL = %d %q, want a refusal naming --admin-url", code, stderr)
	}
	// A control plane that refuses the key.
	url, _ := fleetServer(t, nil)
	wrong := filepath.Join(t.TempDir(), "wrong")
	if err := os.WriteFile(wrong, []byte("wak_wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code = runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--activate",
		"--state-dir", stateDir, "--admin-url", url, "--api-key-file", wrong)
	if code == 0 || !strings.Contains(stderr, "401") || strings.Contains(stderr, "wak_wrong") {
		t.Fatalf("activate with a rejected key = %d %q, want a 401 refusal without the key", code, stderr)
	}
	if after := keyStates(t, stateDir, "bundle"); after[old] != "active" {
		t.Fatalf("a refused activation changed the rows: %v", after)
	}

	_, stderr, code = runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--activate", "--force", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("forced activate exit = %d, stderr %q", code, stderr)
	}
	rows := auditRowsWithOp(t, stateDir, "activate")
	if len(rows) != 1 || rows[0]["forced"] != "true" || rows[0]["pins_unverified"] != "true" || rows[0]["kid"] != next {
		t.Fatalf("forced activate rows = %v, want one marked forced and pins_unverified", rows)
	}
}

// TestKeysRotateBundleStepFlags: the step flags are checked before anything
// opens.
func TestKeysRotateBundleStepFlags(t *testing.T) {
	stateDir := bundleStateDir(t)
	for name, args := range map[string][]string{
		"stage and activate": {"--purpose", "bundle", "--stage", "--activate"},
		"stage on token":     {"--purpose", "token", "--stage"},
		"force alone":        {"--purpose", "bundle", "--force"},
		"stage emergency":    {"--purpose", "bundle", "--stage", "--emergency", "--yes"},
		"unstage and stage":  {"--purpose", "bundle", "--unstage", "--stage"},
		"unstage on token":   {"--purpose", "token", "--unstage"},
		"plain http admin":   {"--purpose", "bundle", "--activate", "--admin-url", "http://cp.example.com:7070"},
	} {
		_, stderr, code := runWarden(t, append([]string{"control-plane", "keys", "rotate", "--state-dir", stateDir}, args...)...)
		if code != exitAuditUsage {
			t.Errorf("%s: exit = %d (%q), want the usage exit", name, code, stderr)
		}
	}
}

// TestKeysExportBundleIsAPinSet: the exported bundle JWKS parses as the pin set
// a worker loads (controlPlane.bundleKeysFile), carries no private member, and
// lists the active and the next key.
func TestKeysExportBundleIsAPinSet(t *testing.T) {
	stateDir := bundleStateDir(t)
	stdout, stderr, code := runWarden(t, "control-plane", "keys", "export", "--purpose", "bundle", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("export exit = %d, stderr %q", code, stderr)
	}
	for _, member := range []string{`"d"`, `"p"`, `"q"`, `"k"`, "PRIVATE"} {
		if strings.Contains(stdout, member) {
			t.Fatalf("export carries %s:\n%s", member, stdout)
		}
	}
	file := filepath.Join(t.TempDir(), "bundle-keys.json")
	if err := os.WriteFile(file, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "worker.yaml")
	if err := os.WriteFile(cfg, []byte("policy:\n  allowlist:\n    - domain: api.example.com\ncontrolPlane:\n  endpoint: https://cp.example.com/policy\n  bundleKeysFile: "+file+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prov, err := config.NewLocalYAMLProvider(cfg)
	if err != nil {
		t.Fatalf("the exported JWKS is not a valid pin file: %v", err)
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	bs := keyStates(t, stateDir, "bundle")
	var kids []string
	for _, k := range pol.ControlPlane.BundleKeys {
		kids = append(kids, k.Kid)
	}
	if len(kids) != 2 || !sliceHas(kids, stateKid(bs, "active")) || !sliceHas(kids, stateKid(bs, "next")) {
		t.Errorf("pinned kids = %v, want the active and next bundle key (%v)", kids, bs)
	}
}

// TestCheckAdminURL: the API key travels with every request, so only https, or
// http to a loopback host, is accepted.
func TestCheckAdminURL(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://cp.example.com:7070": true, "http://127.0.0.1:7070": true, "http://localhost:7070": true, "http://[::1]:7070": true,
		"http://cp.example.com:7070": false, "http://10.0.0.5:7070": false, "ftp://localhost": false, "cp.example.com": false, "": false,
	} {
		if err := checkAdminURL(url); (err == nil) != ok {
			t.Errorf("checkAdminURL(%q) = %v, want ok=%v", url, err, ok)
		}
	}
}

// TestKeysRotateBundleUnstage: --unstage takes the second signature away, audits
// once, and a repeat is a no-op.
func TestKeysRotateBundleUnstage(t *testing.T) {
	stateDir := bundleStateDir(t)
	rotate := func(flag string) (string, string, int) {
		return runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", flag, "--state-dir", stateDir)
	}
	if _, stderr, code := rotate("--stage"); code != 0 {
		t.Fatalf("stage: %q", stderr)
	}
	stdout, stderr, code := rotate("--unstage")
	if code != 0 || !strings.Contains(stdout, "unstaged") {
		t.Fatalf("unstage = %d %q %q", code, stdout, stderr)
	}
	if rows := auditRowsWithOp(t, stateDir, "unstage"); len(rows) != 1 {
		t.Fatalf("unstage audit rows = %v, want one", rows)
	}
	if stdout, _, code := rotate("--unstage"); code != 0 || !strings.Contains(stdout, "nothing is staged") {
		t.Errorf("second unstage = %d %q, want a no-op", code, stdout)
	}
	// The activate gate sees an unstaged key as unstaged.
	if _, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--activate", "--force", "--state-dir", stateDir); code == 0 || !strings.Contains(stderr, "not staged") {
		t.Errorf("activate after the unstage = %d %q, want a not-staged refusal", code, stderr)
	}
}
