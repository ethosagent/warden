//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// keysCLIConfig is the config the keys CLI tests boot the control plane with:
// keys enabled, admin audit enabled (the CLI's audit rows are assertions).
const keysCLIConfig = minimalConfig + "keys:\n  enabled: true\nconsole:\n  adminAudit:\n    enabled: true\n"

// startKeysCP boots a keys-enabled control plane on stateDir with an injected
// listener and waits until it serves; stop cancels it and returns Run's error.
func startKeysCP(t *testing.T, stateDir string) (addr string, stop func() error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	var out cpSyncBuffer
	go func() {
		errCh <- controlplane.Run(ctx, &out, controlplane.Params{
			ConfigPath: writeTempConfig(t, keysCLIConfig), StateDir: stateDir, Listener: ln,
			AnalyticsProvider: "memory",
			OnReady:           func(a string) { ready <- a },
		})
	}()
	select {
	case addr = <-ready:
	case err := <-errCh:
		cancel()
		t.Fatalf("control plane exited before ready: %v\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for the control plane")
	}
	var once sync.Once
	var stopErr error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopErr = <-errCh:
			case <-time.After(10 * time.Second):
				stopErr = errors.New("control plane did not stop")
			}
		})
		return stopErr
	}
	t.Cleanup(func() { _ = stop() })
	return addr, stop
}

// keyStates reads one purpose's kid→state rows from a state dir's database.
func keyStates(t *testing.T, stateDir, purpose string) map[string]string {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT kid, state FROM signing_keys WHERE purpose = ?`, purpose)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var kid, state string
		if err := rows.Scan(&kid, &state); err != nil {
			t.Fatal(err)
		}
		out[kid] = state
	}
	return out
}

// stateKid returns the kid whose state is state.
func stateKid(kids map[string]string, state string) string {
	for kid, s := range kids {
		if s == state {
			return kid
		}
	}
	return ""
}

func sliceHas(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// fetchJWKSKids fetches the served token JWKS and returns its kids. A fetch
// error returns nil: callers poll.
func fetchJWKSKids(addr string) ([]string, error) {
	resp, err := http.Get("http://" + addr + "/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET jwks: %s", resp.Status)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	kids := make([]string, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		kids = append(kids, k.Kid)
	}
	return kids, nil
}

// pollJWKSKids fetches the JWKS until want holds or the deadline passes: a
// rotation the CLI applied reaches the running control plane through the
// data-version poll within about 2 seconds.
func pollJWKSKids(t *testing.T, addr string, want func(kids []string) bool) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var kids []string
	for {
		got, err := fetchJWKSKids(addr)
		if err == nil {
			kids = got
			if want(kids) {
				return kids
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("jwks never matched; last kids = %v (last err %v)", kids, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// backdateNextPublish moves purpose's next key's publish_at behind its
// prepublish window (1h default), so a real-time non-emergency rotation may
// promote it.
func backdateNextPublish(t *testing.T, stateDir, purpose string) {
	t.Helper()
	execInDB(t, stateDir, fmt.Sprintf(
		`UPDATE signing_keys SET publish_at = publish_at - %d WHERE purpose = '%s' AND state = 'next'`,
		int64(time.Hour/time.Second), purpose))
}

// auditActionCount counts admin audit rows with action and auth method.
func auditActionCount(t *testing.T, stateDir, action, authMethod string) int {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM admin_audit WHERE action = ? AND auth_method = ?`,
		action, authMethod).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// auditOutcomeCount counts admin audit rows with action and outcome.
func auditOutcomeCount(t *testing.T, stateDir, action, outcome string) int {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM admin_audit WHERE action = ? AND outcome = ?`,
		action, outcome).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// extractJWKSKids parses a JWKS document and returns its kids.
func extractJWKSKids(t *testing.T, jwks string) []string {
	t.Helper()
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &doc); err != nil {
		t.Fatalf("jwks %q is not JSON: %v", jwks, err)
	}
	kids := make([]string, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

// TestKeysRotateCLI: with a control plane running on the same state dir, the
// CLI rotates the token key, prints the new active kid, and the served JWKS
// reflects the rotation within a few seconds through the data-version poll.
func TestKeysRotateCLI(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	addr, stop := startKeysCP(t, stateDir)

	before := keyStates(t, stateDir, "token")
	oldActive, oldNext := stateKid(before, "active"), stateKid(before, "next")
	if oldActive == "" || oldNext == "" {
		t.Fatalf("token rows = %v, want an active and a next key", before)
	}
	backdateNextPublish(t, stateDir, "token")

	stdout, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "token",
		"--state-dir", stateDir, "--config", writeTempConfig(t, keysCLIConfig))
	if code != 0 {
		t.Fatalf("rotate exit = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, oldNext) {
		t.Errorf("rotate output %q does not name the promoted kid %s", stdout, oldNext)
	}
	// The running control plane serves the promoted kid within seconds; the
	// retired one stays published for its overlap.
	kids := pollJWKSKids(t, addr, func(kids []string) bool {
		return sliceHas(kids, oldNext)
	})
	if !sliceHas(kids, oldActive) {
		t.Errorf("retired kid %s left the jwks at once: %v", oldActive, kids)
	}
	if n := auditActionCount(t, stateDir, "keys.rotate_requested", adminaudit.AuthMethodCLI); n != 1 {
		t.Errorf("cli rotate audit rows = %d, want 1", n)
	}
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

// TestKeysRotateEmergency: --emergency without --yes on a non-interactive
// stdin exits non-zero and changes nothing; with --yes it promotes the next
// key past its prepublish window, and the revoked kid leaves the served JWKS
// at once.
func TestKeysRotateEmergency(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	addr, stop := startKeysCP(t, stateDir)

	before := keyStates(t, stateDir, "token")
	oldActive := stateKid(before, "active")

	stdout, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "token",
		"--emergency", "--state-dir", stateDir)
	if code == 0 {
		t.Fatalf("emergency without --yes exit = 0, stdout %q", stdout)
	}
	if !strings.Contains(stderr, "--yes") {
		t.Errorf("refusal %q does not name --yes", stderr)
	}
	if after := keyStates(t, stateDir, "token"); len(after) != len(before) || stateKid(after, "active") != oldActive {
		t.Fatalf("a refused emergency changed the rows: %v -> %v", before, after)
	}

	stdout, stderr, code = runWarden(t, "control-plane", "keys", "rotate", "--purpose", "token",
		"--emergency", "--yes", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("emergency rotate exit = %d, stderr %q", code, stderr)
	}
	newActive := stateKid(keyStates(t, stateDir, "token"), "active")
	if newActive == "" || newActive == oldActive {
		t.Fatalf("emergency rotate left %s active", oldActive)
	}
	if !strings.Contains(stdout, newActive) {
		t.Errorf("rotate output %q does not name the new kid %s", stdout, newActive)
	}
	// The revoked kid is out of the published set at once.
	pollJWKSKids(t, addr, func(kids []string) bool {
		return !sliceHas(kids, oldActive) && sliceHas(kids, newActive)
	})
	if n := auditActionCount(t, stateDir, "keys.rotate_requested", adminaudit.AuthMethodCLI); n != 1 {
		t.Errorf("cli emergency rotate audit rows = %d, want 1 (the refused attempt appends none)", n)
	}
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

// TestKeysRotateEmergencyStood: an --emergency whose fresh next key cannot be
// written (a read-only key dir; the metadata database stays writable) still
// revokes: the command exits exitKeysRotationStood, says the compromised key
// IS revoked, and its audit row is outcome error — the rotation stands, only
// the next slot is empty.
func TestKeysRotateEmergencyStood(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	_, stop := startKeysCP(t, stateDir)
	before := keyStates(t, stateDir, "token")
	oldActive, oldNext := stateKid(before, "active"), stateKid(before, "next")
	if oldActive == "" || oldNext == "" {
		t.Fatalf("token rows = %v, want an active and a next key", before)
	}
	// Stopped, so nothing refills the empty next slot under the assertions.
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	pdir := filepath.Join(stateDir, "keys", "token")
	if err := os.Chmod(pdir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(pdir, 0o700) })

	stdout, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "token",
		"--emergency", "--yes", "--state-dir", stateDir)
	if code != exitKeysRotationStood {
		t.Fatalf("stood emergency exit = %d, want %d (stderr %q)", code, exitKeysRotationStood, stderr)
	}
	if !strings.Contains(stderr, "IS revoked") {
		t.Errorf("the stood message does not say the old key is revoked:\n%s", stderr)
	}
	after := keyStates(t, stateDir, "token")
	if stateKid(after, "active") != oldNext || stateKid(after, "revoked") != oldActive || stateKid(after, "next") != "" {
		t.Errorf("token rows = %v, want %s revoked and %s active with no next", after, oldActive, oldNext)
	}
	if n := auditOutcomeCount(t, stateDir, "keys.rotate_requested", adminaudit.OutcomeError); n != 1 {
		t.Errorf("stood rotate audit rows = %d, want the one error row", n)
	}
	if stdout != "" {
		t.Errorf("a stood rotation printed to stdout: %q", stdout)
	}
}

// TestKeysListExportOffline: list --json prints public metadata only — no `d`
// member and no PEM block — and export prints the published JWKS, or one
// key's public JWK with --state, with the control plane stopped and without a
// --config.
func TestKeysListExportOffline(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	_, stop := startKeysCP(t, stateDir)
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	stdout, stderr, code := runWarden(t, "control-plane", "keys", "list", "--state-dir", stateDir, "--json")
	if code != 0 {
		t.Fatalf("list exit = %d, stderr %q", code, stderr)
	}
	if strings.Contains(stdout, `"d"`) || strings.Contains(stdout, "PRIVATE") {
		t.Fatalf("list output leaks private material:\n%s", stdout)
	}
	var views []map[string]any
	if err := json.Unmarshal([]byte(stdout), &views); err != nil {
		t.Fatalf("list output is not JSON: %v\n%s", err, stdout)
	}
	if len(views) != 4 {
		t.Errorf("list = %d rows, want 2 per purpose", len(views))
	}
	for _, v := range views {
		for _, f := range []string{"kid", "purpose", "state", "alg"} {
			if _, ok := v[f]; !ok {
				t.Errorf("list row missing %q: %v", f, v)
			}
		}
	}

	stdout, stderr, code = runWarden(t, "control-plane", "keys", "export", "--purpose", "bundle", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("export exit = %d, stderr %q", code, stderr)
	}
	if strings.Contains(stdout, `"d"`) {
		t.Fatalf("export output leaks a d member:\n%s", stdout)
	}
	bundle := keyStates(t, stateDir, "bundle")
	got := extractJWKSKids(t, stdout)
	if len(got) != 2 ||
		!sliceHas(got, stateKid(bundle, "active")) || !sliceHas(got, stateKid(bundle, "next")) {
		t.Fatalf("exported jwks kids = %v, want the active and next bundle key (%v)", got, bundle)
	}

	stdout, stderr, code = runWarden(t, "control-plane", "keys", "export", "--purpose", "bundle",
		"--state", "next", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("export --state next exit = %d, stderr %q", code, stderr)
	}
	var jwk map[string]any
	if err := json.Unmarshal([]byte(stdout), &jwk); err != nil {
		t.Fatalf("export --state output is not a JWK: %v\n%s", err, stdout)
	}
	if jwk["kid"] != stateKid(bundle, "next") {
		t.Errorf("export --state next kid = %v, want %s", jwk["kid"], stateKid(bundle, "next"))
	}
}

// TestKeysRotateBundleAndResetRefusals: a bundle rotation exits non-zero and
// prints the next kid to pin, reset refuses --yes-less and refuses while the
// control plane holds the state dir lock, and a stopped reset regenerates the
// purpose.
func TestKeysRotateBundleAndResetRefusals(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	_, stop := startKeysCP(t, stateDir)

	bundle := keyStates(t, stateDir, "bundle")
	next := stateKid(bundle, "next")
	_, stderr, code := runWarden(t, "control-plane", "keys", "rotate", "--purpose", "bundle", "--state-dir", stateDir)
	if code == 0 {
		t.Fatalf("bundle rotate exit = 0, want a staged refusal")
	}
	if !strings.Contains(stderr, next) {
		t.Errorf("bundle refusal %q does not name the next kid %s", stderr, next)
	}
	if after := keyStates(t, stateDir, "bundle"); len(after) != len(bundle) {
		t.Errorf("a refused bundle rotation changed the rows: %v -> %v", bundle, after)
	}

	_, stderr, code = runWarden(t, "control-plane", "keys", "reset", "--purpose", "token", "--state-dir", stateDir)
	if code == 0 {
		t.Fatalf("reset without --yes exit = 0")
	}
	if !strings.Contains(stderr, "--yes") {
		t.Errorf("reset refusal %q does not name --yes", stderr)
	}
	_, stderr, code = runWarden(t, "control-plane", "keys", "reset", "--purpose", "token", "--yes", "--state-dir", stateDir)
	if code == 0 {
		t.Fatalf("reset under the running control plane exit = 0")
	}
	if !strings.Contains(stderr, "control plane is running") {
		t.Errorf("reset refusal %q does not name the running control plane", stderr)
	}
	if after := keyStates(t, stateDir, "token"); len(after) != 2 {
		t.Errorf("a refused reset changed the token rows: %v", after)
	}
	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// Stopped: the reset replaces the purpose, printing the fresh kid, and the
	// old kids are gone from the rows and the published set.
	before := keyStates(t, stateDir, "token")
	stdout, stderr, code := runWarden(t, "control-plane", "keys", "reset", "--purpose", "token",
		"--yes", "--state-dir", stateDir, "--config", writeTempConfig(t, keysCLIConfig))
	if code != 0 {
		t.Fatalf("reset exit = %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "removed 2 token key(s)") {
		t.Errorf("reset output %q does not report the removal", stdout)
	}
	after := keyStates(t, stateDir, "token")
	if stateKid(after, "active") == "" || stateKid(after, "next") == "" {
		t.Fatalf("token rows after the reset = %v, want a fresh active and next", after)
	}
	for kid := range before {
		if _, ok := after[kid]; ok {
			t.Errorf("kid %s survived the reset", kid)
		}
	}
	stdout, stderr, code = runWarden(t, "control-plane", "keys", "export", "--purpose", "token", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("token export after the reset exit = %d, stderr %q", code, stderr)
	}
	if got := extractJWKSKids(t, stdout); len(got) != 2 {
		t.Fatalf("token export after the reset = %v, want the two fresh keys", got)
	}
}
