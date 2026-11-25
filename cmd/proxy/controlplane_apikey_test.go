package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/apikeys/adapters/sqlitestore"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The offline `warden control-plane api-key` commands (W-P2-APIK-05).

const (
	apiKeyCLIOwner = "alice"
	apiKeyCLIGroup = "console-admins"
)

// apiKeyCLIConfig is an oidc console (its issuer unreachable: sessions are not
// needed here) with API keys and admin audit on.
func apiKeyCLIConfig(t *testing.T) string {
	t.Helper()
	return bgInfoConfig + bgConsoleYAML(deadIssuer(t), "  adminAudit:\n    enabled: true\n  apiKeys:\n    enabled: true\n")
}

// apiKeyStoreOn opens a Store handle on stateDir's database, as another process
// would: no Index, no Run.
func apiKeyStoreOn(t *testing.T, stateDir string) *sqlitestore.SQLiteStore {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName),
		cpstate.Enable(controlplane.StateMigrations(), sqlitestore.MigrationID))
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := sqlitestore.New(db, sqlitestore.Options{Registry: apikeys.NewP2Registry()})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func mintCLIKey(t *testing.T, st *sqlitestore.SQLiteStore, owner, name string) (token, id string) {
	t.Helper()
	tok, k, err := st.Create(context.Background(), apikeys.CreateParams{
		Name: name, OwnerIss: "https://idp.test", OwnerSub: owner, OwnerEmail: owner + "@example.com",
		OwnerGroups: []string{apiKeyCLIGroup}, Scopes: []apikeys.Scope{"policy:read"},
		TTL: 24 * time.Hour, MaxTTL: 8760 * time.Hour, MaxActive: 25,
	})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return tok, k.ID
}

func runAPIKey(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runWarden(t, append([]string{"control-plane", "api-key"}, args...)...)
}

// cliAuditRows returns action, target_ref and details_json of the api_keys
// audit rows written by the CLI, oldest first.
func cliAuditRows(t *testing.T, stateDir string) (rows [][3]string) {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rs, err := db.SQL().Query(`SELECT action, target_ref, details_json FROM admin_audit WHERE target = 'api_keys' AND auth_method = 'cli' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()
	for rs.Next() {
		var r [3]string
		if err := rs.Scan(&r[0], &r[1], &r[2]); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return rows
}

// TestAPIKeyCLIRevoke: with a control plane running on the state dir and a
// valid key, `api-key revoke --id` exits 0, the key's next requests turn 401
// within the Index's poll, and exactly one admin_audit row with auth_method cli
// is appended. A second revoke changes nothing and appends nothing.
func TestAPIKeyCLIRevoke(t *testing.T) {
	t.Setenv(bgTestSecretEn, bgTestSecret)
	cp := startBreakGlassCP(t, apiKeyCLIConfig(t))
	st := apiKeyStoreOn(t, cp.stateDir)
	token, id := mintCLIKey(t, st, apiKeyCLIOwner, "ci")
	bearer := map[string]string{"Authorization": "Bearer " + token}

	// Created behind the control plane's back: accepted after its next poll.
	waitStatus := func(want int, within time.Duration) time.Duration {
		t.Helper()
		start := time.Now()
		for {
			if code, _, _ := cp.do(t, http.MethodGet, "/dashboard/api/policy", "", "", bearer); code == want {
				return time.Since(start)
			}
			if time.Since(start) > within {
				t.Fatalf("GET /dashboard/api/policy never returned %d within %s", want, within)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitStatus(http.StatusOK, 10*time.Second)

	stdout, stderr, code := runAPIKey(t, "revoke", "--id", id, "--state-dir", cp.stateDir)
	if code != 0 {
		t.Fatalf("revoke exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, id) {
		t.Errorf("revoke output %q does not name the key", stdout)
	}
	// The poll is 2s; the ceiling leaves room for a loaded machine.
	waitStatus(http.StatusUnauthorized, 6*time.Second)

	rows := cliAuditRows(t, cp.stateDir)
	if len(rows) != 1 || rows[0][0] != "api_key.revoke" || rows[0][1] != "api_key:"+id {
		t.Fatalf("cli audit rows = %v, want one api_key.revoke for %s", rows, id)
	}
	k, err := st.Get(context.Background(), id)
	if err != nil || !strings.HasPrefix(k.RevokedBy, "cli:") {
		t.Fatalf("revoked_by = %q, %v; want cli:<os user>", k.RevokedBy, err)
	}
	for _, out := range []string{stdout, stderr, rows[0][2], cp.out.String()} {
		if strings.Contains(out, token) || strings.Contains(out, "wak_") {
			t.Fatalf("the key secret leaked: %q", out)
		}
	}

	// Idempotent: nothing changes, no second row.
	stdout, _, code = runAPIKey(t, "revoke", "--id", id, "--state-dir", cp.stateDir)
	if code != 0 || !strings.Contains(stdout, "already revoked") {
		t.Fatalf("second revoke = %d %q, want 0 and already revoked", code, stdout)
	}
	if rows := cliAuditRows(t, cp.stateDir); len(rows) != 1 {
		t.Fatalf("cli audit rows after a repeat = %d, want 1", len(rows))
	}
}

// TestAPIKeyCLIRevokeOwnerAndRefusals: --owner-sub revokes every unrevoked key
// of the owner (and only theirs) with one audit row; the refusals exit 1 or 2
// and change nothing.
func TestAPIKeyCLIRevokeOwnerAndRefusals(t *testing.T) {
	t.Setenv(bgTestSecretEn, bgTestSecret)
	cp := startBreakGlassCP(t, apiKeyCLIConfig(t))
	st := apiKeyStoreOn(t, cp.stateDir)
	_, a1 := mintCLIKey(t, st, "alice", "one")
	_, a2 := mintCLIKey(t, st, "alice", "two")
	_, b1 := mintCLIKey(t, st, "bob", "three")

	if _, _, code := runAPIKey(t, "revoke", "--state-dir", cp.stateDir); code != 2 {
		t.Errorf("revoke with no target exit = %d, want 2", code)
	}
	if _, _, code := runAPIKey(t, "revoke", "--id", a1, "--owner-sub", "alice", "--state-dir", cp.stateDir); code != 2 {
		t.Errorf("revoke with both targets exit = %d, want 2", code)
	}
	if _, stderr, code := runAPIKey(t, "revoke", "--id", "0000000000000000", "--state-dir", cp.stateDir); code != 1 || !strings.Contains(stderr, "no API key") {
		t.Errorf("revoke of an unknown id = %d %q, want 1", code, stderr)
	}
	if _, _, code := runAPIKey(t, "revoke", "--id", a1, "--state-dir", filepath.Join(t.TempDir(), "absent")); code != 1 {
		t.Errorf("revoke in a missing state dir exit = %d, want 1", code)
	}
	if rows := cliAuditRows(t, cp.stateDir); len(rows) != 0 {
		t.Fatalf("refusals wrote audit rows: %v", rows)
	}

	stdout, stderr, code := runAPIKey(t, "revoke", "--owner-sub", "alice", "--state-dir", cp.stateDir)
	if code != 0 || !strings.Contains(stdout, a1) || !strings.Contains(stdout, a2) || strings.Contains(stdout, b1) {
		t.Fatalf("owner revoke = %d %q %q, want alice's two keys only", code, stdout, stderr)
	}
	rows := cliAuditRows(t, cp.stateDir)
	if len(rows) != 1 || rows[0][0] != "api_key.revoke_owner" {
		t.Fatalf("audit rows = %v, want one api_key.revoke_owner", rows)
	}
	var d map[string]string
	if err := json.Unmarshal([]byte(rows[0][2]), &d); err != nil || d["count"] != "2" {
		t.Errorf("owner revoke details = %v (%v), want count 2", d, err)
	}
	if k, _ := st.Get(context.Background(), b1); !k.RevokedAt.IsZero() {
		t.Error("bob's key was revoked by an alice revoke")
	}
	if _, stderr, code := runAPIKey(t, "revoke", "--owner-sub", "nobody", "--state-dir", cp.stateDir); code != 1 || !strings.Contains(stderr, "no API keys for owner nobody") {
		t.Errorf("revoke of an unknown owner = %d %q, want 1", code, stderr)
	}
	stdout, _, code = runAPIKey(t, "revoke", "--owner-sub", "alice", "--state-dir", cp.stateDir)
	if code != 0 || !strings.Contains(stdout, "no unrevoked keys") {
		t.Errorf("repeat owner revoke = %d %q", code, stdout)
	}
}

// TestAPIKeyCLIList: list prints id, name, owner email, scopes, expiry and
// status, as a table and as JSON, and never a secret or a hash. A state dir that
// never held keys lists nothing and revoke says so.
func TestAPIKeyCLIList(t *testing.T) {
	t.Setenv(bgTestSecretEn, bgTestSecret)
	cp := startBreakGlassCP(t, apiKeyCLIConfig(t))
	st := apiKeyStoreOn(t, cp.stateDir)
	token, id := mintCLIKey(t, st, "alice", "ci")
	_, id2 := mintCLIKey(t, st, "bob", "other")
	if err := st.Revoke(context.Background(), id2, "cli:test"); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runAPIKey(t, "list", "--state-dir", cp.stateDir)
	if code != 0 {
		t.Fatalf("list exit %d: %s", code, stderr)
	}
	for _, want := range []string{id, "ci", "alice@example.com", "policy:read", "active", id2, "revoked"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list output lacks %q:\n%s", want, stdout)
		}
	}
	jout, _, code := runAPIKey(t, "list", "--json", "--state-dir", cp.stateDir)
	var rows []apiKeyListJSON
	if code != 0 || json.Unmarshal([]byte(jout), &rows) != nil || len(rows) != 2 {
		t.Fatalf("list --json = %d %q", code, jout)
	}
	secret := token[strings.LastIndex(token, "_")+1:]
	for _, out := range []string{stdout, jout} {
		if strings.Contains(out, "wak_") || strings.Contains(out, secret) || strings.Contains(out, "secret_hash") {
			t.Fatalf("list output carries key material:\n%s", out)
		}
	}
	if _, _, code := runAPIKey(t, "list"); code != 2 {
		t.Errorf("list without --state-dir exit = %d, want 2", code)
	}
	if _, _, code := runAPIKey(t); code != 2 {
		t.Errorf("api-key without a subcommand exit = %d, want 2", code)
	}

	// A state dir that never enabled keys.
	plain := seedStateDir(t, restoreCfg)
	if out, _, code := runAPIKey(t, "list", "--state-dir", plain); code != 0 || strings.Count(out, "\n") != 1 {
		t.Errorf("list on a keyless state dir = %d %q, want only the header", code, out)
	}
	if _, stderr, code := runAPIKey(t, "revoke", "--id", id, "--state-dir", plain); code != 1 || !strings.Contains(stderr, "no API keys") {
		t.Errorf("revoke on a keyless state dir = %d %q, want 1", code, stderr)
	}
}

// TestRestoreRevokeAPIKeys: restoring a backup with --revoke-api-keys leaves
// every api_keys row revoked (as cli:<os user>), records the count of keys it
// revoked in the cp.restore row, keeps the audit chain verifying and prints the
// API-key warning. Without the flag the keys come back as they were.
func TestRestoreRevokeAPIKeys(t *testing.T) {
	ctx := context.Background()
	src := seedStateDir(t, restoreCfg)
	st := apiKeyStoreOn(t, src)
	_, active1 := mintCLIKey(t, st, "alice", "one")
	_, active2 := mintCLIKey(t, st, "bob", "two")
	_, revoked := mintCLIKey(t, st, "carol", "three")
	if err := st.Revoke(ctx, revoked, "console-admin"); err != nil {
		t.Fatal(err)
	}
	f := restoreFix{src: src, keyFile: adminaudit.DefaultKeyPath(src)}
	stdout, stderr, code := runWarden(t, "control-plane", "backup", "--state-dir", src, "--backup-dir", filepath.Join(t.TempDir(), "backups"))
	if code != 0 {
		t.Fatalf("backup exit %d: %s", code, stderr)
	}
	f.set = strings.TrimSpace(stdout)

	// Without the flag: the keys are exactly as backed up, and the warning
	// names API-key revocations.
	_, plain := f.target(t)
	out, stderr, code := restoreCLI(t, f.set, plain)
	if code != 0 {
		t.Fatalf("restore exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "API-key revocations") {
		t.Errorf("restore output lacks the API-key warning:\n%s", out)
	}
	if got := countRevoked(t, plain); got != 1 {
		t.Errorf("revoked keys after a plain restore = %d, want the 1 in the backup", got)
	}
	if d := auditEntries(t, plain)[0].Details; d[controlplane.RestoreDetailAPIKeysRevoked] != "" {
		t.Errorf("cp.restore details %v carry api_keys_revoked without the flag", d)
	}

	// With the flag.
	_, state := f.target(t)
	out, stderr, code = restoreCLI(t, f.set, state, "--revoke-api-keys")
	if code != 0 {
		t.Fatalf("restore --revoke-api-keys exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "revoked 2 API key(s)") {
		t.Errorf("restore output lacks the revocation count:\n%s", out)
	}
	restored := apiKeyStoreOn(t, state)
	keys, err := restored.List(ctx, apikeys.ListFilter{})
	if err != nil || len(keys) != 3 {
		t.Fatalf("restored keys = %d, %v; want 3", len(keys), err)
	}
	for _, k := range keys {
		if k.RevokedAt.IsZero() || k.RevokedBy == "" {
			t.Errorf("key %s is not revoked after --revoke-api-keys", k.ID)
		}
		switch k.ID {
		case active1, active2:
			if !strings.HasPrefix(k.RevokedBy, "cli:") {
				t.Errorf("key %s revoked_by = %q, want cli:<os user>", k.ID, k.RevokedBy)
			}
		case revoked:
			if k.RevokedBy != "console-admin" {
				t.Errorf("already revoked key lost its revoked_by: %q", k.RevokedBy)
			}
		}
	}
	if out, errOut, c := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", state); c != 0 {
		t.Fatalf("admin-audit verify exit %d: %s %s", c, out, errOut)
	}
	items := auditEntries(t, state)
	if items[0].Action != controlplane.RestoreAuditAction || items[0].Details[controlplane.RestoreDetailAPIKeysRevoked] != "2" {
		t.Errorf("cp.restore row = %+v, want api_keys_revoked 2", items[0])
	}
}

func countRevoked(t *testing.T, stateDir string) int {
	t.Helper()
	keys, err := apiKeyStoreOn(t, stateDir).List(context.Background(), apikeys.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, k := range keys {
		if !k.RevokedAt.IsZero() {
			n++
		}
	}
	return n
}
