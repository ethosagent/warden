package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The warden control-plane enroll-token commands (W-P2-WCA-02).

// A fixed imported value: a well-formed wet_ token (prefix + 52 base32 chars).
const enrollImportA = "wet_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func enrollDBCount(t *testing.T, stateDir, where string, args ...any) int {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow("SELECT count(*) FROM worker_enroll_tokens WHERE "+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestControlPlaneEnrollTokenCmd: create --from-env twice makes one row and
// prints no plaintext; list shows the metadata and never a value.
func TestControlPlaneEnrollTokenCmdImportIsIdempotent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state") // no database yet: create bootstraps it
	t.Setenv("WARDEN_WORKER_2_ENROLL", enrollImportA)
	args := []string{"control-plane", "enroll-token", "create", "--worker-id", "worker-2",
		"--from-env", "WARDEN_WORKER_2_ENROLL", "--state-dir", stateDir}
	var outs []string
	for i := range 2 {
		stdout, stderr, code := runWarden(t, args...)
		if code != 0 {
			t.Fatalf("run %d exit = %d, %s", i, code, stderr)
		}
		if strings.Contains(stdout+stderr, enrollImportA) {
			t.Fatalf("run %d printed the plaintext", i)
		}
		outs = append(outs, stdout)
	}
	if !strings.Contains(outs[0], "created enrollment token et_") || !strings.Contains(outs[1], "no change") {
		t.Errorf("outputs: %q", outs)
	}
	if n := enrollDBCount(t, stateDir, "worker_id = 'worker-2'"); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	list, stderr, code := runWarden(t, "control-plane", "enroll-token", "list", "--json", "--state-dir", stateDir)
	if code != 0 || strings.Contains(list, enrollImportA) || !strings.Contains(list, `"workerId": "worker-2"`) || !strings.Contains(list, `"status": "active"`) {
		t.Fatalf("list --json = %d %s %s", code, list, stderr)
	}
	table, _, code := runWarden(t, "control-plane", "enroll-token", "list", "--state-dir", stateDir)
	if code != 0 || !strings.Contains(table, "worker-2") || !strings.Contains(table, "0/1") {
		t.Fatalf("list = %d %s", code, table)
	}
	// A conflicting value under the same name, and a bad value, fail.
	t.Setenv("WARDEN_OTHER_ENROLL", "wet_"+strings.Repeat("b", 52))
	if _, _, code := runWarden(t, "control-plane", "enroll-token", "create", "--worker-id", "worker-2",
		"--from-env", "WARDEN_OTHER_ENROLL", "--state-dir", stateDir); code == 0 {
		t.Error("same name, other value exited 0")
	}
	t.Setenv("WARDEN_BAD_ENROLL", "not-a-token")
	stdout, stderr, code := runWarden(t, "control-plane", "enroll-token", "create", "--worker-id", "worker-9",
		"--from-env", "WARDEN_BAD_ENROLL", "--state-dir", stateDir)
	if code != 1 || strings.Contains(stdout+stderr, "not-a-token") {
		t.Errorf("malformed import: exit %d %q %q", code, stdout, stderr)
	}
}

func TestControlPlaneEnrollTokenCmdMintAndFlags(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	out := filepath.Join(t.TempDir(), "pool.token")
	_, stderr, code := runWarden(t, "control-plane", "enroll-token", "create", "--worker-id-prefix", "pool-a-",
		"--max-uses", "3", "--expires-in", "30m", "--out", out, "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("create exit = %d, %s", code, stderr)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("--out: %v %v", err, fi)
	}
	b, _ := os.ReadFile(out)
	if tok := strings.TrimSpace(string(b)); !strings.HasPrefix(tok, "wet_") || len(tok) != 56 {
		t.Fatalf("--out content %q", tok)
	}
	if n := enrollDBCount(t, stateDir, "worker_id_prefix = 'pool-a-' AND max_uses = 3"); n != 1 {
		t.Fatalf("pool rows = %d", n)
	}
	// Without --out the plaintext is alone on stdout.
	stdout, _, code := runWarden(t, "control-plane", "enroll-token", "create", "--worker-id", "worker-1", "--state-dir", stateDir)
	if tok := strings.TrimSpace(stdout); code != 0 || !strings.HasPrefix(tok, "wet_") || strings.Contains(tok, " ") {
		t.Fatalf("stdout %q (exit %d)", stdout, code)
	}
	// An existing --out file is never clobbered and leaves no row.
	if _, _, code := runWarden(t, "control-plane", "enroll-token", "create", "--worker-id", "worker-3", "--out", out, "--state-dir", stateDir); code == 0 {
		t.Error("create over an existing --out file succeeded")
	}
	if n := enrollDBCount(t, stateDir, "worker_id = 'worker-3'"); n != 0 {
		t.Errorf("a failed --out left %d rows", n)
	}
	for name, args := range map[string][]string{
		"no binding":        {"--state-dir", stateDir},
		"both bindings":     {"--worker-id", "a", "--worker-id-prefix", "b-", "--state-dir", stateDir},
		"uses on an id":     {"--worker-id", "a", "--max-uses", "2", "--state-dir", stateDir},
		"too many uses":     {"--worker-id-prefix", "b-", "--max-uses", "101", "--state-dir", stateDir},
		"ttl over the max":  {"--worker-id", "a", "--expires-in", "48h", "--state-dir", stateDir},
		"negative ttl":      {"--worker-id", "a", "--expires-in", "-1h", "--state-dir", stateDir},
		"env and file":      {"--worker-id", "a", "--from-env", "X", "--from-file", "Y", "--state-dir", stateDir},
		"bad worker id":     {"--worker-id", "a b", "--state-dir", stateDir},
		"missing state dir": {"--worker-id", "a"},
	} {
		if _, _, code := runWarden(t, append([]string{"control-plane", "enroll-token", "create"}, args...)...); code == 0 {
			t.Errorf("%s exited 0", name)
		}
	}
	// --config raises the maximum lifetime.
	cfg := writeTempConfig(t, importBaseConfig+"\nworkerCA:\n  enrollTokenMaxTTL: 72h\n")
	if _, stderr, code := runWarden(t, "control-plane", "enroll-token", "create", "--worker-id", "worker-long",
		"--expires-in", "48h", "--config", cfg, "--state-dir", stateDir); code != 0 {
		t.Errorf("--config with a 72h maximum: exit %d %s", code, stderr)
	}
}

func TestControlPlaneEnrollTokenCmdRevokeAndAudit(t *testing.T) {
	stateDir := seedAuditStateDir(t, 3)
	ctx := context.Background()
	stdout, stderr, code := runWarden(t, "control-plane", "enroll-token", "create", "--worker-id", "worker-1", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("create exit = %d, %s", code, stderr)
	}
	tok := strings.TrimSpace(stdout)
	listOut, _, _ := runWarden(t, "control-plane", "enroll-token", "list", "--json", "--state-dir", stateDir)
	i := strings.Index(listOut, `"et_`)
	id := listOut[i+1 : i+1+len("et_")+16]
	if _, stderr, code := runWarden(t, "control-plane", "enroll-token", "revoke", "--id", id, "--state-dir", stateDir); code != 0 {
		t.Fatalf("revoke exit = %d, %s", code, stderr)
	}
	if out, _, code := runWarden(t, "control-plane", "enroll-token", "revoke", "--id", id, "--state-dir", stateDir); code != 0 || !strings.Contains(out, "no change") {
		t.Errorf("second revoke: %d %q", code, out)
	}
	if _, _, code := runWarden(t, "control-plane", "enroll-token", "revoke", "--id", "et_nope", "--state-dir", stateDir); code != 2 {
		t.Errorf("unknown id exit = %d, want 2", code)
	}
	if n := enrollDBCount(t, stateDir, "revoked_at IS NOT NULL"); n != 1 {
		t.Errorf("revoked rows = %d", n)
	}

	rdb, err := cpstate.OpenReadOnly(ctx, filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rdb.Close() }()
	rows, err := rdb.SQL().Query(`SELECT a.action, a.target, a.target_ref, a.details_json, COALESCE(x.sub,'') FROM admin_audit a
		LEFT JOIN admin_audit_actor x ON x.seq = a.seq WHERE a.auth_method = 'cli' ORDER BY a.seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var actions []string
	for rows.Next() {
		var action, target, ref, details, sub string
		if err := rows.Scan(&action, &target, &ref, &details, &sub); err != nil {
			t.Fatal(err)
		}
		if target != "worker_enrollments" || ref != "enroll_token:"+id || sub != cliUser(t) || strings.Contains(details, tok) ||
			!strings.Contains(details, "worker-1") {
			t.Errorf("cli row %s target=%q ref=%q actor=%q details=%q", action, target, ref, sub, details)
		}
		actions = append(actions, action)
	}
	if strings.Join(actions, ",") != "worker_enroll_token.create,worker_enroll_token.revoke" {
		t.Errorf("cli rows: %v", actions)
	}
	vout, vstderr, vcode := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", stateDir)
	if vcode != 0 || !decodeReport(t, vout).OK {
		t.Fatalf("verify = %d %s %s", vcode, vout, vstderr)
	}
	if strings.Contains(vout+vstderr+listOut, tok) {
		t.Error("plaintext leaked")
	}
}

func TestControlPlaneEnrollTokenCmdListNeedsDatabase(t *testing.T) {
	if _, _, code := runWarden(t, "control-plane", "enroll-token", "list", "--state-dir", filepath.Join(t.TempDir(), "none")); code == 0 {
		t.Error("list over a missing state dir exited 0")
	}
}
