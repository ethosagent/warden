package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The offline `warden control-plane block` commands (W-P1-BLOCK-08). The tests
// share a state dir with an in-process control plane.

// runBlock runs `warden control-plane block <args>` and returns stdout, stderr
// and the exit code.
func runBlock(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	root := newRootCmd()
	root.SetArgs(append([]string{"control-plane", "block"}, args...))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetContext(context.Background())
	err := root.Execute()
	code = 0
	if err != nil {
		code = exitCode(err)
		errOut.WriteString(err.Error())
	}
	return out.String(), errOut.String(), code
}

// blockPolicy GETs /policy (optionally parked on etag with wait) and returns
// the status, the ETag and the blockedUsers.
func blockPolicy(t *testing.T, client *http.Client, base, etag, wait string) (int, string, []map[string]string) {
	t.Helper()
	url := base + "/policy"
	if wait != "" {
		url += "?wait=" + wait
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /policy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var w struct {
		BlockedUsers []map[string]string `json:"blockedUsers"`
	}
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&w); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, resp.Header.Get("ETag"), w.BlockedUsers
}

func newStateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// blockRows reads the blocked_users ids.
func blockRows(t *testing.T, stateDir string) []controlplane.BlockEntry {
	t.Helper()
	entries, err := controlplane.ListBlockedOffline(context.Background(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// TestControlPlaneBlockCmd: with a CP running on the state dir and a worker
// long-poll waiting, `block add` exits 0 and the long-poll returns blockedUsers
// with alice within 3s.
func TestControlPlaneBlockCmd(t *testing.T) {
	stateDir := newStateDir(t)
	base := startVersionedCP(t, stateDir, importBaseConfig)
	client := &http.Client{Timeout: 40 * time.Second}
	status, etag, users := blockPolicy(t, client, base, "", "")
	if status != http.StatusOK || etag == "" || len(users) != 0 {
		t.Fatalf("GET /policy = %d %q %v", status, etag, users)
	}
	type result struct {
		status int
		users  []map[string]string
		at     time.Time
	}
	polled := make(chan result, 1)
	go func() {
		s, _, u := blockPolicy(t, client, base, etag, "30s")
		polled <- result{s, u, time.Now()}
	}()

	start := time.Now()
	stdout, stderr, code := runBlock(t, "add", "--email", "alice@corp.com", "--reason", "test", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("add exit %d: %s", code, stderr)
	}
	id := strings.TrimSpace(stdout)
	if !strings.HasPrefix(id, "bu_") {
		t.Errorf("stdout = %q, want the new id", stdout)
	}
	select {
	case r := <-polled:
		if r.status != http.StatusOK || len(r.users) != 1 || r.users[0]["email"] != "alice@corp.com" {
			t.Errorf("long-poll = %d %v, want 200 with alice", r.status, r.users)
		}
		if d := r.at.Sub(start); d > 3*time.Second {
			t.Errorf("long-poll woke after %s, want within 3s", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long-poll did not return after the CLI add")
	}
}

// TestControlPlaneBlockRemove: remove restores the previous /policy ETag, and
// an unknown id exits 2.
func TestControlPlaneBlockRemove(t *testing.T) {
	stateDir := newStateDir(t)
	base := startVersionedCP(t, stateDir, importBaseConfig)
	client := &http.Client{Timeout: 40 * time.Second}
	_, etag0, _ := blockPolicy(t, client, base, "", "")

	stdout, stderr, code := runBlock(t, "add", "--sub", "u-1", "--reason", "r", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("add exit %d: %s", code, stderr)
	}
	id := strings.TrimSpace(stdout)
	_, etag1, _ := blockPolicy(t, client, base, etag0, "10s")
	if etag1 == etag0 {
		t.Fatal("the ETag did not change after the add")
	}

	if _, stderr, code := runBlock(t, "remove", "--id", id, "--state-dir", stateDir); code != 0 {
		t.Fatalf("remove exit %d: %s", code, stderr)
	}
	_, etag2, users := blockPolicy(t, client, base, etag1, "10s")
	if etag2 != etag0 || len(users) != 0 {
		t.Errorf("ETag after remove = %q (%v), want the original %q", etag2, users, etag0)
	}

	_, stderr, code = runBlock(t, "remove", "--id", "bu_0000000000000000", "--state-dir", stateDir)
	if code != 2 || !strings.Contains(stderr, "not found") {
		t.Errorf("unknown id: exit %d %q, want 2 with a not-found message", code, stderr)
	}
}

// TestControlPlaneBlockValidation: a duplicate email in another case exits 1
// with the store's message, and add with neither --sub nor --email exits 1 with
// no row written.
func TestControlPlaneBlockValidation(t *testing.T) {
	stateDir := newStateDir(t)
	if _, stderr, code := runBlock(t, "add", "--email", "alice@corp.com", "--reason", "r", "--state-dir", stateDir); code != 0 {
		t.Fatalf("add exit %d: %s", code, stderr)
	}
	_, stderr, code := runBlock(t, "add", "--email", "ALICE@Corp.com", "--reason", "r", "--state-dir", stateDir)
	if code != 1 || !strings.Contains(stderr, controlplane.ErrDuplicate.Error()) {
		t.Errorf("duplicate: exit %d %q, want 1 with %q", code, stderr, controlplane.ErrDuplicate)
	}
	_, stderr, code = runBlock(t, "add", "--reason", "r", "--state-dir", stateDir)
	if code != 1 || !strings.Contains(stderr, controlplane.ErrInvalid.Error()) {
		t.Errorf("no identity: exit %d %q, want 1 with %q", code, stderr, controlplane.ErrInvalid)
	}
	_, _, code = runBlock(t, "add", "--sub", "u", "--reason", "bad\nreason", "--state-dir", stateDir)
	if code != 1 {
		t.Errorf("control character in the reason: exit %d, want 1", code)
	}
	if rows := blockRows(t, stateDir); len(rows) != 1 || rows[0].Email != "alice@corp.com" {
		t.Errorf("rows = %+v, want only alice", rows)
	}
}

// verifyChain verifies the admin audit chain in stateDir.
func verifyChain(t *testing.T, stateDir string) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s, err := adminaudit.Open(context.Background(), db, adminaudit.OpenOptions{KeyFile: adminaudit.DefaultKeyPath(stateDir)})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Verify(context.Background(), adminaudit.VerifyOptions{})
	if err != nil || !res.OK {
		t.Fatalf("admin audit chain does not verify: %+v %v", res, err)
	}
}

// blockAuditRefs returns the target_ref of every admin_audit row with action.
func blockAuditRefs(t *testing.T, stateDir, action string) []string {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT target_ref FROM admin_audit WHERE action = ? AND auth_method = 'cli' AND target = 'blocked_users' ORDER BY seq`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			t.Fatal(err)
		}
		out = append(out, ref)
	}
	return out
}

// TestControlPlaneBlockAudit: after interleaved block and policy CLI writes
// the chain verifies and each block action has exactly one cli row.
func TestControlPlaneBlockAudit(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig+auditConfig)
	var ids []string
	for _, email := range []string{"a@corp.com", "b@corp.com"} {
		stdout, stderr, code := runBlock(t, "add", "--email", email, "--reason", "r", "--state-dir", stateDir)
		if code != 0 {
			t.Fatalf("add exit %d: %s", code, stderr)
		}
		ids = append(ids, strings.TrimSpace(stdout))
		if len(ids) == 1 {
			// Another offline writer in between, on the same chain.
			file := writeTempConfig(t, importNewConfig)
			if _, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file); err != nil {
				t.Fatalf("import: %v %s", err, stderr)
			}
		}
	}
	if _, stderr, code := runBlock(t, "remove", "--id", ids[0], "--state-dir", stateDir); code != 0 {
		t.Fatalf("remove exit %d: %s", code, stderr)
	}
	// A refused add (duplicate) appends nothing.
	if _, _, code := runBlock(t, "add", "--email", "b@corp.com", "--reason", "r", "--state-dir", stateDir); code != 1 {
		t.Fatalf("duplicate add exit %d, want 1", code)
	}
	// An unknown id appends nothing.
	if _, _, code := runBlock(t, "remove", "--id", "bu_ffffffffffffffff", "--state-dir", stateDir); code != 2 {
		t.Fatalf("unknown remove exit %d, want 2", code)
	}

	verifyChain(t, stateDir)
	adds := blockAuditRefs(t, stateDir, "blocked_users.add")
	if len(adds) != 2 || adds[0] != "block:"+ids[0] || adds[1] != "block:"+ids[1] {
		t.Errorf("add rows = %v, want one per added id %v", adds, ids)
	}
	if rm := blockAuditRefs(t, stateDir, "blocked_users.remove"); len(rm) != 1 || rm[0] != "block:"+ids[0] {
		t.Errorf("remove rows = %v, want one for %s", rm, ids[0])
	}
	if rows := blockRows(t, stateDir); len(rows) != 1 || rows[0].ID != ids[1] || rows[0].CreatedBy != cliUser(t) {
		t.Errorf("rows = %+v, want only %s created by %s", rows, ids[1], cliUser(t))
	}
}

// TestControlPlaneBlockKeyMissing: with admin_audit rows present and the key
// file missing, add and remove exit non-zero and write nothing, block row
// included.
func TestControlPlaneBlockKeyMissing(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig+auditConfig)
	stdout, stderr, code := runBlock(t, "add", "--sub", "keep", "--reason", "r", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("add exit %d: %s", code, stderr)
	}
	id := strings.TrimSpace(stdout)
	if err := os.Remove(adminaudit.DefaultKeyPath(stateDir)); err != nil {
		t.Fatal(err)
	}
	_, stderr, code = runBlock(t, "add", "--sub", "new", "--reason", "r", "--state-dir", stateDir)
	if code == 0 || !strings.Contains(stderr, "admin audit") {
		t.Errorf("add without the key: exit %d %q, want an admin audit error", code, stderr)
	}
	_, stderr, code = runBlock(t, "remove", "--id", id, "--state-dir", stateDir)
	if code == 0 || !strings.Contains(stderr, "admin audit") {
		t.Errorf("remove without the key: exit %d %q, want an admin audit error", code, stderr)
	}
	if rows := blockRows(t, stateDir); len(rows) != 1 || rows[0].ID != id {
		t.Errorf("rows = %+v, want only the first entry", rows)
	}
	if refs := blockAuditRefs(t, stateDir, "blocked_users.add"); len(refs) != 1 {
		t.Errorf("add rows = %v, want 1", refs)
	}
	if refs := blockAuditRefs(t, stateDir, "blocked_users.remove"); len(refs) != 0 {
		t.Errorf("remove rows = %v, want none", refs)
	}
}

// TestControlPlaneBlockNoAudit: with admin audit never enabled the write goes
// through with a one-line notice.
func TestControlPlaneBlockNoAudit(t *testing.T) {
	stateDir := newStateDir(t)
	_, stderr, code := runBlock(t, "add", "--sub", "u", "--reason", "r", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("add exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "admin audit is not enabled") || strings.Count(strings.TrimSpace(stderr), "\n") != 0 {
		t.Errorf("stderr = %q, want a one-line notice", stderr)
	}
}

// TestControlPlaneBlockList: list prints the entries, as JSON with --json.
func TestControlPlaneBlockList(t *testing.T) {
	stateDir := newStateDir(t)
	if _, _, code := runBlock(t, "add", "--email", "Alice@Corp.com", "--sub", "s1", "--reason", "left", "--state-dir", stateDir); code != 0 {
		t.Fatal("add failed")
	}
	stdout, _, code := runBlock(t, "list", "--state-dir", stateDir)
	if code != 0 || !strings.Contains(stdout, "alice@corp.com") || !strings.Contains(stdout, "left") || !strings.Contains(stdout, "ID") {
		t.Errorf("list = %d %q", code, stdout)
	}
	stdout, _, code = runBlock(t, "list", "--json", "--state-dir", stateDir)
	var rows []blockListJSON
	if err := json.Unmarshal([]byte(stdout), &rows); code != 0 || err != nil {
		t.Fatalf("list --json = %d %q (%v)", code, stdout, err)
	}
	if len(rows) != 1 || rows[0].Sub != "s1" || rows[0].Email != "alice@corp.com" || rows[0].CreatedBy != cliUser(t) {
		t.Errorf("rows = %+v", rows)
	}
	// An empty list is [], not null.
	empty := newStateDir(t)
	if _, _, code := runBlock(t, "add", "--sub", "x", "--reason", "r", "--state-dir", empty); code != 0 {
		t.Fatal("add failed")
	}
	rows2 := blockRows(t, empty)
	if _, _, code := runBlock(t, "remove", "--id", rows2[0].ID, "--state-dir", empty); code != 0 {
		t.Fatal("remove failed")
	}
	if stdout, _, _ := runBlock(t, "list", "--json", "--state-dir", empty); strings.TrimSpace(stdout) != "[]" {
		t.Errorf("empty list = %q, want []", stdout)
	}
	// A missing state dir or database is an error.
	if _, _, code := runBlock(t, "list", "--state-dir", filepath.Join(t.TempDir(), "nope")); code == 0 {
		t.Error("list on a missing state dir succeeded")
	}
	if _, _, code := runBlock(t, "remove", "--id", "x", "--state-dir", filepath.Join(t.TempDir(), "nope")); code == 0 {
		t.Error("remove on a missing state dir succeeded")
	}
	if _, _, code := runBlock(t, "add", "--sub", "x", "--state-dir", filepath.Join(t.TempDir(), "nope")); code == 0 {
		t.Error("add on a missing state dir succeeded")
	}
}
