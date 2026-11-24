package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
)

// The offline `warden control-plane agent` commands (W-P2-AREG-06).

func runAgent(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	root := newRootCmd()
	root.SetArgs(append([]string{"control-plane", "agent"}, args...))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetContext(context.Background())
	if err := root.Execute(); err != nil {
		code = exitCode(err)
		errOut.WriteString(err.Error())
	}
	return out.String(), errOut.String(), code
}

// newJWKFile writes a fresh public Ed25519 JWK (extra members merged in) and
// returns its path and x coordinate.
func newJWKFile(t *testing.T, extra map[string]any) (path, x string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, err := keys.PublicJWK(pub, keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(j)
	doc := map[string]any{}
	_ = json.Unmarshal(raw, &doc)
	for k, v := range extra {
		doc[k] = v
	}
	body, _ := json.Marshal(doc)
	path = filepath.Join(t.TempDir(), "k.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, j.X
}

type listedAgent struct {
	ID        string   `json:"id"`
	Status    string   `json:"status"`
	Revision  int64    `json:"revision"`
	Groups    []string `json:"groups"`
	UpdatedBy string   `json:"updated_by"`
	Keys      []struct {
		KID       string `json:"kid"`
		JKTPrefix string `json:"jkt_prefix"`
	} `json:"keys"`
}

func listAgents(t *testing.T, stateDir string) []listedAgent {
	t.Helper()
	stdout, stderr, code := runAgent(t, "list", "--json", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("list exit %d: %s", code, stderr)
	}
	var rows []listedAgent
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("list json: %v\n%s", err, stdout)
	}
	return rows
}

// agentAuditRows returns action, target_ref and details_json of every agents
// audit row, oldest first.
func agentAuditRows(t *testing.T, stateDir string) (rows [][3]string) {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rs, err := db.SQL().Query(`SELECT action, target_ref, details_json FROM admin_audit WHERE target = 'agents' AND auth_method = 'cli' ORDER BY seq`)
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

// TestControlPlaneAgentRegisterList: register exits 0, list --json shows the
// agent active at revision 1 with an 8-character jkt prefix and no key
// coordinates, and the table form never prints the x coordinate either.
func TestControlPlaneAgentRegisterList(t *testing.T) {
	stateDir := newStateDir(t)
	jwk, x := newJWKFile(t, nil)
	stdout, stderr, code := runAgent(t, "register", "--id", "claude-code", "--jwk-file", jwk,
		"--groups", "warden-agents", "--display-name", "Claude Code", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("register exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "claude-code") {
		t.Errorf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "admin audit is not enabled") {
		t.Errorf("no audit warning on stderr: %q", stderr)
	}
	rows := listAgents(t, stateDir)
	if len(rows) != 1 || rows[0].ID != "claude-code" || rows[0].Status != "active" || rows[0].Revision != 1 ||
		len(rows[0].Keys) != 1 || len(rows[0].Keys[0].JKTPrefix) != 8 || len(rows[0].Groups) != 1 || rows[0].UpdatedBy != cliUser(t) {
		t.Fatalf("list = %+v", rows)
	}
	table, _, code := runAgent(t, "list", "--state-dir", stateDir)
	if code != 0 || !strings.Contains(table, "claude-code") || !strings.Contains(table, rows[0].Keys[0].JKTPrefix) {
		t.Errorf("table exit %d: %q", code, table)
	}
	if strings.Contains(table, x) {
		t.Errorf("table leaks the x coordinate: %q", table)
	}
	if _, _, code := runAgent(t, "register", "--id", "claude-code", "--jwk-file", jwk, "--groups", "g", "--state-dir", stateDir); code != 1 {
		t.Errorf("duplicate register exit %d, want 1", code)
	}
}

// TestControlPlaneAgentList_Empty: a state dir with no database lists nothing
// and an unreadable one fails.
func TestControlPlaneAgentListEmpty(t *testing.T) {
	stateDir := newStateDir(t)
	if _, _, code := runAgent(t, "list", "--state-dir", stateDir); code == 0 {
		t.Error("list on a state dir without a database exited 0")
	}
	if _, _, code := runAgent(t, "list"); code != 2 {
		t.Errorf("list without --state-dir exit %d, want 2", code)
	}
}

// TestControlPlaneAgentPrivateKeyRefused: a file with d exits non-zero naming
// keys[0].d, prints nothing else from the file and writes no row.
func TestControlPlaneAgentPrivateKeyRefused(t *testing.T) {
	stateDir := newStateDir(t)
	jwk, x := newJWKFile(t, map[string]any{"d": "c2VjcmV0LXByaXZhdGUtbWF0ZXJpYWw"})
	stdout, stderr, code := runAgent(t, "register", "--id", "a1", "--jwk-file", jwk, "--groups", "g", "--state-dir", stateDir)
	if code == 0 {
		t.Fatal("register with a private member exited 0")
	}
	if !strings.Contains(stderr, "keys[0].d") {
		t.Errorf("stderr does not name keys[0].d: %q", stderr)
	}
	for _, leak := range []string{"c2VjcmV0LXByaXZhdGUtbWF0ZXJpYWw", x} {
		if strings.Contains(stderr, leak) || strings.Contains(stdout, leak) {
			t.Errorf("output leaks file content %q", leak)
		}
	}
	if rows := listAgents(t, stateDir); len(rows) != 0 {
		t.Errorf("rows written: %+v", rows)
	}
}

// TestControlPlaneAgentJWKS: a JWKS file registers every key (a rotation
// pair), and the second key's private member is reported as keys[1].d.
func TestControlPlaneAgentJWKS(t *testing.T) {
	stateDir := newStateDir(t)
	a, _ := newJWKFile(t, nil)
	b, _ := newJWKFile(t, nil)
	ra, _ := os.ReadFile(a)
	rb, _ := os.ReadFile(b)
	set := filepath.Join(t.TempDir(), "set.json")
	_ = os.WriteFile(set, []byte(`{"keys":[`+string(ra)+`,`+string(rb)+`]}`), 0o600)
	if _, stderr, code := runAgent(t, "register", "--id", "pair", "--jwk-file", set, "--groups", "g", "--state-dir", stateDir); code != 0 {
		t.Fatalf("register jwks exit %d: %s", code, stderr)
	}
	if rows := listAgents(t, stateDir); len(rows) != 1 || len(rows[0].Keys) != 2 {
		t.Fatalf("list = %+v", rows)
	}
	bad, _ := newJWKFile(t, map[string]any{"d": "AAAA"})
	rbad, _ := os.ReadFile(bad)
	badSet := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(badSet, []byte(`{"keys":[`+string(ra)+`,`+string(rbad)+`]}`), 0o600)
	_, stderr, code := runAgent(t, "register", "--id", "bad", "--jwk-file", badSet, "--groups", "g", "--state-dir", stateDir)
	if code == 0 || !strings.Contains(stderr, "keys[1].d") {
		t.Errorf("exit %d stderr %q, want keys[1].d", code, stderr)
	}
}

// TestControlPlaneAgentFileErrors: unreadable, non-JSON and empty-set files
// exit 1 naming the file, never its content.
func TestControlPlaneAgentFileErrors(t *testing.T) {
	stateDir := newStateDir(t)
	dir := t.TempDir()
	notJSON := filepath.Join(dir, "n.json")
	_ = os.WriteFile(notJSON, []byte("not json secret-looking-text"), 0o600)
	empty := filepath.Join(dir, "e.json")
	_ = os.WriteFile(empty, []byte(`{"keys":[]}`), 0o600)
	huge := filepath.Join(dir, "h.json")
	_ = os.WriteFile(huge, bytes.Repeat([]byte(" "), 70<<10), 0o600)
	for _, p := range []string{filepath.Join(dir, "missing.json"), notJSON, empty, huge} {
		_, stderr, code := runAgent(t, "register", "--id", "a", "--jwk-file", p, "--groups", "g", "--state-dir", stateDir)
		if code != 1 || !strings.Contains(stderr, p) || strings.Contains(stderr, "secret-looking") {
			t.Errorf("%s: exit %d stderr %q", p, code, stderr)
		}
	}
}

// TestControlPlaneAgentStaleRevision: disable with a stale revision exits 1
// and changes nothing; with the right one it disables, enable re-enables, and
// a key bound to another agent is refused.
func TestControlPlaneAgentStaleRevision(t *testing.T) {
	stateDir := newStateDir(t)
	jwk, _ := newJWKFile(t, nil)
	if _, stderr, code := runAgent(t, "register", "--id", "a1", "--jwk-file", jwk, "--groups", "g", "--state-dir", stateDir); code != 0 {
		t.Fatalf("register: %s", stderr)
	}
	if _, stderr, code := runAgent(t, "disable", "--id", "a1", "--revision", "7", "--state-dir", stateDir); code != 1 || !strings.Contains(stderr, "stale revision") {
		t.Fatalf("stale disable exit %d: %s", code, stderr)
	}
	if rows := listAgents(t, stateDir); rows[0].Status != "active" || rows[0].Revision != 1 {
		t.Fatalf("stale disable changed the row: %+v", rows)
	}
	if _, stderr, code := runAgent(t, "disable", "--id", "a1", "--revision", "1", "--state-dir", stateDir); code != 0 {
		t.Fatalf("disable: %s", stderr)
	}
	if rows := listAgents(t, stateDir); rows[0].Status != "disabled" || rows[0].Revision != 2 {
		t.Fatalf("after disable: %+v", rows)
	}
	if _, stderr, code := runAgent(t, "enable", "--id", "a1", "--revision", "2", "--state-dir", stateDir); code != 0 {
		t.Fatalf("enable: %s", stderr)
	}
	if _, _, code := runAgent(t, "disable", "--id", "nope", "--revision", "1", "--state-dir", stateDir); code != 1 {
		t.Errorf("unknown id exit %d, want 1", code)
	}
	if _, stderr, code := runAgent(t, "register", "--id", "a2", "--jwk-file", jwk, "--groups", "g", "--state-dir", stateDir); code != 1 || !strings.Contains(stderr, "already bound") {
		t.Errorf("key-in-use exit %d: %s", code, stderr)
	}
}

// TestControlPlaneAgentUpdate: update changes only the given fields, requires
// the right revision and replaces keys as a set.
func TestControlPlaneAgentUpdate(t *testing.T) {
	stateDir := newStateDir(t)
	k1, _ := newJWKFile(t, nil)
	k2, _ := newJWKFile(t, nil)
	if _, stderr, code := runAgent(t, "register", "--id", "a1", "--jwk-file", k1, "--groups", "g1", "--state-dir", stateDir); code != 0 {
		t.Fatalf("register: %s", stderr)
	}
	if _, _, code := runAgent(t, "update", "--id", "a1", "--revision", "1", "--state-dir", stateDir); code != 2 {
		t.Errorf("update with nothing to change exit %d, want 2", code)
	}
	if _, stderr, code := runAgent(t, "update", "--id", "a1", "--revision", "9", "--groups", "g2", "--state-dir", stateDir); code != 1 || !strings.Contains(stderr, "stale revision") {
		t.Errorf("stale update exit %d: %s", code, stderr)
	}
	if _, stderr, code := runAgent(t, "update", "--id", "a1", "--revision", "1", "--groups", "g1,g2", "--jwk-file", k1, "--jwk-file", k2, "--state-dir", stateDir); code != 0 {
		t.Fatalf("update: %s", stderr)
	}
	rows := listAgents(t, stateDir)
	if rows[0].Revision != 2 || len(rows[0].Keys) != 2 || len(rows[0].Groups) != 2 {
		t.Fatalf("after update: %+v", rows)
	}
	if _, _, code := runAgent(t, "update", "--id", "a1", "--revision", "2", "--groups", "", "--state-dir", stateDir); code != 1 {
		t.Errorf("clearing groups of an active agent exit %d, want 1", code)
	}
}

// TestControlPlaneAgentAudit: each write appends exactly one cli row with the
// details allowlist and no key coordinate; refused writes append none.
func TestControlPlaneAgentAudit(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig+auditConfig)
	k1, x1 := newJWKFile(t, nil)
	k2, x2 := newJWKFile(t, nil)
	steps := [][]string{
		{"register", "--id", "a1", "--jwk-file", k1, "--groups", "g1"},
		{"update", "--id", "a1", "--revision", "1", "--groups", "g2", "--jwk-file", k2},
		{"disable", "--id", "a1", "--revision", "2"},
		{"enable", "--id", "a1", "--revision", "3"},
	}
	for _, s := range steps {
		if _, stderr, code := runAgent(t, append(s, "--state-dir", stateDir)...); code != 0 {
			t.Fatalf("%v exit %d: %s", s, code, stderr)
		}
	}
	// refused: stale revision
	if _, _, code := runAgent(t, "disable", "--id", "a1", "--revision", "1", "--state-dir", stateDir); code != 1 {
		t.Fatalf("stale exit %d", code)
	}
	rows := agentAuditRows(t, stateDir)
	want := []string{"agent.create", "agent.update", "agent.disable", "agent.enable"}
	if len(rows) != len(want) {
		t.Fatalf("audit rows = %v, want %v", rows, want)
	}
	for i, r := range rows {
		if r[0] != want[i] || r[1] != controlplane.AgentAuditRef("a1") {
			t.Errorf("row %d = %v", i, r)
		}
		if strings.Contains(r[2], x1) || strings.Contains(r[2], x2) || strings.Contains(r[2], `"x"`) {
			t.Errorf("row %d details leak key material: %s", i, r[2])
		}
	}
	if !strings.Contains(rows[1][2], "groupsAdded") || !strings.Contains(rows[1][2], "kidsAdded") || !strings.Contains(rows[1][2], "jktsAdded") {
		t.Errorf("update details = %s", rows[1][2])
	}
	if !strings.Contains(rows[2][2], "statusFrom") || !strings.Contains(rows[2][2], "disabled") {
		t.Errorf("disable details = %s", rows[2][2])
	}
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s, err := adminaudit.Open(context.Background(), db, adminaudit.OpenOptions{KeyFile: adminaudit.DefaultKeyPath(stateDir)})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := s.Verify(context.Background(), adminaudit.VerifyOptions{}); err != nil || !res.OK {
		t.Fatalf("chain does not verify: %+v %v", res, err)
	}
}

// TestControlPlaneAgentUsage: a missing subcommand or required flag exits 2.
func TestControlPlaneAgentUsage(t *testing.T) {
	stateDir := newStateDir(t)
	for _, args := range [][]string{
		{},
		{"register", "--state-dir", stateDir},
		{"disable", "--id", "a", "--state-dir", stateDir},
		{"register", "extra", "--id", "a", "--jwk-file", "x", "--state-dir", stateDir},
	} {
		if _, _, code := runAgent(t, args...); code != 2 {
			t.Errorf("%v exit %d, want 2", args, code)
		}
	}
	if _, _, code := runAgent(t, "register", "--id", "a", "--jwk-file", "x", "--state-dir", filepath.Join(stateDir, "missing")); code != 1 {
		t.Errorf("missing state dir should exit 1")
	}
}

// TestControlPlaneAgentRunningCP: a CLI write while a control plane holds the
// state dir succeeds (no lock refusal) and a store handle with the CP's watch
// sees it within the policy reload interval. The /policy wire for agents is
// AREG-04; until it lands the visibility proof is at the store level.
func TestControlPlaneAgentRunningCP(t *testing.T) {
	stateDir := newStateDir(t)
	startVersionedCP(t, stateDir, importBaseConfig)
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store := agentregsqlite.New(db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.Watch(ctx, 0)
	if got, _ := store.List(ctx); len(got) != 0 {
		t.Fatalf("pre-existing agents: %v", got)
	}
	jwk, _ := newJWKFile(t, nil)
	if _, stderr, code := runAgent(t, "register", "--id", "a1", "--jwk-file", jwk, "--groups", "g", "--state-dir", stateDir); code != 0 {
		t.Fatalf("register while CP runs: exit %d %s", code, stderr)
	}
	waitAgentStatus(t, store, "a1", agentreg.StatusActive)
	if _, stderr, code := runAgent(t, "disable", "--id", "a1", "--revision", "1", "--state-dir", stateDir); code != 0 {
		t.Fatalf("disable while CP runs: exit %d %s", code, stderr)
	}
	waitAgentStatus(t, store, "a1", agentreg.StatusDisabled)
}

func waitAgentStatus(t *testing.T, s *agentregsqlite.Store, id string, want agentreg.Status) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a, err := s.Get(context.Background(), id); err == nil && a.Status == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent %s not %s within 5s", id, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestControlPlaneAgentNoDBNotCreated: update, disable and enable on a state
// dir with no database exit 1 and create none.
func TestControlPlaneAgentNoDBNotCreated(t *testing.T) {
	stateDir := newStateDir(t)
	for _, args := range [][]string{
		{"disable", "--id", "a", "--revision", "1"},
		{"enable", "--id", "a", "--revision", "1"},
		{"update", "--id", "a", "--revision", "1", "--groups", "g"},
	} {
		if _, stderr, code := runAgent(t, append(args, "--state-dir", stateDir)...); code != 1 || !strings.Contains(stderr, "not found") {
			t.Errorf("%v exit %d: %s", args, code, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, adminaudit.StateDBFileName)); !os.IsNotExist(err) {
		t.Errorf("a database was created: %v", err)
	}
}
