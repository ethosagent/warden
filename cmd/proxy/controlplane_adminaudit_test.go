package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// seedAuditStateDir creates a state dir whose warden-cp.db holds a chain of
// genesis + n entries signed by a key in the same dir, the way a CP with
// console.adminAudit.enabled leaves it.
func seedAuditStateDir(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	db, err := cpstate.Open(ctx, filepath.Join(dir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s, err := adminaudit.Open(ctx, db, adminaudit.OpenOptions{KeyFile: adminaudit.DefaultKeyPath(dir)})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := s.Record(ctx, adminaudit.Input{
			Actor:     adminaudit.Actor{Sub: fmt.Sprintf("sub-%d", i%2), Email: fmt.Sprintf("person%d@example.org", i%2)},
			ActorRole: "admin", AuthMethod: adminaudit.AuthMethodOIDC,
			Action: "policy.update", Target: "policy", TargetRef: fmt.Sprintf("policy@%d", i),
			Outcome: adminaudit.OutcomeOK, HTTPStatus: 200,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// execInDB runs one statement on the state dir's database.
func execInDB(t *testing.T, dir, q string) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(dir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.SQL().Exec(q); err != nil {
		t.Fatal(err)
	}
}

// runWarden runs the root command with args and returns stdout, stderr and
// the process exit code main would use.
func runWarden(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetContext(context.Background())
	err := root.Execute()
	if err != nil {
		code = exitCode(err)
		errb.WriteString(err.Error())
	}
	return out.String(), errb.String(), code
}

func decodeReport(t *testing.T, stdout string) adminaudit.Report {
	t.Helper()
	var r adminaudit.Report
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("verify output %q is not a JSON report: %v", stdout, err)
	}
	return r
}

// TestAdminAuditVerifyCmd: on a seeded state dir verify exits 0 and prints
// ok=true; after one row is altered in SQL it exits 1 and prints its seq. An
// anchor at the old head catches removed newest rows.
func TestAdminAuditVerifyCmd(t *testing.T) {
	dir := seedAuditStateDir(t, 12)
	// The key files are not needed: move them away.
	keyDir := t.TempDir()
	for _, f := range []string{adminaudit.DefaultKeyFileName, adminaudit.HMACKeyFileName} {
		if err := os.Rename(filepath.Join(dir, f), filepath.Join(keyDir, f)); err != nil {
			t.Fatal(err)
		}
	}

	stdout, stderr, code := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir)
	if code != 0 {
		t.Fatalf("verify exit = %d, stderr %q", code, stderr)
	}
	r := decodeReport(t, stdout)
	if !r.OK || r.Checked != 13 || r.HeadSeq != 13 || len(r.HeadHash) != 64 || r.FirstBadSeq != 0 {
		t.Fatalf("verify report = %+v", r)
	}
	if !strings.Contains(stdout, `"ok":true`) {
		t.Errorf("stdout %q lacks ok=true", stdout)
	}
	anchor := fmt.Sprintf("%d:%s", r.HeadSeq, r.HeadHash)
	if _, stderr, code := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir, "--anchor", anchor); code != 0 {
		t.Fatalf("verify with the head anchor exit = %d, %s", code, stderr)
	}
	if stdout, _, code := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir, "--from-seq", "5"); code != 0 || decodeReport(t, stdout).Checked != 9 {
		t.Fatalf("verify --from-seq 5 = %d, %s", code, stdout)
	}

	execInDB(t, dir, "UPDATE admin_audit SET target_ref = 'policy@forged' WHERE seq = 7")
	stdout, stderr, code = runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir)
	if code != 1 {
		t.Fatalf("verify after tamper exit = %d, want 1 (stderr %q)", code, stderr)
	}
	r = decodeReport(t, stdout)
	if r.OK || r.FirstBadSeq != 7 || r.Reason != adminaudit.ReasonEntryHash {
		t.Fatalf("verify report after tamper = %+v, want firstBadSeq 7", r)
	}
	if !strings.Contains(stdout, `"firstBadSeq":7`) || !strings.Contains(stderr, "seq 7") {
		t.Errorf("tamper not reported at seq 7: stdout %q stderr %q", stdout, stderr)
	}

	// A fresh chain whose newest rows are then deleted: a plain verify passes,
	// the anchor at the old head fails.
	dir2 := seedAuditStateDir(t, 5)
	stdout, _, _ = runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir2)
	old := decodeReport(t, stdout)
	execInDB(t, dir2, "DELETE FROM admin_audit WHERE seq >= 5")
	if _, _, code := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir2); code != 0 {
		t.Fatalf("plain verify after tail deletion exit = %d, want 0", code)
	}
	stdout, _, code = runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir2, "--anchor", fmt.Sprintf("%d:%s", old.HeadSeq, old.HeadHash))
	if r := decodeReport(t, stdout); code != 1 || r.FirstBadSeq != 5 || r.Reason != adminaudit.ReasonAnchorMissing {
		t.Fatalf("anchored verify after tail deletion = %d %+v, want exit 1 at 5", code, r)
	}
}

// TestAdminAuditCmdUsageErrors: usage and I/O errors exit 2 and print no
// report.
func TestAdminAuditCmdUsageErrors(t *testing.T) {
	dir := seedAuditStateDir(t, 1)
	empty := t.TempDir()
	for name, args := range map[string][]string{
		"no subcommand":      {"control-plane", "admin-audit"},
		"unknown subcommand": {"control-plane", "admin-audit", "verfy", "--state-dir", dir},
		"no state dir":       {"control-plane", "admin-audit", "verify"},
		"unknown flag":       {"control-plane", "admin-audit", "verify", "--state-dir", dir, "--nope"},
		"positional arg":     {"control-plane", "admin-audit", "verify", "--state-dir", dir, "extra"},
		"bad anchor":         {"control-plane", "admin-audit", "verify", "--state-dir", dir, "--anchor", "7"},
		"negative from-seq":  {"control-plane", "admin-audit", "verify", "--state-dir", dir, "--from-seq", "-1"},
		"no database":        {"control-plane", "admin-audit", "verify", "--state-dir", empty},
		"export no out":      {"control-plane", "admin-audit", "export", "--state-dir", dir},
		"export no database": {"control-plane", "admin-audit", "export", "--state-dir", empty, "--out", filepath.Join(empty, "x.jsonl")},
		"export bad flag":    {"control-plane", "admin-audit", "export", "--bogus"},
		"export positional":  {"control-plane", "admin-audit", "export", "--state-dir", dir, "--out", filepath.Join(empty, "y.jsonl"), "z"},
		"export unwritable":  {"control-plane", "admin-audit", "export", "--state-dir", dir, "--out", filepath.Join(empty, "missing-dir", "x.jsonl")},
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
	if _, err := os.Stat(filepath.Join(empty, adminaudit.StateDBFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Error("a read-only command created a database")
	}
}

// TestExportNoIdentityByDefault (CLI): export writes no sub or email unless
// --include-identity is passed, the file is 0600, and it verifies with
// VerifyExport.
func TestExportNoIdentityByDefault(t *testing.T) {
	dir := seedAuditStateDir(t, 6)
	out := filepath.Join(t.TempDir(), "audit.jsonl")
	stdout, stderr, code := runWarden(t, "control-plane", "admin-audit", "export", "--state-dir", dir, "--out", out)
	if code != 0 {
		t.Fatalf("export exit = %d, %s", code, stderr)
	}
	var summary adminaudit.ExportResult
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil || summary.Entries != 7 || summary.Keys != 1 || summary.Identity {
		t.Fatalf("export summary = %q (%v)", stdout, err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"sub-0", "sub-1", "person0@example.org", "example.org"} {
		if bytes.Contains(b, []byte(v)) {
			t.Errorf("default export contains %q", v)
		}
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("export file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	if res, err := adminaudit.VerifyExport(out, adminaudit.VerifyExportOptions{}); err != nil || !res.OK || res.Checked != 7 {
		t.Fatalf("VerifyExport = %+v, %v", res, err)
	}
	// An existing file is never overwritten.
	if _, _, code := runWarden(t, "control-plane", "admin-audit", "export", "--state-dir", dir, "--out", out); code != exitAuditUsage {
		t.Errorf("export onto an existing file exit = %d, want 2", code)
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(after, b) {
		t.Error("a refused export changed the existing file")
	}

	withID := filepath.Join(t.TempDir(), "audit-id.jsonl")
	if _, stderr, code := runWarden(t, "control-plane", "admin-audit", "export", "--state-dir", dir, "--out", withID, "--include-identity"); code != 0 {
		t.Fatalf("export --include-identity exit = %d, %s", code, stderr)
	}
	b, err = os.ReadFile(withID)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"sub-0", "person1@example.org"} {
		if !bytes.Contains(b, []byte(v)) {
			t.Errorf("identity export lacks %q", v)
		}
	}
}

// TestVerifyExportReadOnly (CLI): verify and export leave warden-cp.db's
// bytes and mtime unchanged, never read the key files (they are made
// unreadable) and write no audit row.
func TestVerifyExportReadOnly(t *testing.T) {
	dir := seedAuditStateDir(t, 9)
	db := filepath.Join(dir, adminaudit.StateDBFileName)
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(db, past, past); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{adminaudit.DefaultKeyFileName, adminaudit.HMACKeyFileName} {
		if err := os.Chmod(filepath.Join(dir, f), 0); err != nil {
			t.Fatal(err)
		}
	}

	if _, stderr, code := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", dir); code != 0 {
		t.Fatalf("verify exit = %d, %s", code, stderr)
	}
	out := filepath.Join(t.TempDir(), "a.jsonl")
	if _, stderr, code := runWarden(t, "control-plane", "admin-audit", "export", "--state-dir", dir, "--out", out, "--include-identity"); code != 0 {
		t.Fatalf("export exit = %d, %s", code, stderr)
	}

	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("warden-cp.db bytes changed")
	}
	fi, err := os.Stat(db)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(past) {
		t.Errorf("warden-cp.db mtime changed: %v -> %v", past, fi.ModTime())
	}
	ro, err := cpstate.OpenReadOnly(context.Background(), db, controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	var n int
	if err := ro.SQL().QueryRow("SELECT count(*) FROM admin_audit").Scan(&n); err != nil || n != 10 {
		t.Errorf("admin_audit rows = %d (%v), want 10: verify and export write no row", n, err)
	}
}

// TestRunbookMentionsCommands: the key runbook names both commands and every
// flag they take, plus the rotation flags of the control plane.
func TestRunbookMentionsCommands(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", "admin-audit-key.md"))
	if err != nil {
		t.Fatalf("runbook: %v", err)
	}
	doc := string(b)
	want := []string{
		"warden control-plane admin-audit verify",
		"warden control-plane admin-audit export",
		adminaudit.KeyFileFlag, adminaudit.NewSegmentFlag,
		"admin-audit rotate-key", "W-P2-KEYS-06",
	}
	flagRE := regexp.MustCompile(`--[a-z][a-z-]*`)
	for _, c := range []string{newAdminAuditVerifyCmd().Flags().FlagUsages(), newAdminAuditExportCmd().Flags().FlagUsages()} {
		want = append(want, flagRE.FindAllString(c, -1)...)
	}
	if len(want) < 6+5 {
		t.Fatalf("found too few flags in the command definitions: %v", want)
	}
	for _, w := range want {
		if !strings.Contains(doc, w) {
			t.Errorf("runbook does not mention %q", w)
		}
	}
	cp, err := os.ReadFile(filepath.Join("..", "..", "docs", "control-plane.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"admin-audit verify", "admin-audit export", "docs/runbooks/admin-audit-key.md"} {
		if !strings.Contains(string(cp), w) {
			t.Errorf("docs/control-plane.md does not mention %q", w)
		}
	}
}
