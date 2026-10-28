package main

import (
	"context"
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

// The warden control-plane token commands (W-P1-WTOK-05). The tests share a
// state dir with an in-process control plane.

// Fixed imported values: well-formed wwt_ tokens (prefix + 52 base32 chars).
const (
	tokImportA = "wwt_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tokImportB = "wwt_" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// startTokenCP runs a control plane on stateDir (open worker auth: any wwt_
// bearer is validated against the token store) and returns its base URL.
func startTokenCP(t *testing.T, stateDir string) string {
	t.Helper()
	cfg := writeTempConfig(t, importBaseConfig)
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
			ConfigPath: cfg, StateDir: stateDir, Listener: ln, AnalyticsProvider: "memory",
			OnReady: func(a string) { ready <- a },
		})
	}()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		cancel()
		t.Fatalf("control plane exited before ready: %v\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for the control plane")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(10 * time.Second):
			t.Error("control plane did not stop")
		}
	})
	return "http://" + addr
}

func policyStatus(t *testing.T, base, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/policy", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// waitPolicyStatus polls /policy until it answers want or 4 s pass (the CP
// reloads within its 2 s poll).
func waitPolicyStatus(t *testing.T, base, token string, want int) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for {
		got := policyStatus(t, base, token)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/policy = %d, want %d", got, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func tokenIDFrom(t *testing.T, stdout string) string {
	t.Helper()
	for _, f := range strings.Fields(stdout) {
		if strings.HasPrefix(f, "wt_") {
			return f
		}
	}
	t.Fatalf("no token id in %q", stdout)
	return ""
}

func tokenDBCount(t *testing.T, stateDir, where string, args ...any) int {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRow("SELECT count(*) FROM worker_tokens WHERE "+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestControlPlaneTokenCmd: a token created with --out while a CP runs on the
// state dir is accepted by /policy within the reload interval, no restart.
func TestControlPlaneTokenCmd(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig)
	base := startTokenCP(t, stateDir)
	out := filepath.Join(t.TempDir(), "w2.token")

	stdout, stderr, code := runWarden(t, "control-plane", "token", "create", "--name", "w2", "--proxy-id", "worker-2",
		"--state-dir", stateDir, "--out", out)
	if code != 0 {
		t.Fatalf("create exit = %d, %s", code, stderr)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("--out mode = %v, want 0600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(out)
	tok := strings.TrimSpace(string(b))
	if !strings.HasPrefix(tok, "wwt_") {
		t.Fatalf("--out content is not a token")
	}
	if strings.Contains(stdout+stderr, tok) {
		t.Error("the plaintext was printed although --out was given")
	}
	_ = tokenIDFrom(t, stdout)
	waitPolicyStatus(t, base, tok, http.StatusOK)

	// A second --out onto the same file must not clobber it or leave a token.
	if _, _, code := runWarden(t, "control-plane", "token", "create", "--name", "w3", "--proxy-id", "worker-3",
		"--state-dir", stateDir, "--out", out); code == 0 {
		t.Error("create over an existing --out file succeeded")
	}
	if n := tokenDBCount(t, stateDir, "name = 'w3'"); n != 0 {
		t.Errorf("a failed --out left %d token rows", n)
	}
}

// TestControlPlaneTokenStdoutAndList: without --out the plaintext is the only
// thing on stdout; list shows metadata and never a value.
func TestControlPlaneTokenStdoutAndList(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state") // no database yet: create bootstraps it
	stdout, stderr, code := runWarden(t, "control-plane", "token", "create", "--name", "boot", "--proxy-id", "worker-1",
		"--state-dir", stateDir, "--expires-in", "24h")
	if code != 0 {
		t.Fatalf("create exit = %d, %s", code, stderr)
	}
	tok := strings.TrimSpace(stdout)
	if !strings.HasPrefix(tok, "wwt_") || strings.ContainsAny(tok, " \n") {
		t.Fatalf("stdout is not just the token: %q", stdout)
	}
	if !strings.Contains(stderr, "admin audit is not enabled") {
		t.Errorf("stderr %q lacks the audit notice", stderr)
	}
	for _, args := range [][]string{{"list"}, {"list", "--json"}} {
		out, errb, code := runWarden(t, append([]string{"control-plane", "token"}, append(args, "--state-dir", stateDir)...)...)
		if code != 0 {
			t.Fatalf("%v exit = %d, %s", args, code, errb)
		}
		if strings.Contains(out+errb, tok) || !strings.Contains(out, "boot") || !strings.Contains(out, "worker-1") {
			t.Errorf("%v output = %q", args, out)
		}
	}
	if _, _, code := runWarden(t, "control-plane", "token", "list", "--state-dir", filepath.Join(t.TempDir(), "none")); code == 0 {
		t.Error("list of a missing state dir exited 0")
	}
}

// TestControlPlaneTokenImport: --from-env registers the value; a re-run is a
// no-op; a malformed value or a different value under the same name fails.
func TestControlPlaneTokenImport(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig)
	t.Setenv("WARDEN_WORKER_1_TOKEN", tokImportA)
	args := []string{"control-plane", "token", "create", "--name", "w1", "--proxy-id", "worker-1",
		"--from-env", "WARDEN_WORKER_1_TOKEN", "--state-dir", stateDir}
	for i := range 2 {
		stdout, stderr, code := runWarden(t, args...)
		if code != 0 {
			t.Fatalf("run %d exit = %d, %s", i, code, stderr)
		}
		if strings.Contains(stdout+stderr, tokImportA) {
			t.Fatalf("run %d printed the plaintext", i)
		}
	}
	if n := tokenDBCount(t, stateDir, "name = 'w1'"); n != 1 {
		t.Errorf("rows for w1 = %d, want 1", n)
	}

	t.Setenv("WARDEN_BAD", "not-a-token")
	stdout, stderr, code := runWarden(t, "control-plane", "token", "create", "--name", "bad", "--proxy-id", "worker-9",
		"--from-env", "WARDEN_BAD", "--state-dir", stateDir)
	if code != 1 || strings.Contains(stdout+stderr, "not-a-token") {
		t.Errorf("malformed import: exit %d, output %q %q", code, stdout, stderr)
	}
	t.Setenv("WARDEN_OTHER", tokImportB)
	if _, _, code := runWarden(t, "control-plane", "token", "create", "--name", "w1", "--proxy-id", "worker-1",
		"--from-env", "WARDEN_OTHER", "--state-dir", stateDir); code == 0 {
		t.Error("same name, different value exited 0")
	}
	if _, _, code := runWarden(t, "control-plane", "token", "create", "--name", "w1", "--proxy-id", "worker-1",
		"--from-env", "WARDEN_UNSET_VAR", "--state-dir", stateDir); code != 1 {
		t.Errorf("unset env var exit = %d, want 1", code)
	}

	// --from-file works the same and trims the trailing newline.
	f := filepath.Join(t.TempDir(), "w4.tok")
	if err := os.WriteFile(f, []byte(tokImportB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runWarden(t, "control-plane", "token", "create", "--name", "w4", "--proxy-id", "worker-4",
		"--from-file", f, "--state-dir", stateDir); code != 0 {
		t.Fatalf("from-file exit = %d, %s", code, stderr)
	}
	if _, _, code := runWarden(t, "control-plane", "token", "create", "--name", "w5", "--proxy-id", "worker-5",
		"--from-file", f, "--from-env", "WARDEN_OTHER", "--state-dir", stateDir); code == 0 {
		t.Error("--from-env with --from-file exited 0")
	}
	if _, _, code := runWarden(t, "control-plane", "token", "create", "--name", "w6", "--proxy-id", "worker-6",
		"--from-file", f, "--out", filepath.Join(t.TempDir(), "x"), "--state-dir", stateDir); code == 0 {
		t.Error("import with --out exited 0")
	}
}

// TestControlPlaneTokenRevoke: a revoke while a CP runs makes the token's next
// request a 401; an unknown id exits 2; a repeat is a no-op.
func TestControlPlaneTokenRevoke(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig)
	base := startTokenCP(t, stateDir)
	stdout, stderr, code := runWarden(t, "control-plane", "token", "create", "--name", "w1", "--proxy-id", "worker-1", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("create exit = %d, %s", code, stderr)
	}
	tok := strings.TrimSpace(stdout)
	waitPolicyStatus(t, base, tok, http.StatusOK)
	_, stderr, _ = runWarden(t, "control-plane", "token", "list", "--json", "--state-dir", stateDir)
	listOut, _, _ := runWarden(t, "control-plane", "token", "list", "--json", "--state-dir", stateDir)
	id := ""
	if i := strings.Index(listOut, `"wt_`); i >= 0 {
		id = listOut[i+1 : i+1+len("wt_")+16]
	}
	if id == "" {
		t.Fatalf("no id in list %q (%s)", listOut, stderr)
	}

	if out, errb, code := runWarden(t, "control-plane", "token", "revoke", "--id", id, "--state-dir", stateDir); code != 0 {
		t.Fatalf("revoke exit = %d, %s %s", code, out, errb)
	}
	waitPolicyStatus(t, base, tok, http.StatusUnauthorized)
	if out, _, code := runWarden(t, "control-plane", "token", "revoke", "--id", id, "--state-dir", stateDir); code != 0 || !strings.Contains(out, "already revoked") {
		t.Errorf("repeat revoke = %d %q", code, out)
	}
	if _, _, code := runWarden(t, "control-plane", "token", "revoke", "--id", "wt_unknown", "--state-dir", stateDir); code != 2 {
		t.Errorf("unknown id exit = %d, want 2", code)
	}
}

// TestControlPlaneTokenAudit: CLI creates and revokes interleaved with another
// writer on the same chain leave a chain that verifies, with each action once
// as auth_method cli.
func TestControlPlaneTokenAudit(t *testing.T) {
	stateDir := seedAuditStateDir(t, 3)
	ctx := context.Background()
	db, err := cpstate.Open(ctx, filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	other, err := adminaudit.Open(ctx, db, adminaudit.OpenOptions{KeyFile: adminaudit.DefaultKeyPath(stateDir)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // the "CP" writing API-originated rows while the CLI works
		defer wg.Done()
		for i := range 15 {
			_, err := other.Record(ctx, adminaudit.Input{
				Actor: adminaudit.Actor{Sub: "ada"}, ActorRole: "admin", AuthMethod: adminaudit.AuthMethodOIDC,
				Action: "worker_token.create", Target: "worker_tokens", TargetRef: fmt.Sprintf("token:wt_api%d", i),
				Outcome: adminaudit.OutcomeOK, HTTPStatus: 201,
			})
			if err != nil {
				t.Errorf("api-side record: %v", err)
				return
			}
		}
	}()
	stdout, stderr, code := runWarden(t, "control-plane", "token", "create", "--name", "w1", "--proxy-id", "worker-1", "--state-dir", stateDir)
	if code != 0 {
		t.Fatalf("create exit = %d, %s", code, stderr)
	}
	tok := strings.TrimSpace(stdout)
	listOut, _, _ := runWarden(t, "control-plane", "token", "list", "--json", "--state-dir", stateDir)
	i := strings.Index(listOut, `"wt_`)
	id := listOut[i+1 : i+1+len("wt_")+16]
	if _, stderr, code := runWarden(t, "control-plane", "token", "revoke", "--id", id, "--state-dir", stateDir); code != 0 {
		t.Fatalf("revoke exit = %d, %s", code, stderr)
	}
	wg.Wait()

	var cliCreate, cliRevoke int
	rdb, err := cpstate.OpenReadOnly(ctx, filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rdb.Close() }()
	rows, err := rdb.SQL().Query(`SELECT a.action, a.auth_method, a.target_ref, COALESCE(x.sub,'') FROM admin_audit a
		LEFT JOIN admin_audit_actor x ON x.seq = a.seq WHERE a.auth_method = 'cli' ORDER BY a.seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a, m, ref, sub string
		if err := rows.Scan(&a, &m, &ref, &sub); err != nil {
			t.Fatal(err)
		}
		if ref != "token:"+id || sub != cliUser(t) {
			t.Errorf("cli row %s ref=%q actor=%q", a, ref, sub)
		}
		switch a {
		case "worker_token.create":
			cliCreate++
		case "worker_token.revoke":
			cliRevoke++
		}
	}
	if cliCreate != 1 || cliRevoke != 1 {
		t.Errorf("cli rows: create %d revoke %d, want 1 each", cliCreate, cliRevoke)
	}
	vout, vstderr, vcode := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", stateDir)
	if vcode != 0 || !decodeReport(t, vout).OK {
		t.Fatalf("verify = %d %s %s", vcode, vout, vstderr)
	}
	if strings.Contains(vout+vstderr+listOut, tok) {
		t.Error("plaintext leaked")
	}
	var details string
	if err := rdb.SQL().QueryRow(`SELECT details_json FROM admin_audit WHERE auth_method='cli' AND action='worker_token.create'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, tok) || !strings.Contains(details, id) || !strings.Contains(details, "worker-1") {
		t.Errorf("details = %q", details)
	}
}

// TestControlPlaneTokenKeyMissing: with audit rows present and the key file
// gone, create and revoke exit non-zero and write nothing.
func TestControlPlaneTokenKeyMissing(t *testing.T) {
	stateDir := seedAuditStateDir(t, 2)
	if _, stderr, code := runWarden(t, "control-plane", "token", "create", "--name", "ok", "--proxy-id", "worker-1", "--state-dir", stateDir); code != 0 {
		t.Fatalf("create with the key present exit = %d, %s", code, stderr)
	}
	before := tokenDBCount(t, stateDir, "1 = 1")
	if err := os.Remove(adminaudit.DefaultKeyPath(stateDir)); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runWarden(t, "control-plane", "token", "create", "--name", "w2", "--proxy-id", "worker-2", "--state-dir", stateDir)
	if code == 0 {
		t.Fatalf("create without the key exited 0: %s", stdout)
	}
	if strings.Contains(stdout, "wwt_") {
		t.Error("a token was printed")
	}
	if n := tokenDBCount(t, stateDir, "1 = 1"); n != before {
		t.Errorf("token rows %d, want %d", n, before)
	}
	if _, _, code := runWarden(t, "control-plane", "token", "revoke", "--id", "wt_x", "--state-dir", stateDir); code == 0 || code == 2 {
		t.Errorf("revoke without the key exit = %d, want a non-zero audit failure", code)
	}
	_ = stderr
}
