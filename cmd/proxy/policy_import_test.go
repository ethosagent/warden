package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The warden policy import/export commands (W-P1-PVER-06). The tests share a
// state dir with an in-process control plane in versioned mode.

// importBaseConfig is the --config a control plane boots from; it becomes
// version 1 on the first versioned start.
const importBaseConfig = `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: error
  format: json
`

// importNewConfig adds a domain, so importing it makes a new version.
const importNewConfig = `
policy:
  allowlist:
    - domain: api.openai.com
    - domain: api.anthropic.com
logging:
  level: error
  format: json
`

// importLiveSecret is a raw AWS credential value that must never be stored or
// printed.
const importLiveSecret = "live-secret-value-do-not-print-0123456789"

// importCredentialConfig carries a raw secretAccessKey.
const importCredentialConfig = `
policy:
  allowlist:
    - domain: api.openai.com
    - domain: secretsmanager.us-east-1.amazonaws.com
secretStore:
  backend: aws
  aws:
    region: us-east-1
    accessKeyId: AKIAEXAMPLEEXAMPLE00
    secretAccessKey: ` + importLiveSecret + `
logging:
  level: error
  format: json
`

// auditConfig enables admin audit on the control plane.
const auditConfig = "console:\n  adminAudit:\n    enabled: true\n"

// cpSyncBuffer is a goroutine-safe buffer for the control plane's log output.
type cpSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *cpSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *cpSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startVersionedCP runs a control plane in versioned mode on stateDir, seeded
// from configBody, and returns its base URL. It stops at test cleanup.
func startVersionedCP(t *testing.T, stateDir, configBody string) string {
	t.Helper()
	cfg := writeTempConfig(t, configBody)
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
			ConfigPath: cfg, StateDir: stateDir, Listener: ln,
			AnalyticsProvider: "memory", PolicyStore: controlplane.PolicyStoreVersioned,
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
		case err := <-errCh:
			if err != nil {
				t.Errorf("control plane: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("control plane did not stop")
		}
	})
	return "http://" + addr
}

// seedStateDir boots a versioned control plane on a fresh state dir once (so
// the store holds version 1) and stops it.
func seedStateDir(t *testing.T, configBody string) string {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := writeTempConfig(t, configBody)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	var out cpSyncBuffer
	go func() {
		errCh <- controlplane.Run(ctx, &out, controlplane.Params{
			ConfigPath: cfg, StateDir: stateDir, ListenAddr: "127.0.0.1:0",
			AnalyticsProvider: "memory", PolicyStore: controlplane.PolicyStoreVersioned,
			OnReady: func(string) { ready <- struct{}{} },
		})
	}()
	select {
	case <-ready:
	case err := <-errCh:
		cancel()
		t.Fatalf("control plane exited before ready: %v\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for the control plane")
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("control plane: %v", err)
	}
	return stateDir
}

// runPolicy runs `warden policy <args>` and returns stdout, stderr and the
// error.
func runPolicy(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	root := newRootCmd()
	root.SetArgs(append([]string{"policy"}, args...))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetContext(context.Background())
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// storedVersion is one policy_versions row.
type storedVersion struct {
	version                            int64
	authorSub, authorKind, source, msg string
	docJSON, docSHA256                 string
}

// readStore returns every version, oldest first, and the head.
func readStore(t *testing.T, stateDir string) ([]storedVersion, int64) {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT version, author_sub, author_kind, source, message, doc_json, doc_sha256 FROM policy_versions ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []storedVersion
	for rows.Next() {
		var v storedVersion
		if err := rows.Scan(&v.version, &v.authorSub, &v.authorKind, &v.source, &v.msg, &v.docJSON, &v.docSHA256); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var head int64
	if err := db.SQL().QueryRow("SELECT version FROM policy_head").Scan(&head); err != nil {
		t.Fatal(err)
	}
	return out, head
}

// auditRow is one admin_audit row, with the actor from its identity side
// table.
type auditRow struct {
	actor, method, target, outcome, before, after string
}

// readAudit returns the admin_audit rows with action.
func readAudit(t *testing.T, stateDir, action string) []auditRow {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT COALESCE(x.sub, ''), a.auth_method, a.target, a.outcome, a.before_hash, a.after_hash
		FROM admin_audit a LEFT JOIN admin_audit_actor x ON x.seq = a.seq WHERE a.action = ? ORDER BY a.seq`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.actor, &r.method, &r.target, &r.outcome, &r.before, &r.after); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// cliUser is the actor the CLI records: cli:<os user>.
func cliUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil || u.Username == "" {
		return "cli:unknown"
	}
	return "cli:" + u.Username
}

// getPolicyETag GETs /policy (with If-None-Match and wait when set) and
// returns the status and ETag.
func getPolicyETag(t *testing.T, client *http.Client, base, etag, wait string) (int, string, error) {
	t.Helper()
	url := base + "/policy"
	if wait != "" {
		url += "?wait=" + wait
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("ETag"), nil
}

// TestPolicyImport: with a control plane running on the state dir and a worker
// long-polling with wait=30s, importing a new file makes the worker receive
// the new ETag within 5s, stores version 2 authored cli:<user> with source
// import and the message, and appends a policy.import admin audit row.
func TestPolicyImport(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := startVersionedCP(t, stateDir, importBaseConfig+auditConfig)
	client := &http.Client{Timeout: 40 * time.Second}
	status, etag, err := getPolicyETag(t, client, base, "", "")
	if err != nil || status != http.StatusOK || etag == "" {
		t.Fatalf("GET /policy = %d %q %v", status, etag, err)
	}

	type result struct {
		status int
		etag   string
		err    error
		at     time.Time
	}
	polled := make(chan result, 1)
	go func() {
		s, e, err := getPolicyETag(t, client, base, etag, "30s")
		polled <- result{s, e, err, time.Now()}
	}()
	// The import lands before the CP's next reload tick (3s), so the poll is
	// parked on the old ETag whichever starts first.

	file := writeTempConfig(t, importNewConfig)
	start := time.Now()
	stdout, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file, "--message", "m")
	if err != nil {
		t.Fatalf("import: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "version 2") {
		t.Errorf("stdout = %q, want it to name version 2", stdout)
	}

	select {
	case r := <-polled:
		if r.err != nil || r.status != http.StatusOK || r.etag == etag {
			t.Fatalf("long-poll = %d %q %v, want 200 with a new ETag", r.status, r.etag, r.err)
		}
		if d := r.at.Sub(start); d > 5*time.Second {
			t.Errorf("worker saw the new ETag after %s, want within 5s", d)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("the worker did not receive the new ETag within 5s")
	}

	versions, head := readStore(t, stateDir)
	if head != 2 || len(versions) != 2 {
		t.Fatalf("store head v%d with %d versions, want v2 with 2", head, len(versions))
	}
	v := versions[1]
	if v.authorSub != cliUser(t) || v.authorKind != "cli" || v.source != "import" || v.msg != "m" {
		t.Errorf("version 2 = author %q/%q source %q message %q, want %s/cli, import, m", v.authorSub, v.authorKind, v.source, v.msg, cliUser(t))
	}
	rows := readAudit(t, stateDir, "policy.import")
	if len(rows) != 1 {
		t.Fatalf("%d policy.import audit rows, want 1", len(rows))
	}
	r := rows[0]
	if r.actor != cliUser(t) || r.method != adminaudit.AuthMethodCLI || r.target != "policy" || r.outcome != adminaudit.OutcomeOK {
		t.Errorf("audit row = actor %q method %q target %q outcome %q, want %s/cli/policy/ok", r.actor, r.method, r.target, r.outcome, cliUser(t))
	}
	if want := "v1:" + versions[0].docSHA256; r.before != want {
		t.Errorf("before_hash = %q, want %q", r.before, want)
	}
	if want := "v2:" + v.docSHA256; r.after != want {
		t.Errorf("after_hash = %q, want %q", r.after, want)
	}
}

// TestPolicyImportNoChange: re-importing the same file prints "no change",
// exits 0 and adds no version or audit row.
func TestPolicyImportNoChange(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig)
	file := writeTempConfig(t, importNewConfig)
	if _, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file); err != nil {
		t.Fatalf("first import: %v\n%s", err, stderr)
	}
	stdout, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file)
	if err != nil {
		t.Fatalf("re-import: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "no change") {
		t.Errorf("stdout = %q, want \"no change\"", stdout)
	}
	if versions, head := readStore(t, stateDir); head != 2 || len(versions) != 2 {
		t.Errorf("store head v%d with %d versions after re-import, want v2 with 2", head, len(versions))
	}
}

// TestPolicyImportConflict: an import whose expected head is stale exits
// non-zero, names the current head and creates nothing.
func TestPolicyImportConflict(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig)
	file := writeTempConfig(t, importNewConfig)
	stdout, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file, "--expected-head", "0")
	if err == nil {
		t.Fatalf("import with a stale head succeeded: %s", stdout)
	}
	if msg := err.Error() + stderr; !strings.Contains(msg, "v1") {
		t.Errorf("error = %q, want it to name the current head v1", msg)
	}
	if versions, head := readStore(t, stateDir); head != 1 || len(versions) != 1 {
		t.Errorf("store head v%d with %d versions, want v1 with 1", head, len(versions))
	}
}

// TestPolicyImportInvalidFile: a file the loader rejects (an empty allowlist,
// an unknown key) exits non-zero naming the file and creates nothing.
func TestPolicyImportInvalidFile(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig)
	for name, body := range map[string]string{
		"empty allowlist": "policy:\n  allowlist: []\n",
		"unknown key":     importBaseConfig + "bogusKey: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			file := writeTempConfig(t, body)
			_, _, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file)
			if err == nil {
				t.Fatal("invalid file imported")
			}
			if !strings.Contains(err.Error(), file) {
				t.Errorf("error = %q, want it to name %s", err, file)
			}
			if versions, head := readStore(t, stateDir); head != 1 || len(versions) != 1 {
				t.Errorf("store head v%d with %d versions, want v1 with 1", head, len(versions))
			}
		})
	}
}

// TestPolicyImportNeedsStore: a state dir without a versioned policy store is
// a clear error, and nothing is created there.
func TestPolicyImportNeedsStore(t *testing.T) {
	stateDir := t.TempDir()
	file := writeTempConfig(t, importNewConfig)
	_, _, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file)
	if err == nil || !strings.Contains(err.Error(), "policy store") {
		t.Fatalf("import into an empty state dir = %v, want a policy store error", err)
	}
	if _, serr := os.Stat(filepath.Join(stateDir, "warden-cp.db")); !os.IsNotExist(serr) {
		t.Errorf("import created warden-cp.db (stat err %v)", serr)
	}
	if _, _, err := runPolicy(t, "export", "--state-dir", stateDir); err == nil {
		t.Error("export from an empty state dir succeeded")
	}
}

// TestPolicyImportCredentialFingerprint: a raw secretAccessKey in the imported
// file is stored as its fingerprint and never printed; a credential that
// differs from the served config's is refused, because a version keeps only
// the fingerprint and the control plane serves the served config's value.
func TestPolicyImportCredentialFingerprint(t *testing.T) {
	stateDir := seedStateDir(t, importCredentialConfig)
	file := writeTempConfig(t, strings.Replace(importCredentialConfig,
		"    - domain: api.openai.com\n", "    - domain: api.openai.com\n    - domain: api.anthropic.com\n", 1))
	stdout, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file)
	if err != nil {
		t.Fatalf("import: %v\n%s", err, stderr)
	}
	if strings.Contains(stdout+stderr, importLiveSecret) {
		t.Error("import printed the credential value")
	}
	versions, head := readStore(t, stateDir)
	if head != 2 {
		t.Fatalf("head = v%d, want v2", head)
	}
	doc := versions[len(versions)-1].docJSON
	if strings.Contains(doc, importLiveSecret) {
		t.Error("the stored version holds the raw credential")
	}
	if !strings.Contains(doc, `"secretAccessKey":"sha256:`) {
		t.Errorf("stored doc = %s, want the credential as its fingerprint", doc)
	}

	rotated := writeTempConfig(t, strings.Replace(importCredentialConfig, importLiveSecret, "rotated-"+importLiveSecret, 1))
	_, stderr, err = runPolicy(t, "import", "--state-dir", stateDir, "--file", rotated)
	if err == nil {
		t.Fatal("import of a credential that differs from the served config succeeded")
	}
	if strings.Contains(err.Error()+stderr, importLiveSecret) {
		t.Error("the refusal printed a credential value")
	}
	if _, head := readStore(t, stateDir); head != 2 {
		t.Errorf("head = v%d after the refused import, want v2", head)
	}

	out, errOut, err := runPolicy(t, "export", "--state-dir", stateDir)
	if err != nil {
		t.Fatalf("export: %v\n%s", err, errOut)
	}
	if strings.Contains(out+errOut, importLiveSecret) || strings.Contains(out, "secretAccessKey") || strings.Contains(out, "sha256:") {
		t.Errorf("export printed a credential or its fingerprint:\n%s", out)
	}
	assertLoadable(t, out)
}

// assertLoadable writes out to a file and loads it with the config loader.
func assertLoadable(t *testing.T, out string) config.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "export.yaml")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("export does not load: %v\n%s", err, out)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPolicyExport: export --version 1 writes a config YAML that loads with
// config.NewLocalYAMLProvider, has version 1's allowlist and no
// secretAccessKey; export without --version writes the head.
func TestPolicyExport(t *testing.T) {
	stateDir := seedStateDir(t, importCredentialConfig)
	file := writeTempConfig(t, strings.Replace(importCredentialConfig,
		"    - domain: secretsmanager.us-east-1.amazonaws.com\n", "    - domain: api.anthropic.com\n", 1))
	if _, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file); err != nil {
		t.Fatalf("import: %v\n%s", err, stderr)
	}

	out, stderr, err := runPolicy(t, "export", "--state-dir", stateDir, "--version", "1")
	if err != nil {
		t.Fatalf("export: %v\n%s", err, stderr)
	}
	if strings.Contains(out+stderr, importLiveSecret) || strings.Contains(out, "secretAccessKey") {
		t.Errorf("export printed a secretAccessKey:\n%s", out)
	}
	for _, key := range []string{"policy:", "secretStore:"} {
		if !strings.Contains(out, key) {
			t.Errorf("export lacks %s:\n%s", key, out)
		}
	}
	p := assertLoadable(t, out)
	if len(p.Allowlist) != 2 || p.Allowlist[1].Domain != "secretsmanager.us-east-1.amazonaws.com" {
		t.Errorf("version 1 allowlist = %+v, want the seeded two domains", p.Allowlist)
	}

	head, _, err := runPolicy(t, "export", "--state-dir", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	hp := assertLoadable(t, head)
	if len(hp.Allowlist) != 2 || hp.Allowlist[1].Domain != "api.anthropic.com" {
		t.Errorf("head allowlist = %+v, want the imported file's", hp.Allowlist)
	}

	if _, _, err := runPolicy(t, "export", "--state-dir", stateDir, "--version", "9"); err == nil {
		t.Error("export of a missing version succeeded")
	}
}

// TestPolicyImportCredentialDropRefused: a file without the AWS credential
// (for example an unedited export) is refused when the served config carries
// one, because the control plane would then serve no credential.
func TestPolicyImportCredentialDropRefused(t *testing.T) {
	stateDir := seedStateDir(t, importCredentialConfig)
	exported, _, err := runPolicy(t, "export", "--state-dir", stateDir)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	for name, body := range map[string]string{"export round-trip": exported, "no secretStore": importNewConfig} {
		t.Run(name, func(t *testing.T) {
			file := writeTempConfig(t, body)
			_, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file)
			if err == nil {
				t.Fatal("import without the served credential succeeded")
			}
			if strings.Contains(err.Error()+stderr, importLiveSecret) {
				t.Error("the refusal printed a credential value")
			}
			if !strings.Contains(err.Error(), "secretAccessKey") {
				t.Errorf("error = %q, want it to name secretAccessKey", err)
			}
			if _, head := readStore(t, stateDir); head != 1 {
				t.Errorf("head = v%d after the refused import, want v1", head)
			}
		})
	}
}

// TestPolicyImportAuditKeyMissing: with admin_audit rows present and the key
// file missing, import exits non-zero and creates no version.
func TestPolicyImportAuditKeyMissing(t *testing.T) {
	stateDir := seedStateDir(t, importBaseConfig+auditConfig)
	if err := os.Remove(adminaudit.DefaultKeyPath(stateDir)); err != nil {
		t.Fatal(err)
	}
	file := writeTempConfig(t, importNewConfig)
	_, _, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file)
	if err == nil {
		t.Fatal("import without the audit key succeeded")
	}
	if !strings.Contains(err.Error(), "admin audit") {
		t.Errorf("error = %q, want an admin audit key error", err)
	}
	if versions, head := readStore(t, stateDir); head != 1 || len(versions) != 1 {
		t.Errorf("store head v%d with %d versions, want v1 with 1", head, len(versions))
	}
	if rows := readAudit(t, stateDir, "policy.import"); len(rows) != 0 {
		t.Errorf("%d policy.import rows, want none", len(rows))
	}
}

// TestPolicyImportNoAuditTable: a state DB with the policy store but no
// admin_audit table imports and prints a one-line notice instead of an audit
// row.
func TestPolicyImportNoAuditTable(t *testing.T) {
	stateDir := t.TempDir()
	db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, "warden-cp.db"), controlplane.PolicyStoreMigrations())
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	file := writeTempConfig(t, importNewConfig)
	stdout, stderr, err := runPolicy(t, "import", "--state-dir", stateDir, "--file", file, "--message", "first")
	if err != nil {
		t.Fatalf("import: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "admin audit") || strings.Count(strings.TrimSpace(stderr), "\n") != 0 {
		t.Errorf("stderr = %q, want a one-line admin audit notice", stderr)
	}
	if !strings.Contains(stdout, "version 1") {
		t.Errorf("stdout = %q, want version 1", stdout)
	}
	if versions, head := readStore(t, stateDir); head != 1 || len(versions) != 1 || versions[0].msg != "first" {
		t.Errorf("store head v%d with %+v, want v1 with message first", head, versions)
	}
}
