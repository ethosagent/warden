//go:build unix

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// restoreFix is a stopped control plane's state dir with a worker token, a
// console session and a policy head in it, and a backup set of that state
// taken with `warden control-plane backup`.
type restoreFix struct {
	src, set  string
	token     string
	sessionID string
	etag      string
	keyFile   string
}

const restoreCfg = minimalConfig + auditConfig

// runRestoreCP runs a versioned control plane with admin audit on stateDir and
// returns its base URL and a stop func (also run at cleanup).
func runRestoreCP(t *testing.T, stateDir string) (base string, stop func()) {
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
			ConfigPath: writeTempConfig(t, restoreCfg), StateDir: stateDir, Listener: ln,
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
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("control plane: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("control plane did not stop")
		}
	}
	t.Cleanup(stop)
	return "http://" + addr, stop
}

func getETag(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Get(base + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") == "" {
		t.Fatalf("GET /policy = %d, ETag %q", resp.StatusCode, resp.Header.Get("ETag"))
	}
	return resp.Header.Get("ETag")
}

func newRestoreFix(t *testing.T) restoreFix {
	t.Helper()
	ctx := context.Background()
	f := restoreFix{src: seedStateDir(t, restoreCfg)}
	f.keyFile = adminaudit.DefaultKeyPath(f.src)

	db, err := cpstate.Open(ctx, filepath.Join(f.src, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	ts, err := controlplane.NewWorkerTokenStore(db, controlplane.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if f.token, _, err = ts.Create(ctx, controlplane.CreateOpts{Name: "restore-worker", ProxyID: "p1", Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	if f.sessionID, _, err = controlplane.NewSessionStore(db.SQL(), time.Hour, 8*time.Hour, time.Now).Create(ctx,
		controlplane.SessionInput{Iss: "i", Sub: "alice", Email: "alice@example.org", AuthMethod: "oidc"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	base, stop := runRestoreCP(t, f.src)
	f.etag = getETag(t, base)
	stop()

	stdout, stderr, code := runWarden(t, "control-plane", "backup", "--state-dir", f.src, "--backup-dir", filepath.Join(t.TempDir(), "backups"))
	if code != 0 {
		t.Fatalf("backup exit %d: %s", code, stderr)
	}
	f.set = strings.TrimSpace(stdout)
	return f
}

// copySet returns a private copy of the set, so a test may tamper with it.
func (f restoreFix) copySet(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), filepath.Base(f.set))
	copyTree(t, f.set, dst)
	return dst
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// target returns a state dir (under its own parent, so a stray write beside it
// shows in snapshot of the parent) holding the signing and HMAC keys of the
// fixture, the way a rebuilt host with the keys restored looks.
func (f restoreFix) target(t *testing.T) (root, state string) {
	t.Helper()
	root = t.TempDir()
	state = filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{f.keyFile, adminaudit.DefaultHMACKeyPath(f.keyFile)} {
		b, err := os.ReadFile(k)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(state, filepath.Base(k)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, state
}

// snapshot maps every path under dir to its mode and content hash, leaving out
// the lock file (the lock is taken even by a refused restore and never removed).
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.Name() == cpstate.LockFileName {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			out[rel] = "dir " + fi.Mode().String()
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[rel] = fi.Mode().String() + " " + hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertUnchanged(t *testing.T, dir string, before map[string]string) {
	t.Helper()
	after := snapshot(t, dir)
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s changed: %q -> %q", k, v, after[k])
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("%s was created", k)
		}
	}
}

// rewriteManifest applies mutate to the set's manifest. With rehash the file
// entries are recomputed from the files in the set (a deliberate, consistent
// edit); without it the hashes stay as written.
func rewriteManifest(t *testing.T, set string, rehash bool, mutate func(*controlplane.BackupManifest)) {
	t.Helper()
	path := filepath.Join(set, controlplane.BackupManifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m controlplane.BackupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	mutate(&m)
	if rehash {
		for i, bf := range m.Files {
			b, err := os.ReadFile(filepath.Join(set, bf.Name))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			m.Files[i].SHA256, m.Files[i].Size = hex.EncodeToString(sum[:]), int64(len(b))
		}
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readManifest(t *testing.T, set string) controlplane.BackupManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(set, controlplane.BackupManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m controlplane.BackupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func restoreCLI(t *testing.T, set, state string, extra ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runWarden(t, append([]string{"control-plane", "restore", "--from", set, "--state-dir", state}, extra...)...)
}

// auditEntries lists the state dir's admin audit chain, newest first.
func auditEntries(t *testing.T, state string) []adminaudit.ListItem {
	t.Helper()
	st, closeFn, err := adminaudit.OpenReadOnly(context.Background(), state, controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFn() }()
	items, err := st.List(context.Background(), adminaudit.Filter{}, 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func countAction(items []adminaudit.ListItem, action string) int {
	n := 0
	for _, it := range items {
		if it.Action == action {
			n++
		}
	}
	return n
}

func TestControlPlaneRestore_RoundTrip(t *testing.T) {
	f := newRestoreFix(t)
	_, state := f.target(t)

	stdout, stderr, code := restoreCLI(t, f.set, state)
	if code != 0 {
		t.Fatalf("restore exit %d: %s", code, stderr)
	}

	// The chain verifies and ends with exactly one cp.restore entry.
	if out, errOut, c := runWarden(t, "control-plane", "admin-audit", "verify", "--state-dir", state); c != 0 {
		t.Fatalf("admin-audit verify exit %d: %s %s", c, out, errOut)
	}
	items := auditEntries(t, state)
	if items[0].Action != controlplane.RestoreAuditAction || countAction(items, controlplane.RestoreAuditAction) != 1 {
		t.Fatalf("audit entries (newest first) = %v, want one cp.restore at the end", items)
	}
	if items[0].AuthMethod != adminaudit.AuthMethodCLI || items[0].Details["new_audit_key"] != "false" {
		t.Errorf("cp.restore row = %+v", items[0])
	}
	manifestRaw, err := os.ReadFile(filepath.Join(f.set, controlplane.BackupManifestName))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(manifestRaw)
	if items[0].Target != hex.EncodeToString(sum[:]) {
		t.Errorf("cp.restore target = %q, want the sha256 of manifest.json", items[0].Target)
	}
	if want := readManifest(t, f.set).CreatedAt.UTC().Format(time.RFC3339); items[0].Details["set_created_at"] != want {
		t.Errorf("set_created_at = %q, want %q", items[0].Details["set_created_at"], want)
	}
	if !strings.Contains(stdout, "restored files:") {
		t.Errorf("stdout = %q", stdout)
	}

	// The worker token authenticates and the earlier session does not.
	ctx := context.Background()
	db, err := cpstate.Open(ctx, filepath.Join(state, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	ts, err := controlplane.NewWorkerTokenStore(db, controlplane.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ts.Authenticate(f.token); err != nil || tok.Name != "restore-worker" {
		t.Errorf("Authenticate after restore = %v, %v", tok, err)
	}
	if _, ok, err := controlplane.NewSessionStore(db.SQL(), time.Hour, 8*time.Hour, time.Now).Lookup(ctx, f.sessionID); err != nil || ok {
		t.Errorf("session after restore: found=%v err=%v, want gone", ok, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The control plane starts on the restored dir and serves the same policy.
	base, stop := runRestoreCP(t, state)
	if got := getETag(t, base); got != f.etag {
		t.Errorf("GET /policy ETag = %s, want %s", got, f.etag)
	}
	stop()
}

func TestControlPlaneRestore_TamperedFile(t *testing.T) {
	f := newRestoreFix(t)
	set := f.copySet(t)
	path := filepath.Join(set, "warden-cp.db")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	root, state := f.target(t)
	before := snapshot(t, root)

	_, stderr, code := restoreCLI(t, set, state)
	if code == 0 || !strings.Contains(stderr, "manifest mismatch: warden-cp.db") {
		t.Fatalf("exit %d, stderr %q, want non-zero with 'manifest mismatch: warden-cp.db'", code, stderr)
	}
	assertUnchanged(t, root, before)
}

func TestControlPlaneRestore_RefusesWhileLocked(t *testing.T) {
	f := newRestoreFix(t)
	root, state := f.target(t)
	release, err := cpstate.AcquireDirLock(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	before := snapshot(t, root)

	stdout, stderr, code := restoreCLI(t, f.set, state)
	if code != 1 || !strings.Contains(stderr, "control plane is running") {
		t.Fatalf("exit %d, stderr %q, want 1 naming 'control plane is running'", code, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("printed %q on refusal", stdout)
	}
	assertUnchanged(t, root, before)
}

func TestControlPlaneRestore_Refusals(t *testing.T) {
	f := newRestoreFix(t)

	t.Run("newer schema_version", func(t *testing.T) {
		set := f.copySet(t)
		db, err := cpstate.Open(context.Background(), filepath.Join(set, "warden-cp.db"), controlplane.StateMigrations())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.SQL().Exec("INSERT INTO schema_migrations (id, applied_at) VALUES ('future/0001', 1)"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		rewriteManifest(t, set, true, func(*controlplane.BackupManifest) {})
		root, state := f.target(t)
		before := snapshot(t, root)

		_, stderr, code := restoreCLI(t, set, state)
		re := regexp.MustCompile(`backup schema_version \d+ is newer than this binary supports \(\d+\)`)
		if code == 0 || !re.MatchString(stderr) {
			t.Fatalf("exit %d, stderr %q, want a match for %v", code, stderr, re)
		}
		assertUnchanged(t, root, before)
	})

	t.Run("audit key fingerprint", func(t *testing.T) {
		set := f.copySet(t)
		rewriteManifest(t, set, false, func(m *controlplane.BackupManifest) { m.AuditKeyFingerprint = "0123456789abcdef" })
		root, state := f.target(t)
		before := snapshot(t, root)

		_, stderr, code := restoreCLI(t, set, state)
		if code == 0 || !strings.Contains(stderr, "audit key fingerprint") {
			t.Fatalf("exit %d, stderr %q, want a fingerprint refusal", code, stderr)
		}
		if strings.Contains(stderr, "PRIVATE KEY") {
			t.Error("the refusal printed key material")
		}
		assertUnchanged(t, root, before)

		// --new-audit-key allows it and the audit row records the override.
		if _, stderr, code := restoreCLI(t, set, state, "--new-audit-key"); code != 0 {
			t.Fatalf("--new-audit-key exit %d: %s", code, stderr)
		}
		items := auditEntries(t, state)
		if items[0].Action != controlplane.RestoreAuditAction || items[0].Details["new_audit_key"] != "true" {
			t.Errorf("newest entry = %+v, want cp.restore with new_audit_key true", items[0])
		}
	})

	t.Run("matching fingerprint and missing key file", func(t *testing.T) {
		s, err := audit.LoadOrCreateSigner(f.keyFile)
		if err != nil {
			t.Fatal(err)
		}
		set := f.copySet(t)
		rewriteManifest(t, set, false, func(m *controlplane.BackupManifest) { m.AuditKeyFingerprint = audit.KeyID(s.PubKey()) })
		_, state := f.target(t)
		if _, stderr, code := restoreCLI(t, set, state); code != 0 {
			t.Fatalf("matching fingerprint: exit %d: %s", code, stderr)
		}

		// No key at the target: refused, the key is not created.
		root := t.TempDir()
		empty := filepath.Join(root, "state")
		if err := os.Mkdir(empty, 0o700); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, root)
		_, stderr, code := restoreCLI(t, set, empty)
		if code == 0 || !strings.Contains(stderr, "audit key") {
			t.Fatalf("missing key: exit %d, stderr %q", code, stderr)
		}
		assertUnchanged(t, root, before)
	})
}

func TestControlPlaneRestore_StaleWAL(t *testing.T) {
	f := newRestoreFix(t)
	_, state := f.target(t)
	stale := map[string]string{
		"warden-cp.db":     "OLD-DB-BYTES",
		"warden-cp.db-wal": "STALE-WAL-BYTES",
		"warden-cp.db-shm": "STALE-SHM-BYTES",
	}
	for n, c := range stale {
		if err := os.WriteFile(filepath.Join(state, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	stdout, stderr, code := restoreCLI(t, f.set, state, "--force")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	pre, _ := filepath.Glob(filepath.Join(state, "pre-restore-*"))
	if len(pre) != 1 {
		t.Fatalf("pre-restore dirs = %v", pre)
	}
	if !strings.Contains(stdout, pre[0]) {
		t.Errorf("stdout %q does not name %s", stdout, pre[0])
	}
	if fi, err := os.Stat(pre[0]); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("pre-restore dir: %v, %v, want mode 0700", fi, err)
	}
	for n, want := range stale {
		got, err := os.ReadFile(filepath.Join(pre[0], n))
		if err != nil || string(got) != want {
			t.Errorf("pre-restore/%s = %q, %v, want %q", n, got, err, want)
		}
	}
	for _, n := range []string{"warden-cp.db-wal", "warden-cp.db-shm"} {
		if _, err := os.Stat(filepath.Join(state, n)); err == nil {
			t.Errorf("stale %s is still in the state dir", n)
		}
	}
	if fi, err := os.Stat(filepath.Join(state, "warden-cp.db")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("restored db: %v, %v, want mode 0600", fi, err)
	}
	// The restored database is the backup's, not the stale one: its token is there.
	db, err := cpstate.Open(context.Background(), filepath.Join(state, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("restored db does not open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ts, err := controlplane.NewWorkerTokenStore(db, controlplane.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Authenticate(f.token); err != nil {
		t.Errorf("token after restore over stale files: %v", err)
	}
}

func TestControlPlaneRestore_ManifestNames(t *testing.T) {
	f := newRestoreFix(t)
	for _, name := range []string{"../x.db", "unknown.db", "sub/warden-cp.db", "..", "", "/etc/passwd", "warden-cp.db/../warden-cp.db"} {
		t.Run(name, func(t *testing.T) {
			set := f.copySet(t)
			rewriteManifest(t, set, false, func(m *controlplane.BackupManifest) {
				m.Files = append(m.Files, controlplane.BackupFile{Name: name, SHA256: strings.Repeat("0", 64), Size: 1})
			})
			root, state := f.target(t)
			before := snapshot(t, root)
			_, stderr, code := restoreCLI(t, set, state)
			if code == 0 || !strings.Contains(stderr, "refused") {
				t.Fatalf("exit %d, stderr %q, want a refusal", code, stderr)
			}
			assertUnchanged(t, root, before)
		})
	}

	t.Run("unsupported format", func(t *testing.T) {
		set := f.copySet(t)
		rewriteManifest(t, set, false, func(m *controlplane.BackupManifest) { m.Format = "warden.cp.backup.v9" })
		root, state := f.target(t)
		before := snapshot(t, root)
		_, stderr, code := restoreCLI(t, set, state)
		if code == 0 || !strings.Contains(stderr, "unsupported backup format") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		assertUnchanged(t, root, before)
	})
}

func TestControlPlaneRestore_NonEmptyNeedsForce(t *testing.T) {
	f := newRestoreFix(t)
	root, state := f.target(t)
	if err := os.WriteFile(filepath.Join(state, "config.yaml"), []byte("old: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, root)
	_, stderr, code := restoreCLI(t, f.set, state)
	if code == 0 || !strings.Contains(stderr, "target state dir is not empty; pass --force") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	assertUnchanged(t, root, before)

	if _, stderr, code := restoreCLI(t, f.set, state, "--force"); code != 0 {
		t.Fatalf("--force exit %d: %s", code, stderr)
	}
	pre, _ := filepath.Glob(filepath.Join(state, "pre-restore-*"))
	if len(pre) != 1 {
		t.Fatalf("pre-restore dirs = %v", pre)
	}
	if got, err := os.ReadFile(filepath.Join(pre[0], "config.yaml")); err != nil || string(got) != "old: true\n" {
		t.Errorf("pre-restore/config.yaml = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(state, "config.yaml")); err != nil || !strings.Contains(string(got), "api.openai.com") {
		t.Errorf("restored config.yaml = %q, %v", got, err)
	}
	if left, _ := filepath.Glob(filepath.Join(state, ".restore-*")); len(left) != 0 {
		t.Errorf("staging left behind: %v", left)
	}
}

func TestControlPlaneRestore_RollbackOnFailure(t *testing.T) {
	f := newRestoreFix(t)
	root, state := f.target(t)
	for n, c := range map[string]string{
		"warden-cp.db": "OLD-DB", "warden-cp.db-wal": "OLD-WAL", "config.yaml": "old: true\n",
	} {
		if err := os.WriteFile(filepath.Join(state, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshot(t, root)

	errBoom := errors.New("injected rename failure")
	_, err := controlplane.RunRestore(context.Background(), controlplane.RestoreParams{
		From: f.set, StateDir: state, Force: true,
		Ops: controlplane.RestoreOps{Rename: func(oldpath, newpath string) error {
			// Fail the last placement, after the database is already in place.
			if strings.HasSuffix(newpath, string(filepath.Separator)+"config.yaml") && strings.Contains(oldpath, ".restore-") {
				return errBoom
			}
			return os.Rename(oldpath, newpath)
		}},
	})
	if !errors.Is(err, errBoom) || !strings.Contains(err.Error(), "rolled back") || !strings.Contains(err.Error(), "pre-restore-") {
		t.Fatalf("err = %v, want the injected failure, 'rolled back' and the pre-restore dir", err)
	}
	assertUnchanged(t, root, before)
}

func TestControlPlaneRestore_Output(t *testing.T) {
	f := newRestoreFix(t)
	_, state := f.target(t)
	stdout, stderr, code := restoreCLI(t, f.set, state)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	all := stdout + stderr
	created := readManifest(t, f.set).CreatedAt.UTC().Format(time.RFC3339)
	for _, want := range []string{created, "WARNING", "worker-token revocations", "user blocks", "policy versions", "admin_audit", "warden-cp.db", "config.yaml"} {
		if !strings.Contains(all, want) {
			t.Errorf("output lacks %q:\n%s", want, all)
		}
	}
	key, err := os.ReadFile(f.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"api.openai.com", "PRIVATE KEY", f.token, strings.TrimSpace(strings.Split(string(key), "\n")[1])} {
		if strings.Contains(all, secret) {
			t.Errorf("output contains %q", secret)
		}
	}
}

func TestControlPlaneRestore_Usage(t *testing.T) {
	for _, args := range [][]string{
		{"control-plane", "restore", "--state-dir", t.TempDir()},
		{"control-plane", "restore", "--from", t.TempDir()},
		{"control-plane", "restore", "--from", t.TempDir(), "--state-dir", t.TempDir(), "extra"},
	} {
		if _, stderr, code := runWarden(t, args...); code != exitAuditUsage || stderr == "" {
			t.Errorf("%v: exit %d, stderr %q, want %d", args, code, stderr, exitAuditUsage)
		}
	}
	// A directory that is no backup set is an error (exit 1), not a usage error.
	if _, stderr, code := runWarden(t, "control-plane", "restore", "--from", t.TempDir(), "--state-dir", t.TempDir()); code != 1 || !strings.Contains(stderr, "manifest") {
		t.Errorf("not a set: exit %d, stderr %q", code, stderr)
	}
}
