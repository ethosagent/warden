package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The initial import (W-P1-PVER-07): the first versioned start on an empty
// store stores the served YAML's policy doc as version 1 without changing the
// served /policy bytes or ETag.

// importStateDir returns a state dir whose served config.yaml is the rich
// overlay fixture (allow/deny plus settings), and the --config path that seeds
// it (the same content).
func importStateDir(t *testing.T) (stateDir, configPath string) {
	t.Helper()
	configPath = overlayFixture(t)
	stateDir = filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "config.yaml"), []byte(readFile(t, configPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	return stateDir, configPath
}

// bootPolicy boots Run with p until it is ready, fetches GET /policy, shuts it
// down and returns the body, the ETag and everything Run logged.
func bootPolicy(t *testing.T, p Params) (body []byte, etag, logs string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	p.OnReady = func(a string) { ready <- a }
	p.ListenAddr = "127.0.0.1:0"
	p.AnalyticsProvider = "memory"
	var out syncBuffer
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, &out, p) }()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("Run returned before OnReady: %v\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}
	_, body, etag = getPolicy(t, "http://"+addr+"/policy", nil)
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run = %v", err)
	}
	return body, etag, out.String()
}

// storedVersion is one policy_versions row as the import tests read it.
type storedVersion struct {
	version                       int64
	authorSub, authorKind, source string
	message, docJSON, docSHA256   string
}

// readVersions opens the state DB read-only and returns every version, oldest
// first, and the head.
func readVersions(t *testing.T, dbPath string) ([]storedVersion, int64) {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), dbPath, StateMigrations())
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
		if err := rows.Scan(&v.version, &v.authorSub, &v.authorKind, &v.source, &v.message, &v.docJSON, &v.docSHA256); err != nil {
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

// TestPolicyMigrationByteIdentical: a state dir with a populated config.yaml
// and an empty store, started with --policy-store=versioned, serves /policy
// byte-identical to file mode with the same ETag, and the store holds exactly
// one version authored system:import.
func TestPolicyMigrationByteIdentical(t *testing.T) {
	stateDir, configPath := importStateDir(t)
	fileBody, fileETag, _ := bootPolicy(t, Params{ConfigPath: configPath, StateDir: stateDir})
	if versions, head := readVersions(t, filepath.Join(stateDir, "warden-cp.db")); len(versions) != 0 || head != 0 {
		t.Fatalf("file mode wrote %d versions (head %d), want none", len(versions), head)
	}

	body, etag, logs := bootPolicy(t, Params{ConfigPath: configPath, StateDir: stateDir, PolicyStore: PolicyStoreVersioned})
	if !bytes.Equal(body, fileBody) || etag != fileETag {
		t.Errorf("versioned /policy after import differs from file mode\n got %s %s\nwant %s %s", etag, body, fileETag, fileBody)
	}
	versions, head := readVersions(t, filepath.Join(stateDir, "warden-cp.db"))
	if len(versions) != 1 || head != 1 {
		t.Fatalf("store holds %d versions (head %d), want exactly version 1", len(versions), head)
	}
	v := versions[0]
	servedPath := filepath.Join(stateDir, "config.yaml")
	if v.authorSub != "system:import" || v.authorKind != AuthorKindSystem || v.source != SourceImport ||
		v.message != "initial import from "+servedPath {
		t.Errorf("version 1 = author %q/%q source %q message %q, want system:import/system, import, %q",
			v.authorSub, v.authorKind, v.source, v.message, "initial import from "+servedPath)
	}
	// The served wire is now version 1's doc, not the YAML.
	var stored policyWire
	if err := json.Unmarshal([]byte(v.docJSON), &stored); err != nil {
		t.Fatal(err)
	}
	if want := `"` + etagFor(stored) + `"`; etag != want {
		t.Errorf("served ETag %s is not version 1's (%s)", etag, want)
	}

	// The creation log line is the import's only line, and carries no content.
	var created int
	for _, line := range strings.Split(logs, "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "policy version created" {
			continue
		}
		created++
		if rec["source"] != SourceImport || rec["version"] != float64(1) || rec["doc_sha256"] != v.docSHA256 {
			t.Errorf("creation log = %s, want source import, version 1, doc_sha256 %s", line, v.docSHA256)
		}
		if strings.Contains(line, "api.openai.com") {
			t.Errorf("creation log carries policy content: %s", line)
		}
	}
	if created != 1 {
		t.Errorf("%d 'policy version created' lines, want 1:\n%s", created, logs)
	}
}

// TestPolicyImportIdempotent: a restart after the import, and a start on a
// store that already has versions, create no version.
func TestPolicyImportIdempotent(t *testing.T) {
	stateDir, configPath := importStateDir(t)
	p := Params{ConfigPath: configPath, StateDir: stateDir, PolicyStore: PolicyStoreVersioned}
	_, etag1, _ := bootPolicy(t, p)
	_, etag2, logs := bootPolicy(t, p)
	if etag1 != etag2 {
		t.Errorf("ETag changed across a restart: %s then %s", etag1, etag2)
	}
	if strings.Contains(logs, "policy version created") {
		t.Errorf("the restart created a version:\n%s", logs)
	}
	if versions, head := readVersions(t, filepath.Join(stateDir, "warden-cp.db")); len(versions) != 1 || head != 1 {
		t.Errorf("after a restart the store holds %d versions (head %d), want 1", len(versions), head)
	}

	// A non-empty store written by someone else is never re-imported.
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	if _, _, err := s.versions.Create(context.Background(), docWithAllow(baseDoc(t, s), "v1.example.com"), testAuthor, "", SourcePolicy, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatalf("importInitialVersion on a non-empty store = %v", err)
	}
	if h := mustHead(t, s.versions); h != 1 || countRows(t, s, "policy_versions") != 1 {
		t.Errorf("non-empty store: head %d, %d rows; want the one existing version", h, countRows(t, s, "policy_versions"))
	}
}

// TestPolicyImportRace: two control planes starting on the same empty state DB
// at once create exactly one version, and neither fails.
func TestPolicyImportRace(t *testing.T) {
	path := overlayFixture(t)
	dbPath := filepath.Join(t.TempDir(), "warden-cp.db")
	const cps = 4
	servers := make([]*Server, cps)
	for i := range servers {
		db, err := cpstate.Open(context.Background(), dbPath, StateMigrations())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		servers[i] = New(Config{PolicyPath: path, State: db, PolicyStore: PolicyStoreVersioned,
			Logger: slog.New(slog.DiscardHandler)})
	}
	var wg sync.WaitGroup
	errs := make([]error, cps)
	for i, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.importInitialVersion(context.Background())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("control plane %d: importInitialVersion = %v", i, err)
		}
	}
	versions, head := readVersions(t, dbPath)
	if len(versions) != 1 || head != 1 {
		t.Fatalf("racing imports left %d versions (head %d), want exactly 1", len(versions), head)
	}
	want := servers[0].policy.currentETag()
	for i, s := range servers {
		s.policy.Refresh()
		if got := s.policy.currentETag(); got != want {
			t.Errorf("control plane %d serves ETag %s, want %s", i, got, want)
		}
	}
}

// TestPolicyImportEtagMismatchFailsStartup: when the import would change the
// served ETag (a fake prediction stands in for a doc the store cannot carry
// faithfully), the import fails with an actionable error and the store stays
// empty.
func TestPolicyImportEtagMismatchFailsStartup(t *testing.T) {
	s := newVersionedServer(t, overlayFixture(t), nil)
	im := s.policyImport()
	im.predict = func(context.Context, policyWire) (string, error) { return "0000000000000000", nil }
	err := im.run(context.Background())
	if err == nil {
		t.Fatal("import with a changing ETag = nil, want a startup error")
	}
	for _, want := range []string{"--policy-store=versioned", "ETag", "--policy-store=file", "empty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if h := mustHead(t, s.versions); h != 0 || countRows(t, s, "policy_versions") != 0 || countRows(t, s, "policy_publish_log") != 0 {
		t.Errorf("after a refused import: head %d, %d versions, %d log rows; want an empty store",
			h, countRows(t, s, "policy_versions"), countRows(t, s, "policy_publish_log"))
	}
}

// TestPolicyImportAudited: with admin audit enabled the import appends one
// policy.initial_import row: target policy, auth_method system, before
// file:<sha256 of the served YAML>, after v1:<doc_sha256>.
func TestPolicyImportAudited(t *testing.T) {
	stateDir, configPath := importStateDir(t)
	cfg := readFile(t, configPath) + "console:\n  adminAudit:\n    enabled: true\n"
	for _, p := range []string{configPath, filepath.Join(stateDir, "config.yaml")} {
		if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := Params{ConfigPath: configPath, StateDir: stateDir, PolicyStore: PolicyStoreVersioned}
	bootPolicy(t, p)
	bootPolicy(t, p) // a restart appends nothing

	versions, _ := readVersions(t, filepath.Join(stateDir, "warden-cp.db"))
	if len(versions) != 1 {
		t.Fatalf("%d versions, want 1", len(versions))
	}
	fileSum := sha256.Sum256([]byte(cfg))
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query(`SELECT action, target, auth_method, actor_role, outcome, before_hash, after_hash FROM admin_audit WHERE action = ?`, "policy.initial_import")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var n int
	for rows.Next() {
		n++
		var action, target, method, role, outcome, before, after string
		if err := rows.Scan(&action, &target, &method, &role, &outcome, &before, &after); err != nil {
			t.Fatal(err)
		}
		if target != "policy" || method != adminaudit.AuthMethodSystem || role != "system" || outcome != adminaudit.OutcomeOK {
			t.Errorf("row = target %q auth_method %q role %q outcome %q, want policy/system/system/ok", target, method, role, outcome)
		}
		if want := "file:" + hex.EncodeToString(fileSum[:]); before != want {
			t.Errorf("before_hash = %q, want %q", before, want)
		}
		if want := "v1:" + versions[0].docSHA256; after != want {
			t.Errorf("after_hash = %q, want %q", after, want)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d policy.initial_import rows, want 1", n)
	}
}

// failingRecorder is an admin audit Recorder whose appends always fail.
type failingRecorder struct{ calls int }

func (r *failingRecorder) Record(context.Context, adminaudit.Input) (adminaudit.Entry, error) {
	r.calls++
	return adminaudit.Entry{}, errors.New("disk full")
}

// TestPolicyImportAuditErrorKeepsStarting: a Recorder error is logged at ERROR
// and does not fail the import.
func TestPolicyImportAuditErrorKeepsStarting(t *testing.T) {
	var logs syncBuffer
	s := newVersionedServer(t, overlayFixture(t), &logs)
	im := s.policyImport()
	rec := &failingRecorder{}
	im.audit = rec
	if err := im.run(context.Background()); err != nil {
		t.Fatalf("import with a failing recorder = %v, want nil", err)
	}
	if rec.calls != 1 || mustHead(t, s.versions) != 1 {
		t.Errorf("recorder calls %d, head %d; want 1 and 1", rec.calls, mustHead(t, s.versions))
	}
	if !strings.Contains(logs.String(), `"level":"ERROR"`) || !strings.Contains(logs.String(), "policy.initial_import") {
		t.Errorf("no ERROR line for the failed audit append:\n%s", logs.String())
	}
}

// TestPolicyImportRedacts: the stored doc carries the credential's fingerprint,
// never its value, while /policy keeps serving the live value byte-identical
// to file mode.
func TestPolicyImportRedacts(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	fileTS := httptest.NewServer(New(Config{PolicyPath: path}).Handler())
	defer fileTS.Close()
	_, fileBody, fileETag := getPolicy(t, fileTS.URL+"/policy", nil)

	var logs syncBuffer
	s := newVersionedServer(t, path, &logs)
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatalf("importInitialVersion = %v", err)
	}
	var docJSON string
	if err := s.cfg.State.SQL().QueryRow("SELECT doc_json FROM policy_versions WHERE version = 1").Scan(&docJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(docJSON, policyStoreSecret) {
		t.Fatal("version 1 holds the raw secretAccessKey")
	}
	if !strings.Contains(docJSON, `"secretAccessKey":"`+redactCredential(policyStoreSecret)+`"`) {
		t.Errorf("version 1 does not carry the credential fingerprint: %s", docJSON)
	}
	if strings.Contains(logs.String(), policyStoreSecret) {
		t.Error("a log line holds the raw secretAccessKey")
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	code, body, etag := getPolicy(t, ts.URL+"/policy", nil)
	if code != http.StatusOK || !bytes.Equal(body, fileBody) || etag != fileETag {
		t.Errorf("versioned /policy after import differs from file mode\n got %d %s %s\nwant %s %s", code, etag, body, fileETag, fileBody)
	}
}

// TestPolicyImportFileModeNoop: importInitialVersion does nothing in file mode.
func TestPolicyImportFileModeNoop(t *testing.T) {
	s := New(Config{PolicyPath: overlayFixture(t), State: openPolicyState(t), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatalf("importInitialVersion in file mode = %v", err)
	}
	if n := countRows(t, s, "policy_versions"); n != 0 {
		t.Errorf("file mode wrote %d versions", n)
	}
}
