package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// policyStoreSecret is the fake AWS secretAccessKey the redaction tests plant
// in the served YAML. It must never reach doc_json, the DB file or a log line.
const policyStoreSecret = "sk-live-PVER01-do-not-store"

var testAuthor = PolicyAuthor{Sub: "u1", Email: "a@example.com", Kind: AuthorKindOIDC}

// openPolicyState opens a fresh cpstate DB with every migration Run registers.
func openPolicyState(t *testing.T) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newVersionedServer builds a versioned-mode Server over policyPath and a fresh
// state DB, logging to logs (nil discards).
func newVersionedServer(t *testing.T, policyPath string, logs io.Writer) *Server {
	t.Helper()
	if logs == nil {
		logs = io.Discard
	}
	return New(Config{
		PolicyPath:  policyPath,
		State:       openPolicyState(t),
		PolicyStore: PolicyStoreVersioned,
		Logger:      slog.New(slog.NewJSONHandler(logs, nil)),
	})
}

// writeCredentialPolicyFile writes a served config whose secretStore carries an
// explicit AWS credential (the sanctioned credential-on-wire exception).
func writeCredentialPolicyFile(t *testing.T) string {
	t.Helper()
	path := writePolicyFile(t, "api.openai.com")
	body := readFile(t, path) +
		"secretStore:\n  backend: aws\n  aws:\n    region: us-east-1\n    namePrefix: warden/\n" +
		"    accessKeyId: AKIAPVER01\n    secretAccessKey: " + policyStoreSecret + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// docWithAllow returns base with domain appended to the allowlist (a copy).
func docWithAllow(base policyWire, domain string) policyWire {
	out := base
	out.Allowlist = append(append([]config.AllowlistEntry(nil), base.Allowlist...), config.AllowlistEntry{Domain: domain})
	return out
}

func baseDoc(t *testing.T, s *Server) policyWire {
	t.Helper()
	doc, err := s.policy.loadBase(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func countRows(t *testing.T, s *Server, table string) int {
	t.Helper()
	var n int
	if err := s.cfg.State.SQL().QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustHead(t *testing.T, st PolicyVersionStore) int64 {
	t.Helper()
	h, err := st.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func getPolicy(t *testing.T, base string, hdr map[string]string) (int, []byte, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b, resp.Header.Get("ETag")
}

// TestPolicyVersionStoreCAS: Create is a compare-and-swap on the head. A stale
// expectedHead writes nothing; of many racers on one head exactly one wins,
// in-process and across two database handles (the CLI and the CP).
func TestPolicyVersionStoreCAS(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	ctx := context.Background()
	base := baseDoc(t, s)
	for i, d := range []string{"v1.example.com", "v2.example.com", "v3.example.com"} {
		v, changed, err := s.versions.Create(ctx, docWithAllow(base, d), testAuthor, "save", SourcePolicy, int64(i))
		if err != nil || !changed || v != int64(i+1) {
			t.Fatalf("Create #%d = %d, %v, %v", i+1, v, changed, err)
		}
	}
	rows := countRows(t, s, "policy_versions")
	logRows := countRows(t, s, "policy_publish_log")

	_, _, err := s.versions.Create(ctx, docWithAllow(base, "stale.example.com"), testAuthor, "stale", SourcePolicy, 2)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create with expectedHead=2 on head 3 = %v, want ErrConflict", err)
	}
	if got := countRows(t, s, "policy_versions"); got != rows {
		t.Errorf("policy_versions rows after conflict = %d, want %d", got, rows)
	}
	if got := countRows(t, s, "policy_publish_log"); got != logRows {
		t.Errorf("policy_publish_log rows after conflict = %d, want %d", got, logRows)
	}
	if h := mustHead(t, s.versions); h != 3 {
		t.Fatalf("Head after conflict = %d, want 3", h)
	}

	// A second handle on the same file is the out-of-process writer.
	other, err := cpstate.Open(ctx, s.cfg.State.Path(), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	stores := []PolicyVersionStore{s.versions, newSQLitePolicyStore(other.SQL(), time.Now, slog.New(slog.DiscardHandler))}

	const racers = 20
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, changed, err := stores[i%2].Create(ctx, docWithAllow(base, "race"+string(rune('a'+i))+".example.com"), testAuthor, "race", SourcePolicy, 3)
			switch {
			case err == nil && changed:
				wins.Add(1)
			case errors.Is(err, ErrConflict):
				conflicts.Add(1)
			default:
				t.Errorf("racer %d: changed=%v err=%v", i, changed, err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != racers-1 {
		t.Fatalf("wins=%d conflicts=%d, want exactly one winner of %d", wins.Load(), conflicts.Load(), racers)
	}
	if h := mustHead(t, s.versions); h != 4 {
		t.Errorf("Head after race = %d, want 4", h)
	}
	if got := countRows(t, s, "policy_versions"); got != rows+1 {
		t.Errorf("policy_versions rows after race = %d, want %d", got, rows+1)
	}
}

// TestPolicyVersionStoreReads covers Get, List paging (version order, never
// created_at), PublishLog, the unchanged-doc no-op and input checks.
func TestPolicyVersionStoreReads(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	ctx := context.Background()
	base := baseDoc(t, s)
	for i := range 3 {
		if _, _, err := s.versions.Create(ctx, docWithAllow(base, "r"+string(rune('a'+i))+".example.com"),
			testAuthor, "msg\x00 with\x1b control chars", SourceSettings, int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Same doc as head: nothing written, changed=false, head returned.
	v, changed, err := s.versions.Create(ctx, docWithAllow(base, "rc.example.com"), testAuthor, "again", SourcePolicy, 3)
	if err != nil || changed || v != 3 {
		t.Fatalf("Create(head doc) = %d, %v, %v; want 3, false, nil", v, changed, err)
	}
	if got := countRows(t, s, "policy_versions"); got != 3 {
		t.Errorf("rows after no-op Create = %d, want 3", got)
	}

	got, err := s.versions.Get(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.Parent != 1 || got.Author != testAuthor || got.Source != SourceSettings {
		t.Errorf("Get(2) = %+v", got)
	}
	if got.Message != "msg with control chars" {
		t.Errorf("Message = %q, want control characters stripped", got.Message)
	}
	if d := allowDomainsOf(got.Doc); d[len(d)-1] != "rb.example.com" {
		t.Errorf("Get(2) doc allowlist = %v", d)
	}
	if _, err := s.versions.Get(ctx, 99); !errors.Is(err, ErrVersionNotFound) {
		t.Errorf("Get(99) = %v, want ErrVersionNotFound", err)
	}

	page, next, err := s.versions.List(ctx, 0, 2)
	if err != nil || len(page) != 2 || page[0].Version != 3 || page[1].Version != 2 || next != 2 {
		t.Fatalf("List(0,2) = %+v next=%d err=%v", page, next, err)
	}
	page, next, err = s.versions.List(ctx, next, 2)
	if err != nil || len(page) != 1 || page[0].Version != 1 || next != 0 {
		t.Fatalf("List(2,2) = %+v next=%d err=%v", page, next, err)
	}
	if page[0].DocSHA256 == "" {
		t.Error("List entries carry doc_sha256")
	}

	log, err := s.versions.PublishLog(ctx, 0, 10)
	if err != nil || len(log) != 3 {
		t.Fatalf("PublishLog = %+v, %v", log, err)
	}
	for i, e := range log {
		if e.Version != int64(i+1) || e.Reason != SourceSettings || e.ActorSub != "u1" || e.ETag == "" {
			t.Errorf("publish log %d = %+v", i, e)
		}
	}
	// The publish log carries the served ETag of the head it records.
	_, etag, _, _ := s.policy.snapshot()
	if log[2].ETag != etag {
		t.Errorf("publish log ETag = %s, served ETag %s", log[2].ETag, etag)
	}
	if later, err := s.versions.PublishLog(ctx, log[1].Seq, 10); err != nil || len(later) != 1 {
		t.Errorf("PublishLog(after seq %d) = %+v, %v", log[1].Seq, later, err)
	}

	long := strings.Repeat("é", maxPolicyMessage+50)
	v, _, err = s.versions.Create(ctx, docWithAllow(base, "long.example.com"), testAuthor, long, SourcePolicy, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.versions.Get(ctx, v); len([]rune(got.Message)) != maxPolicyMessage {
		t.Errorf("message length = %d runes, want capped at %d", len([]rune(got.Message)), maxPolicyMessage)
	}

	for name, call := range map[string]func() error{
		"unknown author kind": func() error {
			_, _, err := s.versions.Create(ctx, base, PolicyAuthor{Sub: "x", Kind: "root"}, "", SourcePolicy, 4)
			return err
		},
		"empty author sub": func() error {
			_, _, err := s.versions.Create(ctx, base, PolicyAuthor{Kind: AuthorKindSystem}, "", SourcePolicy, 4)
			return err
		},
		"unknown source": func() error {
			_, _, err := s.versions.Create(ctx, base, testAuthor, "", "yaml", 4)
			return err
		},
	} {
		if err := call(); err == nil || errors.Is(err, ErrConflict) {
			t.Errorf("%s: Create = %v, want an input error", name, err)
		}
	}
	if h := mustHead(t, s.versions); h != 4 {
		t.Errorf("Head after refused Creates = %d, want 4", h)
	}
}

func allowDomainsOf(w policyWire) []string {
	out := make([]string, 0, len(w.Allowlist))
	for _, e := range w.Allowlist {
		out = append(out, e.Domain)
	}
	return out
}

// TestPolicyVersionValidate: validateDoc runs the candidate through the real
// loader, so an invalid domain pattern or an empty allowlist (default-deny) is
// rejected with the loader's error and nothing moves.
func TestPolicyVersionValidate(t *testing.T) {
	s := newVersionedServer(t, overlayFixture(t), nil)
	base := baseDoc(t, s)
	etag := s.policy.currentETag()

	if err := s.validateDoc(docWithAllow(base, "ok.example.com")); err != nil {
		t.Fatalf("validateDoc(valid) = %v", err)
	}
	empty := base
	empty.Allowlist = nil
	badRegex := docWithAllow(base, "~(")
	noProvider := base
	settings := *base.Settings
	settings.LLMProviders = nil // the judge still names p1
	noProvider.Settings = &settings
	for name, doc := range map[string]policyWire{"empty allowlist": empty, "invalid domain pattern": badRegex, "dangling llmProvider": noProvider} {
		err := s.validateDoc(doc)
		if err == nil || !strings.Contains(err.Error(), "invalid policy") {
			t.Errorf("%s: validateDoc = %v, want the loader error", name, err)
		}
	}
	if h := mustHead(t, s.versions); h != 0 {
		t.Errorf("Head after failed validation = %d, want 0", h)
	}
	if got := s.policy.currentETag(); got != etag {
		t.Errorf("served ETag moved after failed validation: %s -> %s", etag, got)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(s.cfg.PolicyPath), ".warden-policy-*"))
	if len(matches) != 0 {
		t.Errorf("validateDoc left temp files: %v", matches)
	}
}

// TestPolicyVersionRedactsCredential: the AWS secretAccessKey is replaced by
// its fingerprint before it is hashed and stored, so neither doc_json nor the
// DB file holds it, while GET /policy still serves the live value.
func TestPolicyVersionRedactsCredential(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	fileSrv := New(Config{PolicyPath: path})
	fileTS := httptest.NewServer(fileSrv.Handler())
	defer fileTS.Close()
	_, fileBody, fileETag := getPolicy(t, fileTS.URL+"/policy", nil)

	s := newVersionedServer(t, path, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	doc := baseDoc(t, s)
	if doc.Settings.Secrets.SecretAccessKey != policyStoreSecret {
		t.Fatal("fixture: the base doc should carry the live credential before redaction")
	}
	v, changed, err := s.versions.Create(context.Background(), docWithAllow(doc, "new.example.com"), testAuthor, "add", SourcePolicy, 0)
	if err != nil || !changed {
		t.Fatalf("Create = %d, %v, %v", v, changed, err)
	}
	if doc.Settings.Secrets.SecretAccessKey != policyStoreSecret {
		t.Error("Create mutated the caller's doc")
	}

	var docJSON string
	if err := s.cfg.State.SQL().QueryRow("SELECT doc_json FROM policy_versions WHERE version = ?", v).Scan(&docJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(docJSON, policyStoreSecret) {
		t.Fatal("doc_json holds the raw secretAccessKey")
	}
	if want := RedactCredentials(doc).Settings.Secrets.SecretAccessKey; !regexp.MustCompile(`^sha256:[0-9a-f]{16}$`).MatchString(want) ||
		!strings.Contains(docJSON, `"secretAccessKey":"`+want+`"`) {
		t.Errorf("doc_json does not carry the sha256:<16 hex> fingerprint %q: %s", want, docJSON)
	}
	if err := s.cfg.State.SQL().QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(new(int), new(int), new(int)); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(s.cfg.State.Path() + "*")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(policyStoreSecret)) {
			t.Errorf("%s holds the raw secretAccessKey", filepath.Base(f))
		}
	}

	_, body, _ := getPolicy(t, ts.URL+"/policy", nil)
	var served policyWire
	if err := json.Unmarshal(body, &served); err != nil {
		t.Fatal(err)
	}
	if served.Settings == nil || served.Settings.Secrets == nil || served.Settings.Secrets.SecretAccessKey != policyStoreSecret {
		t.Errorf("GET /policy lost the live credential: %+v", served.Settings)
	}
	if fp := s.policy.overlayFingerprints()["credential"]; fp != redactCredential(policyStoreSecret) {
		t.Errorf("credential overlay fingerprint = %q, want the live value's fingerprint", fp)
	}

	// The unchanged doc as version 2 serves exactly what file mode serves.
	if _, _, err := s.versions.Create(context.Background(), doc, testAuthor, "revert", SourcePolicy, v); err != nil {
		t.Fatal(err)
	}
	_, body, etag := getPolicy(t, ts.URL+"/policy", nil)
	if !bytes.Equal(body, fileBody) || etag != fileETag {
		t.Errorf("versioned head with the file's doc differs from file mode\n got %s %s\nwant %s %s", etag, body, fileETag, fileBody)
	}
}

// TestPolicyVersionExcludesOverlays: serve-time overlay data (the block list
// stands in as a test overlay) reaches GET /policy but never doc_json, because
// versions are built from the base wire, before overlays.
func TestPolicyVersionExcludesOverlays(t *testing.T) {
	db := openPolicyState(t)
	st := newSQLitePolicyStore(db.SQL(), time.Now, slog.New(slog.DiscardHandler))
	ps := newPolicyServer(writePolicyFile(t, "api.openai.com"), "", slog.New(slog.DiscardHandler), NewWorkerRegistry())
	ps.versions = st
	st.etagOf = ps.servedETag
	st.onCreated = ps.Refresh
	const marker = "blocked-users-overlay.example"
	if err := ps.addOverlay(appendAllow("blocked_users", marker, "fp")); err != nil {
		t.Fatal(err)
	}
	ps.Refresh()

	doc, err := ps.loadBase(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Create(context.Background(), docWithAllow(doc, "v1.example.com"), testAuthor, "", SourcePolicy, 0); err != nil {
		t.Fatal(err)
	}
	var docJSON string
	if err := db.SQL().QueryRow("SELECT doc_json FROM policy_versions WHERE version = 1").Scan(&docJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(docJSON, marker) {
		t.Errorf("doc_json holds overlay data: %s", docJSON)
	}
	body, _ := servePolicyOnce(t, ps)
	got := allowDomains(t, body)
	if got[len(got)-1] != marker || got[len(got)-2] != "v1.example.com" {
		t.Errorf("served allowlist = %v, want head v1 with the overlay applied", got)
	}
}

// TestPolicyServerVersionedLongPoll: Create with changed content wakes a
// long-poll waiter at once; Create with identical content writes nothing and
// leaves the ETag alone.
func TestPolicyServerVersionedLongPoll(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	_, _, etag := getPolicy(t, ts.URL+"/policy", nil)

	type result struct {
		code int
		body []byte
		at   time.Time
	}
	done := make(chan result, 1)
	go func() {
		code, body, _ := getPolicy(t, ts.URL+"/policy?wait=5s", map[string]string{"If-None-Match": etag})
		done <- result{code, body, time.Now()}
	}()
	// Let the waiter block on the current ETag before the write.
	time.Sleep(100 * time.Millisecond)
	doc := docWithAllow(baseDoc(t, s), "woken.example.com")
	start := time.Now()
	if _, changed, err := s.versions.Create(context.Background(), doc, testAuthor, "wake", SourcePolicy, 0); err != nil || !changed {
		t.Fatalf("Create = %v, %v", changed, err)
	}
	select {
	case r := <-done:
		if r.code != http.StatusOK || !strings.Contains(string(r.body), "woken.example.com") {
			t.Fatalf("waiter got %d %s, want 200 with the new doc", r.code, r.body)
		}
		if d := r.at.Sub(start); d > time.Second {
			t.Errorf("waiter woke after %s, want within 1s", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long-poll waiter not woken by Create")
	}

	_, _, etag2 := getPolicy(t, ts.URL+"/policy", nil)
	rows := countRows(t, s, "policy_versions")
	if _, changed, err := s.versions.Create(context.Background(), doc, testAuthor, "same", SourcePolicy, 1); err != nil || changed {
		t.Fatalf("Create(identical) = %v, %v; want unchanged", changed, err)
	}
	if got := countRows(t, s, "policy_versions"); got != rows {
		t.Errorf("identical Create wrote a row: %d -> %d", rows, got)
	}
	if _, _, etag3 := getPolicy(t, ts.URL+"/policy", nil); etag3 != etag2 {
		t.Errorf("identical Create moved the ETag: %s -> %s", etag2, etag3)
	}
}

// TestPolicyServerVersionedByteIdentity: in file mode and in versioned mode
// with an empty store, GET /policy matches the golden captured on main.
func TestPolicyServerVersionedByteIdentity(t *testing.T) {
	wantBody, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantETagRaw, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.etag"))
	if err != nil {
		t.Fatal(err)
	}
	wantETag := strings.TrimSpace(string(wantETagRaw))
	fixture := filepath.Join("testdata", "policy_overlay_none.yaml")

	for name, srv := range map[string]*Server{
		"file default":       New(Config{PolicyPath: fixture}),
		"file explicit":      New(Config{PolicyPath: fixture, PolicyStore: PolicyStoreFile, State: openPolicyState(t)}),
		"versioned, head 0":  newVersionedServer(t, fixture, nil),
		"versioned, no rows": newVersionedServer(t, overlayFixture(t), nil),
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()
			_, body, etag := getPolicy(t, ts.URL+"/policy", nil)
			if !bytes.Equal(body, wantBody) || etag != wantETag {
				t.Errorf("GET /policy differs from golden\n got %s %s\nwant %s %s", etag, body, wantETag, wantBody)
			}
		})
	}
}

// runParams are Run params for a versioned control plane on a loopback port.
func runParams(t *testing.T, stateDir string) (Params, *atomic.Bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := &atomic.Bool{}
	return Params{
		ConfigPath:        writePolicyFile(t, "api.openai.com"),
		StateDir:          stateDir,
		AnalyticsProvider: "memory",
		Listener:          ln,
		PolicyStore:       PolicyStoreVersioned,
		OnReady:           func(string) { ready.Store(true) },
	}, ready
}

// runOnce runs a control plane that stops as soon as it is ready and returns
// Run's error.
func runOnce(t *testing.T, p Params) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inner := p.OnReady
	p.OnReady = func(addr string) {
		if inner != nil {
			inner(addr)
		}
		cancel()
	}
	return Run(ctx, io.Discard, p)
}

// TestPolicyStoreFlag: versioned without a state dir and an unknown mode are
// startup errors before the listener serves.
func TestPolicyStoreFlag(t *testing.T) {
	p, ready := runParams(t, "")
	err := runOnce(t, p)
	if err == nil || !strings.Contains(err.Error(), "--state-dir") {
		t.Errorf("versioned without --state-dir = %v, want an error naming --state-dir", err)
	}
	p, ready2 := runParams(t, filepath.Join(t.TempDir(), "state"))
	p.PolicyStore = "git"
	err = runOnce(t, p)
	if err == nil || !strings.Contains(err.Error(), "--policy-store") {
		t.Errorf("unknown --policy-store = %v, want an error naming the flag", err)
	}
	if ready.Load() || ready2.Load() {
		t.Error("the control plane started listening despite a bad --policy-store")
	}
	for _, mode := range []string{"", PolicyStoreFile, PolicyStoreVersioned} {
		p, ready := runParams(t, filepath.Join(t.TempDir(), "state"))
		p.PolicyStore = mode
		if err := runOnce(t, p); err != nil || !ready.Load() {
			t.Errorf("--policy-store=%q: Run = %v, ready=%v", mode, err, ready.Load())
		}
	}
}

// TestPolicyStoreFailClosedStartup: in versioned mode an unreadable store, a
// head pointing at a missing version or a doc failing its doc_sha256 check
// refuses startup; the CP never falls back to the YAML.
func TestPolicyStoreFailClosedStartup(t *testing.T) {
	cases := map[string]struct {
		break_ string
		want   string
	}{
		"unreadable store": {"DROP TABLE policy_head", "policy store"},
		"missing version":  {"UPDATE policy_head SET version = 7", "version 7"},
		"sha mismatch": {`INSERT INTO policy_versions (version, parent_version, created_at, author_sub, author_email, author_kind, message, source, doc_json, doc_sha256)
		  VALUES (1, 0, 0, 'u1', '', 'cli', '', 'import', '{"allowlist":[{"domain":"x.example.com"}],"denylist":null}', 'deadbeef');
		  UPDATE policy_head SET version = 1`, "doc_sha256"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			db, err := cpstate.Open(context.Background(), filepath.Join(stateDir, "warden-cp.db"), StateMigrations())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.SQL().Exec(tc.break_); err != nil {
				t.Fatal(err)
			}
			_ = db.Close()
			p, ready := runParams(t, stateDir)
			err = runOnce(t, p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run = %v, want a startup error containing %q", err, tc.want)
			}
			if ready.Load() {
				t.Error("the control plane started listening on a broken store")
			}
		})
	}
}

// TestPolicyStoreRuntimeErrorKeepsLastGood: a store read error after startup
// keeps serving the last-known-good wire and logs.
func TestPolicyStoreRuntimeErrorKeepsLastGood(t *testing.T) {
	var logs syncBuffer
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), &logs)
	if _, _, err := s.versions.Create(context.Background(), docWithAllow(baseDoc(t, s), "v1.example.com"), testAuthor, "", SourcePolicy, 0); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	_, body, etag := getPolicy(t, ts.URL+"/policy", nil)

	if _, err := s.cfg.State.SQL().Exec("DROP TABLE policy_head"); err != nil {
		t.Fatal(err)
	}
	s.policy.Refresh()
	code, body2, etag2 := getPolicy(t, ts.URL+"/policy", nil)
	if code != http.StatusOK || etag2 != etag || !bytes.Equal(body2, body) {
		t.Errorf("after a store error GET /policy = %d %s, want last-known-good %s", code, etag2, etag)
	}
	if !strings.Contains(logs.String(), "keeping last-known-good") {
		t.Errorf("no reload-failure log line: %s", logs.String())
	}
}

// TestPolicyVersionLogsNoContent: the creation log line carries version,
// parent, source, author_sub and doc_sha256 only.
func TestPolicyVersionLogsNoContent(t *testing.T) {
	var logs syncBuffer
	s := newVersionedServer(t, writeCredentialPolicyFile(t), &logs)
	const marker, msg = "content-marker.example.com", "message-marker-text"
	if _, _, err := s.versions.Create(context.Background(), docWithAllow(baseDoc(t, s), marker), testAuthor, msg, SourcePolicy, 0); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		for _, banned := range []string{marker, msg, policyStoreSecret, "api.openai.com", testAuthor.Email} {
			if strings.Contains(line, banned) {
				t.Errorf("log line holds %q: %s", banned, line)
			}
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec["msg"] != "policy version created" {
			continue
		}
		found = true
		for _, k := range []string{"version", "parent", "source", "author_sub", "doc_sha256"} {
			if _, ok := rec[k]; !ok {
				t.Errorf("creation log lacks %s: %s", k, line)
			}
		}
		for k := range rec {
			switch k {
			case "time", "level", "msg", "version", "parent", "source", "author_sub", "doc_sha256":
			default:
				t.Errorf("creation log has unexpected key %q: %s", k, line)
			}
		}
	}
	if !found {
		t.Fatalf("no \"policy version created\" line: %s", logs.String())
	}
}

// appendOnlySQL matches any statement that would rewrite or delete history.
var appendOnlySQL = regexp.MustCompile(`(?i)(update|delete\s+from|replace\s+into|insert\s+or\s+replace\s+into)\s+(policy_versions|policy_publish_log)\b`)

// TestPolicyStoreAppendOnly: no non-test Go file in the module updates or
// deletes policy_versions or policy_publish_log rows, and the schema refuses
// it too.
func TestPolicyStoreAppendOnly(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if m := appendOnlySQL.Find(b); m != nil {
			t.Errorf("%s rewrites policy history: %q", path, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	if _, _, err := s.versions.Create(context.Background(), docWithAllow(baseDoc(t, s), "v1.example.com"), testAuthor, "", SourcePolicy, 0); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"UPDATE policy_versions SET message = 'x'",
		"DELETE FROM policy_versions",
		"UPDATE policy_publish_log SET etag = 'x'",
		"DELETE FROM policy_publish_log",
	} {
		if _, err := s.cfg.State.SQL().Exec(stmt); err == nil {
			t.Errorf("%s succeeded; history must be append-only", stmt)
		}
	}
}

// TestRedactCredentials pins the redaction form and that it never changes a doc
// without a credential.
func TestRedactCredentials(t *testing.T) {
	if got := RedactCredentials(policyWire{}); got.Settings != nil {
		t.Errorf("RedactCredentials(empty) = %+v", got)
	}
	in := policyWire{Settings: &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws", AccessKeyID: "AKIA", SecretAccessKey: "s3cr3t"}}}
	out := RedactCredentials(in)
	fp := out.Settings.Secrets.SecretAccessKey
	if !isRedactedCredential(fp) || fp != redactCredential("s3cr3t") {
		t.Errorf("redacted = %q", fp)
	}
	if in.Settings.Secrets.SecretAccessKey != "s3cr3t" {
		t.Error("RedactCredentials mutated its input")
	}
	if again := RedactCredentials(out); again.Settings.Secrets.SecretAccessKey != fp {
		t.Error("RedactCredentials is not idempotent")
	}
	for _, s := range []string{"sha256:ABCDEF0123456789", "sha256:0123", "sha256:0123456789abcdefg", "md5:0123456789abcdef"} {
		if isRedactedCredential(s) {
			t.Errorf("isRedactedCredential(%q) = true", s)
		}
	}
}
