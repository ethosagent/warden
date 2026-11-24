package keys_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/filestore"
	"github.com/ethosagent/warden/internal/keys/adapters/metastore"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type recAudit struct {
	mu  sync.Mutex
	evs []keys.AuditEvent
}

func (r *recAudit) RecordKeyEvent(_ context.Context, ev keys.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *recAudit) events() []keys.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]keys.AuditEvent(nil), r.evs...)
}

type recAlerts struct {
	mu sync.Mutex
	as []keys.Alert
}

func (r *recAlerts) Raise(_ context.Context, a keys.Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.as = append(r.as, a)
}

func (r *recAlerts) alerts() []keys.Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]keys.Alert(nil), r.as...)
}

// flakyStore wraps a PrivateKeyStore with switchable failures.
type flakyStore struct {
	keys.PrivateKeyStore
	failGet, failPut atomic.Bool
}

func (f *flakyStore) Get(ctx context.Context, purpose, kid string) ([]byte, error) {
	if f.failGet.Load() {
		return nil, errors.New("backend unavailable")
	}
	return f.PrivateKeyStore.Get(ctx, purpose, kid)
}

func (f *flakyStore) Put(ctx context.Context, purpose, kid string, b []byte) error {
	if f.failPut.Load() {
		return errors.New("backend read-only")
	}
	return f.PrivateKeyStore.Put(ctx, purpose, kid, b)
}

// failInsertMeta fails InsertIfEmpty.
type failInsertMeta struct{ keys.MetaStore }

func (failInsertMeta) InsertIfEmpty(context.Context, string, []keys.Record) (bool, error) {
	return false, errors.New("database is locked")
}

// failPromoteMeta fails Promote: a database that cannot run the promotion
// transaction.
type failPromoteMeta struct {
	keys.MetaStore
	fail atomic.Bool
}

func (f *failPromoteMeta) Promote(ctx context.Context, purpose, oldKID string, oldTo keys.State, nextKID string, at time.Time) (bool, error) {
	if f.fail.Load() {
		return false, errors.New("database is locked")
	}
	return f.MetaStore.Promote(ctx, purpose, oldKID, oldTo, nextKID, at)
}

// waitOn adapts the fake clock to ManagerConfig.Wait.
func waitOn(clk *clocktest.Fake) func(context.Context, time.Duration) bool {
	return func(ctx context.Context, d time.Duration) bool {
		t := clk.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C():
			return true
		}
	}
}

type env struct {
	t      *testing.T
	dir    string // key directory
	dbPath string
	db     *cpstate.DB
	meta   keys.MetaStore
	store  *flakyStore
	clk    *clocktest.Fake
	logs   *syncBuffer
	audit  *recAudit
	alerts *recAlerts
	// timings is what e.manager() wires; rotation tests shrink the windows so
	// a schedule fits in a few clock advances.
	timings map[string]keys.Timing
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		t:      t,
		dir:    filepath.Join(root, "keys"),
		dbPath: filepath.Join(root, "warden-cp.db"),
		clk:    clocktest.NewFake(time.Unix(1_800_000_000, 0)),
		logs:   &syncBuffer{},
		audit:  &recAudit{},
		alerts: &recAlerts{},
		timings: map[string]keys.Timing{
			keys.PurposeToken:  {Interval: 24 * time.Hour, Prepublish: time.Hour, Overlap: 2 * time.Hour},
			keys.PurposeBundle: {Prepublish: time.Hour, Overlap: 2 * time.Hour},
		},
	}
	e.openDB()
	fs, err := filestore.New(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	e.store = &flakyStore{PrivateKeyStore: fs}
	return e
}

func (e *env) openDB() {
	e.t.Helper()
	if e.db != nil {
		_ = e.db.Close()
	}
	db, err := cpstate.Open(context.Background(), e.dbPath, cpstate.Enable(metastore.Migrations(), metastore.MigrationID))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = db.Close() })
	e.db = db
	e.meta = metastore.New(db)
}

func (e *env) manager() *keys.Manager {
	e.t.Helper()
	return e.managerOn(e.meta)
}

// managerOn builds a manager over another metadata store handle — a second
// process on the same database file, with its own lock and its own snapshot.
func (e *env) managerOn(meta keys.MetaStore) *keys.Manager {
	e.t.Helper()
	return e.managerWith(meta, e.store)
}

// managerWith is managerOn with the private-key store named too: a peer
// process holds its own handles on both.
func (e *env) managerWith(meta keys.MetaStore, store keys.PrivateKeyStore) *keys.Manager {
	e.t.Helper()
	m, err := keys.NewManager(keys.ManagerConfig{
		Store: store, Meta: meta, Codec: signer.Codec{}, Backend: "file",
		Algs:    map[string]string{keys.PurposeToken: keys.AlgEdDSA, keys.PurposeBundle: keys.AlgEdDSA},
		Timings: e.timings,
		Now:     e.clk.Now, Wait: waitOn(e.clk), Logger: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Audit: e.audit, Alerts: e.alerts,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

// anotherMeta opens a second connection to the same database file: what the
// keys CLI holds while the control plane runs.
func (e *env) anotherMeta() keys.MetaStore {
	e.t.Helper()
	db, err := cpstate.Open(context.Background(), e.dbPath, cpstate.Enable(metastore.Migrations(), metastore.MigrationID))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = db.Close() })
	return metastore.New(db)
}

func (e *env) rows() []keys.Record {
	e.t.Helper()
	rows, err := e.meta.List(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func kidsByState(rows []keys.Record, purpose string, st keys.State) []string {
	var out []string
	for _, r := range rows {
		if r.Purpose == purpose && r.State == st {
			out = append(out, r.KID)
		}
	}
	return out
}

// TestKeyStoreReloadSameKID: a restart keeps the same active and next kids and
// creates no extra rows.
func TestKeyStoreReloadSameKID(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m1 := e.manager()
	m1.Init(ctx)
	first := e.rows()
	if len(first) != 4 {
		t.Fatalf("rows after first start = %d, want 4 (active+next for token and bundle)", len(first))
	}
	for _, p := range []string{keys.PurposeToken, keys.PurposeBundle} {
		if len(kidsByState(first, p, keys.StateActive)) != 1 || len(kidsByState(first, p, keys.StateNext)) != 1 {
			t.Fatalf("%s: want one active and one next, rows %+v", p, first)
		}
	}
	signerBefore, err := m1.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}

	// Restart: new database handle, new manager, same files.
	e.openDB()
	m2 := e.manager()
	m2.Init(ctx)
	second := e.rows()
	if len(second) != len(first) {
		t.Fatalf("restart changed row count: %d -> %d", len(first), len(second))
	}
	for i := range first {
		if first[i].KID != second[i].KID || first[i].State != second[i].State {
			t.Errorf("row %d changed across restart: %+v -> %+v", i, first[i], second[i])
		}
	}
	signerAfter, err := m2.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if signerBefore.KID() != signerAfter.KID() {
		t.Errorf("active token kid changed across restart: %s -> %s", signerBefore.KID(), signerAfter.KID())
	}
	if !m2.Ready() {
		t.Error("Ready() = false after a clean restart")
	}
	if len(e.alerts.alerts()) != 0 {
		t.Errorf("clean start raised alerts: %+v", e.alerts.alerts())
	}
}

// TestKeysActiveSignsAndVerifies: the loaded signer produces a signature that
// verifies against the public JWK stored in its row.
func TestKeysActiveSignsAndVerifies(t *testing.T) {
	e := newEnv(t)
	m := e.manager()
	m.Init(context.Background())
	for _, p := range []string{keys.PurposeToken, keys.PurposeBundle} {
		sg, err := m.KeySet().Active(p)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sg.Sign(context.Background(), []byte("header.payload"))
		if err != nil {
			t.Fatal(err)
		}
		var jwk keys.JWK
		for _, r := range e.rows() {
			if r.KID == sg.KID() {
				jwk = r.PublicJWK
			}
		}
		if err := keys.Verify(jwk, sg.Alg(), []byte("header.payload"), sig); err != nil {
			t.Errorf("%s: signature does not verify against the stored JWK: %v", p, err)
		}
	}
}

// TestNoPrivateKeyInStateDB: neither the PEM body nor the raw seed of any key
// appears in warden-cp.db, its -wal file, or the captured logs.
func TestNoPrivateKeyInStateDB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	// Also exercise the noisy paths: a failed load and an import.
	e.store.failGet.Store(true)
	m2 := e.manager()
	m2.Init(ctx)
	e.store.failGet.Store(false)
	imported, _ := signer.GenerateKey(keys.AlgEdDSA)
	if _, err := m.ImportKey(ctx, keys.PurposeCA, imported, keys.Actor{Subject: "ops", AuthMethod: "cli"}); err != nil {
		t.Fatal(err)
	}

	var needles [][]byte
	var files int
	for _, p := range keys.Purposes() {
		matches, _ := filepath.Glob(filepath.Join(e.dir, p, "*.pem"))
		for _, f := range matches {
			files++
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(raw)
			if block == nil {
				t.Fatalf("%s is not PEM", f)
			}
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			seed := key.(ed25519.PrivateKey).Seed()
			body := base64.StdEncoding.EncodeToString(block.Bytes)
			needles = append(needles,
				[]byte(body), block.Bytes, seed,
				[]byte(base64.StdEncoding.EncodeToString(seed)),
				[]byte(base64.RawStdEncoding.EncodeToString(seed)),
				[]byte(base64.RawURLEncoding.EncodeToString(seed)),
				[]byte(base64.URLEncoding.EncodeToString(seed)),
				[]byte(hex.EncodeToString(seed)),
				[]byte("BEGIN PRIVATE KEY"))
		}
	}
	if files != 5 {
		t.Fatalf("key files = %d, want 5 (2 token, 2 bundle, 1 ca)", files)
	}
	haystacks := map[string][]byte{"logs": []byte(e.logs.String())}
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(e.dbPath + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		haystacks[filepath.Base(e.dbPath)+suffix] = b
	}
	if len(haystacks["warden-cp.db"]) == 0 {
		t.Fatal("state db is empty; the search would prove nothing")
	}
	for name, hay := range haystacks {
		for i, n := range needles {
			if bytes.Contains(hay, n) {
				t.Errorf("private key material (needle %d) found in %s", i, name)
			}
		}
	}
}

// TestFirstKeyRace: concurrent first loads — on one manager and on two
// managers sharing a database and directory — end with exactly one active and
// one next row per purpose, nothing orphaned on disk, files 0600 and dirs 0700.
func TestFirstKeyRace(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	managers := []*keys.Manager{e.manager(), e.manager()}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		for _, p := range []string{keys.PurposeToken, keys.PurposeBundle} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := managers[i%2].LoadKeySet(ctx, p); err != nil {
					t.Errorf("LoadKeySet(%s): %v", p, err)
				}
			}()
		}
	}
	wg.Wait()

	rows := e.rows()
	for _, p := range []string{keys.PurposeToken, keys.PurposeBundle} {
		if n := len(kidsByState(rows, p, keys.StateActive)); n != 1 {
			t.Errorf("%s: %d active rows, want 1", p, n)
		}
		if n := len(kidsByState(rows, p, keys.StateNext)); n != 1 {
			t.Errorf("%s: %d next rows, want 1", p, n)
		}
	}
	if len(rows) != 4 {
		t.Errorf("rows = %d, want 4", len(rows))
	}
	onDisk := map[string]bool{}
	for _, p := range []string{keys.PurposeToken, keys.PurposeBundle} {
		files, _ := filepath.Glob(filepath.Join(e.dir, p, "*.pem"))
		for _, f := range files {
			onDisk[strings.TrimSuffix(filepath.Base(f), ".pem")] = true
			if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode = %v, want 0600", f, fi.Mode().Perm())
			}
		}
		if fi, _ := os.Stat(filepath.Join(e.dir, p)); fi.Mode().Perm() != 0o700 {
			t.Errorf("%s dir mode = %v, want 0700", p, fi.Mode().Perm())
		}
	}
	if fi, _ := os.Stat(e.dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("key dir mode = %v, want 0700", fi.Mode().Perm())
	}
	if len(onDisk) != 4 {
		t.Errorf("key files on disk = %d, want exactly the 4 with rows (losers discarded)", len(onDisk))
	}
	for _, r := range rows {
		if !onDisk[r.KID] {
			t.Errorf("row %s has no material", r.KID)
		}
	}
	for _, m := range managers {
		if !m.Ready() {
			t.Error("a manager is not ready after the race")
		}
	}
}

// TestKeysBackendDownWithRows: rows exist but the store cannot be read. No new
// key or row appears, signing fails with ErrNoActiveKey, one Finding-bound
// alert is raised for the episode, and Run recovers without a restart.
func TestKeysBackendDownWithRows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.manager().Init(ctx)
	before := e.rows()
	filesBefore := listPEMs(t, e.dir)

	e.store.failGet.Store(true)
	m := e.manager()
	m.Init(ctx)
	if _, err := m.KeySet().Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("Active during outage = %v, want ErrNoActiveKey", err)
	}
	if m.Ready() {
		t.Error("Ready() = true during the outage")
	}
	if got := e.rows(); len(got) != len(before) {
		t.Errorf("outage created rows: %d -> %d", len(before), len(got))
	}
	if got := listPEMs(t, e.dir); strings.Join(got, ",") != strings.Join(filesBefore, ",") {
		t.Errorf("outage changed key files: %v -> %v", filesBefore, got)
	}
	al := e.alerts.alerts()
	if len(al) != 2 || al[0].Rule != keys.AlertSigningKeyUnavailable {
		t.Fatalf("alerts = %+v, want one signing_key_unavailable per purpose", al)
	}
	if m.LastError(keys.PurposeToken) == "" {
		t.Error("LastError is empty during the outage")
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); m.Run(runCtx) }()
	t.Cleanup(func() { cancel(); <-done })

	// Still down: the retry fails and raises nothing new. The clock is driven
	// until the retry has actually run — Run's scheduler and data-version poll
	// arm timers of their own, so PendingTimers can no longer mean "the retry
	// timer is armed" and a fixed advance cannot target it (the flake that
	// taught us: the advance fired the other loops' timers, the reload loop
	// re-armed past the frozen clock, and the retry never ran).
	loadFailures := func() int { return strings.Count(e.logs.String(), "keys_load_failed") }
	failures := loadFailures()
	// One reload pass logs and then alerts for each purpose in turn, on one
	// goroutine. Seeing the first line of the next pass (two purposes + 1)
	// means the whole first retry pass, alerts included, has finished.
	e.pollAdvance(t, func() bool { return loadFailures() >= failures+3 })
	if len(e.alerts.alerts()) != 2 {
		t.Errorf("retry re-raised the alert: %+v", e.alerts.alerts())
	}

	// The store returns; the next retry adopts the rows and the manager
	// recovers without a restart.
	e.store.failGet.Store(false)
	e.pollAdvance(t, func() bool { return m.Ready() })
	if _, err := m.KeySet().Active(keys.PurposeToken); err != nil {
		t.Errorf("Active after recovery: %v", err)
	}
	if got := e.rows(); len(got) != len(before) {
		t.Errorf("recovery created rows: %d -> %d", len(before), len(got))
	}
	if m.LastError(keys.PurposeToken) != "" {
		t.Error("LastError not cleared after recovery")
	}
}

func listPEMs(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// TestKeysNoActiveRowNeverGenerates: rows exist but none is active — nothing is
// generated.
func TestKeysNoActiveRowNeverGenerates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.manager().Init(ctx)
	rows := e.rows()
	active := kidsByState(rows, keys.PurposeToken, keys.StateActive)[0]
	if ok, err := e.meta.UpdateState(ctx, active, keys.StateActive, keys.StateRetired, e.clk.Now()); err != nil || !ok {
		t.Fatalf("retire: %v %v", ok, err)
	}
	m := e.manager()
	m.Init(ctx)
	if _, err := m.KeySet().Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("Active = %v, want ErrNoActiveKey", err)
	}
	if got := e.rows(); len(got) != len(rows) {
		t.Errorf("rows %d -> %d: a key was generated although rows existed", len(rows), len(got))
	}
}

// TestKeysMismatchedMaterialRefused: a key file swapped for another key must
// not sign under the old kid.
func TestKeysMismatchedMaterialRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.manager().Init(ctx)
	rows := e.rows()
	tokActive := kidsByState(rows, keys.PurposeToken, keys.StateActive)[0]
	tokNext := kidsByState(rows, keys.PurposeToken, keys.StateNext)[0]
	a := filepath.Join(e.dir, keys.PurposeToken, tokActive+".pem")
	b, err := os.ReadFile(filepath.Join(e.dir, keys.PurposeToken, tokNext+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, b, 0o600); err != nil {
		t.Fatal(err)
	}
	m := e.manager()
	m.Init(ctx)
	if _, err := m.KeySet().Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("Active with swapped material = %v, want ErrNoActiveKey", err)
	}
	if err := os.WriteFile(a, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	m = e.manager()
	m.Init(ctx)
	if _, err := m.KeySet().Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("Active with garbage material = %v, want ErrNoActiveKey", err)
	}
	if strings.Contains(e.logs.String(), "not a key") {
		t.Error("garbage key bytes reached the logs")
	}
}

// TestKeysCreationFailuresLeaveNothing: a store that cannot Put, or a database
// that cannot insert, leaves no rows and no key files, and the purpose stays
// unavailable.
func TestKeysCreationFailuresLeaveNothing(t *testing.T) {
	ctx := context.Background()
	t.Run("put fails", func(t *testing.T) {
		e := newEnv(t)
		e.store.failPut.Store(true)
		m := e.manager()
		m.Init(ctx)
		if len(e.rows()) != 0 || len(listPEMs(t, e.dir)) != 0 {
			t.Errorf("rows=%d files=%v, want none", len(e.rows()), listPEMs(t, e.dir))
		}
		if _, err := m.KeySet().Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
			t.Errorf("Active = %v, want ErrNoActiveKey", err)
		}
		e.store.failPut.Store(false)
		if err := m.LoadKeySet(ctx, keys.PurposeToken); err != nil {
			t.Errorf("retry after the store recovered: %v", err)
		}
	})
	t.Run("insert fails", func(t *testing.T) {
		e := newEnv(t)
		m, err := keys.NewManager(keys.ManagerConfig{
			Store: e.store, Meta: failInsertMeta{e.meta}, Codec: signer.Codec{}, Backend: "file",
			Now: e.clk.Now, Wait: waitOn(e.clk),
			Algs:    map[string]string{keys.PurposeToken: keys.AlgEdDSA, keys.PurposeBundle: keys.AlgEdDSA},
			Timings: e.timings,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.LoadKeySet(ctx, keys.PurposeToken); err == nil {
			t.Fatal("LoadKeySet succeeded although the insert failed")
		}
		if files := listPEMs(t, e.dir); len(files) != 0 {
			t.Errorf("material left after a failed insert: %v", files)
		}
	})
}

// TestKeysOrphanSweep: material with no row is deleted at startup and logged by
// kid and purpose only.
func TestKeysOrphanSweep(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	orphan, _ := signer.GenerateKey(keys.AlgEdDSA)
	osg, _ := signer.NewLocalSigner(orphan)
	body, _ := signer.MarshalPKCS8PEM(orphan)
	if err := e.store.Put(ctx, keys.PurposeBundle, osg.KID(), body); err != nil {
		t.Fatal(err)
	}
	e.manager().Init(ctx)
	if _, err := e.store.Get(ctx, keys.PurposeBundle, osg.KID()); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("orphan survived the sweep: %v", err)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, osg.KID()) || !strings.Contains(logs, "keys_orphan_swept") {
		t.Errorf("sweep not logged with kid: %s", logs)
	}
	if strings.Contains(logs, string(body[:40])) {
		t.Error("PEM reached the logs")
	}
	// Material with a row is never swept.
	if got := e.rows(); len(got) != 4 {
		t.Fatalf("rows = %d", len(got))
	}
	m := e.manager()
	if n, err := m.Sweep(ctx); err != nil || n != 0 {
		t.Errorf("second sweep = %d, %v; want 0", n, err)
	}
}

// TestKeysGenerationAudited: each generated key writes a keys.generated entry
// with the system actor, and a keys_transition and keys_loaded log line.
func TestKeysGenerationAudited(t *testing.T) {
	e := newEnv(t)
	e.manager().Init(context.Background())
	evs := e.audit.events()
	if len(evs) != 4 {
		t.Fatalf("audit events = %d, want 4", len(evs))
	}
	kids := map[string]bool{}
	for _, r := range e.rows() {
		kids[r.KID] = true
	}
	for _, ev := range evs {
		if ev.Action != keys.ActionGenerated || ev.Actor != keys.SystemActor || !kids[ev.KID] {
			t.Errorf("unexpected audit event %+v", ev)
		}
	}
	logs := e.logs.String()
	for _, want := range []string{"keys_loaded", "keys_transition", "purpose=token", "purpose=bundle"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
	// A restart generates nothing, so audits nothing.
	e.manager().Init(context.Background())
	if n := len(e.audit.events()); n != 4 {
		t.Errorf("restart wrote audit events: %d", n)
	}
}

// TestKeysCAPurpose: ca is never generated or loaded; ImportKey stores an
// external key with an active row and Signer loads it.
func TestKeysCAPurpose(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	for _, r := range e.rows() {
		if r.Purpose == keys.PurposeCA {
			t.Fatalf("Init created a ca row: %+v", r)
		}
	}
	if err := m.LoadKeySet(ctx, keys.PurposeCA); !errors.Is(err, keys.ErrInvalidPurpose) {
		t.Errorf("LoadKeySet(ca) = %v, want ErrInvalidPurpose", err)
	}
	if _, err := m.Signer(ctx, keys.PurposeCA); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Errorf("Signer(ca) before import = %v, want ErrNoActiveKey", err)
	}

	priv, _ := signer.GenerateKey(keys.AlgES256)
	actor := keys.Actor{Subject: "ops@example.com", AuthMethod: "cli"}
	kid, err := m.ImportKey(ctx, keys.PurposeCA, priv, actor)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := m.Signer(ctx, keys.PurposeCA)
	if err != nil {
		t.Fatal(err)
	}
	if sg.KID() != kid || sg.Alg() != keys.AlgES256 {
		t.Errorf("Signer(ca) = %s/%s, want %s/ES256", sg.KID(), sg.Alg(), kid)
	}
	ca := kidsByState(e.rows(), keys.PurposeCA, keys.StateActive)
	if len(ca) != 1 || ca[0] != kid {
		t.Errorf("ca rows = %v, want the imported kid", ca)
	}
	if m.KeySet().Loaded(keys.PurposeCA) {
		t.Error("ca entered the KeySet")
	}
	last := e.audit.events()[len(e.audit.events())-1]
	if last.Action != keys.ActionImported || last.Actor != actor || last.KID != kid || last.Purpose != keys.PurposeCA {
		t.Errorf("import audit = %+v", last)
	}

	// A second import is refused and leaves no extra material.
	other, _ := signer.GenerateKey(keys.AlgEdDSA)
	if _, err := m.ImportKey(ctx, keys.PurposeCA, other, actor); !errors.Is(err, keys.ErrConflict) {
		t.Errorf("second import = %v, want ErrConflict", err)
	}
	if files, _ := filepath.Glob(filepath.Join(e.dir, "ca", "*.pem")); len(files) != 1 {
		t.Errorf("ca files = %v, want only the first import", files)
	}
	// Re-importing the same key is a collision on the file, which is not
	// deleted.
	if _, err := m.ImportKey(ctx, keys.PurposeCA, priv, actor); !errors.Is(err, keys.ErrKeyExists) {
		t.Errorf("re-import = %v, want ErrKeyExists", err)
	}
	if _, err := m.Signer(ctx, keys.PurposeCA); err != nil {
		t.Errorf("Signer(ca) after refused imports: %v", err)
	}
	if _, err := m.ImportKey(ctx, keys.PurposeToken, other, actor); !errors.Is(err, keys.ErrInvalidPurpose) {
		t.Errorf("import into token = %v, want ErrInvalidPurpose", err)
	}
	// The sweep does not eat imported material.
	if n, _ := m.Sweep(ctx); n != 0 {
		t.Errorf("sweep removed %d files that have rows", n)
	}
}

func TestNewManagerValidation(t *testing.T) {
	e := newEnv(t)
	good := map[string]string{keys.PurposeToken: keys.AlgES256, keys.PurposeBundle: keys.AlgEdDSA}
	base := keys.ManagerConfig{Store: e.store, Meta: e.meta, Codec: signer.Codec{}, Algs: good, Timings: e.timings, Now: e.clk.Now, Wait: waitOn(e.clk)}
	if _, err := keys.NewManager(base); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for name, mut := range map[string]func(*keys.ManagerConfig){
		"no store": func(c *keys.ManagerConfig) { c.Store = nil },
		"no meta":  func(c *keys.ManagerConfig) { c.Meta = nil },
		"no codec": func(c *keys.ManagerConfig) { c.Codec = nil },
		"bundle ES256": func(c *keys.ManagerConfig) {
			c.Algs = map[string]string{keys.PurposeToken: keys.AlgEdDSA, keys.PurposeBundle: keys.AlgES256}
		},
		"missing alg": func(c *keys.ManagerConfig) { c.Algs = map[string]string{keys.PurposeToken: keys.AlgEdDSA} },
		"unknown alg": func(c *keys.ManagerConfig) {
			c.Algs = map[string]string{keys.PurposeToken: "RS256", keys.PurposeBundle: keys.AlgEdDSA}
		},
		"missing timing": func(c *keys.ManagerConfig) {
			c.Timings = map[string]keys.Timing{keys.PurposeBundle: e.timings[keys.PurposeBundle]}
		},
		"negative window": func(c *keys.ManagerConfig) {
			c.Timings = map[string]keys.Timing{
				keys.PurposeToken:  {Interval: 24 * time.Hour, Prepublish: -time.Hour, Overlap: time.Hour},
				keys.PurposeBundle: e.timings[keys.PurposeBundle],
			}
		},
		"interval shorter than windows": func(c *keys.ManagerConfig) {
			c.Timings = map[string]keys.Timing{
				keys.PurposeToken:  {Interval: 30 * time.Minute, Prepublish: 20 * time.Minute, Overlap: 20 * time.Minute},
				keys.PurposeBundle: e.timings[keys.PurposeBundle],
			}
		},
	} {
		cfg := base
		mut(&cfg)
		if _, err := keys.NewManager(cfg); err == nil {
			t.Errorf("%s: NewManager accepted the config", name)
		}
	}
}

// TestKeySetPurposeIsolation: the KeySet returns each purpose's own key.
func TestKeySetPurposeIsolation(t *testing.T) {
	e := newEnv(t)
	m := e.manager()
	m.Init(context.Background())
	tok, _ := m.KeySet().Active(keys.PurposeToken)
	bun, _ := m.KeySet().Active(keys.PurposeBundle)
	if tok.KID() == bun.KID() {
		t.Error("token and bundle share a key")
	}
	if _, err := m.KeySet().Active("audit"); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Errorf("Active(audit) = %v, want ErrNoActiveKey", err)
	}
	recs := m.KeySet().Records(keys.PurposeToken)
	if len(recs) != 2 {
		t.Errorf("Records(token) = %d, want 2", len(recs))
	}
	for _, r := range recs {
		if r.Purpose != keys.PurposeToken {
			t.Errorf("record of another purpose in token set: %+v", r)
		}
	}
}
