package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
)

type wtEnv struct {
	path  string
	clk   *clocktest.Fake
	store *WorkerTokenStore
	db    *cpstate.DB
	logs  *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func openWT(t *testing.T, path string, clk clock.Clock, opts StoreOptions) (*cpstate.DB, *WorkerTokenStore, *syncBuf) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), path, WorkerTokenMigrations())
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logs := &syncBuf{}
	opts.Clock = clk
	opts.Logger = slog.New(slog.NewTextHandler(logs, nil))
	s, err := NewWorkerTokenStore(db, opts)
	if err != nil {
		t.Fatalf("NewWorkerTokenStore: %v", err)
	}
	return db, s, logs
}

func newWT(t *testing.T) *wtEnv {
	t.Helper()
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db, s, logs := openWT(t, path, clk, StoreOptions{})
	return &wtEnv{path: path, clk: clk, store: s, db: db, logs: logs}
}

func (e *wtEnv) create(t *testing.T, name, proxy string) (string, Token) {
	t.Helper()
	pt, tok, err := e.store.Create(context.Background(), CreateOpts{Name: name, ProxyID: proxy, Actor: "admin"})
	if err != nil {
		t.Fatalf("Create(%s): %v", name, err)
	}
	return pt, tok
}

func TestWorkerTokenStoreHashedAtRest(t *testing.T) {
	e := newWT(t)
	pt, tok := e.create(t, "w1", "proxy-a")
	if !wellFormed(pt) || !strings.HasPrefix(tok.ID, "wt_") || len(tok.ID) != 19 {
		t.Fatalf("bad token/id shape: %q %q", tok.ID, "<redacted>")
	}
	var busy, logFrames, ckpt int
	if err := e.db.SQL().QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &ckpt); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{e.path, e.path + "-wal"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bytes.Contains(raw, []byte(pt)) {
			t.Fatalf("%s contains the plaintext", filepath.Base(f))
		}
	}
	var hash []byte
	if err := e.db.SQL().QueryRow(`SELECT token_hash FROM worker_tokens WHERE id = ?`, tok.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(pt))
	if !bytes.Equal(hash, want[:]) {
		t.Fatal("token_hash is not sha256(plaintext)")
	}
}

func TestWorkerTokenStoreAuthenticate(t *testing.T) {
	e := newWT(t)
	ctx := context.Background()
	pt, tok := e.create(t, "ok", "p1")
	got, err := e.store.Authenticate(pt)
	if err != nil || got.ID != tok.ID || got.ProxyID != "p1" {
		t.Fatalf("Authenticate = %v, %v", got, err)
	}

	exp := e.clk.Now().Add(time.Hour)
	ptExp, _, err := e.store.Create(ctx, CreateOpts{Name: "exp", ProxyID: "p2", Actor: "a", ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Authenticate(ptExp); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	e.clk.Advance(time.Hour)
	if _, err := e.store.Authenticate(ptExp); !errors.Is(err, ErrExpired) {
		t.Fatalf("after expiry: %v", err)
	}

	if err := e.store.Revoke(ctx, tok.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Authenticate(pt); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	unknown, _ := generateWorkerToken()
	if _, err := e.store.Authenticate(unknown); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	for _, bad := range []string{"", "x", strings.Repeat("a", 56), "wwt_short", pt + "a", "wwt_" + strings.Repeat("A", 52), "wwt_" + strings.Repeat("1", 52)} {
		if _, err := e.store.Authenticate(bad); !errors.Is(err, ErrMalformed) {
			t.Fatalf("malformed %d chars: %v", len(bad), err)
		}
	}
}

func TestWorkerTokenStoreCrossProcessReload(t *testing.T) {
	e := newWT(t)
	_ = e.db.Close()
	_, s1, _ := openWT(t, e.path, clock.Real(), StoreOptions{PollInterval: 10 * time.Millisecond})
	_, s2, _ := openWT(t, e.path, clock.Real(), StoreOptions{})

	revoked := make(chan string, 4)
	s1.OnRevoked(func(id string) { revoked <- id })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s1.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	pt, tok, err := s2.Create(ctx, CreateOpts{Name: "cli", ProxyID: "p", Actor: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, err := s1.Authenticate(pt); return err == nil })
	if err := s2.Revoke(ctx, tok.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, err := s1.Authenticate(pt); return errors.Is(err, ErrRevoked) })
	select {
	case id := <-revoked:
		if id != tok.ID {
			t.Fatalf("OnRevoked id = %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnRevoked did not fire")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWorkerTokenStoreRunLoopOnFakeClock(t *testing.T) {
	e := newWT(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.store.Run(ctx); close(done) }()
	waitFor(t, func() bool { return e.clk.PendingTimers() >= 2 })
	_, tok := e.create(t, "w", "p")
	e.store.MarkUsed(tok.ID, e.clk.Now())
	e.clk.Advance(defaultTokenFlushInterval)
	waitFor(t, func() bool { return e.store.flushTx.Load() == 1 })
	cancel()
	<-done
}

func TestWorkerTokenStoreReloadErrorKeepsIndex(t *testing.T) {
	e := newWT(t)
	ctx := context.Background()
	live, liveTok := e.create(t, "live", "p1")
	dead, deadTok := e.create(t, "dead", "p2")
	if err := e.store.Revoke(ctx, deadTok.ID, "a"); err != nil {
		t.Fatal(err)
	}
	_ = liveTok
	_ = e.db.Close() // every later read fails
	e.store.poll(ctx)
	if err := e.store.reload(ctx); err == nil {
		t.Fatal("reload on a closed DB should fail")
	}
	if _, err := e.store.Authenticate(live); err != nil {
		t.Fatalf("valid token after failed reload: %v", err)
	}
	if _, err := e.store.Authenticate(dead); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked token after failed reload: %v", err)
	}
	if !strings.Contains(e.logs.String(), "level=WARN") || !strings.Contains(e.logs.String(), "keeping the last good index") {
		t.Fatalf("no warning logged: %q", e.logs.String())
	}
}

func TestWorkerTokenStoreMarkUsedBatching(t *testing.T) {
	e := newWT(t)
	ctx := context.Background()
	var ids []string
	for _, n := range []string{"a", "b", "c"} {
		_, tok := e.create(t, n, "p-"+n)
		ids = append(ids, tok.ID)
	}
	base := e.clk.Now()
	for i := 0; i < 10_000; i++ {
		e.store.MarkUsed(ids[i%3], base.Add(time.Duration(i)*time.Second))
	}
	if n := e.store.flushTx.Load(); n != 0 {
		t.Fatalf("MarkUsed wrote %d transactions", n)
	}
	var got int64
	if err := e.db.SQL().QueryRow(`SELECT COUNT(*) FROM worker_tokens WHERE last_used_at IS NOT NULL`).Scan(&got); err != nil || got != 0 {
		t.Fatalf("rows with last_used_at before flush = %d, %v", got, err)
	}
	listed, err := e.store.List(ctx)
	if err != nil || listed[0].LastUsedAt.IsZero() {
		t.Fatalf("List should show pending last-used: %v %v", listed, err)
	}
	if err := e.store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.store.flushTx.Load(); n != 1 {
		t.Fatalf("flush transactions = %d, want 1", n)
	}
	if err := e.store.Flush(ctx); err != nil || e.store.flushTx.Load() != 1 {
		t.Fatalf("clean flush must not write: %v", err)
	}
	var last int64
	if err := e.db.SQL().QueryRow(`SELECT last_used_at FROM worker_tokens WHERE id = ?`, ids[0]).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if want := base.Add(9999 * time.Second).Unix(); last != want { // i=9999 -> 9999%3==0
		t.Fatalf("last_used_at = %d, want %d", last, want)
	}
}

func TestWorkerTokenStoreFlushFailureKeepsValues(t *testing.T) {
	e := newWT(t)
	_, tok := e.create(t, "a", "p")
	e.store.MarkUsed(tok.ID, e.clk.Now())
	_ = e.db.Close()
	if err := e.store.Flush(context.Background()); err == nil {
		t.Fatal("flush on a closed DB should fail")
	}
	if len(e.store.dirty) != 1 {
		t.Fatalf("dirty = %d, want the value kept", len(e.store.dirty))
	}
}

func TestWorkerTokenStoreLimits(t *testing.T) {
	e := newWT(t)
	ctx := context.Background()
	e.create(t, "a", "p")
	_, second := e.create(t, "b", "p")
	if _, _, err := e.store.Create(ctx, CreateOpts{Name: "c", ProxyID: "p", Actor: "x"}); !errors.Is(err, ErrTooManyActive) {
		t.Fatalf("third active: %v", err)
	}
	if _, _, err := e.store.Create(ctx, CreateOpts{Name: "a", ProxyID: "other", Actor: "x"}); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	if err := e.store.Revoke(ctx, second.ID, "x"); err != nil {
		t.Fatal(err)
	}
	e.create(t, "c", "p") // a slot is free again
	// A revoked name stays taken.
	if _, _, err := e.store.Create(ctx, CreateOpts{Name: "b", ProxyID: "z", Actor: "x"}); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("revoked name: %v", err)
	}
	// Expired tokens do not count as active.
	exp := e.clk.Now().Add(time.Minute)
	if _, _, err := e.store.Create(ctx, CreateOpts{Name: "e1", ProxyID: "q", Actor: "x", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	e.create(t, "e2", "q")
	e.clk.Advance(time.Minute)
	e.create(t, "e3", "q")
}

func TestWorkerTokenStoreRevoke(t *testing.T) {
	e := newWT(t)
	ctx := context.Background()
	var fired []string
	e.store.OnRevoked(func(id string) { fired = append(fired, id) })
	_, tok := e.create(t, "a", "p")
	if err := e.store.Revoke(ctx, tok.ID, "first"); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(time.Hour)
	if err := e.store.Revoke(ctx, tok.ID, "second"); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if len(fired) != 1 || fired[0] != tok.ID {
		t.Fatalf("OnRevoked calls = %v, want one", fired)
	}
	if err := e.store.Revoke(ctx, "wt_nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if err := e.store.Revoke(ctx, tok.ID, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty actor: %v", err)
	}
	list, err := e.store.List(ctx)
	if err != nil || len(list) != 1 || list[0].RevokedBy != "first" || list[0].RevokedAt.IsZero() {
		t.Fatalf("List = %+v, %v", list, err)
	}
}

func TestWorkerTokenStoreImport(t *testing.T) {
	e := newWT(t)
	ctx := context.Background()
	value, _ := generateWorkerToken()
	imp := CreateOpts{Name: "imp", ProxyID: "p", Actor: "cli", Plaintext: value}
	pt, tok, err := e.store.Create(ctx, imp)
	if err != nil || pt != value {
		t.Fatalf("import: %v", err)
	}
	pt2, tok2, err := e.store.Create(ctx, imp)
	if err != nil || pt2 != value || tok2.ID != tok.ID {
		t.Fatalf("re-import should be a no-op: %v", err)
	}
	if l, _ := e.store.List(ctx); len(l) != 1 {
		t.Fatalf("rows = %d, want 1", len(l))
	}
	if _, err := e.store.Authenticate(value); err != nil {
		t.Fatalf("imported token: %v", err)
	}
	// Same value under another name.
	if _, _, err := e.store.Create(ctx, CreateOpts{Name: "other", ProxyID: "p", Actor: "cli", Plaintext: value}); !errors.Is(err, ErrTokenInUse) {
		t.Fatalf("value reuse: %v", err)
	}
	// Same name, different value.
	other, _ := generateWorkerToken()
	if _, _, err := e.store.Create(ctx, CreateOpts{Name: "imp", ProxyID: "p", Actor: "cli", Plaintext: other}); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("name reuse: %v", err)
	}

	// Malformed input is rejected before any DB access: a closed DB would error differently.
	_ = e.db.Close()
	for _, bad := range []CreateOpts{
		{Name: "n", ProxyID: "p", Actor: "a", Plaintext: "wwt_short"},
		{Name: "n", ProxyID: "p", Actor: "a", Plaintext: strings.ToUpper(value)},
		{Name: "", ProxyID: "p", Actor: "a"},
		{Name: strings.Repeat("n", 65), ProxyID: "p", Actor: "a"},
		{Name: "bad\nname", ProxyID: "p", Actor: "a"},
		{Name: "n", ProxyID: "has space", Actor: "a"},
		{Name: "n", ProxyID: "", Actor: "a"},
		{Name: "n", ProxyID: strings.Repeat("p", 129), Actor: "a"},
		{Name: "n", ProxyID: "p"},
		{Name: "n", ProxyID: "p", Actor: "a", ExpiresAt: e.clk.Now()},
	} {
		if _, _, err := e.store.Create(ctx, bad); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Create(%+v) = %v, want ErrInvalidInput", bad.Name, err)
		}
	}
}

func TestWorkerTokenStoreNoSecretsInLogs(t *testing.T) {
	e := newWT(t)
	ctx := context.Background()
	pt, tok := e.create(t, "w", "p")
	hash := sha256.Sum256([]byte(pt))
	var errs []string
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	_, _, err := e.store.Create(ctx, CreateOpts{Name: "w", ProxyID: "p", Actor: "a", Plaintext: pt})
	collect(err)
	_, _, err = e.store.Create(ctx, CreateOpts{Name: "w2", ProxyID: "p", Actor: "a", Plaintext: pt})
	collect(err)
	_, err = e.store.Authenticate(pt + "x")
	collect(err)
	collect(e.store.Revoke(ctx, tok.ID, "a"))
	_, err = e.store.Authenticate(pt)
	collect(err)
	_ = e.db.Close()
	e.store.poll(ctx)
	collect(e.store.Flush(ctx))

	l := slog.New(slog.NewTextHandler(e.logs, nil))
	l.Info("x", "tok", tok, "str", tok.String())
	l.Info("y", slog.Any("tok", tok))
	out := e.logs.String() + strings.Join(errs, "\n") + tok.String()
	for _, secret := range []string{pt, string(hash[:]), hexOf(hash[:]), strings.TrimPrefix(pt, workerTokenPrefix)} {
		if strings.Contains(out, secret) {
			t.Fatal("log or error output contains a secret")
		}
	}
	if !strings.Contains(e.logs.String(), tok.ID) {
		t.Fatal("expected the token id in the log capture")
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func TestWorkerTokenAuthenticateAllocs(t *testing.T) {
	e := newWT(t)
	pt, _ := e.create(t, "w", "p")
	var sink atomic.Value
	allocs := testing.AllocsPerRun(200, func() {
		tok, err := e.store.Authenticate(pt)
		if err != nil {
			t.Fatal(err)
		}
		sink.Store(tok.ID)
	})
	// sink.Store boxes a string; Authenticate itself must stay at or under 2.
	if allocs > 2 {
		t.Fatalf("allocs per Authenticate = %v, want <= 2", allocs)
	}
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if _, err := e.store.Authenticate(pt); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("1000 lookups took %v, want < 50ms", d)
	}
}

func TestWorkerTokenMigrationsInStateMigrations(t *testing.T) {
	found := false
	for _, m := range StateMigrations() {
		if m.ID == "workertokens/0001" {
			found = true
		}
	}
	if !found {
		t.Fatal("StateMigrations lacks workertokens/0001")
	}
}

func TestWorkerTokenStringAndLogValue(t *testing.T) {
	tok := Token{ID: "wt_1", Name: "n", ProxyID: "p"}
	if s := tok.String(); !strings.Contains(s, "wt_1") || !strings.Contains(s, "p") {
		t.Fatalf("String = %q", s)
	}
	if v := tok.LogValue(); v.Kind() != slog.KindGroup || len(v.Group()) != 3 {
		t.Fatalf("LogValue = %v", v)
	}
}
