package apikeys

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
)

var t0 = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// memStore is an in-memory Store for Index tests. External writes (another
// process) go through ext* and bump the version without firing hooks.
type memStore struct {
	clk *clocktest.Fake
	rd  io.Reader

	mu      sync.Mutex
	rows    map[string]entry
	version int64
	hooks   []func(Change)
	uses    map[string]Use

	failSnapshot atomic.Bool
	failVersion  atomic.Bool
	failFlush    atomic.Bool
	calls        atomic.Int64 // every store method an Index may call
	flushes      atomic.Int64
}

func newMemStore(clk *clocktest.Fake) *memStore {
	return &memStore{clk: clk, rd: testRand(9), rows: map[string]entry{}, uses: map[string]Use{}}
}

func (m *memStore) Create(_ context.Context, p CreateParams) (string, Key, error) {
	g, err := Generate(m.rd, nil)
	if err != nil {
		return "", Key{}, err
	}
	now := m.clk.Now()
	k := Key{ID: g.ID, Name: p.Name, OwnerIss: p.OwnerIss, OwnerSub: p.OwnerSub, Scopes: p.Scopes,
		CreatedAt: now, ExpiresAt: now.Add(p.TTL)}
	m.mu.Lock()
	m.rows[k.ID] = entry{key: k, hash: g.StorageHash()}
	m.mu.Unlock()
	m.fire(Change{})
	return g.Plaintext, k, nil
}

func (m *memStore) fire(c Change) {
	m.mu.Lock()
	hooks := append([]func(Change){}, m.hooks...)
	m.mu.Unlock()
	for _, fn := range hooks {
		fn(c)
	}
}

func (m *memStore) revokeLocked(id, by string, at time.Time) {
	if e, ok := m.rows[id]; ok && e.key.RevokedAt.IsZero() {
		e.key.RevokedAt, e.key.RevokedBy = at, by
		m.rows[id] = e
	}
}

func (m *memStore) Revoke(_ context.Context, id, by string) error {
	at := m.clk.Now()
	m.mu.Lock()
	m.revokeLocked(id, by, at)
	m.mu.Unlock()
	m.fire(Change{RevokedIDs: []string{id}, RevokedAt: at, RevokedBy: by})
	return nil
}

func (m *memStore) RevokeByOwner(_ context.Context, iss, sub, by string) (int, error) {
	at := m.clk.Now()
	n := 0
	m.mu.Lock()
	for id, e := range m.rows {
		if e.key.OwnerIss == iss && e.key.OwnerSub == sub && e.key.RevokedAt.IsZero() {
			m.revokeLocked(id, by, at)
			n++
		}
	}
	m.mu.Unlock()
	m.fire(Change{OwnerIss: iss, OwnerSub: sub, RevokedAt: at, RevokedBy: by})
	return n, nil
}

// extRevoke is a revoke by another process: the version moves and no hook
// fires. Local writes leave the version alone, as SQLite's data_version does.
func (m *memStore) extRevoke(id string) {
	m.mu.Lock()
	m.revokeLocked(id, "cli", m.clk.Now())
	m.version++
	m.mu.Unlock()
}

func (m *memStore) Get(context.Context, string) (Key, error)        { return Key{}, ErrNotFound }
func (m *memStore) List(context.Context, ListFilter) ([]Key, error) { return nil, nil }

func (m *memStore) FlushLastUsed(_ context.Context, u map[string]Use) error {
	m.calls.Add(1)
	m.flushes.Add(1)
	if m.failFlush.Load() {
		return errors.New("injected flush failure")
	}
	m.mu.Lock()
	for id, use := range u {
		m.uses[id] = use
	}
	m.mu.Unlock()
	return nil
}

func (m *memStore) lastUse(id string) Use {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.uses[id]
}

func (m *memStore) Snapshot(context.Context) (Snapshot, error) {
	m.calls.Add(1)
	if m.failSnapshot.Load() {
		return Snapshot{}, errors.New("injected snapshot failure")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var snap Snapshot
	snap.SetVersion(m.version)
	ids := make([]string, 0, len(m.rows))
	for id := range m.rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		snap.Add(m.rows[id].key, m.rows[id].hash)
	}
	return snap, nil
}

func (m *memStore) DataVersion(context.Context) (int64, error) {
	m.calls.Add(1)
	if m.failVersion.Load() {
		return 0, errors.New("injected data_version failure")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version, nil
}

func (m *memStore) OnChange(fn func(Change)) {
	m.mu.Lock()
	m.hooks = append(m.hooks, fn)
	m.mu.Unlock()
}

func mkParams(owner, name string) CreateParams {
	return CreateParams{Name: name, OwnerIss: "https://idp", OwnerSub: owner,
		Scopes: []Scope{"policy:read"}, TTL: 24 * time.Hour}
}

func setup(t *testing.T) (*memStore, *clocktest.Fake, *Index) {
	t.Helper()
	clk := clocktest.NewFake(t0)
	m := newMemStore(clk)
	ix, err := NewIndex(context.Background(), m, IndexOptions{Now: clk.Now, After: clk.After, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return m, clk, ix
}

// runIndex starts ix.Run and stops it at test end.
func runIndex(t *testing.T, ix *Index) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ix.Run(ctx) }()
	t.Cleanup(func() { cancel(); wg.Wait() })
}

// drive advances the fake clock one poll interval at a time until cond holds.
func drive(t *testing.T, clk *clocktest.Fake, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		clk.Advance(DefaultPollInterval)
		time.Sleep(2 * time.Millisecond)
	}
}

func TestIndexAuthenticate(t *testing.T) {
	m, _, ix := setup(t)
	ctx := context.Background()
	p := mkParams("alice", "ci")
	p.TTL = 2 * time.Hour
	pt, k, _ := m.Create(ctx, p) // the local-write hook rebuilds the index
	exp := k.ExpiresAt

	got, reason, err := ix.Authenticate(pt, exp.Add(-time.Second))
	if err != nil || reason != "" || got.ID != k.ID || got.OwnerSub != "alice" || !got.HasScope("policy:read") {
		t.Fatalf("T-1s: %v %q %v", got, reason, err)
	}

	flip := pt[:Length-1] + "q"
	if pt[Length-1] == 'q' {
		flip = pt[:Length-1] + "a"
	}
	other, _ := Generate(testRand(10), nil)
	for name, tc := range map[string]struct {
		token  string
		now    time.Time
		reason Reason
	}{
		"expired at T":  {pt, exp, ReasonExpired},
		"expired after": {pt, exp.Add(time.Hour), ReasonExpired},
		"bad secret":    {flip, exp.Add(-time.Second), ReasonBadSecret},
		"other secret":  {pt[:sepOffset+1] + other.Plaintext[sepOffset+1:], t0, ReasonBadSecret},
		"unknown id":    {"wak_0000000000000000_" + pt[sepOffset+1:], t0, ReasonUnknown},
		"malformed":     {"wak_nope", t0, ReasonMalformed},
		"empty":         {"", t0, ReasonMalformed},
	} {
		if _, r, err := ix.Authenticate(tc.token, tc.now); !errors.Is(err, ErrUnauthorized) || r != tc.reason {
			t.Errorf("%s: reason %q err %v, want %q", name, r, err, tc.reason)
		}
	}

	_ = m.Revoke(ctx, k.ID, "alice")
	for _, now := range []time.Time{t0, exp.Add(time.Hour)} { // revoked wins over expired
		if _, r, err := ix.Authenticate(pt, now); !errors.Is(err, ErrUnauthorized) || r != ReasonRevoked {
			t.Fatalf("after revoke at %v: %q %v", now, r, err)
		}
	}
	if kk, ok := ix.Key(k.ID); !ok || kk.RevokedBy != "alice" {
		t.Fatalf("Key() = %v %v", kk, ok)
	}
	if _, ok := ix.Key("zzz"); ok {
		t.Fatal("Key() found a missing id")
	}
}

// A local revoke must take effect even when the full reload that follows it
// fails: the revocation is applied to the in-memory snapshot first.
func TestIndexLocalRevokeSurvivesReloadFailure(t *testing.T) {
	m, clk, ix := setup(t)
	ctx := context.Background()
	ptA, kA, _ := m.Create(ctx, mkParams("alice", "a"))
	ptB, _, _ := m.Create(ctx, mkParams("alice", "b"))
	ptC, _, _ := m.Create(ctx, mkParams("bob", "c"))

	m.failSnapshot.Store(true)
	if err := m.Revoke(ctx, kA.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, r, _ := ix.Authenticate(ptA, clk.Now()); r != ReasonRevoked {
		t.Fatalf("revoked key reason = %q while Snapshot fails, want revoked", r)
	}
	if _, _, err := ix.Authenticate(ptB, clk.Now()); err != nil {
		t.Fatalf("an unrelated key was revoked: %v", err)
	}

	if _, err := m.RevokeByOwner(ctx, "https://idp", "alice", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, r, _ := ix.Authenticate(ptB, clk.Now()); r != ReasonRevoked {
		t.Fatalf("owner revoke reason = %q while Snapshot fails, want revoked", r)
	}
	if _, _, err := ix.Authenticate(ptC, clk.Now()); err != nil {
		t.Fatalf("another owner's key was revoked: %v", err)
	}
	if _, _, err := ix.Authenticate(ptC, clk.Now()); err != nil {
		t.Fatal(err)
	}
}

// A new key whose local rebuild failed is picked up by the next poll even
// though the database version never moves for our own write.
func TestIndexLocalRebuildFailureIsRetried(t *testing.T) {
	m, clk, ix := setup(t)
	runIndex(t, ix)
	m.failSnapshot.Store(true)
	pt, _, _ := m.Create(context.Background(), mkParams("alice", "ci"))
	if _, r, _ := ix.Authenticate(pt, clk.Now()); r != ReasonUnknown {
		t.Fatalf("setup: reason %q, want unknown while the rebuild fails", r)
	}
	m.failSnapshot.Store(false)
	// Local writes do not move the version, so only the stale flag can trigger
	// the reload.
	drive(t, clk, func() bool { _, _, err := ix.Authenticate(pt, clk.Now()); return err == nil })
}

func TestIndexExternalRevokeReload(t *testing.T) {
	m, clk, ix := setup(t)
	runIndex(t, ix)
	pt1, k1, _ := m.Create(context.Background(), mkParams("alice", "one"))
	pt2, k2, _ := m.Create(context.Background(), mkParams("alice", "two"))
	ok := func(pt string) bool { _, _, err := ix.Authenticate(pt, clk.Now()); return err == nil }

	m.extRevoke(k1.ID)
	drive(t, clk, func() bool { return !ok(pt1) })

	m.failSnapshot.Store(true)
	m.extRevoke(k2.ID)
	before := m.calls.Load()
	drive(t, clk, func() bool { return m.calls.Load() >= before+6 })
	if ok(pt1) {
		t.Fatal("a failed reload re-admitted a revoked key")
	}
	if !ok(pt2) {
		t.Fatal("expected the last good snapshot to still hold key two")
	}
	m.failSnapshot.Store(false)
	drive(t, clk, func() bool { return !ok(pt2) })
}

func TestIndexStalenessCeiling(t *testing.T) {
	m, clk, ix := setup(t)
	runIndex(t, ix)
	pt, _, _ := m.Create(context.Background(), mkParams("alice", "ci"))
	ok := func() bool { _, _, err := ix.Authenticate(pt, clk.Now()); return err == nil }
	drive(t, clk, ok) // healthy polls keep it fresh far beyond 30s of fake time
	for range 40 {
		clk.Advance(DefaultPollInterval)
		time.Sleep(time.Millisecond)
	}
	drive(t, clk, ok)

	m.failVersion.Store(true)
	var reason Reason
	drive(t, clk, func() bool {
		_, reason, _ = ix.Authenticate(pt, clk.Now())
		return reason == ReasonIndexStale
	})
	if _, _, err := ix.Authenticate(pt, clk.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale index accepted a key: %v", err)
	}

	m.failVersion.Store(false)
	drive(t, clk, ok) // a successful check clears the ceiling
}

func TestIndexNoStaleCeilingWithoutRun(t *testing.T) {
	m, clk, ix := setup(t)
	pt, _, _ := m.Create(context.Background(), mkParams("alice", "ci"))
	clk.Advance(time.Hour / 2)
	if _, _, err := ix.Authenticate(pt, clk.Now()); err != nil {
		t.Fatalf("ceiling applied without a poll loop: %v", err)
	}
}

func TestIndexNoStoreCallsOnRequestPath(t *testing.T) {
	m, clk, ix := setup(t)
	pt, k, _ := m.Create(context.Background(), mkParams("alice", "ci"))
	m.calls.Store(0)
	for range 1000 {
		if _, _, err := ix.Authenticate(pt, clk.Now()); err != nil {
			t.Fatal(err)
		}
		ix.MarkUsed(k.ID, clk.Now(), "10.0.0.9")
	}
	if n := m.calls.Load(); n != 0 {
		t.Fatalf("%d store calls on the request path, want 0", n)
	}
	if err := ix.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ix.Flush(context.Background()); err != nil { // nothing pending
		t.Fatal(err)
	}
	if m.flushes.Load() != 1 {
		t.Fatalf("flush writes = %d, want 1", m.flushes.Load())
	}
	if u := m.lastUse(k.ID); !u.At.Equal(t0) || u.IP != "10.0.0.9" {
		t.Fatalf("last use = %+v", u)
	}
}

func TestIndexFlushFailureKeepsValues(t *testing.T) {
	m, _, ix := setup(t)
	_, k, _ := m.Create(context.Background(), mkParams("alice", "ci"))
	ix.MarkUsed(k.ID, t0, "1.1.1.1")
	m.failFlush.Store(true)
	if err := ix.Flush(context.Background()); err == nil {
		t.Fatal("expected the injected flush failure")
	}
	m.failFlush.Store(false)
	if err := ix.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u := m.lastUse(k.ID); u.IP != "1.1.1.1" {
		t.Fatalf("value lost after a failed flush: %+v", u)
	}
}

func TestIndexRunFlushes(t *testing.T) {
	m, clk, ix := setup(t)
	_, k, _ := m.Create(context.Background(), mkParams("alice", "ci"))
	ix.MarkUsed(k.ID, t0, "3.3.3.3")
	runIndex(t, ix)
	drive(t, clk, func() bool { return m.lastUse(k.ID).IP == "3.3.3.3" }) // the 60 s timer
}

func TestIndexRunFlushesOnShutdown(t *testing.T) {
	m, _, ix := setup(t)
	_, k, _ := m.Create(context.Background(), mkParams("alice", "ci"))
	ix.MarkUsed(k.ID, t0, "2.2.2.2")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ix.Run(ctx); close(done) }()
	cancel()
	<-done
	if u := m.lastUse(k.ID); u.IP != "2.2.2.2" {
		t.Fatalf("not flushed on shutdown: %+v", u)
	}
}

func TestNewIndexLoadError(t *testing.T) {
	clk := clocktest.NewFake(t0)
	m := newMemStore(clk)
	m.failSnapshot.Store(true)
	if _, err := NewIndex(context.Background(), m, IndexOptions{Now: clk.Now, After: clk.After}); err == nil {
		t.Fatal("NewIndex succeeded with an unreadable store")
	}
}

func BenchmarkIndexAuthenticate(b *testing.B) {
	clk := clocktest.NewFake(t0)
	m := newMemStore(clk)
	ix, err := NewIndex(context.Background(), m, IndexOptions{Now: clk.Now, After: clk.After})
	if err != nil {
		b.Fatal(err)
	}
	pt, _, _ := m.Create(context.Background(), mkParams("alice", "bench"))
	now := clk.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := ix.Authenticate(pt, now); err != nil {
			b.Fatal(err)
		}
	}
}

func TestNewIndexRequiresClock(t *testing.T) {
	m := newMemStore(clocktest.NewFake(t0))
	if _, err := NewIndex(context.Background(), m, IndexOptions{}); err == nil {
		t.Fatal("NewIndex without a clock succeeded")
	}
}
