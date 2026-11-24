package apikeys

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
)

func newIndex(t *testing.T, s Store, clk *clocktest.Fake) *Index {
	t.Helper()
	ix, err := NewIndex(context.Background(), s, IndexOptions{Clock: clk, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func TestIndexAuthenticate(t *testing.T) {
	s, clk, _ := newStore(t)
	ix := newIndex(t, s, clk)
	ctx := context.Background()
	p := params("alice", "ci")
	p.TTL = 2 * time.Hour
	pt, k, err := s.Create(ctx, p) // the local-write hook rebuilds the index
	if err != nil {
		t.Fatal(err)
	}
	exp := k.ExpiresAt

	got, reason, err := ix.Authenticate(pt, exp.Add(-time.Second))
	if err != nil || reason != "" || got.ID != k.ID || got.OwnerSub != "alice" || !got.HasScope("policy:read") {
		t.Fatalf("T-1s: %v %q %v", got, reason, err)
	}

	secretFlip := pt[:Length-1] + "q"
	if pt[Length-1] == 'q' {
		secretFlip = pt[:Length-1] + "a"
	}
	other, _ := Generate(nil)
	unknownID := "wak_0000000000000000_" + pt[sepOffset+1:]
	for name, tc := range map[string]struct {
		token  string
		now    time.Time
		reason Reason
	}{
		"expired at T":  {pt, exp, ReasonExpired},
		"expired after": {pt, exp.Add(time.Hour), ReasonExpired},
		"bad secret":    {secretFlip, exp.Add(-time.Second), ReasonBadSecret},
		"other secret":  {pt[:sepOffset+1] + other.Plaintext[sepOffset+1:], t0, ReasonBadSecret},
		"unknown id":    {unknownID, t0, ReasonUnknown},
		"malformed":     {"wak_nope", t0, ReasonMalformed},
		"empty":         {"", t0, ReasonMalformed},
	} {
		if _, r, err := ix.Authenticate(tc.token, tc.now); !errors.Is(err, ErrUnauthorized) || r != tc.reason {
			t.Errorf("%s: reason %q err %v, want %q", name, r, err, tc.reason)
		}
	}

	if err := s.Revoke(ctx, k.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, r, err := ix.Authenticate(pt, t0); !errors.Is(err, ErrUnauthorized) || r != ReasonRevoked {
		t.Fatalf("after revoke: %q %v", r, err)
	}
	if kk, ok := ix.Key(k.ID); !ok || kk.RevokedBy != "alice" {
		t.Fatalf("Key() = %v %v", kk, ok)
	}
	if _, ok := ix.Key("zzz"); ok {
		t.Fatal("Key() found a missing id")
	}
}

func TestIndexRevokeByOwnerRebuilds(t *testing.T) {
	s, clk, _ := newStore(t)
	ix := newIndex(t, s, clk)
	ctx := context.Background()
	var pts []string
	for _, n := range []string{"a", "b", "c"} {
		pt, _, _ := s.Create(ctx, params("alice", n))
		pts = append(pts, pt)
	}
	if n, err := s.RevokeByOwner(ctx, "https://idp", "alice", "admin"); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	for _, pt := range pts {
		if _, r, _ := ix.Authenticate(pt, t0); r != ReasonRevoked {
			t.Fatalf("reason = %q, want revoked immediately after RevokeByOwner", r)
		}
	}
}

// failingStore wraps a Store; it fails Snapshot while fail is set and counts
// every call so tests can prove the request path touches no SQL.
type failingStore struct {
	Store
	fail  atomic.Bool
	calls atomic.Int64
	flush atomic.Int64
}

func (f *failingStore) Snapshot(ctx context.Context) (Snapshot, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return Snapshot{}, errors.New("injected reload failure")
	}
	return f.Store.Snapshot(ctx)
}

func (f *failingStore) DataVersion(ctx context.Context) (int64, error) {
	f.calls.Add(1)
	return f.Store.DataVersion(ctx)
}

func (f *failingStore) FlushLastUsed(ctx context.Context, u map[string]Use) error {
	f.calls.Add(1)
	f.flush.Add(1)
	return f.Store.FlushLastUsed(ctx, u)
}

// drive advances the fake poll clock until cond holds.
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

func TestIndexCrossProcessReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	clk := clocktest.NewFake(t0)
	storeA := NewSQLiteStore(openDB(t, path), clk, NewP2Registry())
	storeB := NewSQLiteStore(openDB(t, path), clk, NewP2Registry())
	fs := &failingStore{Store: storeA}
	ix := newIndex(t, fs, clk)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ix.Run(ctx) }()
	t.Cleanup(func() { cancel(); wg.Wait() })

	ptOne, k1, err := storeB.Create(ctx, params("alice", "one")) // created by "another process"
	if err != nil {
		t.Fatal(err)
	}
	ptTwo, k2, _ := storeB.Create(ctx, params("alice", "two"))
	ptThree, k3, _ := storeB.Create(ctx, params("alice", "three"))
	ok := func(pt string) bool { _, _, err := ix.Authenticate(pt, clk.Now()); return err == nil }
	drive(t, clk, func() bool { return ok(ptOne) && ok(ptTwo) && ok(ptThree) })

	if err := storeB.Revoke(ctx, k1.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	drive(t, clk, func() bool { return !ok(ptOne) })
	if _, r, _ := ix.Authenticate(ptOne, clk.Now()); r != ReasonRevoked {
		t.Fatalf("reason = %q", r)
	}

	// Reload now fails: the revocation already loaded stays in force, the key
	// revoked meanwhile is still the last good state, and polls keep retrying.
	fs.fail.Store(true)
	if err := storeB.Revoke(ctx, k2.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	before := fs.calls.Load()
	drive(t, clk, func() bool { return fs.calls.Load() >= before+4 })
	if ok(ptOne) {
		t.Fatal("a failed reload re-admitted a revoked key")
	}
	if !ok(ptTwo) {
		t.Fatal("expected the last good index to still hold key two")
	}
	fs.fail.Store(false)
	drive(t, clk, func() bool { return !ok(ptTwo) })
	if ok(ptOne) || !ok(ptThree) {
		t.Fatal("recovered index is wrong")
	}
	_ = k3
}

func TestIndexLocalRebuildFailureIsRetried(t *testing.T) {
	s, clk, _ := newStore(t)
	fs := &failingStore{Store: s}
	ix := newIndex(t, fs, clk)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ix.Run(ctx) }()
	t.Cleanup(func() { cancel(); wg.Wait() })

	pt, k, _ := s.Create(ctx, params("alice", "ci"))
	fs.fail.Store(true)
	if err := s.Revoke(ctx, k.ID, "alice"); err != nil { // commits; hook rebuild fails
		t.Fatal(err)
	}
	if _, _, err := ix.Authenticate(pt, clk.Now()); err != nil {
		t.Fatal("setup: the failing rebuild should have left the old index")
	}
	fs.fail.Store(false)
	// The database version never moves for our own write; the stale flag must
	// make the next poll reload anyway.
	drive(t, clk, func() bool { _, _, err := ix.Authenticate(pt, clk.Now()); return err != nil })
}

func TestIndexNoSQLOnRequestPath(t *testing.T) {
	s, clk, _ := newStore(t)
	fs := &failingStore{Store: s}
	ix := newIndex(t, fs, clk)
	ctx := context.Background()
	pt, k, _ := s.Create(ctx, params("alice", "ci"))
	fs.calls.Store(0)

	for range 1000 {
		if _, _, err := ix.Authenticate(pt, clk.Now()); err != nil {
			t.Fatal(err)
		}
		ix.MarkUsed(k.ID, clk.Now(), "10.0.0.9")
	}
	if n := fs.calls.Load(); n != 0 {
		t.Fatalf("%d store calls on the request path, want 0", n)
	}
	if got, _ := s.Get(ctx, k.ID); !got.LastUsedAt.IsZero() {
		t.Fatal("last_used_at written before the flush")
	}
	clk.Advance(time.Minute)
	if err := ix.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ix.Flush(ctx); err != nil { // nothing pending: no second write
		t.Fatal(err)
	}
	if fs.flush.Load() != 1 {
		t.Fatalf("flush writes = %d, want 1", fs.flush.Load())
	}
	got, _ := s.Get(ctx, k.ID)
	if !got.LastUsedAt.Equal(t0) || got.LastUsedIP != "10.0.0.9" {
		t.Fatalf("last used = %v %q", got.LastUsedAt, got.LastUsedIP)
	}
}

func TestIndexFlushFailureKeepsValues(t *testing.T) {
	s, clk, _ := newStore(t)
	ix := newIndex(t, flushFailer{s}, clk)
	_, k, _ := s.Create(context.Background(), params("alice", "ci"))
	ix.MarkUsed(k.ID, t0, "1.1.1.1")
	if err := ix.Flush(context.Background()); err == nil {
		t.Fatal("expected the injected flush failure")
	}
	ix.store = s
	if err := ix.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(context.Background(), k.ID); got.LastUsedIP != "1.1.1.1" {
		t.Fatalf("value lost after a failed flush: %+v", got)
	}
}

type flushFailer struct{ Store }

func (flushFailer) FlushLastUsed(context.Context, map[string]Use) error {
	return errors.New("injected flush failure")
}

func TestIndexRunFlushesOnShutdown(t *testing.T) {
	s, clk, _ := newStore(t)
	ix := newIndex(t, s, clk)
	_, k, _ := s.Create(context.Background(), params("alice", "ci"))
	ix.MarkUsed(k.ID, t0, "2.2.2.2")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ix.Run(ctx); close(done) }()
	cancel()
	<-done
	if got, _ := s.Get(context.Background(), k.ID); got.LastUsedIP != "2.2.2.2" {
		t.Fatalf("not flushed on shutdown: %+v", got)
	}
}

func TestIndexRunFlushesEvery60s(t *testing.T) {
	s, clk, _ := newStore(t)
	ix := newIndex(t, s, clk)
	_, k, _ := s.Create(context.Background(), params("alice", "ci"))
	ix.MarkUsed(k.ID, t0, "3.3.3.3")
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ix.Run(ctx) }()
	t.Cleanup(func() { cancel(); wg.Wait() })
	flushed := func() bool { got, _ := s.Get(context.Background(), k.ID); return got.LastUsedIP == "3.3.3.3" }
	deadline := time.Now().Add(10 * time.Second)
	for !flushed() {
		if time.Now().After(deadline) {
			t.Fatal("last use never flushed by the timer")
		}
		clk.Advance(DefaultPollInterval)
		time.Sleep(2 * time.Millisecond)
	}
}

func TestNewIndexLoadError(t *testing.T) {
	s, clk, _ := newStore(t)
	fs := &failingStore{Store: s}
	fs.fail.Store(true)
	if _, err := NewIndex(context.Background(), fs, IndexOptions{Clock: clk}); err == nil {
		t.Fatal("NewIndex succeeded with an unreadable store")
	}
}

func BenchmarkIndexAuthenticate(b *testing.B) {
	path := filepath.Join(b.TempDir(), "warden-cp.db")
	db, err := openBenchDB(path)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s := NewSQLiteStore(db, nil, NewP2Registry())
	ix, err := NewIndex(context.Background(), s, IndexOptions{})
	if err != nil {
		b.Fatal(err)
	}
	p := params("alice", "bench")
	pt, _, err := s.Create(context.Background(), p)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := ix.Authenticate(pt, now); err != nil {
			b.Fatal(err)
		}
	}
}
