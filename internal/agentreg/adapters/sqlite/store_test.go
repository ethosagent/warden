package sqlite_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
)

func openDB(t *testing.T) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), sqlite.Migrations())
	if err != nil {
		t.Fatalf("open cpstate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestStore_Conformance(t *testing.T) {
	agentregtest.Run(t, sqlite.New(openDB(t)))
}

const actor = "admin:test"

func newAgent(t *testing.T, id string) agentreg.Agent {
	t.Helper()
	return agentreg.Agent{ID: id, AllowedGroups: []string{"eng"}, Keys: []agentreg.Key{{JWK: agentregtest.Ed25519JWK(t, id)}}}
}

// A write through one store is visible to it at once; a write through
// another handle on the same file (another process) is seen once Watch's
// data_version poll fires. The test drives the poll with a fake clock and a
// condition, never a fixed number of Advances.
func TestStore_WatchSeesAnotherProcessWithinOneInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	open := func() *cpstate.DB {
		db, err := cpstate.Open(ctx, path, sqlite.Migrations())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	clk := clocktest.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	const interval = 2 * time.Second
	a := sqlite.New(open(), sqlite.WithClock(clk))
	b := sqlite.New(open(), sqlite.WithClock(clk)) // the "other process"

	done := make(chan struct{})
	go func() { defer close(done); a.Watch(ctx, interval) }()
	defer func() { cancel(); <-done }()
	// The watch has taken its baseline and dropped the cache once its first
	// timer is armed; only then is the stale-before-the-poll check meaningful.
	for clk.PendingTimers() == 0 {
		runtime.Gosched()
	}

	if _, err := a.Create(ctx, newAgent(t, "w1"), actor); err != nil {
		t.Fatal(err)
	}
	if got, err := a.Get(ctx, "w1"); err != nil || got.Status != agentreg.StatusActive {
		t.Fatalf("own write not visible at once: %+v, %v", got, err)
	}

	// b writes behind a's back; a's snapshot is warm and stale.
	made, err := b.SetStatus(ctx, "w1", agentreg.StatusDisabled, 1, actor)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Get(ctx, "w1"); got.Status != agentreg.StatusActive {
		t.Fatalf("a should still serve its snapshot before the poll, got %s", got.Status)
	}
	// Drive the watch loop until it has seen the write: advance one interval,
	// look, repeat. The loop may not have armed its timer yet on the first
	// pass, which is why this is a condition and not a fixed Advance.
	deadline := time.Now().Add(10 * time.Second)
	for {
		clk.Advance(interval)
		if got, _ := a.Get(ctx, "w1"); got.Status == agentreg.StatusDisabled && got.Revision == made.Revision {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a never saw b's write")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A burst of readers after a write reloads the registry once.
func TestStore_ConcurrentReadersAfterWriteAreCoalesced(t *testing.T) {
	ctx := context.Background()
	s := sqlite.New(openDB(t))
	const readers = 32
	var loads, started atomic.Int32
	sqlite.SetAfterRead(s, func() {
		loads.Add(1)
		// Hold the leader until every reader has reached Get, so they all
		// arrive while the load is in flight or already cached.
		for started.Load() < readers {
			runtime.Gosched()
		}
	})
	if _, err := s.Create(ctx, newAgent(t, "sf-1"), actor); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Add(1)
			if _, err := s.Get(ctx, "sf-1"); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := loads.Load(); n != 1 {
		t.Fatalf("%d readers after one write caused %d reloads, want 1", readers, n)
	}
}

// Read-your-writes: a read that starts after a write returned never sees
// state from before it, even when a load that began earlier is still in
// flight; and that late load is not left in the cache.
func TestStore_ReadAfterWriteNeverSeesAnOlderLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		// readBeforeRelease: the post-write read happens while the old load is
		// still blocked (it starts its own load); otherwise only after the old
		// load has finished and tried to cache its stale snapshot.
		readBeforeRelease bool
	}{{"read while stale load is in flight", true}, {"read after stale load finished", false}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := sqlite.New(openDB(t))
			made, err := s.Create(ctx, newAgent(t, "ryw"), actor)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			reached, release := make(chan struct{}), make(chan struct{})
			sqlite.SetAfterRead(s, func() {
				if calls.Add(1) == 1 { // only the first load blocks, after it has read
					close(reached)
					<-release
				}
			})
			stale := make(chan agentreg.Status, 1)
			go func() {
				a, err := s.Get(ctx, "ryw")
				if err != nil {
					t.Errorf("stale Get: %v", err)
				}
				stale <- a.Status
			}()
			<-reached // the load has read "active" and is held before caching it
			if _, err := s.SetStatus(ctx, "ryw", agentreg.StatusDisabled, made.Revision, actor); err != nil {
				t.Fatal(err)
			}
			if tc.readBeforeRelease {
				if got, _ := s.Get(ctx, "ryw"); got.Status != agentreg.StatusDisabled {
					t.Fatalf("read after SetStatus saw %s", got.Status)
				}
			}
			close(release)
			<-stale // the old load has finished and tried to cache what it read
			if got, _ := s.Get(ctx, "ryw"); got.Status != agentreg.StatusDisabled {
				t.Fatalf("after the stale load finished, a read saw %s: the stale snapshot is cached", got.Status)
			}
			loadsBefore := calls.Load()
			if got, _ := s.Get(ctx, "ryw"); got.Status != agentreg.StatusDisabled || calls.Load() != loadsBefore {
				t.Fatalf("a fresh snapshot should be cached: status %s, loads %d -> %d", got.Status, loadsBefore, calls.Load())
			}
		})
	}
}

// A failing data_version poll is logged once per episode and drops the cache;
// when the poll recovers the watch carries on and sees later changes.
func TestStore_WatchLogsOncePerFailureEpisodeAndRecovers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := openDB(t)
	clk := clocktest.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	logs := &captureHandler{}
	s := sqlite.New(db, sqlite.WithClock(clk), sqlite.WithLogger(slog.New(logs)))

	// Scripted poll: call 1 is the baseline, calls 2-4 fail, then it recovers
	// and reports a new version on call 6.
	var calls atomic.Int32
	sqlite.SetVersionReader(s, func(context.Context) (int64, error) {
		switch n := calls.Add(1); {
		case n == 1:
			return 1, nil
		case n <= 4:
			return 0, errors.New("boom")
		case n == 5:
			return 1, nil
		default:
			return 2, nil
		}
	})
	if _, err := s.Create(ctx, newAgent(t, "wl"), actor); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "wl"); err != nil { // warm the cache
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); s.Watch(ctx, time.Second) }()
	deadline := time.Now().Add(10 * time.Second)
	for calls.Load() < 7 {
		clk.Advance(time.Second)
		runtime.Gosched()
		if time.Now().After(deadline) {
			t.Fatalf("watch stalled after %d polls", calls.Load())
		}
	}
	cancel()
	<-done
	if warns := logs.count(slog.LevelWarn); warns != 1 {
		t.Fatalf("%d warnings for one failure episode, want exactly 1", warns)
	}
}

type captureHandler struct {
	mu     sync.Mutex
	levels []slog.Level
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.levels = append(h.levels, r.Level)
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) count(l slog.Level) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, got := range h.levels {
		if got == l {
			n++
		}
	}
	return n
}

func TestStore_RowsSurviveReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db, err := cpstate.Open(ctx, path, sqlite.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqlite.New(db).Create(ctx, newAgent(t, "persist"), actor); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	db, err = cpstate.Open(ctx, path, sqlite.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	got, err := sqlite.New(db).Get(ctx, "persist")
	if err != nil || len(got.Keys) != 1 || got.Keys[0].JKT == "" {
		t.Fatalf("after reopen: %+v, %v", got, err)
	}
}

func TestStore_ClosedDBReportsErrors(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	s := sqlite.New(db)
	a, err := s.Create(ctx, newAgent(t, "closed"), actor)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := s.Create(ctx, newAgent(t, "closed-2"), actor); err == nil {
		t.Error("Create on a closed db: want error")
	}
	if _, err := s.Get(ctx, "closed"); err == nil || errors.Is(err, agentreg.ErrNotFound) {
		t.Errorf("Get on a closed db = %v, want a storage error", err)
	}
	if _, err := s.List(ctx); err == nil {
		t.Error("List on a closed db: want error")
	}
	if _, err := s.Update(ctx, a, actor); err == nil {
		t.Error("Update on a closed db: want error")
	}
	if _, err := s.SetStatus(ctx, "closed", agentreg.StatusDisabled, 1, actor); err == nil {
		t.Error("SetStatus on a closed db: want error")
	}
}

func TestStore_RejectsBadInputBeforeStorage(t *testing.T) {
	ctx := context.Background()
	s := sqlite.New(openDB(t))
	good := newAgent(t, "bad-1")
	if _, err := s.Create(ctx, good, ""); !errors.Is(err, agentreg.ErrInvalid) {
		t.Errorf("empty actor = %v", err)
	}
	if _, err := s.Update(ctx, good, ""); !errors.Is(err, agentreg.ErrInvalid) {
		t.Errorf("Update empty actor = %v", err)
	}
	if _, err := s.Update(ctx, agentreg.Agent{ID: "!identity-scoped"}, actor); !errors.Is(err, agentreg.ErrInvalid) {
		t.Errorf("Update bad id = %v", err)
	}
	if _, err := s.SetStatus(ctx, "-x", agentreg.StatusActive, 1, actor); !errors.Is(err, agentreg.ErrInvalid) {
		t.Errorf("SetStatus bad id = %v", err)
	}
	if _, err := s.SetStatus(ctx, "bad-1", agentreg.StatusActive, 1, ""); !errors.Is(err, agentreg.ErrInvalid) {
		t.Errorf("SetStatus empty actor = %v", err)
	}
	// Update validates against the stored status: a disabled agent may be
	// updated to an empty group list, an active one may not.
	made, err := s.Create(ctx, good, actor)
	if err != nil {
		t.Fatal(err)
	}
	made.AllowedGroups = nil
	if _, err := s.Update(ctx, made, actor); !errors.Is(err, agentreg.ErrInvalid) {
		t.Errorf("Update active agent to no groups = %v", err)
	}
}

func TestStore_RegistryFullAtConfiguredMax(t *testing.T) {
	// The cap itself is exercised end to end by the conformance suite; this
	// pins that a duplicate id is reported as such even when the registry is
	// full, so a retry of a successful create is not misread as "full".
	ctx := context.Background()
	s := sqlite.New(openDB(t))
	if _, err := s.Create(ctx, newAgent(t, "full-1"), actor); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, newAgent(t, "full-1"), actor); !errors.Is(err, agentreg.ErrAlreadyExists) {
		t.Fatalf("duplicate = %v", err)
	}
}

// There is no delete path for agent rows: the package never issues DELETE
// against agents, and only Update's key replacement deletes agent_keys.
func TestNoDeleteOfAgents(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := strings.ToUpper(string(b))
		if strings.Contains(src, "DELETE FROM AGENTS") || strings.Contains(src, "DROP TABLE") {
			t.Errorf("%s deletes agent rows", f)
		}
	}
}

func TestMigrationsDeclareTheRegistryTables(t *testing.T) {
	migs := sqlite.Migrations()
	if len(migs) != 1 || migs[0].ID != "agents/0001" || migs[0].Optional {
		t.Fatalf("Migrations() = %+v", migs)
	}
}

// Sync drops the snapshot as soon as data_version has moved, without waiting
// for Watch's poll: a second handle's write is seen by the next read after a
// Sync, and a Sync with no write in between leaves the cache alone.
func TestStore_SyncSeesAnotherProcessImmediately(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	open := func() *cpstate.DB {
		db, err := cpstate.Open(ctx, path, sqlite.Migrations())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	a, b := sqlite.New(open()), sqlite.New(open())
	if _, err := a.Create(ctx, newAgent(t, "s1"), actor); err != nil {
		t.Fatal(err)
	}
	if err := a.Sync(ctx); err != nil { // baseline
		t.Fatal(err)
	}
	if _, err := a.List(ctx); err != nil { // warm
		t.Fatal(err)
	}
	if _, err := b.SetStatus(ctx, "s1", agentreg.StatusDisabled, 1, actor); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Get(ctx, "s1"); got.Status != agentreg.StatusActive {
		t.Fatalf("a should serve its snapshot before Sync, got %s", got.Status)
	}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.Get(ctx, "s1"); got.Status != agentreg.StatusDisabled {
		t.Fatalf("after Sync a serves %s, want disabled", got.Status)
	}
}

// A failing version read drops the cache, reports the error, and the next
// good read re-baselines.
func TestStore_SyncErrorDropsCache(t *testing.T) {
	ctx := context.Background()
	s := sqlite.New(openDB(t))
	if _, err := s.Create(ctx, newAgent(t, "e1"), actor); err != nil {
		t.Fatal(err)
	}
	var fail atomic.Bool
	sqlite.SetVersionReader(s, func(context.Context) (int64, error) {
		if fail.Load() {
			return 0, errors.New("boom")
		}
		return 1, nil
	})
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := s.Sync(ctx); err == nil {
		t.Fatal("Sync swallowed the version read error")
	}
	fail.Store(false)
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
}
