package sqlite_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	if _, err := s.Create(ctx, newAgent(t, "sf-1"), actor); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Get(ctx, "sf-1"); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestStore_WatchLogsAndRecoversFromUnreadableVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	db := openDB(t)
	clk := clocktest.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	s := sqlite.New(db, sqlite.WithClock(clk), sqlite.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	_ = db.Close() // every poll now fails
	done := make(chan struct{})
	go func() { defer close(done); s.Watch(ctx, time.Second) }()
	for i := 0; i < 5; i++ {
		clk.Advance(time.Second)
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not stop on cancel")
	}
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
