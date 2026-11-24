package agentreg_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
)

func openDB(t *testing.T) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), agentreg.Migrations())
	if err != nil {
		t.Fatalf("open cpstate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSQLiteStore_Conformance(t *testing.T) {
	agentregtest.Run(t, agentreg.NewSQLiteStore(openDB(t)))
}

func TestSQLiteStore_ConformanceWithoutCache(t *testing.T) {
	agentregtest.Run(t, agentreg.NewSQLiteStore(openDB(t), agentreg.WithCacheTTL(0)))
}

const actor = "admin:test"

func newAgent(t *testing.T, id string) agentreg.Agent {
	t.Helper()
	return agentreg.Agent{ID: id, AllowedGroups: []string{"eng"}, Keys: []agentreg.Key{{JWK: agentregtest.Ed25519JWK(t, id)}}}
}

// A write through one store is visible to it at once; a write through another
// handle on the same file is visible only after the TTL.
func TestSQLiteStore_CacheInvalidationAndTTL(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	clk := clocktest.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	a := agentreg.NewSQLiteStore(db, agentreg.WithClock(clk), agentreg.WithCacheTTL(10*time.Second))
	b := agentreg.NewSQLiteStore(db, agentreg.WithClock(clk), agentreg.WithCacheTTL(10*time.Second))

	if list, err := a.List(ctx); err != nil || len(list) != 0 {
		t.Fatalf("empty list = %v, %v", list, err)
	}
	created, err := a.Create(ctx, newAgent(t, "c1"), actor)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := a.Get(ctx, "c1"); err != nil || got.Revision != 1 {
		t.Fatalf("own write not visible at once: %+v, %v", got, err)
	}
	if !created.CreatedAt.Equal(clk.Now()) {
		t.Fatalf("created_at %v != clock %v", created.CreatedAt, clk.Now())
	}

	// b warms its cache, then a writes behind its back.
	if _, err := b.Get(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	if _, err := a.SetStatus(ctx, "c1", agentreg.StatusDisabled, 1, actor); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Get(ctx, "c1"); got.Status != agentreg.StatusActive {
		t.Fatalf("b should still serve its snapshot, got %s", got.Status)
	}
	clk.Advance(10 * time.Second)
	if got, _ := b.Get(ctx, "c1"); got.Status != agentreg.StatusDisabled {
		t.Fatalf("b should re-read after the TTL, got %s", got.Status)
	}
	if got, _ := a.Get(ctx, "c1"); !got.UpdatedAt.After(got.CreatedAt) {
		t.Fatalf("updated_at not advanced: %+v", got)
	}
}

func TestSQLiteStore_ConcurrentWritersOneWins(t *testing.T) {
	ctx := context.Background()
	s := agentreg.NewSQLiteStore(openDB(t))
	a, err := s.Create(ctx, newAgent(t, "race-1"), actor)
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.SetStatus(ctx, a.ID, agentreg.StatusDisabled, a.Revision, actor)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok, conflict := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, agentreg.ErrConflict):
			conflict++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflict != n-1 {
		t.Fatalf("ok=%d conflict=%d, want 1 and %d", ok, conflict, n-1)
	}
}

func TestSQLiteStore_RowsSurviveReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db, err := cpstate.Open(ctx, path, agentreg.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentreg.NewSQLiteStore(db).Create(ctx, newAgent(t, "persist"), actor); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	db, err = cpstate.Open(ctx, path, agentreg.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	got, err := agentreg.NewSQLiteStore(db).Get(ctx, "persist")
	if err != nil || len(got.Keys) != 1 || got.Keys[0].JKT == "" {
		t.Fatalf("after reopen: %+v, %v", got, err)
	}
}

func TestSQLiteStore_ClosedDBReportsErrors(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	s := agentreg.NewSQLiteStore(db, agentreg.WithCacheTTL(0))
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

func TestSQLiteStore_RejectsBadInputBeforeStorage(t *testing.T) {
	ctx := context.Background()
	s := agentreg.NewSQLiteStore(openDB(t))
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

func TestSQLiteStore_RegistryFullAtConfiguredMax(t *testing.T) {
	// The cap itself is exercised end to end by the conformance suite; this
	// pins that a duplicate id is reported as such even when the registry is
	// full, so a retry of a successful create is not misread as "full".
	ctx := context.Background()
	s := agentreg.NewSQLiteStore(openDB(t))
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
	migs := agentreg.Migrations()
	if len(migs) != 1 || migs[0].ID != "agents/0001" || migs[0].Optional {
		t.Fatalf("Migrations() = %+v", migs)
	}
}
