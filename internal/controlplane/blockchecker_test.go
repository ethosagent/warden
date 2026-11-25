package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/tokensvc"
)

var _ tokensvc.BlockChecker = (*TokenBlockChecker)(nil)

func TestTokenBlockChecker(t *testing.T) {
	ctx := context.Background()
	db, err := cpstate.Open(ctx, filepath.Join(t.TempDir(), "warden-cp.db"), BlockMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store := NewBlockStore(db, BlockStoreOptions{})
	if _, err := store.Add(ctx, BlockEntry{Sub: "u-1"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(ctx, BlockEntry{Email: "Mail@Example.test"}, "test"); err != nil {
		t.Fatal(err)
	}
	c := NewTokenBlockChecker(store)
	for _, tc := range []struct {
		sub, email string
		want       bool
	}{
		{"u-1", "", true},
		{"u-2", "mail@example.test", true},
		{"u-2", "MAIL@example.test", true},
		{"u-2", "", false},
		{"u-2", "other@example.test", false},
		{"", "", false},
	} {
		got, err := c.IsBlocked(ctx, tc.sub, tc.email)
		if err != nil || got != tc.want {
			t.Errorf("IsBlocked(%q, %q) = %v, %v, want %v", tc.sub, tc.email, got, err, tc.want)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.IsBlocked(cancelled, "u-2", ""); err == nil {
		t.Error("cancelled context gave an answer")
	}
}

func TestTokenBlockCheckerNotReady(t *testing.T) {
	ctx := context.Background()
	// No block table: the first load fails and the snapshot stays nil.
	db, err := cpstate.Open(ctx, filepath.Join(t.TempDir(), "warden-cp.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store := NewBlockStore(db, BlockStoreOptions{})
	if store.Ready() {
		t.Fatal("store is ready without a table")
	}
	got, err := NewTokenBlockChecker(store).IsBlocked(ctx, "u-1", "")
	if !errors.Is(err, ErrBlockListNotReady) || got {
		t.Fatalf("IsBlocked = %v, %v; an unloaded list must be an error, never allow", got, err)
	}
	if _, err := (*TokenBlockChecker)(nil).IsBlocked(ctx, "u", ""); !errors.Is(err, ErrBlockListNotReady) {
		t.Fatalf("nil checker: %v", err)
	}
	if _, err := NewTokenBlockChecker(nil).IsBlocked(ctx, "u", ""); !errors.Is(err, ErrBlockListNotReady) {
		t.Fatalf("nil store: %v", err)
	}
}
