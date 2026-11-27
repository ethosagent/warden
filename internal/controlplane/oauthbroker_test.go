package controlplane

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/oauthbroker"
	oauthbrokersqlite "github.com/ethosagent/warden/internal/oauthbroker/adapters/sqlite"
	"github.com/ethosagent/warden/internal/oauthbroker/oauthbrokertest"
)

func brokerTables(t *testing.T, db *cpstate.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table'
AND name IN ('pending_authorizations','connect_attempts','oauth_grants')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestStateMigrationsBrokerGated: the broker migrations are registered for the
// downgrade guard but create no table unless the broker is enabled.
func TestStateMigrationsBrokerGated(t *testing.T) {
	for _, id := range oauthbrokersqlite.EnabledMigrationIDs() {
		if !slices.ContainsFunc(StateMigrations(), func(m cpstate.Migration) bool { return m.ID == id && m.Optional }) {
			t.Fatalf("StateMigrations lacks optional %s", id)
		}
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db, err := cpstate.Open(ctx, path, stateMigrationsWithBroker(StateMigrations(), false))
	if err != nil {
		t.Fatalf("Open (broker off): %v", err)
	}
	if n := brokerTables(t, db); n != 0 {
		t.Fatalf("broker off created %d broker tables", n)
	}
	_ = db.Close()
	db, err = cpstate.Open(ctx, path, stateMigrationsWithBroker(StateMigrations(), true))
	if err != nil {
		t.Fatalf("Open (broker on): %v", err)
	}
	if n := brokerTables(t, db); n != 3 {
		t.Fatalf("broker on created %d broker tables, want 3", n)
	}
	_ = db.Close()
	// Switching the broker off again keeps the file openable (downgrade guard).
	db, err = cpstate.Open(ctx, path, StateMigrations())
	if err != nil {
		t.Fatalf("Open after the broker was on: %v", err)
	}
	_ = db.Close()
}

// TestStartRunsBrokerSweeper: Start runs the broker sweeper when a GrantStore
// is configured; its first pass expires a pending already past expires_at and
// wakes the waiter.
func TestStartRunsBrokerSweeper(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := cpstate.Open(ctx, filepath.Join(t.TempDir(), "warden-cp.db"), stateMigrationsWithBroker(StateMigrations(), true))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clk := clocktest.NewFake(oauthbrokertest.Start)
	store := oauthbrokersqlite.New(db, oauthbrokersqlite.Options{Clock: clk})
	p, err := store.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google"), time.Minute)
	if err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	ch, unsubscribe := store.Subscribe(p.ID)
	defer unsubscribe()
	clk.Advance(time.Minute)

	srv := New(Config{PolicyPath: writePolicyFile(t, "api.example.com"), Clock: clk, GrantStore: store})
	srv.Start(ctx)
	if st := oauthbrokertest.Received(t, ch); st != oauthbroker.StatusExpired {
		t.Fatalf("waiter got %q, want expired from the startup sweep", st)
	}
}
