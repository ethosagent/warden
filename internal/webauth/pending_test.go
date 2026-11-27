package webauth_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/webauth"
)

func openDB(t *testing.T, migs ...[]cpstate.Migration) *cpstate.DB {
	t.Helper()
	var all []cpstate.Migration
	for _, m := range migs {
		all = append(all, m...)
	}
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), all)
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPendingPurpose(t *testing.T) {
	ctx := context.Background()
	ps := webauth.NewPendingStore(openDB(t, webauth.PendingMigrations()).SQL(), nil)
	in := webauth.Pending{StateHash: "s1", Purpose: webauth.PurposeConsole, Nonce: "n", Verifier: "v", Next: "/dashboard/", BrowserHash: "b"}
	if err := ps.Put(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ps.Take(ctx, "s1", webauth.PurposePortal); err != nil || ok {
		t.Fatalf("portal take of a console row = %v %v, want not found", ok, err)
	}
	if n, _ := ps.Count(ctx); n != 1 {
		t.Fatalf("rows after a mismatched take = %d, want 1", n)
	}
	p, ok, err := ps.Take(ctx, "s1", webauth.PurposeConsole)
	if err != nil || !ok {
		t.Fatalf("console take = %v %v, want found", ok, err)
	}
	if p.Purpose != webauth.PurposeConsole || p.Nonce != "n" || p.Verifier != "v" || p.Next != "/dashboard/" || p.BrowserHash != "b" {
		t.Fatalf("row read back wrong: %+v", p)
	}
	if _, ok, _ := ps.Take(ctx, "s1", webauth.PurposeConsole); ok {
		t.Fatal("a state was taken twice")
	}

	t.Run("portal row is not taken by the console", func(t *testing.T) {
		in := in
		in.StateHash, in.Purpose = "s2", webauth.PurposePortal
		if err := ps.Put(ctx, in); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := ps.Take(ctx, "s2", webauth.PurposeConsole); ok {
			t.Fatal("console took a portal row")
		}
		if _, ok, _ := ps.Take(ctx, "s2", webauth.PurposePortal); !ok {
			t.Fatal("portal could not take its own row")
		}
	})
	t.Run("a row needs a purpose", func(t *testing.T) {
		in := in
		in.StateHash, in.Purpose = "s3", ""
		if err := ps.Put(ctx, in); err == nil {
			t.Fatal("Put without a purpose succeeded")
		}
	})
}

// A row stored before oidc_pending/0002 reads back as a console login.
func TestPendingMigrationDefaultsToConsole(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	v1 := webauth.PendingMigrations()[:1]
	db, err := cpstate.Open(ctx, path, v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().Exec(`INSERT INTO oidc_pending (state_hash, nonce, verifier, next, browser_hash, expires_at) VALUES ('old', 'n', 'v', '/dashboard/', 'b', ?)`,
		time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	db = openDBAt(t, path, webauth.PendingMigrations())
	ps := webauth.NewPendingStore(db.SQL(), nil)
	if _, ok, _ := ps.Take(ctx, "old", webauth.PurposePortal); ok {
		t.Fatal("an old row was taken as a portal login")
	}
	if p, ok, err := ps.Take(ctx, "old", webauth.PurposeConsole); err != nil || !ok || p.Purpose != webauth.PurposeConsole {
		t.Fatalf("old row as console = %+v %v %v", p, ok, err)
	}
}

func openDBAt(t *testing.T, path string, migs []cpstate.Migration) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), path, migs)
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPendingCapIsShared(t *testing.T) {
	ctx := context.Background()
	db := openDB(t, webauth.PendingMigrations())
	now := time.Unix(1_800_000_000, 0)
	ps := webauth.NewPendingStore(db.SQL(), func() time.Time { return now })
	if _, err := db.SQL().Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
		INSERT INTO oidc_pending (state_hash, purpose, nonce, verifier, next, browser_hash, expires_at)
		SELECT 'h' || i, 'console', 'n', 'v', '/dashboard/', 'b', ? FROM n`,
		webauth.PendingCap, now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	err := ps.Put(ctx, webauth.Pending{StateHash: "p", Purpose: webauth.PurposePortal, Nonce: "n", Verifier: "v", Next: "/portal", BrowserHash: "b"})
	if !errors.Is(err, webauth.ErrPendingFull) {
		t.Fatalf("portal Put at the cap = %v, want ErrPendingFull", err)
	}
	now = now.Add(2 * time.Hour)
	if n, err := ps.Sweep(ctx); err != nil || n != webauth.PendingCap {
		t.Fatalf("sweep = %d %v", n, err)
	}
}
