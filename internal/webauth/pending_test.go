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

// Each purpose has its own cap: a flood of portal logins never makes console
// login answer login_busy, and the reverse.
func TestPendingCapIsPerPurpose(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	fill := func(t *testing.T, db *cpstate.DB, purpose string) {
		t.Helper()
		if _, err := db.SQL().Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
			INSERT INTO oidc_pending (state_hash, purpose, nonce, verifier, next, browser_hash, expires_at)
			SELECT ? || i, ?, 'n', 'v', '/', 'b', ? FROM n`,
			webauth.PendingCap, purpose+"-", purpose, now.Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	row := func(state, purpose string) webauth.Pending {
		return webauth.Pending{StateHash: state, Purpose: purpose, Nonce: "n", Verifier: "v", Next: "/", BrowserHash: "b"}
	}
	for _, tc := range []struct{ full, other string }{
		{webauth.PurposePortal, webauth.PurposeConsole},
		{webauth.PurposeConsole, webauth.PurposePortal},
	} {
		t.Run(tc.full+" full", func(t *testing.T) {
			db := openDB(t, webauth.PendingMigrations())
			ps := webauth.NewPendingStore(db.SQL(), func() time.Time { return now })
			fill(t, db, tc.full)
			if err := ps.Put(ctx, row("x", tc.full)); !errors.Is(err, webauth.ErrPendingFull) {
				t.Fatalf("%s Put at its cap = %v, want ErrPendingFull", tc.full, err)
			}
			if err := ps.Put(ctx, row("y", tc.other)); err != nil {
				t.Fatalf("%s Put with %s full = %v, want ok", tc.other, tc.full, err)
			}
			if _, ok, err := ps.Take(ctx, "y", tc.other); err != nil || !ok {
				t.Fatalf("%s take = %v %v", tc.other, ok, err)
			}
			now := now.Add(2 * time.Hour)
			ps = webauth.NewPendingStore(db.SQL(), func() time.Time { return now })
			if n, err := ps.Sweep(ctx); err != nil || n != webauth.PendingCap {
				t.Fatalf("sweep = %d %v", n, err)
			}
		})
	}
}
