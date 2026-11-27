package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/internal/portal/adapters/sqlite"
)

func openRepo(t *testing.T) (*sqlite.Repo, *cpstate.DB) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), sqlite.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlite.New(db), db
}

// TestRepo: Upsert inserts generation 1 and then increments it, keeping
// linked_at and clearing the refresh and offboarding columns; Rotate is a
// compare-and-swap on generation; NULL times read back as zero; Get of an
// absent row is ErrLinkNotFound; user_key is unique.
func TestRepo(t *testing.T) {
	ctx := context.Background()
	r, db := openRepo(t)
	t0 := time.UnixMilli(1_800_000_000_000).UTC()
	in := portal.IdPLink{Iss: "https://i", Sub: "s", UserKey: "0123456789abcdef0123456789abcdef", Email: "e@x",
		SecretKey: "idp/0123456789abcdef0123456789abcdef", RefreshRef: "ref1",
		LinkedAt: t0, RefreshIssuedAt: t0, RelinkDueAt: t0.Add(time.Hour)}
	got, err := r.Upsert(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	want := in
	want.Generation = 1
	if got != want {
		t.Fatalf("Upsert = %+v, want %+v", got, want)
	}
	if err := r.Rotate(ctx, "https://i", "s", 1, "ref2", t0.Add(time.Minute), portal.RefreshStatusRotated); err != nil {
		t.Fatal(err)
	}
	if err := r.Rotate(ctx, "https://i", "s", 1, "ref3", t0, "x"); !errors.Is(err, portal.ErrStaleGeneration) {
		t.Fatalf("stale Rotate = %v", err)
	}
	g, err := r.Get(ctx, "https://i", "s")
	if err != nil || g.Generation != 2 || g.RefreshRef != "ref2" || !g.LastRefreshAt.Equal(t0.Add(time.Minute)) || g.LastRefreshStatus != portal.RefreshStatusRotated {
		t.Fatalf("after Rotate = %+v, %v", g, err)
	}
	if _, err := db.SQL().Exec(`UPDATE idp_links SET offboarded_at = 1`); err != nil {
		t.Fatal(err)
	}
	re := in
	re.RefreshRef, re.LinkedAt, re.RefreshIssuedAt = "ref4", t0.Add(time.Hour), t0.Add(time.Hour)
	got, err = r.Upsert(ctx, re)
	if err != nil {
		t.Fatal(err)
	}
	if got.Generation != 3 || !got.LinkedAt.Equal(t0) || !got.RefreshIssuedAt.Equal(t0.Add(time.Hour)) || got.RefreshRef != "ref4" ||
		!got.LastRefreshAt.IsZero() || got.LastRefreshStatus != "" || !got.OffboardedAt.IsZero() {
		t.Fatalf("re-login Upsert = %+v", got)
	}
	if _, err := r.Get(ctx, "https://i", "other"); !errors.Is(err, portal.ErrLinkNotFound) {
		t.Fatalf("Get absent = %v", err)
	}
	dup := in
	dup.Sub = "other"
	if _, err := r.Upsert(ctx, dup); err == nil {
		t.Fatal("a second (iss, sub) took the same user_key")
	}
	if err := r.Rotate(ctx, "https://i", "absent", 1, "r", t0, "x"); !errors.Is(err, portal.ErrStaleGeneration) {
		t.Fatalf("Rotate of an absent row = %v", err)
	}
	all, err := r.List(ctx)
	if err != nil || len(all) != 1 || all[0].Generation != 3 {
		t.Fatalf("List = %+v, %v", all, err)
	}
}
