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
	want.Generation, want.State = 1, portal.LinkActive
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

// TestRepoSetState: SetState writes every refresh-job column under the
// generation compare-and-swap without changing the generation; a re-login
// Upsert resets the record to active but keeps last_ok_at.
func TestRepoSetState(t *testing.T) {
	ctx := context.Background()
	r, _ := openRepo(t)
	t0 := time.UnixMilli(1_800_000_000_000).UTC()
	in := portal.IdPLink{Iss: "https://i", Sub: "s", UserKey: "0123456789abcdef0123456789abcdef", Email: "e@x",
		SecretKey: "idp/0123456789abcdef0123456789abcdef", RefreshRef: "ref1",
		LinkedAt: t0, RefreshIssuedAt: t0, RelinkDueAt: t0.Add(time.Hour)}
	if _, err := r.Upsert(ctx, in); err != nil {
		t.Fatal(err)
	}
	st := portal.RefreshState{
		State: portal.LinkTokenLost, LastOKAt: t0.Add(time.Minute), LastRefreshAt: t0.Add(2 * time.Minute),
		LastRefreshStatus: "failed", ConsecutiveFailures: 2, LastErrorCode: "token_lost",
		RotationPendingRef: "pending-ref", Email: "new@x", EmailVerified: true,
	}
	if err := r.SetState(ctx, "https://i", "s", 2, st); !errors.Is(err, portal.ErrStaleGeneration) {
		t.Fatalf("stale SetState = %v", err)
	}
	if err := r.SetState(ctx, "https://i", "s", 1, st); err != nil {
		t.Fatal(err)
	}
	g, err := r.Get(ctx, "https://i", "s")
	if err != nil || g.Generation != 1 || g.RefreshState() != st {
		t.Fatalf("after SetState = %+v, %v", g, err)
	}
	if err := r.SetState(ctx, "https://i", "absent", 1, st); !errors.Is(err, portal.ErrStaleGeneration) {
		t.Fatalf("SetState of an absent row = %v", err)
	}
	re := in
	re.RefreshRef, re.EmailVerified = "ref2", false
	got, err := r.Upsert(ctx, re)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != portal.LinkActive || got.ConsecutiveFailures != 0 || got.LastErrorCode != "" ||
		got.RotationPendingRef != "" || got.EmailVerified || !got.LastOKAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("re-login Upsert = %+v, want the record reset and last_ok_at kept", got)
	}
}
