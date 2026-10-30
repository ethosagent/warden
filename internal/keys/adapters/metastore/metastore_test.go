package metastore

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

func openDB(t *testing.T, enable bool) *cpstate.DB {
	t.Helper()
	migs := Migrations()
	if enable {
		migs = cpstate.Enable(migs, MigrationID)
	}
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), migs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func tableCount(t *testing.T, db *cpstate.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'signing_keys'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func rec(t *testing.T, purpose string, st keys.State) keys.Record {
	t.Helper()
	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(sg.Public(), sg.Alg())
	if err != nil {
		t.Fatal(err)
	}
	return keys.Record{
		KID: sg.KID(), Purpose: purpose, Alg: sg.Alg(), State: st, PublicJWK: jwk,
		StoreBackend: "file", CreatedAt: t0, PublishAt: t0, CreatedBy: "system",
	}
}

// TestMigrationOptional: no table without Enable; the table once enabled; a
// file that has it still opens when the migration is left disabled.
func TestMigrationOptional(t *testing.T) {
	off := openDB(t, false)
	if tableCount(t, off) != 0 {
		t.Fatal("signing_keys exists although the migration was not enabled")
	}
	on := openDB(t, true)
	if tableCount(t, on) != 1 {
		t.Fatal("signing_keys missing after Enable")
	}
	path := on.Path()
	_ = on.Close()
	again, err := cpstate.Open(context.Background(), path, Migrations())
	if err != nil {
		t.Fatalf("reopening an enabled file with the migration disabled: %v", err)
	}
	_ = again.Close()
}

func TestInsertListRoundTrip(t *testing.T) {
	s := New(openDB(t, true))
	ctx := context.Background()
	r := rec(t, keys.PurposeToken, keys.StateActive)
	r.ActivateAt = t0.Add(time.Minute)
	if err := s.Insert(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("List = %v, %v", got, err)
	}
	if got[0] != r {
		t.Errorf("round trip changed the record:\n got %+v\nwant %+v", got[0], r)
	}
}

// TestOneActiveOneNextPerPurpose: the partial unique indexes.
func TestOneActiveOneNextPerPurpose(t *testing.T) {
	s := New(openDB(t, true))
	ctx := context.Background()
	if err := s.Insert(ctx, rec(t, keys.PurposeToken, keys.StateActive)); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, rec(t, keys.PurposeToken, keys.StateActive)); !errors.Is(err, keys.ErrConflict) {
		t.Errorf("second active = %v, want ErrConflict", err)
	}
	if err := s.Insert(ctx, rec(t, keys.PurposeToken, keys.StateNext)); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, rec(t, keys.PurposeToken, keys.StateNext)); !errors.Is(err, keys.ErrConflict) {
		t.Errorf("second next = %v, want ErrConflict", err)
	}
	// Other purposes and non-live states are unconstrained.
	if err := s.Insert(ctx, rec(t, keys.PurposeBundle, keys.StateActive)); err != nil {
		t.Errorf("active in another purpose: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Insert(ctx, rec(t, keys.PurposeToken, keys.StateRetired)); err != nil {
			t.Errorf("retired row %d: %v", i, err)
		}
	}
	dup := rec(t, keys.PurposeToken, keys.StateDestroyed)
	if err := s.Insert(ctx, dup); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, dup); !errors.Is(err, keys.ErrConflict) {
		t.Errorf("duplicate kid = %v, want ErrConflict", err)
	}
}

func TestInsertIfEmpty(t *testing.T) {
	s := New(openDB(t, true))
	ctx := context.Background()
	pair := []keys.Record{rec(t, keys.PurposeToken, keys.StateActive), rec(t, keys.PurposeToken, keys.StateNext)}
	ok, err := s.InsertIfEmpty(ctx, keys.PurposeToken, pair)
	if err != nil || !ok {
		t.Fatalf("first InsertIfEmpty = %v, %v", ok, err)
	}
	other := []keys.Record{rec(t, keys.PurposeToken, keys.StateActive), rec(t, keys.PurposeToken, keys.StateNext)}
	ok, err = s.InsertIfEmpty(ctx, keys.PurposeToken, other)
	if err != nil || ok {
		t.Fatalf("second InsertIfEmpty = %v, %v; want false, nil", ok, err)
	}
	if rows, _ := s.List(ctx); len(rows) != 2 {
		t.Errorf("rows = %d, want 2", len(rows))
	}
	// A row of the wrong purpose rolls the whole batch back.
	bad := []keys.Record{rec(t, keys.PurposeBundle, keys.StateActive), rec(t, keys.PurposeToken, keys.StateNext)}
	if _, err := s.InsertIfEmpty(ctx, keys.PurposeBundle, bad); err == nil {
		t.Error("mixed-purpose batch accepted")
	}
	for _, r := range mustList(t, s) {
		if r.Purpose == keys.PurposeBundle {
			t.Errorf("partial batch committed: %+v", r)
		}
	}
}

func mustList(t *testing.T, s *Store) []keys.Record {
	t.Helper()
	rows, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestInsertIfEmptyConcurrent: many callers, one winner.
func TestInsertIfEmptyConcurrent(t *testing.T) {
	s := New(openDB(t, true))
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < 8; i++ {
		pair := []keys.Record{rec(t, keys.PurposeToken, keys.StateActive), rec(t, keys.PurposeToken, keys.StateNext)}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.InsertIfEmpty(ctx, keys.PurposeToken, pair)
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Errorf("winners = %d, want 1", winners)
	}
	if rows := mustList(t, s); len(rows) != 2 {
		t.Errorf("rows = %d, want 2", len(rows))
	}
}

func TestUpdateStateCAS(t *testing.T) {
	s := New(openDB(t, true))
	ctx := context.Background()
	active, next := rec(t, keys.PurposeToken, keys.StateActive), rec(t, keys.PurposeToken, keys.StateNext)
	for _, r := range []keys.Record{active, next} {
		if err := s.Insert(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	at := t0.Add(time.Hour)
	ok, err := s.UpdateState(ctx, active.KID, keys.StateActive, keys.StateRetired, at)
	if err != nil || !ok {
		t.Fatalf("retire = %v, %v", ok, err)
	}
	// Stale from-state: nothing changes.
	if ok, err := s.UpdateState(ctx, active.KID, keys.StateActive, keys.StateRetired, at); err != nil || ok {
		t.Errorf("stale CAS = %v, %v; want false, nil", ok, err)
	}
	if ok, _ := s.UpdateState(ctx, "missing", keys.StateActive, keys.StateRetired, at); ok {
		t.Error("CAS on a missing kid reported a change")
	}
	// Promote next: now allowed, and stamps activate_at.
	if ok, err := s.UpdateState(ctx, next.KID, keys.StateNext, keys.StateActive, at); err != nil || !ok {
		t.Fatalf("promote = %v, %v", ok, err)
	}
	byKID := map[string]keys.Record{}
	for _, r := range mustList(t, s) {
		byKID[r.KID] = r
	}
	if r := byKID[active.KID]; r.State != keys.StateRetired || !r.RetireAt.Equal(at) {
		t.Errorf("retired row = %+v", r)
	}
	if r := byKID[next.KID]; r.State != keys.StateActive || !r.ActivateAt.Equal(at) {
		t.Errorf("promoted row = %+v", r)
	}
	if ok, err := s.UpdateState(ctx, active.KID, keys.StateRetired, keys.StateDestroyed, at); err != nil || !ok {
		t.Fatalf("destroy = %v, %v", ok, err)
	}
	if r := mustList(t, s); r[0].DestroyedAt.IsZero() {
		t.Errorf("destroyed_at not stamped: %+v", r[0])
	}
	if _, err := s.UpdateState(ctx, active.KID, keys.StateDestroyed, keys.State("bogus"), at); err == nil {
		t.Error("unknown target state accepted")
	}
}

// TestUpdateStateRespectsUniqueIndex: promoting a second key to active while
// one is active is a conflict, not a fork.
func TestUpdateStateRespectsUniqueIndex(t *testing.T) {
	s := New(openDB(t, true))
	ctx := context.Background()
	active, next := rec(t, keys.PurposeToken, keys.StateActive), rec(t, keys.PurposeToken, keys.StateNext)
	for _, r := range []keys.Record{active, next} {
		if err := s.Insert(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := s.UpdateState(ctx, next.KID, keys.StateNext, keys.StateActive, t0); !errors.Is(err, keys.ErrConflict) || ok {
		t.Errorf("double activation = %v, %v; want ErrConflict", ok, err)
	}
}

func TestListRejectsCorruptJWK(t *testing.T) {
	db := openDB(t, true)
	s := New(db)
	r := rec(t, keys.PurposeToken, keys.StateActive)
	if err := s.Insert(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// A JWK carrying a private member must never be accepted from the table.
	if _, err := db.SQL().Exec(`UPDATE signing_keys SET public_jwk = '{"kty":"OKP","crv":"Ed25519","x":"AA","d":"AA"}'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(context.Background()); err == nil {
		t.Error("List accepted a row whose public_jwk has a private member")
	}
}

func TestStateCheckConstraint(t *testing.T) {
	db := openDB(t, true)
	_, err := db.SQL().Exec(`INSERT INTO signing_keys (kid, purpose, alg, state, public_jwk, store_backend, created_at, created_by)
		VALUES ('k', 'token', 'EdDSA', 'bogus', '{}', 'file', 1, 'x')`)
	if err == nil {
		t.Error("state outside next|active|retired|revoked|destroyed accepted")
	}
}

// insertPair inserts an active and a next row for a purpose.
func insertPair(t *testing.T, s *Store, purpose string) (active, next keys.Record) {
	t.Helper()
	active, next = rec(t, purpose, keys.StateActive), rec(t, purpose, keys.StateNext)
	for _, r := range []keys.Record{active, next} {
		if err := s.Insert(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	return active, next
}

// rowOf finds one row by kid.
func rowOf(t *testing.T, s *Store, kid string) keys.Record {
	t.Helper()
	for _, r := range listAll(t, s) {
		if r.KID == kid {
			return r
		}
	}
	t.Fatalf("no row for kid %s", kid)
	return keys.Record{}
}

func listAll(t *testing.T, s *Store) []keys.Record {
	t.Helper()
	rows, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestPromoteCAS: the retire and the activate commit as one pair, both
// stamped. Either side of the pair not being where the caller expects is a
// lost race that writes nothing at all — in particular a next key that is no
// longer next leaves the old key active, which is the state a two-write
// promotion used to strand.
func TestPromoteCAS(t *testing.T) {
	s := New(openDB(t, true))
	ctx := context.Background()
	active, next := insertPair(t, s, keys.PurposeToken)
	t1 := t0.Add(time.Hour)

	// Lost race on the second write: the next key moved on. Nothing commits —
	// the old key stays active with no retire_at.
	if ok, err := s.UpdateState(ctx, next.KID, keys.StateNext, keys.StateDestroyed, t0); err != nil || !ok {
		t.Fatalf("destroy the next key = %v, %v", ok, err)
	}
	if ok, err := s.Promote(ctx, keys.PurposeToken, active.KID, keys.StateRetired, next.KID, t1); err != nil || ok {
		t.Fatalf("promote a destroyed next = %v, %v; want false, nil", ok, err)
	}
	if r := rowOf(t, s, active.KID); r.State != keys.StateActive || !r.RetireAt.IsZero() {
		t.Errorf("a failed second write left the old key %+v, want still active", r)
	}

	// Lost race on the first write: the old key moved on. Again nothing.
	if ok, err := s.UpdateState(ctx, active.KID, keys.StateActive, keys.StateRetired, t0); err != nil || !ok {
		t.Fatalf("retire the old key = %v, %v", ok, err)
	}
	fresh, freshNext := rec(t, keys.PurposeToken, keys.StateActive), rec(t, keys.PurposeToken, keys.StateNext)
	for _, r := range []keys.Record{fresh, freshNext} {
		if err := s.Insert(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := s.Promote(ctx, keys.PurposeToken, active.KID, keys.StateRetired, freshNext.KID, t1); err != nil || ok {
		t.Fatalf("promote a retired old = %v, %v; want false, nil", ok, err)
	}
	if r := rowOf(t, s, freshNext.KID); r.State != keys.StateNext {
		t.Errorf("a lost race moved the next key: %+v", r)
	}
	if r := rowOf(t, s, fresh.KID); r.State != keys.StateActive {
		t.Errorf("a lost race moved the active key: %+v", r)
	}

	// The pair commits: both rows stamped, one transaction.
	if ok, err := s.Promote(ctx, keys.PurposeToken, fresh.KID, keys.StateRetired, freshNext.KID, t1); err != nil || !ok {
		t.Fatalf("promote = %v, %v; want true, nil", ok, err)
	}
	if r := rowOf(t, s, fresh.KID); r.State != keys.StateRetired || !r.RetireAt.Equal(t1) {
		t.Errorf("the old key after promote = %+v, want retired at t1", r)
	}
	if r := rowOf(t, s, freshNext.KID); r.State != keys.StateActive || !r.ActivateAt.Equal(t1) {
		t.Errorf("the next key after promote = %+v, want active at t1", r)
	}

	// An empty oldKID skips the retire: the vacant-slot promotion.
	vacantNext := rec(t, keys.PurposeToken, keys.StateNext)
	if err := s.Insert(ctx, vacantNext); err != nil {
		t.Fatal(err)
	}
	t2 := t1.Add(time.Hour)
	if ok, err := s.UpdateState(ctx, freshNext.KID, keys.StateActive, keys.StateRevoked, t2); err != nil || !ok {
		t.Fatalf("revoke to vacate = %v, %v", ok, err)
	}
	if ok, err := s.Promote(ctx, keys.PurposeToken, "", keys.StateRetired, vacantNext.KID, t2); err != nil || !ok {
		t.Fatalf("vacant promote = %v, %v; want true, nil", ok, err)
	}
	if r := rowOf(t, s, vacantNext.KID); r.State != keys.StateActive || !r.ActivateAt.Equal(t2) {
		t.Errorf("the vacant-slot promotion = %+v, want active at t2", r)
	}
}

// TestPromoteRespectsUniqueIndex: activating the next key while another key is
// still active — an empty-oldKID promotion whose retire the caller skipped —
// is a conflict, and the transaction rolls back leaving both rows as they
// were.
func TestPromoteRespectsUniqueIndex(t *testing.T) {
	s := New(openDB(t, true))
	ctx := context.Background()
	active, next := insertPair(t, s, keys.PurposeToken)
	if _, err := s.Promote(ctx, keys.PurposeToken, "", keys.StateRetired, next.KID, t0); !errors.Is(err, keys.ErrConflict) {
		t.Fatalf("promoting into an occupied slot = %v, want ErrConflict", err)
	}
	if r := rowOf(t, s, next.KID); r.State != keys.StateNext {
		t.Errorf("the conflicted promotion wrote anyway: %+v", r)
	}
	if r := rowOf(t, s, active.KID); r.State != keys.StateActive {
		t.Errorf("the active key moved: %+v", r)
	}
}

// TestPromoteAtomicToAPeer: while a promotion commits, a peer reading on
// another connection sees either both changes or neither — never the purpose
// with no active key. A read transaction opened before the promotion pins the
// pre-promotion snapshot for its lifetime, which is exactly what a poller
// caught between the two writes when they were two transactions.
func TestPromoteAtomicToAPeer(t *testing.T) {
	db := openDB(t, true)
	s := New(db)
	ctx := context.Background()
	active, next := insertPair(t, s, keys.PurposeToken)

	peerDB, err := cpstate.Open(ctx, db.Path(), cpstate.Enable(Migrations(), MigrationID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peerDB.Close() })

	// The peer's read transaction pins the snapshot at its first read. The
	// pool holds exactly one connection (cpstate pins MaxOpenConns), so the
	// conn must go back before anything else queries this handle.
	conn, err := peerDB.SQL().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	var activeKID string
	if err := conn.QueryRowContext(ctx,
		`SELECT kid FROM signing_keys WHERE purpose = 'token' AND state = 'active'`).Scan(&activeKID); err != nil || activeKID != active.KID {
		t.Fatalf("the peer's pinned read = %q, %v; want the old active", activeKID, err)
	}

	// The promotion commits while that snapshot is pinned.
	if ok, err := s.Promote(ctx, keys.PurposeToken, active.KID, keys.StateRetired, next.KID, t0); err != nil || !ok {
		t.Fatalf("promote = %v, %v", ok, err)
	}

	// Still inside its read transaction the peer sees the old state whole: the
	// old key active — the purpose was never observable without an active key.
	if err := conn.QueryRowContext(ctx,
		`SELECT kid FROM signing_keys WHERE purpose = 'token' AND state = 'active'`).Scan(&activeKID); err != nil || activeKID != active.KID {
		t.Fatalf("the peer saw a mid-promotion state: %q, %v", activeKID, err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	conn = nil

	// Past the read transaction, both changes are there at once.
	rows := listAll(t, New(peerDB))
	for _, r := range rows {
		switch r.KID {
		case active.KID:
			if r.State != keys.StateRetired {
				t.Errorf("the old key = %s, want retired", r.State)
			}
		case next.KID:
			if r.State != keys.StateActive {
				t.Errorf("the new key = %s, want active", r.State)
			}
		}
	}
}
