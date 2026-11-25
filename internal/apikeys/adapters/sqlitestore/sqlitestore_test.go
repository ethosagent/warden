package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
)

var t0 = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func openDB(t *testing.T, path string) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), path, cpstate.Enable(Migrations(), MigrationID))
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testRand(seed byte) io.Reader {
	var key [32]byte
	key[0] = seed
	return mrand.NewChaCha8(key)
}

func newStoreAt(t *testing.T, path string, clk *clocktest.Fake, rd io.Reader) *SQLiteStore {
	t.Helper()
	s, err := New(openDB(t, path), Options{Registry: apikeys.NewP2Registry(), Clock: clk, Rand: rd})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newStore(t *testing.T) (*SQLiteStore, *clocktest.Fake, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	clk := clocktest.NewFake(t0)
	return newStoreAt(t, path, clk, testRand(1)), clk, path
}

func params(owner, name string) apikeys.CreateParams {
	return apikeys.CreateParams{
		Name: name, OwnerIss: "https://idp", OwnerSub: owner, OwnerEmail: owner + "@example.com",
		OwnerGroups: []string{"eng"}, Scopes: []apikeys.Scope{"policy:read"},
		TTL: 24 * time.Hour, MaxTTL: 365 * 24 * time.Hour, MaxActive: 25,
	}
}

func count(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_keys`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMigrationOptionalUntilEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.db")
	db, err := cpstate.Open(context.Background(), path, Migrations())
	if err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.SQL().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='api_keys'`).Scan(&n)
	if n != 0 {
		t.Fatal("api_keys table created while the migration was not enabled")
	}
	_ = db.Close()
	db2 := openDB(t, path)
	_ = db2.SQL().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='api_keys'`).Scan(&n)
	if n != 1 {
		t.Fatal("api_keys table missing after enabling the migration")
	}
}

func TestStoreCreateGetList(t *testing.T) {
	s, clk, _ := newStore(t)
	ctx := context.Background()
	p := params("alice", "ci")
	p.Description = "deploys"
	pt, k, err := s.Create(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := apikeys.Parse(pt); err != nil || id != k.ID {
		t.Fatalf("plaintext does not parse to the key id: %v", err)
	}
	if !k.ExpiresAt.Equal(t0.Add(24*time.Hour)) || !k.CreatedAt.Equal(t0) {
		t.Fatalf("times = %v / %v", k.CreatedAt, k.ExpiresAt)
	}
	got, err := s.Get(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "ci" || got.Description != "deploys" || got.OwnerSub != "alice" ||
		got.OwnerEmail != "alice@example.com" || len(got.OwnerGroups) != 1 || got.OwnerGroups[0] != "eng" ||
		len(got.Scopes) != 1 || got.Scopes[0] != "policy:read" || !got.HasScope("policy:read") || got.HasScope("policy:write") {
		t.Fatalf("Get = %+v", got)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, apikeys.ErrNotFound) {
		t.Fatalf("Get unknown = %v", err)
	}

	clk.Advance(time.Minute)
	_, k2, _ := s.Create(ctx, params("bob", "ci"))
	if _, _, err := s.Create(ctx, params("alice", "ci")); !errors.Is(err, apikeys.ErrNameTaken) {
		t.Fatalf("duplicate name = %v, want apikeys.ErrNameTaken", err)
	}
	short := params("alice", "short")
	short.TTL = time.Hour
	_, k3, _ := s.Create(ctx, short)

	all, _ := s.List(ctx, apikeys.ListFilter{})
	if len(all) != 3 || all[0].ID != k.ID {
		t.Fatalf("List all = %v", all)
	}
	if mine, _ := s.List(ctx, apikeys.ListFilter{OwnerSub: "bob"}); len(mine) != 1 || mine[0].ID != k2.ID {
		t.Fatalf("List owner = %v", mine)
	}
	soon, _ := s.List(ctx, apikeys.ListFilter{ExpiresBefore: t0.Add(2 * time.Hour)})
	if len(soon) != 1 || soon[0].ID != k3.ID {
		t.Fatalf("List expiring = %v", soon)
	}
	_ = s.Revoke(ctx, k3.ID, "alice")
	if soon, _ := s.List(ctx, apikeys.ListFilter{ExpiresBefore: t0.Add(2 * time.Hour)}); len(soon) != 0 {
		t.Fatalf("a revoked key listed as expiring: %v", soon)
	}
	clk.Advance(48 * time.Hour)
	if act, _ := s.List(ctx, apikeys.ListFilter{ActiveOnly: true}); len(act) != 0 {
		t.Fatalf("ActiveOnly after expiry = %v", act)
	}
	if got, _ := s.Get(ctx, k.ID); got.StatusAt(clk.Now()) != apikeys.StatusExpired {
		t.Fatalf("status = %v", got.StatusAt(clk.Now()))
	}
	if got, _ := s.Get(ctx, k3.ID); got.StatusAt(clk.Now()) != apikeys.StatusRevoked {
		t.Fatalf("status = %v", got.StatusAt(clk.Now()))
	}
}

func TestStoreCreateLimits(t *testing.T) {
	s, clk, _ := newStore(t)
	ctx := context.Background()
	db := s.db

	for name, tc := range map[string]struct {
		mut  func(*apikeys.CreateParams)
		want error
	}{
		"ttl zero":      {func(p *apikeys.CreateParams) { p.TTL = 0 }, apikeys.ErrInvalidTTL},
		"ttl below 1h":  {func(p *apikeys.CreateParams) { p.TTL = time.Hour - time.Second }, apikeys.ErrInvalidTTL},
		"ttl above max": {func(p *apikeys.CreateParams) { p.TTL = p.MaxTTL + time.Second }, apikeys.ErrInvalidTTL},
		"no max":        {func(p *apikeys.CreateParams) { p.MaxTTL = 0 }, apikeys.ErrInvalidTTL},
		"unknown scope": {func(p *apikeys.CreateParams) { p.Scopes = []apikeys.Scope{"foo:bar"} }, apikeys.ErrUnknownScope},
		"dup scope":     {func(p *apikeys.CreateParams) { p.Scopes = []apikeys.Scope{"policy:read", "policy:read"} }, apikeys.ErrDuplicateScope},
		"no scopes":     {func(p *apikeys.CreateParams) { p.Scopes = nil }, apikeys.ErrNoScopes},
		"empty name":    {func(p *apikeys.CreateParams) { p.Name = "" }, apikeys.ErrInvalidInput},
		"long name":     {func(p *apikeys.CreateParams) { p.Name = strings.Repeat("n", 65) }, apikeys.ErrInvalidInput},
		"control name":  {func(p *apikeys.CreateParams) { p.Name = "a\nb" }, apikeys.ErrInvalidInput},
		"long desc":     {func(p *apikeys.CreateParams) { p.Description = strings.Repeat("d", 513) }, apikeys.ErrInvalidInput},
		"no owner":      {func(p *apikeys.CreateParams) { p.OwnerSub = "" }, apikeys.ErrInvalidInput},
		"no cap":        {func(p *apikeys.CreateParams) { p.MaxActive = 0 }, apikeys.ErrInvalidInput},
	} {
		p := params("alice", "k")
		tc.mut(&p)
		if _, _, err := s.Create(ctx, p); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	if n := count(t, db); n != 0 {
		t.Fatalf("%d rows written by rejected creates", n)
	}

	// The cap counts active keys only, per owner, and the 26th is refused.
	for i := range 25 {
		if _, _, err := s.Create(ctx, params("alice", fmt.Sprintf("k%d", i))); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, _, err := s.Create(ctx, params("alice", "k25")); !errors.Is(err, apikeys.ErrTooMany) {
		t.Fatalf("26th key = %v, want apikeys.ErrTooMany", err)
	}
	if n := count(t, db); n != 25 {
		t.Fatalf("rows = %d, want 25", n)
	}
	if _, _, err := s.Create(ctx, params("bob", "k0")); err != nil {
		t.Fatalf("another owner is capped by alice's keys: %v", err)
	}
	keys, _ := s.List(ctx, apikeys.ListFilter{OwnerSub: "alice"})
	_ = s.Revoke(ctx, keys[0].ID, "alice")
	if _, _, err := s.Create(ctx, params("alice", "k25")); err != nil {
		t.Fatalf("a revoked key still counted against the cap: %v", err)
	}
	clk.Advance(48 * time.Hour) // every remaining key expires
	if _, _, err := s.Create(ctx, params("alice", "k26")); err != nil {
		t.Fatalf("expired keys still counted against the cap: %v", err)
	}
}

func TestStoreRevoke(t *testing.T) {
	s, clk, _ := newStore(t)
	ctx := context.Background()
	var changes int
	var changeLog []apikeys.Change
	s.OnChange(func(c apikeys.Change) { changes++; changeLog = append(changeLog, c) })
	_, k, _ := s.Create(ctx, params("alice", "a"))
	_, k2, _ := s.Create(ctx, params("alice", "b"))
	_, _, _ = s.Create(ctx, params("bob", "a"))
	if changes != 3 {
		t.Fatalf("OnChange after creates = %d", changes)
	}
	if err := s.Revoke(ctx, k.ID, ""); !errors.Is(err, apikeys.ErrInvalidInput) {
		t.Fatalf("Revoke without actor = %v", err)
	}
	if err := s.Revoke(ctx, k.ID, "admin1"); err != nil {
		t.Fatal(err)
	}
	first, _ := s.Get(ctx, k.ID)
	clk.Advance(time.Hour)
	if err := s.Revoke(ctx, k.ID, "admin2"); err != nil {
		t.Fatalf("revoking twice = %v, want nil", err)
	}
	again, _ := s.Get(ctx, k.ID)
	if !again.RevokedAt.Equal(first.RevokedAt) || again.RevokedBy != "admin1" || first.RevokedAt.IsZero() {
		t.Fatalf("second revoke changed the row: %+v vs %+v", first, again)
	}
	// An already-revoked key still notifies (repairs an Index that missed the
	// first notice); the row itself is untouched, as checked above.
	if changes != 5 || len(changeLog[4].RevokedIDs) != 1 || changeLog[4].RevokedIDs[0] != k.ID {
		t.Fatalf("idempotent revoke notice: %d changes, last %+v", changes, changeLog[len(changeLog)-1])
	}
	if err := s.Revoke(ctx, "missing", "x"); !errors.Is(err, apikeys.ErrNotFound) {
		t.Fatalf("Revoke unknown = %v", err)
	}

	n, err := s.RevokeByOwner(ctx, "https://idp", "alice", "admin3")
	if err != nil || n != 1 {
		t.Fatalf("RevokeByOwner = %d, %v; want 1 (one already revoked)", n, err)
	}
	if got, _ := s.Get(ctx, k2.ID); got.RevokedBy != "admin3" {
		t.Fatalf("owner revoke by = %q", got.RevokedBy)
	}
	if n, _ := s.RevokeByOwner(ctx, "https://idp", "alice", "admin3"); n != 0 {
		t.Fatalf("second RevokeByOwner = %d", n)
	}
	if n, _ := s.RevokeByOwner(ctx, "https://other-idp", "bob", "admin3"); n != 0 {
		t.Fatalf("RevokeByOwner crossed issuers: %d", n)
	}
	if _, err := s.RevokeByOwner(ctx, "", "bob", "x"); !errors.Is(err, apikeys.ErrInvalidInput) {
		t.Fatalf("RevokeByOwner without issuer = %v", err)
	}
	if rows := count(t, s.db); rows != 3 {
		t.Fatalf("rows = %d: nothing may be deleted", rows)
	}
}

func TestStoreNoPlaintext(t *testing.T) {
	s, _, path := newStore(t)
	ctx := context.Background()
	pt, k, err := s.Create(ctx, params("alice", "ci"))
	if err != nil {
		t.Fatal(err)
	}
	secret := secretOf(pt)

	var hashLen int
	if err := s.db.QueryRow(`SELECT length(secret_hash) FROM api_keys WHERE id = ?`, k.ID).Scan(&hashLen); err != nil || hashLen != 32 {
		t.Fatalf("secret_hash length = %d, %v; want 32", hashLen, err)
	}

	rows, err := s.db.Query(`SELECT * FROM api_keys`)
	if err != nil {
		t.Fatal(err)
	}
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, v := range vals {
			if strings.Contains(fmt.Sprint(v), secret) || strings.Contains(fmt.Sprint(v), pt) {
				t.Errorf("column %s holds the key", cols[i])
			}
		}
	}
	_ = rows.Close()

	// The raw database and WAL bytes hold neither form (the WAL still holds
	// the insert because nothing has checkpointed it).
	for _, f := range []string{path, path + "-wal"} {
		b, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(pt)) || bytes.Contains(b, []byte(secret)) || bytes.Contains(b, bytes.ToUpper([]byte(secret))) {
			t.Errorf("%s holds the plaintext or the base32 secret", filepath.Base(f))
		}
	}
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {
		t.Log("wal empty or absent; the main file was checked instead")
	}
}

func TestKeyNeverPrintsSecrets(t *testing.T) {
	s, _, _ := newStore(t)
	pt, k, _ := s.Create(context.Background(), params("alice", "ci"))
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("key", "key", k)
	out := fmt.Sprintf("%v %+v %#v %s", k, k, k, buf.String())
	if strings.Contains(out, secretOf(pt)) || strings.Contains(out, "alice@example.com") {
		t.Fatalf("Key formatting leaks: %s", out)
	}
	if !strings.Contains(buf.String(), k.ID) || !strings.Contains(buf.String(), "policy:read") {
		t.Fatalf("log line lacks id/scopes: %s", buf.String())
	}
}

func TestStoreFlushLastUsedOnlyMovesForward(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()
	_, k, _ := s.Create(ctx, params("alice", "ci"))
	if err := s.FlushLastUsed(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.FlushLastUsed(ctx, map[string]apikeys.Use{k.ID: {At: t0.Add(time.Minute), IP: "10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.FlushLastUsed(ctx, map[string]apikeys.Use{k.ID: {At: t0, IP: "10.0.0.2"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, k.ID)
	if !got.LastUsedAt.Equal(t0.Add(time.Minute)) || got.LastUsedIP != "10.0.0.1" {
		t.Fatalf("last used = %v %q", got.LastUsedAt, got.LastUsedIP)
	}
}

func secretOf(plaintext string) string { return plaintext[strings.LastIndex(plaintext, "_")+1:] }

func TestNewRequiresRegistry(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "cp.db"))
	if _, err := New(db, Options{}); err == nil {
		t.Fatal("New without a registry succeeded")
	}
}

// A collision on the generated id retries with the next random bytes. The
// reader yields: id A + secret X, then id A again (collides) + secret Z, then
// id B + secret Y.
func TestStoreCreateRetriesOnIDCollision(t *testing.T) {
	blk := func(idByte, secByte byte) []byte {
		b := make([]byte, 0, 40)
		for range 8 {
			b = append(b, idByte)
		}
		for range 32 {
			b = append(b, secByte)
		}
		return b
	}
	var stream []byte
	stream = append(stream, blk(0x0a, 1)...)
	stream = append(stream, blk(0x0a, 2)...)
	stream = append(stream, blk(0x0b, 3)...)
	path := filepath.Join(t.TempDir(), "cp.db")
	s := newStoreAt(t, path, clocktest.NewFake(t0), bytes.NewReader(stream))
	ctx := context.Background()
	_, k1, err := s.Create(ctx, params("alice", "one"))
	if err != nil {
		t.Fatal(err)
	}
	_, k2, err := s.Create(ctx, params("alice", "two"))
	if err != nil {
		t.Fatalf("Create after an id collision: %v", err)
	}
	if k1.ID != "0a0a0a0a0a0a0a0a" || k2.ID != "0b0b0b0b0b0b0b0b" {
		t.Fatalf("ids = %s, %s", k1.ID, k2.ID)
	}
	if n := count(t, s.db); n != 2 {
		t.Fatalf("rows = %d", n)
	}
}

func TestStoreCreateFailsWhenRandomSourceRepeats(t *testing.T) {
	blk := bytes.Repeat([]byte{7}, 40)
	s := newStoreAt(t, filepath.Join(t.TempDir(), "cp.db"), clocktest.NewFake(t0),
		bytes.NewReader(bytes.Repeat(blk, 20)))
	if _, _, err := s.Create(context.Background(), params("alice", "one")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(context.Background(), params("alice", "two")); err == nil {
		t.Fatal("Create succeeded with a random source that only repeats")
	}
}

func TestStoreChangePayloads(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()
	var log []apikeys.Change
	s.OnChange(func(c apikeys.Change) { log = append(log, c) })
	_, k, _ := s.Create(ctx, params("alice", "a"))
	_ = s.Revoke(ctx, k.ID, "admin")
	_, _ = s.RevokeByOwner(ctx, "https://idp", "alice", "admin")
	_, _, _ = s.Create(ctx, params("alice", "b"))
	_, _ = s.RevokeByOwner(ctx, "https://idp", "alice", "admin2")
	if len(log) != 4 {
		t.Fatalf("changes = %+v", log)
	}
	if len(log[1].RevokedIDs) != 1 || log[1].RevokedIDs[0] != k.ID || log[1].RevokedBy != "admin" || log[1].RevokedAt.IsZero() {
		t.Fatalf("revoke change = %+v", log[1])
	}
	if log[3].OwnerSub != "alice" || log[3].OwnerIss != "https://idp" || log[3].RevokedBy != "admin2" {
		t.Fatalf("owner change = %+v", log[3])
	}
}

// failingStore wraps a Store; it fails Snapshot while fail is set and counts
// every call, so tests can prove the request path touches no SQL.
type failingStore struct {
	apikeys.Store
	fail  atomic.Bool
	calls atomic.Int64
	flush atomic.Int64
}

func (f *failingStore) Snapshot(ctx context.Context) (apikeys.Snapshot, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return apikeys.Snapshot{}, errors.New("injected reload failure")
	}
	return f.Store.Snapshot(ctx)
}

func (f *failingStore) DataVersion(ctx context.Context) (int64, error) {
	f.calls.Add(1)
	return f.Store.DataVersion(ctx)
}

func (f *failingStore) FlushLastUsed(ctx context.Context, u map[string]apikeys.Use) error {
	f.calls.Add(1)
	f.flush.Add(1)
	return f.Store.FlushLastUsed(ctx, u)
}

func startIndex(t *testing.T, st apikeys.Store, clk *clocktest.Fake) *apikeys.Index {
	t.Helper()
	ix, err := apikeys.NewIndex(context.Background(), st, apikeys.IndexOptions{Now: clk.Now, After: clk.After, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

// drive advances one poll interval at a time, waiting for Run to finish a poll
// after each step, until cond holds. The deadline is only a safety net.
func drive(t *testing.T, clk *clocktest.Fake, ix *apikeys.Index, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		before := ix.Polls()
		for ix.Polls() == before {
			clk.Advance(apikeys.DefaultPollInterval)
			end := time.Now().Add(50 * time.Millisecond)
			for ix.Polls() == before && time.Now().Before(end) {
				runtime.Gosched()
			}
		}
	}
}

func TestIndexCrossProcessReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	clk := clocktest.NewFake(t0)
	storeA := newStoreAt(t, path, clk, testRand(2))
	storeB := newStoreAt(t, path, clk, testRand(3))
	fs := &failingStore{Store: storeA}
	ix := startIndex(t, fs, clk)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ix.Run(ctx) }()
	t.Cleanup(func() { cancel(); wg.Wait() })

	ptOne, k1, err := storeB.Create(ctx, params("alice", "one")) // written by "another process"
	if err != nil {
		t.Fatal(err)
	}
	ptTwo, k2, _ := storeB.Create(ctx, params("alice", "two"))
	ptThree, _, _ := storeB.Create(ctx, params("alice", "three"))
	ok := func(pt string) bool { _, _, err := ix.Authenticate(pt, clk.Now()); return err == nil }
	drive(t, clk, ix, func() bool { return ok(ptOne) && ok(ptTwo) && ok(ptThree) })

	if err := storeB.Revoke(ctx, k1.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	drive(t, clk, ix, func() bool { return !ok(ptOne) })
	if _, r, _ := ix.Authenticate(ptOne, clk.Now()); r != apikeys.ReasonRevoked {
		t.Fatalf("reason = %q", r)
	}

	// Reload now fails: the revocation already loaded stays in force, the key
	// revoked meanwhile is invisible until the reload works again.
	fs.fail.Store(true)
	if err := storeB.Revoke(ctx, k2.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	before := fs.calls.Load()
	drive(t, clk, ix, func() bool { return fs.calls.Load() >= before+4 })
	if ok(ptOne) {
		t.Fatal("a failed reload re-admitted a revoked key")
	}
	if !ok(ptTwo) {
		t.Fatal("expected the last good index to still hold key two")
	}
	fs.fail.Store(false)
	drive(t, clk, ix, func() bool { return !ok(ptTwo) })
	if ok(ptOne) || !ok(ptThree) {
		t.Fatal("recovered index is wrong")
	}
}

// With a real database, a local Revoke stops the key at once even when the
// follow-up reload fails.
func TestIndexLocalRevokeFailClosed(t *testing.T) {
	s, clk, _ := newStore(t)
	fs := &failingStore{Store: s}
	ix := startIndex(t, fs, clk)
	ctx := context.Background()
	pt, k, _ := s.Create(ctx, params("alice", "ci"))
	if _, _, err := ix.Authenticate(pt, clk.Now()); err != nil {
		t.Fatal(err)
	}
	fs.fail.Store(true)
	if err := s.Revoke(ctx, k.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, r, _ := ix.Authenticate(pt, clk.Now()); r != apikeys.ReasonRevoked {
		t.Fatalf("reason = %q after a revoke whose reload failed", r)
	}
}

func TestIndexNoSQLOnRequestPath(t *testing.T) {
	s, clk, _ := newStore(t)
	fs := &failingStore{Store: s}
	ix := startIndex(t, fs, clk)
	ctx := context.Background()
	pt, k, _ := s.Create(ctx, params("alice", "ci"))
	fs.calls.Store(0)
	for range 1000 {
		if _, _, err := ix.Authenticate(pt, clk.Now()); err != nil {
			t.Fatal(err)
		}
		ix.MarkUsed(k.ID, clk.Now(), "10.0.0.9")
	}
	if n := fs.calls.Load(); n != 0 {
		t.Fatalf("%d store calls on the request path, want 0", n)
	}
	if got, _ := s.Get(ctx, k.ID); !got.LastUsedAt.IsZero() {
		t.Fatal("last_used_at written before the flush")
	}
	if err := ix.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ix.Flush(ctx); err != nil { // nothing pending: no second write
		t.Fatal(err)
	}
	if fs.flush.Load() != 1 {
		t.Fatalf("flush writes = %d, want 1", fs.flush.Load())
	}
	got, _ := s.Get(ctx, k.ID)
	if !got.LastUsedAt.Equal(t0) || got.LastUsedIP != "10.0.0.9" {
		t.Fatalf("last used = %v %q", got.LastUsedAt, got.LastUsedIP)
	}
}
