package apikeys

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func newStore(t *testing.T) (*SQLiteStore, *clocktest.Fake, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	clk := clocktest.NewFake(t0)
	return NewSQLiteStore(openDB(t, path), clk, NewP2Registry()), clk, path
}

func params(owner, name string) CreateParams {
	return CreateParams{
		Name: name, OwnerIss: "https://idp", OwnerSub: owner, OwnerEmail: owner + "@example.com",
		OwnerGroups: []string{"eng"}, Scopes: []Scope{"policy:read"},
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
	if id, err := Parse(pt); err != nil || id != k.ID {
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
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get unknown = %v", err)
	}

	clk.Advance(time.Minute)
	_, k2, _ := s.Create(ctx, params("bob", "ci"))
	if _, _, err := s.Create(ctx, params("alice", "ci")); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name = %v, want ErrNameTaken", err)
	}
	short := params("alice", "short")
	short.TTL = time.Hour
	_, k3, _ := s.Create(ctx, short)

	all, _ := s.List(ctx, ListFilter{})
	if len(all) != 3 || all[0].ID != k.ID {
		t.Fatalf("List all = %v", all)
	}
	if mine, _ := s.List(ctx, ListFilter{OwnerSub: "bob"}); len(mine) != 1 || mine[0].ID != k2.ID {
		t.Fatalf("List owner = %v", mine)
	}
	soon, _ := s.List(ctx, ListFilter{ExpiresBefore: t0.Add(2 * time.Hour)})
	if len(soon) != 1 || soon[0].ID != k3.ID {
		t.Fatalf("List expiring = %v", soon)
	}
	_ = s.Revoke(ctx, k3.ID, "alice")
	if soon, _ := s.List(ctx, ListFilter{ExpiresBefore: t0.Add(2 * time.Hour)}); len(soon) != 0 {
		t.Fatalf("a revoked key listed as expiring: %v", soon)
	}
	clk.Advance(48 * time.Hour)
	if act, _ := s.List(ctx, ListFilter{ActiveOnly: true}); len(act) != 0 {
		t.Fatalf("ActiveOnly after expiry = %v", act)
	}
	if got, _ := s.Get(ctx, k.ID); got.StatusAt(clk.Now()) != StatusExpired {
		t.Fatalf("status = %v", got.StatusAt(clk.Now()))
	}
	if got, _ := s.Get(ctx, k3.ID); got.StatusAt(clk.Now()) != StatusRevoked {
		t.Fatalf("status = %v", got.StatusAt(clk.Now()))
	}
}

func TestStoreCreateLimits(t *testing.T) {
	s, clk, _ := newStore(t)
	ctx := context.Background()
	db := s.db

	for name, tc := range map[string]struct {
		mut  func(*CreateParams)
		want error
	}{
		"ttl zero":      {func(p *CreateParams) { p.TTL = 0 }, ErrInvalidTTL},
		"ttl below 1h":  {func(p *CreateParams) { p.TTL = time.Hour - time.Second }, ErrInvalidTTL},
		"ttl above max": {func(p *CreateParams) { p.TTL = p.MaxTTL + time.Second }, ErrInvalidTTL},
		"no max":        {func(p *CreateParams) { p.MaxTTL = 0 }, ErrInvalidTTL},
		"unknown scope": {func(p *CreateParams) { p.Scopes = []Scope{"foo:bar"} }, ErrUnknownScope},
		"dup scope":     {func(p *CreateParams) { p.Scopes = []Scope{"policy:read", "policy:read"} }, ErrDuplicateScope},
		"no scopes":     {func(p *CreateParams) { p.Scopes = nil }, ErrNoScopes},
		"empty name":    {func(p *CreateParams) { p.Name = "" }, ErrInvalidInput},
		"long name":     {func(p *CreateParams) { p.Name = strings.Repeat("n", 65) }, ErrInvalidInput},
		"control name":  {func(p *CreateParams) { p.Name = "a\nb" }, ErrInvalidInput},
		"long desc":     {func(p *CreateParams) { p.Description = strings.Repeat("d", 513) }, ErrInvalidInput},
		"no owner":      {func(p *CreateParams) { p.OwnerSub = "" }, ErrInvalidInput},
		"no cap":        {func(p *CreateParams) { p.MaxActive = 0 }, ErrInvalidInput},
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
	if _, _, err := s.Create(ctx, params("alice", "k25")); !errors.Is(err, ErrTooMany) {
		t.Fatalf("26th key = %v, want ErrTooMany", err)
	}
	if n := count(t, db); n != 25 {
		t.Fatalf("rows = %d, want 25", n)
	}
	if _, _, err := s.Create(ctx, params("bob", "k0")); err != nil {
		t.Fatalf("another owner is capped by alice's keys: %v", err)
	}
	keys, _ := s.List(ctx, ListFilter{OwnerSub: "alice"})
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
	s.OnChange(func() { changes++ })
	_, k, _ := s.Create(ctx, params("alice", "a"))
	_, k2, _ := s.Create(ctx, params("alice", "b"))
	_, _, _ = s.Create(ctx, params("bob", "a"))
	if changes != 3 {
		t.Fatalf("OnChange after creates = %d", changes)
	}
	if err := s.Revoke(ctx, k.ID, ""); !errors.Is(err, ErrInvalidInput) {
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
	if changes != 4 {
		t.Fatalf("an idempotent revoke fired OnChange: %d", changes)
	}
	if err := s.Revoke(ctx, "missing", "x"); !errors.Is(err, ErrNotFound) {
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
	if _, err := s.RevokeByOwner(ctx, "", "bob", "x"); !errors.Is(err, ErrInvalidInput) {
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
	secret := pt[sepOffset+1:]

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
	if strings.Contains(out, pt[sepOffset+1:]) || strings.Contains(out, "alice@example.com") {
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
	if err := s.FlushLastUsed(ctx, map[string]Use{k.ID: {At: t0.Add(time.Minute), IP: "10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.FlushLastUsed(ctx, map[string]Use{k.ID: {At: t0, IP: "10.0.0.2"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, k.ID)
	if !got.LastUsedAt.Equal(t0.Add(time.Minute)) || got.LastUsedIP != "10.0.0.1" {
		t.Fatalf("last used = %v %q", got.LastUsedAt, got.LastUsedIP)
	}
}

func openBenchDB(path string) (*cpstate.DB, error) {
	return cpstate.Open(context.Background(), path, cpstate.Enable(Migrations(), MigrationID))
}
