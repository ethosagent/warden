// Package sqlitestore is the apikeys.Store on the control plane's cpstate
// SQLite database. It owns the api_keys table and its migration.
package sqlitestore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
)

// MigrationID is the cpstate migration that creates the api_keys table.
const MigrationID = "api_keys/0001"

// maxIDAttempts bounds Create's retries on an id collision. A 64-bit random id
// colliding even once is astronomically unlikely, so reaching the bound means
// the random source is broken.
const maxIDAttempts = 8

// Migrations returns the api_keys cpstate migrations. They are Optional, so a
// control plane with API keys off creates no table; the feature turns them on
// for its own Open with cpstate.Enable(Migrations(), MigrationID). A caller
// that opens the file for any other reason (the offline CLI, a backup check)
// must pass these too, so the downgrade guard knows the ID.
func Migrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID:       MigrationID,
		Optional: true,
		SQL: `CREATE TABLE api_keys (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  description       TEXT NOT NULL DEFAULT '',
  owner_iss         TEXT NOT NULL,
  owner_sub         TEXT NOT NULL,
  owner_email       TEXT NOT NULL DEFAULT '',
  owner_groups_json TEXT NOT NULL DEFAULT '[]',
  scopes_json       TEXT NOT NULL,
  secret_hash       BLOB NOT NULL UNIQUE,
  created_at        INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  last_used_at      INTEGER NULL,
  last_used_ip      TEXT NULL,
  revoked_at        INTEGER NULL,
  revoked_by        TEXT NULL,
  UNIQUE (owner_sub, name)
);
CREATE INDEX api_keys_owner_sub ON api_keys (owner_sub);
CREATE INDEX api_keys_expires_at ON api_keys (expires_at);`,
	}}
}

// Options configures a Store.
type Options struct {
	// Registry decides which scopes Create accepts. It is required.
	Registry *apikeys.Registry
	// Clock is the time source; nil uses the real clock.
	Clock clock.Clock
	// Rand is the entropy source for new keys; nil uses crypto/rand. Tests
	// inject a deterministic reader.
	Rand io.Reader
}

// SQLiteStore is the apikeys.Store backed by cpstate's SQLite database.
type SQLiteStore struct {
	db   *sql.DB
	clk  clock.Clock
	reg  *apikeys.Registry
	rand io.Reader

	mu    sync.Mutex
	hooks []func(apikeys.Change)
}

var _ apikeys.Store = (*SQLiteStore)(nil)

// New builds a store over db, which must have been opened with the api_keys
// migration enabled.
func New(db *cpstate.DB, o Options) (*SQLiteStore, error) {
	if o.Registry == nil {
		return nil, errors.New("apikeys: a scope registry is required")
	}
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	return &SQLiteStore{db: db.SQL(), clk: o.Clock, reg: o.Registry, rand: o.Rand}, nil
}

// OnChange implements apikeys.Store.
func (s *SQLiteStore) OnChange(fn func(apikeys.Change)) {
	s.mu.Lock()
	s.hooks = append(s.hooks, fn)
	s.mu.Unlock()
}

func (s *SQLiteStore) changed(c apikeys.Change) {
	s.mu.Lock()
	hooks := append([]func(apikeys.Change){}, s.hooks...)
	s.mu.Unlock()
	for _, fn := range hooks {
		fn(c)
	}
}

// sqliteCode returns the extended result code of a driver error, or 0.
func sqliteCode(err error) int {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code()
	}
	return 0
}

// Create implements apikeys.Store. The active-key cap and the insert are one
// statement, so two processes cannot both slip past the count. The cap and the
// name rule key on owner_sub only, as the feature design specifies. A collision
// on the generated id retries with a fresh one.
func (s *SQLiteStore) Create(ctx context.Context, p apikeys.CreateParams) (string, apikeys.Key, error) {
	if err := p.Validate(s.reg); err != nil {
		return "", apikeys.Key{}, err
	}
	now := s.clk.Now()
	exp := now.Add(p.TTL)
	scopes := make([]string, len(p.Scopes))
	for i, sc := range p.Scopes {
		scopes[i] = string(sc)
	}
	scopesJSON, _ := json.Marshal(scopes)
	groups := p.OwnerGroups
	if groups == nil {
		groups = []string{}
	}
	groupsJSON, _ := json.Marshal(groups)

	for range maxIDAttempts {
		g, err := apikeys.Generate(s.rand, nil)
		if err != nil {
			return "", apikeys.Key{}, err
		}
		hash := g.StorageHash()
		res, err := s.db.ExecContext(ctx,
			`INSERT INTO api_keys (id, name, description, owner_iss, owner_sub, owner_email,
			   owner_groups_json, scopes_json, secret_hash, created_at, expires_at)
			 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			 WHERE (SELECT COUNT(*) FROM api_keys
			        WHERE owner_sub = ? AND revoked_at IS NULL AND expires_at > ?) < ?`,
			g.ID, p.Name, p.Description, p.OwnerIss, p.OwnerSub, p.OwnerEmail,
			string(groupsJSON), string(scopesJSON), hash[:], now.Unix(), exp.Unix(),
			p.OwnerSub, now.Unix(), p.MaxActive)
		if err != nil {
			switch sqliteCode(err) {
			case sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
				continue // id collision: mint again
			case sqlite3.SQLITE_CONSTRAINT_UNIQUE:
				// Either (owner_sub, name) or secret_hash. Only the name is a
				// caller error; a duplicate secret hash means a broken random
				// source, so retry.
				if s.nameTaken(ctx, p.OwnerSub, p.Name) {
					return "", apikeys.Key{}, apikeys.ErrNameTaken
				}
				continue
			}
			return "", apikeys.Key{}, fmt.Errorf("apikeys: insert: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return "", apikeys.Key{}, fmt.Errorf("apikeys: insert: %w", err)
		}
		if n == 0 {
			return "", apikeys.Key{}, apikeys.ErrTooMany
		}
		k := apikeys.Key{
			ID: g.ID, Name: p.Name, Description: p.Description,
			OwnerIss: p.OwnerIss, OwnerSub: p.OwnerSub, OwnerEmail: p.OwnerEmail,
			OwnerGroups: append([]string{}, groups...), Scopes: append([]apikeys.Scope{}, p.Scopes...),
			CreatedAt: time.Unix(now.Unix(), 0), ExpiresAt: time.Unix(exp.Unix(), 0),
		}
		s.changed(apikeys.Change{})
		return g.Plaintext, k, nil
	}
	return "", apikeys.Key{}, errors.New("apikeys: could not allocate a unique key id")
}

func (s *SQLiteStore) nameTaken(ctx context.Context, ownerSub, name string) bool {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM api_keys WHERE owner_sub = ? AND name = ?`, ownerSub, name).Scan(&one)
	return err == nil
}

const keyColumns = `id, name, description, owner_iss, owner_sub, owner_email, owner_groups_json,
  scopes_json, secret_hash, created_at, expires_at, last_used_at, last_used_ip, revoked_at, revoked_by`

type row struct {
	key  apikeys.Key
	hash [sha256.Size]byte
}

func scanKey(sc interface{ Scan(...any) error }) (row, error) {
	var (
		r                      row
		groupsJSON, scopesJSON string
		hash                   []byte
		created, expires       int64
		lastUsed, revoked      sql.NullInt64
		lastIP, revokedBy      sql.NullString
	)
	k := &r.key
	if err := sc.Scan(&k.ID, &k.Name, &k.Description, &k.OwnerIss, &k.OwnerSub, &k.OwnerEmail,
		&groupsJSON, &scopesJSON, &hash, &created, &expires, &lastUsed, &lastIP, &revoked, &revokedBy); err != nil {
		return row{}, err
	}
	if len(hash) != sha256.Size {
		return row{}, fmt.Errorf("apikeys: row %s has a malformed hash", k.ID)
	}
	copy(r.hash[:], hash)
	if err := json.Unmarshal([]byte(groupsJSON), &k.OwnerGroups); err != nil {
		return row{}, fmt.Errorf("apikeys: row %s groups: %w", k.ID, err)
	}
	var names []string
	if err := json.Unmarshal([]byte(scopesJSON), &names); err != nil {
		return row{}, fmt.Errorf("apikeys: row %s scopes: %w", k.ID, err)
	}
	for _, n := range names {
		k.Scopes = append(k.Scopes, apikeys.Scope(n))
	}
	k.CreatedAt = time.Unix(created, 0)
	k.ExpiresAt = time.Unix(expires, 0)
	if lastUsed.Valid {
		k.LastUsedAt = time.Unix(lastUsed.Int64, 0)
	}
	k.LastUsedIP = lastIP.String
	if revoked.Valid {
		k.RevokedAt = time.Unix(revoked.Int64, 0)
	}
	k.RevokedBy = revokedBy.String
	return r, nil
}

// Get implements apikeys.Store.
func (s *SQLiteStore) Get(ctx context.Context, id string) (apikeys.Key, error) {
	r, err := scanKey(s.db.QueryRowContext(ctx, `SELECT `+keyColumns+` FROM api_keys WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return apikeys.Key{}, apikeys.ErrNotFound
	}
	if err != nil {
		return apikeys.Key{}, fmt.Errorf("apikeys: get: %w", err)
	}
	return r.key, nil
}

// List implements apikeys.Store: oldest first, last-used values as last flushed.
func (s *SQLiteStore) List(ctx context.Context, f apikeys.ListFilter) ([]apikeys.Key, error) {
	q := `SELECT ` + keyColumns + ` FROM api_keys WHERE 1 = 1`
	var args []any
	now := s.clk.Now().Unix()
	if f.OwnerSub != "" {
		q += ` AND owner_sub = ?`
		args = append(args, f.OwnerSub)
	}
	if f.ActiveOnly {
		q += ` AND revoked_at IS NULL AND expires_at > ?`
		args = append(args, now)
	}
	if !f.ExpiresBefore.IsZero() {
		q += ` AND revoked_at IS NULL AND expires_at > ? AND expires_at < ?`
		args = append(args, now, f.ExpiresBefore.Unix())
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at, id`, args...)
	if err != nil {
		return nil, fmt.Errorf("apikeys: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []apikeys.Key
	for rows.Next() {
		r, err := scanKey(rows)
		if err != nil {
			return nil, fmt.Errorf("apikeys: list: %w", err)
		}
		out = append(out, r.key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("apikeys: list: %w", err)
	}
	return out, nil
}

// Revoke implements apikeys.Store.
func (s *SQLiteStore) Revoke(ctx context.Context, id, by string) error {
	if by == "" {
		return fmt.Errorf("%w: revoker is required", apikeys.ErrInvalidInput)
	}
	at := s.clk.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`,
		at.Unix(), by, id)
	if err != nil {
		return fmt.Errorf("apikeys: revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("apikeys: revoke: %w", err)
	}
	if n == 0 {
		var one int
		err := s.db.QueryRowContext(ctx, `SELECT 1 FROM api_keys WHERE id = ?`, id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return apikeys.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("apikeys: revoke: %w", err)
		}
		return nil // already revoked
	}
	s.changed(apikeys.Change{RevokedIDs: []string{id}, RevokedAt: time.Unix(at.Unix(), 0), RevokedBy: by})
	return nil
}

// RevokeByOwner implements apikeys.Store.
func (s *SQLiteStore) RevokeByOwner(ctx context.Context, iss, sub, by string) (int, error) {
	if by == "" || iss == "" || sub == "" {
		return 0, fmt.Errorf("%w: issuer, subject and revoker are required", apikeys.ErrInvalidInput)
	}
	at := s.clk.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = ?, revoked_by = ?
		 WHERE owner_iss = ? AND owner_sub = ? AND revoked_at IS NULL`,
		at.Unix(), by, iss, sub)
	if err != nil {
		return 0, fmt.Errorf("apikeys: revoke by owner: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("apikeys: revoke by owner: %w", err)
	}
	if n > 0 {
		s.changed(apikeys.Change{OwnerIss: iss, OwnerSub: sub, RevokedAt: time.Unix(at.Unix(), 0), RevokedBy: by})
	}
	return int(n), nil
}

// FlushLastUsed implements apikeys.Store. A value only moves last_used_at forward.
func (s *SQLiteStore) FlushLastUsed(ctx context.Context, uses map[string]apikeys.Use) (err error) {
	if len(uses) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("apikeys: flush last used: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	for id, u := range uses {
		if _, err = tx.ExecContext(ctx,
			`UPDATE api_keys SET last_used_at = ?, last_used_ip = ?
			 WHERE id = ? AND (last_used_at IS NULL OR last_used_at <= ?)`,
			u.At.Unix(), u.IP, id, u.At.Unix()); err != nil {
			return fmt.Errorf("apikeys: flush last used: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("apikeys: flush last used: %w", err)
	}
	return nil
}

// DataVersion implements apikeys.Store. PRAGMA data_version is per connection
// and changes only when a different connection commits; cpstate opens the
// database with a single connection (SetMaxOpenConns(1)), so the value read here
// is always on that one connection and never reflects this store's own writes.
// Local writes reach the Index through OnChange instead.
func (s *SQLiteStore) DataVersion(ctx context.Context) (int64, error) {
	var v int64
	if err := s.db.QueryRowContext(ctx, `PRAGMA data_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("apikeys: data_version: %w", err)
	}
	return v, nil
}

// Snapshot implements apikeys.Store. data_version is read before the rows, so a
// commit that lands in between is picked up by the next poll.
func (s *SQLiteStore) Snapshot(ctx context.Context) (apikeys.Snapshot, error) {
	var snap apikeys.Snapshot
	v, err := s.DataVersion(ctx)
	if err != nil {
		return snap, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+keyColumns+` FROM api_keys`)
	if err != nil {
		return snap, fmt.Errorf("apikeys: snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	snap.SetVersion(v)
	for rows.Next() {
		r, err := scanKey(rows)
		if err != nil {
			return apikeys.Snapshot{}, err
		}
		snap.Add(r.key, r.hash)
	}
	if err := rows.Err(); err != nil {
		return apikeys.Snapshot{}, fmt.Errorf("apikeys: snapshot: %w", err)
	}
	return snap, nil
}
