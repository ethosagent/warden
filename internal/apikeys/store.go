package apikeys

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
)

// MigrationID is the cpstate migration that creates the api_keys table.
const MigrationID = "api_keys/0001"

// TTL and field bounds.
const (
	// MinTTL is the shortest lifetime Create accepts.
	MinTTL = time.Hour

	maxNameChars        = 64
	maxDescriptionChars = 512
)

// Errors returned by a Store.
var (
	// ErrInvalidTTL: ttl below MinTTL or above the caller's maxTTL.
	ErrInvalidTTL = errors.New("apikeys: ttl out of range")
	// ErrTooMany: the owner already has the maximum number of active keys.
	ErrTooMany = errors.New("apikeys: owner already has the maximum number of active keys")
	// ErrNameTaken: the owner already has a key (active or revoked) with this name.
	ErrNameTaken = errors.New("apikeys: key name already in use for this owner")
	// ErrNotFound: no key has this id.
	ErrNotFound = errors.New("apikeys: key not found")
	// ErrInvalidInput: a name, owner, scope list, actor or limit is not acceptable.
	ErrInvalidInput = errors.New("apikeys: invalid input")
)

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

// Key is a key's metadata. It never holds the plaintext, the secret or the
// stored hash. Zero times mean "unset". Slices are shared with the Index's
// snapshot: treat them as read-only.
type Key struct {
	ID          string
	Name        string
	Description string
	// Owner is the human the key acts for, as recorded when it was created.
	OwnerIss    string
	OwnerSub    string
	OwnerEmail  string
	OwnerGroups []string
	Scopes      []Scope
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastUsedAt  time.Time
	LastUsedIP  string
	RevokedAt   time.Time
	RevokedBy   string
}

// Status of a key at an instant.
type Status string

// Key statuses.
const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

// StatusAt reports the key's status at now; revoked wins over expired.
func (k Key) StatusAt(now time.Time) Status {
	switch {
	case !k.RevokedAt.IsZero():
		return StatusRevoked
	case !now.Before(k.ExpiresAt):
		return StatusExpired
	}
	return StatusActive
}

// HasScope reports whether the key was created with s.
func (k Key) HasScope(s Scope) bool {
	for _, have := range k.Scopes {
		if have == s {
			return true
		}
	}
	return false
}

// String prints the id and name only, so %v and %+v are log-safe.
func (k Key) String() string { return fmt.Sprintf("api key id=%s name=%q", k.ID, k.Name) }

// GoString keeps %#v as log-safe as %v (no owner email or groups).
func (k Key) GoString() string { return k.String() }

// LogValue keeps slog output to the id, name and scopes.
func (k Key) LogValue() slog.Value {
	names := make([]string, len(k.Scopes))
	for i, s := range k.Scopes {
		names[i] = string(s)
	}
	return slog.GroupValue(slog.String("id", k.ID), slog.String("name", k.Name),
		slog.String("scopes", strings.Join(names, ",")))
}

// CreateParams describes a key to mint. MaxTTL and MaxActive come from the
// caller's configuration (console.apiKeys), not from this package.
type CreateParams struct {
	Name        string
	Description string
	OwnerIss    string
	OwnerSub    string
	OwnerEmail  string
	OwnerGroups []string
	Scopes      []Scope
	// TTL is the key's lifetime: MinTTL <= TTL <= MaxTTL.
	TTL    time.Duration
	MaxTTL time.Duration
	// MaxActive is the most unrevoked, unexpired keys the owner may hold,
	// counting the new one. It must be positive.
	MaxActive int
}

// ListFilter narrows List. The zero value lists every key, oldest first.
type ListFilter struct {
	// OwnerSub, when set, lists only that owner's keys.
	OwnerSub string
	// ActiveOnly drops revoked and expired keys.
	ActiveOnly bool
	// ExpiresBefore, when non-zero, keeps only unrevoked keys expiring before
	// it that have not expired yet (the expiry-warning query).
	ExpiresBefore time.Time
}

// Use is one key's latest use, recorded in memory and flushed in batches.
type Use struct {
	At time.Time
	IP string
}

// Snapshot is every row of the table plus the data_version it was read at,
// what an Index loads from. It is opaque so no caller can read a stored hash.
type Snapshot struct {
	version int64
	entries []entry
}

type entry struct {
	key  Key
	hash [sha256.Size]byte
}

// Add appends a key and the sha256 of its secret. It is how a Store
// implementation builds a Snapshot.
func (s *Snapshot) Add(k Key, secretHash [sha256.Size]byte) {
	s.entries = append(s.entries, entry{key: k, hash: secretHash})
}

// SetVersion records the change counter the snapshot was read at.
func (s *Snapshot) SetVersion(v int64) { s.version = v }

// Len is the number of keys in the snapshot.
func (s *Snapshot) Len() int { return len(s.entries) }

// Store persists keys. A later Postgres backend implements the same interface.
// No method returns a plaintext or a stored hash except Snapshot, which hands
// its hashes to an Index in an opaque value.
type Store interface {
	// Create mints a key and returns its plaintext, which no later call returns.
	Create(ctx context.Context, p CreateParams) (plaintext string, k Key, err error)
	Get(ctx context.Context, id string) (Key, error)
	List(ctx context.Context, f ListFilter) ([]Key, error)
	// Revoke soft-deletes a key. It is idempotent: a revoked key keeps its first
	// revoked_at and revoked_by. An unknown id is ErrNotFound.
	Revoke(ctx context.Context, id, by string) error
	// RevokeByOwner revokes every unrevoked key of one owner and returns how many.
	RevokeByOwner(ctx context.Context, iss, sub, by string) (int, error)
	// FlushLastUsed writes the given last-use values in one transaction.
	FlushLastUsed(ctx context.Context, uses map[string]Use) error
	// Snapshot reads every row for an Index.
	Snapshot(ctx context.Context) (Snapshot, error)
	// DataVersion is a counter that changes when another process commits to
	// the same database (not for this process's own writes).
	DataVersion(ctx context.Context) (int64, error)
	// OnChange registers fn, called after this process commits a Create, Revoke
	// or RevokeByOwner that changed a row, outside any lock.
	OnChange(fn func())
}

// SQLiteStore is the Store on the control plane's cpstate database.
type SQLiteStore struct {
	db  *sql.DB
	clk clock.Clock
	reg *Registry

	mu    sync.Mutex
	hooks []func()
}

var _ Store = (*SQLiteStore)(nil)

// NewSQLiteStore builds a store over db, which must have been opened with the
// api_keys migration enabled. reg decides which scopes Create accepts (nil: the P2 scopes). A nil
// clk uses the real clock.
func NewSQLiteStore(db *cpstate.DB, clk clock.Clock, reg *Registry) *SQLiteStore {
	if clk == nil {
		clk = clock.Real()
	}
	if reg == nil {
		reg = NewP2Registry()
	}
	return &SQLiteStore{db: db.SQL(), clk: clk, reg: reg}
}

// OnChange implements Store.
func (s *SQLiteStore) OnChange(fn func()) {
	s.mu.Lock()
	s.hooks = append(s.hooks, fn)
	s.mu.Unlock()
}

func (s *SQLiteStore) changed() {
	s.mu.Lock()
	hooks := append([]func(){}, s.hooks...)
	s.mu.Unlock()
	for _, fn := range hooks {
		fn()
	}
}

func validateText(field, v string, min, max int) error {
	n := utf8.RuneCountInString(v)
	if !utf8.ValidString(v) || n < min || n > max {
		return fmt.Errorf("%w: %s must be %d-%d characters", ErrInvalidInput, field, min, max)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s has control characters", ErrInvalidInput, field)
		}
	}
	return nil
}

func (p CreateParams) validate(reg *Registry) error {
	if err := validateText("name", p.Name, 1, maxNameChars); err != nil {
		return err
	}
	if err := validateText("description", p.Description, 0, maxDescriptionChars); err != nil {
		return err
	}
	if p.OwnerIss == "" || p.OwnerSub == "" {
		return fmt.Errorf("%w: owner issuer and subject are required", ErrInvalidInput)
	}
	if p.MaxActive <= 0 {
		return fmt.Errorf("%w: maximum active keys must be positive", ErrInvalidInput)
	}
	if len(p.Scopes) == 0 {
		return ErrNoScopes
	}
	seen := make(map[Scope]struct{}, len(p.Scopes))
	for _, sc := range p.Scopes {
		if _, ok := reg.Lookup(sc); !ok {
			return fmt.Errorf("%w: %q", ErrUnknownScope, string(sc))
		}
		if _, dup := seen[sc]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateScope, string(sc))
		}
		seen[sc] = struct{}{}
	}
	if p.TTL < MinTTL || p.TTL > p.MaxTTL {
		return fmt.Errorf("%w: ttl %s outside [%s, %s]", ErrInvalidTTL, p.TTL, MinTTL, p.MaxTTL)
	}
	return nil
}

// Create implements Store. The active-key cap and the insert are one
// statement, so two processes cannot both slip past the count; a collision on
// the generated id retries with a fresh one.
func (s *SQLiteStore) Create(ctx context.Context, p CreateParams) (string, Key, error) {
	if err := p.validate(s.reg); err != nil {
		return "", Key{}, err
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
		g, err := Generate(func(id string) bool { return s.exists(ctx, id) })
		if err != nil {
			return "", Key{}, err
		}
		res, err := s.db.ExecContext(ctx,
			`INSERT INTO api_keys (id, name, description, owner_iss, owner_sub, owner_email,
			   owner_groups_json, scopes_json, secret_hash, created_at, expires_at)
			 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			 WHERE (SELECT COUNT(*) FROM api_keys
			        WHERE owner_sub = ? AND revoked_at IS NULL AND expires_at > ?) < ?`,
			g.ID, p.Name, p.Description, p.OwnerIss, p.OwnerSub, p.OwnerEmail,
			string(groupsJSON), string(scopesJSON), g.hash[:], now.Unix(), exp.Unix(),
			p.OwnerSub, now.Unix(), p.MaxActive)
		if err != nil {
			switch msg := err.Error(); {
			case strings.Contains(msg, "api_keys.owner_sub"):
				return "", Key{}, ErrNameTaken
			case strings.Contains(msg, "api_keys.id"), strings.Contains(msg, "api_keys.secret_hash"):
				continue // id (or, absurdly, secret) collision: mint again
			}
			return "", Key{}, fmt.Errorf("apikeys: insert: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return "", Key{}, fmt.Errorf("apikeys: insert: %w", err)
		}
		if n == 0 {
			return "", Key{}, ErrTooMany
		}
		k := Key{
			ID: g.ID, Name: p.Name, Description: p.Description,
			OwnerIss: p.OwnerIss, OwnerSub: p.OwnerSub, OwnerEmail: p.OwnerEmail,
			OwnerGroups: append([]string{}, groups...), Scopes: append([]Scope{}, p.Scopes...),
			CreatedAt: time.Unix(now.Unix(), 0), ExpiresAt: time.Unix(exp.Unix(), 0),
		}
		s.changed()
		return g.Plaintext, k, nil
	}
	return "", Key{}, errors.New("apikeys: could not allocate a unique key id")
}

func (s *SQLiteStore) exists(ctx context.Context, id string) bool {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM api_keys WHERE id = ?`, id).Scan(&one)
	return err == nil // a failed lookup is caught by the insert's PRIMARY KEY
}

const keyColumns = `id, name, description, owner_iss, owner_sub, owner_email, owner_groups_json,
  scopes_json, secret_hash, created_at, expires_at, last_used_at, last_used_ip, revoked_at, revoked_by`

func scanKey(sc interface{ Scan(...any) error }) (entry, error) {
	var (
		e                      entry
		groupsJSON, scopesJSON string
		hash                   []byte
		created, expires       int64
		lastUsed, revoked      sql.NullInt64
		lastIP, revokedBy      sql.NullString
	)
	k := &e.key
	if err := sc.Scan(&k.ID, &k.Name, &k.Description, &k.OwnerIss, &k.OwnerSub, &k.OwnerEmail,
		&groupsJSON, &scopesJSON, &hash, &created, &expires, &lastUsed, &lastIP, &revoked, &revokedBy); err != nil {
		return entry{}, err
	}
	if len(hash) != sha256.Size {
		return entry{}, fmt.Errorf("apikeys: row %s has a malformed hash", k.ID)
	}
	copy(e.hash[:], hash)
	if err := json.Unmarshal([]byte(groupsJSON), &k.OwnerGroups); err != nil {
		return entry{}, fmt.Errorf("apikeys: row %s groups: %w", k.ID, err)
	}
	var names []string
	if err := json.Unmarshal([]byte(scopesJSON), &names); err != nil {
		return entry{}, fmt.Errorf("apikeys: row %s scopes: %w", k.ID, err)
	}
	for _, n := range names {
		k.Scopes = append(k.Scopes, Scope(n))
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
	return e, nil
}

// Get implements Store.
func (s *SQLiteStore) Get(ctx context.Context, id string) (Key, error) {
	e, err := scanKey(s.db.QueryRowContext(ctx, `SELECT `+keyColumns+` FROM api_keys WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	if err != nil {
		return Key{}, fmt.Errorf("apikeys: get: %w", err)
	}
	return e.key, nil
}

// List implements Store: oldest first, last-used values as last flushed.
func (s *SQLiteStore) List(ctx context.Context, f ListFilter) ([]Key, error) {
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
	var out []Key
	for rows.Next() {
		e, err := scanKey(rows)
		if err != nil {
			return nil, fmt.Errorf("apikeys: list: %w", err)
		}
		out = append(out, e.key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("apikeys: list: %w", err)
	}
	return out, nil
}

// Revoke implements Store.
func (s *SQLiteStore) Revoke(ctx context.Context, id, by string) error {
	if by == "" {
		return fmt.Errorf("%w: revoker is required", ErrInvalidInput)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`,
		s.clk.Now().Unix(), by, id)
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
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("apikeys: revoke: %w", err)
		}
		return nil // already revoked
	}
	s.changed()
	return nil
}

// RevokeByOwner implements Store.
func (s *SQLiteStore) RevokeByOwner(ctx context.Context, iss, sub, by string) (int, error) {
	if by == "" || iss == "" || sub == "" {
		return 0, fmt.Errorf("%w: issuer, subject and revoker are required", ErrInvalidInput)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = ?, revoked_by = ?
		 WHERE owner_iss = ? AND owner_sub = ? AND revoked_at IS NULL`,
		s.clk.Now().Unix(), by, iss, sub)
	if err != nil {
		return 0, fmt.Errorf("apikeys: revoke by owner: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("apikeys: revoke by owner: %w", err)
	}
	if n > 0 {
		s.changed()
	}
	return int(n), nil
}

// FlushLastUsed implements Store. A value only moves last_used_at forward.
func (s *SQLiteStore) FlushLastUsed(ctx context.Context, uses map[string]Use) (err error) {
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

// DataVersion implements Store.
func (s *SQLiteStore) DataVersion(ctx context.Context) (int64, error) {
	var v int64
	if err := s.db.QueryRowContext(ctx, `PRAGMA data_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("apikeys: data_version: %w", err)
	}
	return v, nil
}

// Snapshot implements Store. data_version is read before the rows, so a commit
// that lands in between is picked up by the next poll.
func (s *SQLiteStore) Snapshot(ctx context.Context) (Snapshot, error) {
	v, err := s.DataVersion(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+keyColumns+` FROM api_keys`)
	if err != nil {
		return Snapshot{}, fmt.Errorf("apikeys: snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	snap := Snapshot{version: v}
	for rows.Next() {
		e, err := scanKey(rows)
		if err != nil {
			return Snapshot{}, err
		}
		snap.entries = append(snap.entries, e)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("apikeys: snapshot: %w", err)
	}
	return snap, nil
}
