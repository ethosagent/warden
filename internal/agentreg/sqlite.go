package agentreg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// SQLiteStore is the Store on the cpstate database. Open the DB with a
// migration list that includes Migrations (controlplane.StateMigrations does).
// There is no statement that deletes an agent row.
type SQLiteStore struct {
	db    *sql.DB
	clock clock.Clock
	max   int
	cache cache
}

var _ Store = (*SQLiteStore)(nil)

// Option configures NewSQLiteStore.
type Option func(*SQLiteStore)

// WithClock sets the time source for created_at, updated_at and the cache TTL.
func WithClock(c clock.Clock) Option {
	return func(s *SQLiteStore) {
		if c != nil {
			s.clock = c
		}
	}
}

// WithCacheTTL sets how long reads are served from the snapshot; zero or
// negative turns the cache off. The default is DefaultCacheTTL.
func WithCacheTTL(d time.Duration) Option {
	return func(s *SQLiteStore) { s.cache.ttl = d }
}

// NewSQLiteStore builds a store over db.
func NewSQLiteStore(db *cpstate.DB, opts ...Option) *SQLiteStore {
	s := &SQLiteStore{
		db:    db.SQL(),
		clock: clock.Real(),
		max:   config.MaxRegisteredAgents,
		cache: cache{ttl: DefaultCacheTTL},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// queryer is the read surface *sql.DB and *sql.Tx share.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const agentColumns = `id, display_name, owner_iss, owner_sub, owner_email, allowed_groups_json,
    allowed_scopes_json, status, revision, created_at, created_by, updated_at, updated_by`

// Create implements Store.
func (s *SQLiteStore) Create(ctx context.Context, a Agent, actor string) (Agent, error) {
	v, err := Validate(a)
	if err != nil {
		return Agent{}, err
	}
	if err := checkActor(actor); err != nil {
		return Agent{}, err
	}
	now := s.clock.Now().UTC().Round(0)
	v.Revision = 1
	v.CreatedAt, v.UpdatedAt = now, now
	v.CreatedBy, v.UpdatedBy = actor, actor

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Agent{}, fmt.Errorf("agentreg: create %s: begin: %w", v.ID, err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM agents WHERE id = ?`, v.ID).Scan(&n); err != nil {
		return Agent{}, fmt.Errorf("agentreg: create %s: %w", v.ID, err)
	}
	if n > 0 {
		return Agent{}, fmt.Errorf("%w: %s", ErrAlreadyExists, v.ID)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM agents`).Scan(&n); err != nil {
		return Agent{}, fmt.Errorf("agentreg: create %s: %w", v.ID, err)
	}
	if n >= s.max {
		return Agent{}, fmt.Errorf("%w: at most %d agents", ErrRegistryFull, s.max)
	}
	groups, scopes, err := marshalLists(v)
	if err != nil {
		return Agent{}, fmt.Errorf("agentreg: create %s: %w", v.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agents (`+agentColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.ID, v.DisplayName, v.OwnerIss, v.OwnerSub, v.OwnerEmail, groups, scopes, string(v.Status),
		v.Revision, now.UnixNano(), actor, now.UnixNano(), actor); err != nil {
		return Agent{}, fmt.Errorf("agentreg: create %s: %w", v.ID, err)
	}
	if err := insertKeys(ctx, tx, v); err != nil {
		return Agent{}, err
	}
	if err := tx.Commit(); err != nil {
		return Agent{}, fmt.Errorf("agentreg: create %s: commit: %w", v.ID, err)
	}
	s.cache.invalidate()
	return clone(v), nil
}

// Get implements Store.
func (s *SQLiteStore) Get(ctx context.Context, id string) (Agent, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return Agent{}, err
	}
	a, ok := snap.byID[id]
	if !ok {
		return Agent{}, ErrNotFound
	}
	return clone(a), nil
}

// List implements Store.
func (s *SQLiteStore) List(ctx context.Context) ([]Agent, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, len(snap.list))
	for i, a := range snap.list {
		out[i] = clone(a)
	}
	return out, nil
}

// snapshot serves the cache or reads through to the database.
func (s *SQLiteStore) snapshot(ctx context.Context) (snapshot, error) {
	if snap, ok := s.cache.get(s.clock.Now()); ok {
		return snap, nil
	}
	gen := s.cache.generation()
	list, err := loadAll(ctx, s.db)
	if err != nil {
		return snapshot{}, err
	}
	s.cache.put(gen, s.clock.Now(), list)
	byID := make(map[string]Agent, len(list))
	for _, a := range list {
		byID[a.ID] = a
	}
	return snapshot{byID: byID, list: list}, nil
}

// Update implements Store.
func (s *SQLiteStore) Update(ctx context.Context, a Agent, actor string) (Agent, error) {
	if err := checkActor(actor); err != nil {
		return Agent{}, err
	}
	if err := idErr(a.ID); err != nil {
		return Agent{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Agent{}, fmt.Errorf("agentreg: update %s: begin: %w", a.ID, err)
	}
	defer func() { _ = tx.Rollback() }()
	cur, err := loadOne(ctx, tx, a.ID)
	if err != nil {
		return Agent{}, err
	}
	// Status is not part of an update: SetStatus owns it, so the activity
	// check below runs against the status the agent really has.
	a.Status = cur.Status
	v, err := Validate(a)
	if err != nil {
		return Agent{}, err
	}
	if a.Revision != cur.Revision {
		return Agent{}, fmt.Errorf("%w: %s", ErrConflict, a.ID)
	}
	now := s.clock.Now().UTC().Round(0)
	groups, scopes, err := marshalLists(v)
	if err != nil {
		return Agent{}, fmt.Errorf("agentreg: update %s: %w", v.ID, err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE agents SET display_name = ?, owner_iss = ?, owner_sub = ?, owner_email = ?,
        allowed_groups_json = ?, allowed_scopes_json = ?, revision = revision + 1, updated_at = ?, updated_by = ?
        WHERE id = ? AND revision = ?`,
		v.DisplayName, v.OwnerIss, v.OwnerSub, v.OwnerEmail, groups, scopes, now.UnixNano(), actor, v.ID, a.Revision)
	if err != nil {
		return Agent{}, fmt.Errorf("agentreg: update %s: %w", v.ID, err)
	}
	if err := requireOneRow(res, v.ID); err != nil {
		return Agent{}, err
	}
	// The key set is replaced as a whole inside the same transaction; the
	// agent row itself is never deleted.
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_keys WHERE agent_id = ?`, v.ID); err != nil {
		return Agent{}, fmt.Errorf("agentreg: update %s: %w", v.ID, err)
	}
	if err := insertKeys(ctx, tx, v); err != nil {
		return Agent{}, err
	}
	out, err := loadOne(ctx, tx, v.ID)
	if err != nil {
		return Agent{}, err
	}
	if err := tx.Commit(); err != nil {
		return Agent{}, fmt.Errorf("agentreg: update %s: commit: %w", v.ID, err)
	}
	s.cache.invalidate()
	return out, nil
}

// SetStatus implements Store.
func (s *SQLiteStore) SetStatus(ctx context.Context, id string, status Status, revision int64, actor string) (Agent, error) {
	if err := idErr(id); err != nil {
		return Agent{}, err
	}
	if !status.Valid() {
		return Agent{}, invalid("status", "must be active or disabled")
	}
	if err := checkActor(actor); err != nil {
		return Agent{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Agent{}, fmt.Errorf("agentreg: set status %s: begin: %w", id, err)
	}
	defer func() { _ = tx.Rollback() }()
	cur, err := loadOne(ctx, tx, id)
	if err != nil {
		return Agent{}, err
	}
	if revision != cur.Revision {
		return Agent{}, fmt.Errorf("%w: %s", ErrConflict, id)
	}
	if status == StatusActive && len(cur.AllowedGroups) == 0 {
		return Agent{}, invalid("allowed_groups", "an active agent needs at least one group")
	}
	res, err := tx.ExecContext(ctx, `UPDATE agents SET status = ?, revision = revision + 1, updated_at = ?, updated_by = ?
        WHERE id = ? AND revision = ?`,
		string(status), s.clock.Now().UTC().UnixNano(), actor, id, revision)
	if err != nil {
		return Agent{}, fmt.Errorf("agentreg: set status %s: %w", id, err)
	}
	if err := requireOneRow(res, id); err != nil {
		return Agent{}, err
	}
	out, err := loadOne(ctx, tx, id)
	if err != nil {
		return Agent{}, err
	}
	if err := tx.Commit(); err != nil {
		return Agent{}, fmt.Errorf("agentreg: set status %s: commit: %w", id, err)
	}
	s.cache.invalidate()
	return out, nil
}

func idErr(id string) error {
	if err := agentid.ValidID(id); err != nil {
		return invalid("id", "must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
	}
	return nil
}

// requireOneRow turns a compare-and-swap that matched nothing into
// ErrConflict (the row was read in this transaction, so it exists).
func requireOneRow(res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("agentreg: %s: %w", id, err)
	}
	if n != 1 {
		return fmt.Errorf("%w: %s", ErrConflict, id)
	}
	return nil
}

func marshalLists(a Agent) (groups, scopes string, err error) {
	g, err := json.Marshal(nonNil(a.AllowedGroups))
	if err != nil {
		return "", "", err
	}
	sc, err := json.Marshal(nonNil(a.AllowedScopes))
	if err != nil {
		return "", "", err
	}
	return string(g), string(sc), nil
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// insertKeys binds each of a's keys, refusing a thumbprint another agent
// holds. The unique primary key is the backstop for a writer in another
// process; the lookup first gives the precise error.
func insertKeys(ctx context.Context, tx *sql.Tx, a Agent) error {
	for _, k := range a.Keys {
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT agent_id FROM agent_keys WHERE jkt = ?`, k.JKT).Scan(&owner)
		switch {
		case err == nil && owner != a.ID:
			return fmt.Errorf("%w: agent %s kid %s jkt %s (prefix)", ErrKeyInUse, a.ID, k.KID, thumbprintPrefixOf(k.JKT))
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("agentreg: agent %s: %w", a.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO agent_keys (jkt, agent_id, kid, alg, jwk_json) VALUES (?,?,?,?,?)`,
			k.JKT, a.ID, k.KID, k.Alg, string(k.JWK)); err != nil {
			if strings.Contains(err.Error(), "agent_keys.jkt") {
				return fmt.Errorf("%w: agent %s kid %s jkt %s (prefix)", ErrKeyInUse, a.ID, k.KID, thumbprintPrefixOf(k.JKT))
			}
			return fmt.Errorf("agentreg: agent %s kid %s: %w", a.ID, k.KID, err)
		}
	}
	return nil
}

func loadOne(ctx context.Context, q queryer, id string) (Agent, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE id = ?`, id)
	if err != nil {
		return Agent{}, fmt.Errorf("agentreg: read %s: %w", id, err)
	}
	list, err := scanAgents(rows)
	if err != nil {
		return Agent{}, err
	}
	if len(list) == 0 {
		return Agent{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err := attachKeys(ctx, q, list, id); err != nil {
		return Agent{}, err
	}
	return list[0], nil
}

func loadAll(ctx context.Context, q queryer) ([]Agent, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("agentreg: list: %w", err)
	}
	list, err := scanAgents(rows)
	if err != nil {
		return nil, err
	}
	if err := attachKeys(ctx, q, list, ""); err != nil {
		return nil, err
	}
	if list == nil {
		list = []Agent{}
	}
	return list, nil
}

func scanAgents(rows *sql.Rows) ([]Agent, error) {
	defer func() { _ = rows.Close() }()
	var out []Agent
	for rows.Next() {
		var a Agent
		var groups, scopes, status string
		var created, updated int64
		if err := rows.Scan(&a.ID, &a.DisplayName, &a.OwnerIss, &a.OwnerSub, &a.OwnerEmail, &groups, &scopes,
			&status, &a.Revision, &created, &a.CreatedBy, &updated, &a.UpdatedBy); err != nil {
			return nil, fmt.Errorf("agentreg: scan agent: %w", err)
		}
		if err := json.Unmarshal([]byte(groups), &a.AllowedGroups); err != nil {
			return nil, fmt.Errorf("agentreg: agent %s: stored groups are corrupt", a.ID)
		}
		if err := json.Unmarshal([]byte(scopes), &a.AllowedScopes); err != nil {
			return nil, fmt.Errorf("agentreg: agent %s: stored scopes are corrupt", a.ID)
		}
		if len(a.AllowedGroups) == 0 {
			a.AllowedGroups = nil
		}
		if len(a.AllowedScopes) == 0 {
			a.AllowedScopes = nil
		}
		a.Status = Status(status)
		a.CreatedAt = time.Unix(0, created).UTC()
		a.UpdatedAt = time.Unix(0, updated).UTC()
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agentreg: read agents: %w", err)
	}
	return out, nil
}

// attachKeys loads the keys of every agent in list (in insertion order); a
// non-empty only restricts the read to that agent.
func attachKeys(ctx context.Context, q queryer, list []Agent, only string) error {
	if len(list) == 0 {
		return nil
	}
	idx := make(map[string]int, len(list))
	for i, a := range list {
		idx[a.ID] = i
	}
	query, args := `SELECT agent_id, kid, jkt, alg, jwk_json FROM agent_keys ORDER BY rowid`, []any(nil)
	if only != "" {
		query, args = `SELECT agent_id, kid, jkt, alg, jwk_json FROM agent_keys WHERE agent_id = ? ORDER BY rowid`, []any{only}
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("agentreg: read keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, doc string
		var k Key
		if err := rows.Scan(&id, &k.KID, &k.JKT, &k.Alg, &doc); err != nil {
			return fmt.Errorf("agentreg: scan key: %w", err)
		}
		k.JWK = json.RawMessage(doc)
		if i, ok := idx[id]; ok {
			list[i].Keys = append(list[i].Keys, k)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("agentreg: read keys: %w", err)
	}
	return nil
}
