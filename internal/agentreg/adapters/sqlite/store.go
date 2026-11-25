package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// DataVersionInterval is how often Watch polls for a write by another process
// (the offline registry CLI). It matches the key manager's and the block
// list's interval.
const DataVersionInterval = 2 * time.Second

// Store is the agentreg.Store on the cpstate database. Open the DB with a
// migration list that includes Migrations (controlplane.StateMigrations does)
// and run Watch beside the server so a write by another process is seen.
// There is no statement that deletes an agent row.
type Store struct {
	db     *sql.DB
	clock  clock.Clock
	logger *slog.Logger
	max    int

	// The read path serves an immutable snapshot of the whole registry (at
	// most config.MaxRegisteredAgents small rows). Every local write and every
	// data_version change drops it. gen counts those drops; a snapshot carries
	// the generation it was loaded under and is cached only while that is still
	// current, with the check and the store (and invalidate) under one mutex, so
	// a load that raced a write can never be cached. Loads are coalesced per
	// generation (singleflight), so a burst of readers after a write costs one
	// query, and a reader never joins a load that began before a write it
	// follows.
	mu    sync.Mutex
	gen   uint64
	snap  *snapshot
	group singleflight.Group

	// syncMu guards syncLast/syncSeen, the data_version Sync last saw.
	syncMu   sync.Mutex
	syncLast int64
	syncSeen bool

	// Test seams (export_test.go); nil in production.
	afterRead func()                               // after a load's reads, before it is cached
	version   func(context.Context) (int64, error) // replaces dataVersion
}

var _ agentreg.Store = (*Store)(nil)

// Option configures New.
type Option func(*Store)

// WithClock sets the time source for created_at, updated_at and Watch.
func WithClock(c clock.Clock) Option {
	return func(s *Store) {
		if c != nil {
			s.clock = c
		}
	}
}

// WithLogger sets the logger Watch reports on.
func WithLogger(l *slog.Logger) Option {
	return func(s *Store) {
		if l != nil {
			s.logger = l
		}
	}
}

// New builds a store over db.
func New(db *cpstate.DB, opts ...Option) *Store {
	s := &Store{
		db:     db.SQL(),
		clock:  clock.Real(),
		logger: slog.Default(),
		max:    config.MaxRegisteredAgents,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// snapshot is an immutable view of every agent, loaded under generation gen.
// Callers clone what they return.
type snapshot struct {
	byID map[string]agentreg.Agent
	list []agentreg.Agent
	gen  uint64
}

// invalidate drops the cached snapshot and starts a new generation. Every
// write calls it after its commit and before it returns.
func (s *Store) invalidate() {
	s.mu.Lock()
	s.gen++
	s.snap = nil
	s.mu.Unlock()
}

func (s *Store) generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

// load returns a snapshot at least as new as the generation current when it
// was called: one loaded after every write that finished before the call. It
// reads through to the database at most once per generation for any number
// of concurrent callers.
func (s *Store) load(ctx context.Context) (*snapshot, error) {
	entry := s.generation()
	for {
		s.mu.Lock()
		p, g := s.snap, s.gen
		s.mu.Unlock()
		if p != nil {
			return p, nil
		}
		v, err, _ := s.group.Do(strconv.FormatUint(g, 10), func() (any, error) {
			// A shared load must not die with the first caller's context. The
			// reads begin after the invalidate that produced generation g,
			// hence after the commit of every write that finished before it.
			list, err := loadAll(context.WithoutCancel(ctx), s.db)
			if err != nil {
				return nil, err
			}
			if s.afterRead != nil {
				s.afterRead()
			}
			p := &snapshot{byID: make(map[string]agentreg.Agent, len(list)), list: list, gen: g}
			for _, a := range list {
				p.byID[a.ID] = a
			}
			s.mu.Lock()
			if s.gen == g {
				s.snap = p
			}
			s.mu.Unlock()
			return p, nil
		})
		if err != nil {
			return nil, err
		}
		if p := v.(*snapshot); p.gen >= entry {
			return p, nil
		}
		// Joined a load from before a write this call follows: go again.
	}
}

// Watch polls PRAGMA data_version every interval until ctx is done and drops
// the snapshot whenever it moves. The pragma changes only when another
// connection (in practice another process: cpstate holds one connection per
// handle) commits to the database, so it catches the offline CLI's writes
// without a table scan; this process's own writes invalidate directly. A poll
// error is logged once per episode and the snapshot is dropped, so the next
// read goes to the database rather than serving a view that cannot be
// confirmed. Assembly starts it the way it starts BlockStore.Watch.
func (s *Store) Watch(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DataVersionInterval
	}
	last, err := s.readVersion(ctx)
	failing := err != nil
	if failing {
		s.logger.Warn("agent registry watch: data_version unreadable", "error", err)
	}
	// A write between the first load and this read is not covered by the
	// baseline, so start from a cold cache.
	s.invalidate()
	for {
		t := s.clock.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C():
		}
		v, err := s.readVersion(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !failing {
				s.logger.Warn("agent registry watch: data_version unreadable", "error", err)
			}
			failing = true
			s.invalidate()
			continue
		}
		failing = false
		if v != last {
			last = v
			s.invalidate()
		}
	}
}

// Sync reads PRAGMA data_version now and drops the snapshot if another
// connection has committed since the previous Sync (or if this is the first
// call, or the read fails), so the next read comes from the database. The
// control plane calls it on every policy reload, which bounds how stale a
// write by the offline CLI can be to the reload interval rather than to the
// reload interval plus Watch's poll. It is a single pragma read; it does not
// touch the registry tables.
func (s *Store) Sync(ctx context.Context) error {
	v, err := s.readVersion(ctx)
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if err != nil {
		s.syncSeen = false
		s.invalidate()
		return err
	}
	if !s.syncSeen || v != s.syncLast {
		s.syncLast, s.syncSeen = v, true
		s.invalidate()
	}
	return nil
}

func (s *Store) readVersion(ctx context.Context) (int64, error) {
	if s.version != nil {
		return s.version(ctx)
	}
	return s.dataVersion(ctx)
}

func (s *Store) dataVersion(ctx context.Context) (int64, error) {
	var v int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA data_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("agentreg: data_version: %w", err)
	}
	return v, nil
}

// conn is the statement surface *sql.Conn and *sql.DB share.
type conn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// immediateTx runs fn in a BEGIN IMMEDIATE transaction on one connection, so
// its reads and writes see no other writer, in this process or another (the
// offline CLI). It commits when fn returns nil and rolls back otherwise, and
// drops the snapshot after a commit.
func (s *Store) immediateTx(ctx context.Context, what string, fn func(c conn) error) error {
	c, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("agentreg: %s: connection: %w", what, err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("agentreg: %s: begin: %w", what, err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = c.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()
	if err := fn(c); err != nil {
		return err
	}
	if _, err := c.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("agentreg: %s: commit: %w", what, err)
	}
	committed = true
	s.invalidate()
	return nil
}

const agentColumns = `id, display_name, owner_iss, owner_sub, owner_email, allowed_groups_json,
    allowed_scopes_json, status, revision, created_at, created_by, updated_at, updated_by`

// SQLite result codes this store distinguishes. The driver's error carries the
// extended code through Code(); only the constraint family is inspected.
const (
	codeConstraint = 19
	codePrimaryKey = 1555 // SQLITE_CONSTRAINT_PRIMARYKEY
	codeUnique     = 2067 // SQLITE_CONSTRAINT_UNIQUE
)

// constraintCode reports the extended code of a constraint violation.
func constraintCode(err error) (int, bool) {
	var c interface{ Code() int }
	if errors.As(err, &c) && c.Code()&0xff == codeConstraint {
		return c.Code(), true
	}
	return 0, false
}

// Create implements agentreg.Store.
func (s *Store) Create(ctx context.Context, a agentreg.Agent, actor string) (agentreg.Agent, error) {
	v, err := agentreg.Validate(a)
	if err != nil {
		return agentreg.Agent{}, err
	}
	if err := agentreg.ValidateActor(actor); err != nil {
		return agentreg.Agent{}, err
	}
	now := s.clock.Now().UTC().Round(0)
	v.Revision = 1
	v.CreatedAt, v.UpdatedAt = now, now
	v.CreatedBy, v.UpdatedBy = actor, actor

	err = s.immediateTx(ctx, "create "+v.ID, func(c conn) error {
		var n int
		if err := c.QueryRowContext(ctx, `SELECT count(*) FROM agents WHERE id = ?`, v.ID).Scan(&n); err != nil {
			return fmt.Errorf("agentreg: create %s: %w", v.ID, err)
		}
		if n > 0 {
			return fmt.Errorf("%w: %s", agentreg.ErrAlreadyExists, v.ID)
		}
		if err := c.QueryRowContext(ctx, `SELECT count(*) FROM agents`).Scan(&n); err != nil {
			return fmt.Errorf("agentreg: create %s: %w", v.ID, err)
		}
		if n >= s.max {
			return fmt.Errorf("%w: at most %d agents", agentreg.ErrRegistryFull, s.max)
		}
		groups, scopes, err := marshalLists(v)
		if err != nil {
			return fmt.Errorf("agentreg: create %s: %w", v.ID, err)
		}
		if _, err := c.ExecContext(ctx, `INSERT INTO agents (`+agentColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			v.ID, v.DisplayName, v.OwnerIss, v.OwnerSub, v.OwnerEmail, groups, scopes, string(v.Status),
			v.Revision, now.UnixNano(), actor, now.UnixNano(), actor); err != nil {
			if _, ok := constraintCode(err); ok {
				// The primary key is the only constraint on this insert.
				return fmt.Errorf("%w: %s", agentreg.ErrAlreadyExists, v.ID)
			}
			return fmt.Errorf("agentreg: create %s: %w", v.ID, err)
		}
		return insertKeys(ctx, c, v)
	})
	if err != nil {
		return agentreg.Agent{}, err
	}
	return clone(v), nil
}

// Get implements agentreg.Store.
func (s *Store) Get(ctx context.Context, id string) (agentreg.Agent, error) {
	snap, err := s.load(ctx)
	if err != nil {
		return agentreg.Agent{}, err
	}
	a, ok := snap.byID[id]
	if !ok {
		return agentreg.Agent{}, agentreg.ErrNotFound
	}
	return clone(a), nil
}

// List implements agentreg.Store.
func (s *Store) List(ctx context.Context) ([]agentreg.Agent, error) {
	snap, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]agentreg.Agent, len(snap.list))
	for i, a := range snap.list {
		out[i] = clone(a)
	}
	return out, nil
}

// Update implements agentreg.Store.
func (s *Store) Update(ctx context.Context, a agentreg.Agent, actor string) (agentreg.Agent, error) {
	if err := agentreg.ValidateActor(actor); err != nil {
		return agentreg.Agent{}, err
	}
	if err := agentreg.ValidateID(a.ID); err != nil {
		return agentreg.Agent{}, err
	}
	var out agentreg.Agent
	err := s.immediateTx(ctx, "update "+a.ID, func(c conn) error {
		cur, err := loadOne(ctx, c, a.ID)
		if err != nil {
			return err
		}
		// Status is not part of an update: SetStatus owns it, so the
		// active-needs-groups check runs against the status the agent has.
		a.Status = cur.Status
		v, err := agentreg.Validate(a)
		if err != nil {
			return err
		}
		if a.Revision != cur.Revision {
			return fmt.Errorf("%w: %s", agentreg.ErrConflict, a.ID)
		}
		groups, scopes, err := marshalLists(v)
		if err != nil {
			return fmt.Errorf("agentreg: update %s: %w", v.ID, err)
		}
		res, err := c.ExecContext(ctx, `UPDATE agents SET display_name = ?, owner_iss = ?, owner_sub = ?, owner_email = ?,
            allowed_groups_json = ?, allowed_scopes_json = ?, revision = revision + 1, updated_at = ?, updated_by = ?
            WHERE id = ? AND revision = ?`,
			v.DisplayName, v.OwnerIss, v.OwnerSub, v.OwnerEmail, groups, scopes,
			s.clock.Now().UTC().UnixNano(), actor, v.ID, a.Revision)
		if err != nil {
			return fmt.Errorf("agentreg: update %s: %w", v.ID, err)
		}
		if err := requireOneRow(res, v.ID); err != nil {
			return err
		}
		// The key set is replaced as a whole in the same transaction; the
		// agent row itself is never deleted.
		if _, err := c.ExecContext(ctx, `DELETE FROM agent_keys WHERE agent_id = ?`, v.ID); err != nil {
			return fmt.Errorf("agentreg: update %s: %w", v.ID, err)
		}
		if err := insertKeys(ctx, c, v); err != nil {
			return err
		}
		out, err = loadOne(ctx, c, v.ID)
		return err
	})
	if err != nil {
		return agentreg.Agent{}, err
	}
	return out, nil
}

// SetStatus implements agentreg.Store.
func (s *Store) SetStatus(ctx context.Context, id string, status agentreg.Status, revision int64, actor string) (agentreg.Agent, error) {
	if err := agentreg.ValidateID(id); err != nil {
		return agentreg.Agent{}, err
	}
	if !status.Valid() {
		return agentreg.Agent{}, agentreg.Invalid("status", "must be active or disabled")
	}
	if err := agentreg.ValidateActor(actor); err != nil {
		return agentreg.Agent{}, err
	}
	var out agentreg.Agent
	err := s.immediateTx(ctx, "set status "+id, func(c conn) error {
		cur, err := loadOne(ctx, c, id)
		if err != nil {
			return err
		}
		if revision != cur.Revision {
			return fmt.Errorf("%w: %s", agentreg.ErrConflict, id)
		}
		if status == agentreg.StatusActive && len(cur.AllowedGroups) == 0 {
			return agentreg.Invalid("allowed_groups", "an active agent needs at least one group")
		}
		res, err := c.ExecContext(ctx, `UPDATE agents SET status = ?, revision = revision + 1, updated_at = ?, updated_by = ?
            WHERE id = ? AND revision = ?`,
			string(status), s.clock.Now().UTC().UnixNano(), actor, id, revision)
		if err != nil {
			return fmt.Errorf("agentreg: set status %s: %w", id, err)
		}
		if err := requireOneRow(res, id); err != nil {
			return err
		}
		out, err = loadOne(ctx, c, id)
		return err
	})
	if err != nil {
		return agentreg.Agent{}, err
	}
	return out, nil
}

// requireOneRow turns a compare-and-swap that matched nothing into
// ErrConflict (the row was read in this transaction, so it exists).
func requireOneRow(res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("agentreg: %s: %w", id, err)
	}
	if n != 1 {
		return fmt.Errorf("%w: %s", agentreg.ErrConflict, id)
	}
	return nil
}

func marshalLists(a agentreg.Agent) (groups, scopes string, err error) {
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
// holds. The primary key is the backstop for a writer that slipped past the
// lookup; it is told apart from the (agent, kid) index by its extended code.
func insertKeys(ctx context.Context, c conn, a agentreg.Agent) error {
	for i, k := range a.Keys {
		inUse := fmt.Errorf("%w: agent %s kid %s jkt %s (prefix)", agentreg.ErrKeyInUse, a.ID, k.KID, agentreg.ThumbprintPrefix(k.JKT))
		var owner string
		err := c.QueryRowContext(ctx, `SELECT agent_id FROM agent_keys WHERE jkt = ?`, k.JKT).Scan(&owner)
		switch {
		case err == nil && owner != a.ID:
			return inUse
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("agentreg: agent %s: %w", a.ID, err)
		}
		if _, err := c.ExecContext(ctx, `INSERT INTO agent_keys (jkt, agent_id, kid, alg, jwk_json) VALUES (?,?,?,?,?)`,
			k.JKT, a.ID, k.KID, k.Alg, string(k.JWK)); err != nil {
			switch code, ok := constraintCode(err); {
			case ok && code == codePrimaryKey:
				return inUse
			case ok && code == codeUnique:
				return agentreg.Invalid(fmt.Sprintf("keys[%d].kid", i), "duplicate kid within the agent")
			}
			return fmt.Errorf("agentreg: agent %s kid %s: %w", a.ID, k.KID, err)
		}
	}
	return nil
}

func loadOne(ctx context.Context, q conn, id string) (agentreg.Agent, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE id = ?`, id)
	if err != nil {
		return agentreg.Agent{}, fmt.Errorf("agentreg: read %s: %w", id, err)
	}
	list, err := scanAgents(rows)
	if err != nil {
		return agentreg.Agent{}, err
	}
	if len(list) == 0 {
		return agentreg.Agent{}, fmt.Errorf("%w: %s", agentreg.ErrNotFound, id)
	}
	if err := attachKeys(ctx, q, list, id); err != nil {
		return agentreg.Agent{}, err
	}
	return list[0], nil
}

// loadAll reads the whole registry in one read transaction on one connection,
// so the agents and their keys come from the same database snapshot.
func loadAll(ctx context.Context, db *sql.DB) ([]agentreg.Agent, error) {
	c, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentreg: list: connection: %w", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.ExecContext(ctx, "BEGIN"); err != nil {
		return nil, fmt.Errorf("agentreg: list: begin: %w", err)
	}
	defer func() { _, _ = c.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }()
	rows, err := c.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("agentreg: list: %w", err)
	}
	list, err := scanAgents(rows)
	if err != nil {
		return nil, err
	}
	if err := attachKeys(ctx, c, list, ""); err != nil {
		return nil, err
	}
	if list == nil {
		list = []agentreg.Agent{}
	}
	return list, nil
}

func scanAgents(rows *sql.Rows) ([]agentreg.Agent, error) {
	defer func() { _ = rows.Close() }()
	var out []agentreg.Agent
	for rows.Next() {
		var a agentreg.Agent
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
		a.Status = agentreg.Status(status)
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
func attachKeys(ctx context.Context, q conn, list []agentreg.Agent, only string) error {
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
		var k agentreg.Key
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

// clone deep-copies a so a caller mutating its result cannot corrupt the
// snapshot.
func clone(a agentreg.Agent) agentreg.Agent {
	out := a
	if a.Keys != nil {
		out.Keys = make([]agentreg.Key, len(a.Keys))
		for i, k := range a.Keys {
			k.JWK = append([]byte(nil), k.JWK...)
			out.Keys[i] = k
		}
	}
	out.AllowedGroups = nil
	if len(a.AllowedGroups) > 0 {
		out.AllowedGroups = append([]string(nil), a.AllowedGroups...)
	}
	out.AllowedScopes = nil
	if len(a.AllowedScopes) > 0 {
		out.AllowedScopes = append([]string(nil), a.AllowedScopes...)
	}
	return out
}
