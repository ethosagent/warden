package analytics

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
)

// FleetSQLiteStore is a pure-Go SQLite-backed FleetStore for the control plane.
// It mirrors SQLiteStore but adds fleet columns (proxy_id, agent_id, event_uid)
// and exposes a read-only SQL query surface (AnalyticsQuery) for the dashboard.
//
// It holds two handles: a read/write handle for ingest and pruning, and a
// separate read-only handle (PRAGMA query_only = ON) used exclusively by Query
// so ad-hoc SQL can never mutate the store.
type FleetSQLiteStore struct {
	db            *sql.DB // read/write
	ro            *sql.DB // read-only query surface
	retentionDays int
	maxEvents     int
	// sharedRO is true when ro aliases db (in-memory DSNs, where a separate ro
	// handle cannot see the same in-memory database). Close then closes db once.
	sharedRO bool
}

var (
	_ FleetStore     = (*FleetSQLiteStore)(nil)
	_ AnalyticsQuery = (*FleetSQLiteStore)(nil)
)

// NewFleetSQLiteStore opens (or creates) a SQLite database at path and ensures
// the fleet schema. retentionDays <= 0 keeps events forever; maxEvents <= 0 uses
// the default cap.
func NewFleetSQLiteStore(path string, retentionDays, maxEvents int) (*FleetSQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("analytics: open fleet sqlite: %w", err)
	}
	// A single connection avoids cross-connection visibility issues for an
	// in-memory DSN and is sufficient for a single-writer control plane.
	db.SetMaxOpenConns(1)

	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	s := &FleetSQLiteStore{db: db, retentionDays: retentionDays, maxEvents: maxEvents}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}

	// Read-only query handle (shared opener; see query.go). For in-memory DSNs
	// it aliases the rw handle (sharedRO=true).
	ro, shared, err := openReadOnlyDB(path, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.ro = ro
	s.sharedRO = shared
	return s, nil
}

// migrate creates the fleet events table and its indexes. Like SQLiteStore there
// is no body column by design.
func (s *FleetSQLiteStore) migrate() error {
	const ddl = `
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uid       TEXT,
    proxy_id        TEXT    NOT NULL DEFAULT '',
    agent_id        TEXT    NOT NULL DEFAULT '',
    ts              INTEGER NOT NULL,
    domain          TEXT    NOT NULL DEFAULT '',
    port            INTEGER NOT NULL DEFAULT 0,
    protocol        TEXT    NOT NULL DEFAULT '',
    method          TEXT    NOT NULL DEFAULT '',
    url             TEXT    NOT NULL DEFAULT '',
    decision        TEXT    NOT NULL DEFAULT '',
    response_status INTEGER NOT NULL DEFAULT 0,
    secret_ref      TEXT    NOT NULL DEFAULT '',
    judge_reason    TEXT    NOT NULL DEFAULT '',
    tool            TEXT    NOT NULL DEFAULT '',
    reason          TEXT    NOT NULL DEFAULT '',
    cost_usd        REAL    NOT NULL DEFAULT 0,
    provider        TEXT    NOT NULL DEFAULT '',
    compliance      TEXT    NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_uid ON events(event_uid) WHERE event_uid IS NOT NULL AND event_uid != '';
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_proxy_ts ON events(proxy_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool);`
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("analytics: fleet migrate: %w", err)
	}
	// Forward-only, add-only migrations for fleet databases created before a
	// column existed. Each is guarded by PRAGMA table_info, so re-running
	// migrate is a no-op and no data is ever dropped.
	for _, c := range fleetColumnMigrations {
		if err := s.addColumnIfAbsent(c.name, c.ddl); err != nil {
			return err
		}
	}
	// The index needs user_sub to exist, so it comes after the column loop.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_user_sub_ts ON events (user_sub, ts)`); err != nil {
		return fmt.Errorf("analytics: fleet migrate user index: %w", err)
	}
	// lower(user_email) lets SQLite plan the User filter's OR as two index
	// lookups (user_sub, lower(user_email)) instead of a scan.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_user_email_lower ON events (lower(user_email))`); err != nil {
		return fmt.Errorf("analytics: migrate user email index: %w", err)
	}
	return nil
}

// fleetColumnMigrations lists the columns added after the original fleet
// schema. Later tickets append here and reuse addColumnIfAbsent.
var fleetColumnMigrations = []struct{ name, ddl string }{
	{"user_sub", `ALTER TABLE events ADD COLUMN user_sub TEXT NOT NULL DEFAULT ''`},
	{"user_email", `ALTER TABLE events ADD COLUMN user_email TEXT NOT NULL DEFAULT ''`},
	{"user_groups", `ALTER TABLE events ADD COLUMN user_groups TEXT NOT NULL DEFAULT ''`},
	{"user_groups_truncated", `ALTER TABLE events ADD COLUMN user_groups_truncated INTEGER NOT NULL DEFAULT 0`},
	{"user_sid", `ALTER TABLE events ADD COLUMN user_sid TEXT NOT NULL DEFAULT ''`},
	{"identity_status", `ALTER TABLE events ADD COLUMN identity_status TEXT NOT NULL DEFAULT ''`},
	{"identity_reason", `ALTER TABLE events ADD COLUMN identity_reason TEXT NOT NULL DEFAULT ''`},
}

// addColumnIfAbsent runs ddl (an ALTER TABLE ADD COLUMN) only when the events
// table has no column called name, checked via PRAGMA table_info(events). The
// control plane is a single writer on one connection, so there is no race to
// retry; a "duplicate column" failure is still re-checked and tolerated.
func (s *FleetSQLiteStore) addColumnIfAbsent(name, ddl string) error {
	present, err := s.columnPresent(name)
	if err != nil {
		return err
	}
	if present {
		return nil
	}
	if _, err := s.db.Exec(ddl); err != nil {
		if again, perr := s.columnPresent(name); perr == nil && again {
			return nil
		}
		return fmt.Errorf("analytics: fleet migrate add %s: %w", name, err)
	}
	return nil
}

func (s *FleetSQLiteStore) columnPresent(name string) (bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		return false, fmt.Errorf("analytics: fleet migrate table_info: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid, notNull, pk int
			col, colType     string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &col, &colType, &notNull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("analytics: fleet migrate scan table_info: %w", err)
		}
		if col == name {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("analytics: fleet migrate table_info rows: %w", err)
	}
	return false, nil
}

// StoreAggregatedEvent persists an aggregated event, then prunes by age and cap.
// event_uid comes from the sending worker (Event.UID); the partial unique index
// means empty uids (pre-UID workers, workers with no proxy id) never conflict,
// so every such event inserts. When a non-empty uid conflicts — a worker
// re-sending a batch whose ack was lost — the insert is a silent no-op, so a
// retried batch never stores duplicates and never fails.
func (s *FleetSQLiteStore) StoreAggregatedEvent(e AggregatedEvent) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	const ins = `INSERT INTO events
        (event_uid, proxy_id, agent_id, ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance,
         user_sub, user_email, user_groups, user_groups_truncated, user_sid, identity_status, identity_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(event_uid) WHERE event_uid IS NOT NULL AND event_uid != '' DO NOTHING`
	_, err := s.db.Exec(ins,
		nullIfEmpty(e.EventUID()), e.ProxyID, e.AgentID, e.Timestamp.UnixNano(),
		e.Domain, e.Port, e.Protocol, e.Method, e.URL, e.Decision, e.ResponseStatus,
		e.SecretRef, e.JudgeReason, e.Tool, e.Reason, e.CostUSD, e.Provider,
		encodeCompliance(e.Compliance),
		e.UserSub, e.UserEmail, EncodeGroups(e.UserGroups), boolToInt(e.UserGroupsTruncated),
		e.UserSID, e.IdentityStatus, e.IdentityReason)
	if err != nil {
		return fmt.Errorf("analytics: fleet insert event: %w", err)
	}
	return s.prune()
}

// EventUID is the dedup key for an aggregated event: the worker-assigned
// Event.UID (a hash of proxy id + local rowid, stamped by the SyncWorker before
// first send, so it is identical on every retry of the same event). Empty when
// the sender predates UIDs or has no proxy id configured; empty keys fall
// outside the partial unique index and are always stored.
func (e AggregatedEvent) EventUID() string { return e.UID }

// nullIfEmpty maps "" to a SQL NULL so empty event_uids stay outside the partial
// unique index (which excludes NULL and ”).
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// prune enforces retention: deletes events older than retentionDays (when > 0),
// then deletes the oldest events while the row count exceeds maxEvents.
func (s *FleetSQLiteStore) prune() error {
	if s.retentionDays > 0 {
		cutoff := time.Now().Add(-time.Duration(s.retentionDays) * 24 * time.Hour).UnixNano()
		if _, err := s.db.Exec(`DELETE FROM events WHERE ts < ?`, cutoff); err != nil {
			return fmt.Errorf("analytics: fleet prune age: %w", err)
		}
	}
	const del = `DELETE FROM events WHERE id IN (
        SELECT id FROM events ORDER BY id ASC
        LIMIT MAX(0, (SELECT COUNT(*) FROM events) - ?)
    )`
	if _, err := s.db.Exec(del, s.maxEvents); err != nil {
		return fmt.Errorf("analytics: fleet prune cap: %w", err)
	}
	return nil
}

// PruneExpired runs the age + cap prune. It is exposed for a periodic caller
// (retention runs on ingest too, but a fleet may go idle between events).
func (s *FleetSQLiteStore) PruneExpired() error { return s.prune() }

// GetEvents returns events matching filter, newest first, with Event.ProxyID set.
func (s *FleetSQLiteStore) GetEvents(filter EventFilter) ([]Event, error) {
	q := `SELECT proxy_id, ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance,
                 user_sub, user_email, user_groups, user_groups_truncated, user_sid, identity_status, identity_reason
          FROM events WHERE 1=1`
	var args []any
	if filter.Domain != "" {
		q += " AND domain = ?"
		args = append(args, filter.Domain)
	}
	if filter.Decision != "" {
		q += " AND decision = ?"
		args = append(args, filter.Decision)
	}
	if filter.Protocol != "" {
		q += " AND protocol = ?"
		args = append(args, filter.Protocol)
	}
	if filter.Tool != "" {
		q += " AND tool = ?"
		args = append(args, filter.Tool)
	}
	if filter.ProxyID != "" {
		q += " AND proxy_id = ?"
		args = append(args, filter.ProxyID)
	}
	if filter.User != "" {
		q += userFilterSQL
		args = append(args, filter.User, filter.User)
	}
	if !filter.Since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, filter.Since.UnixNano())
	}
	q += " ORDER BY id DESC"
	if filter.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("analytics: fleet query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Event
	for rows.Next() {
		var (
			e           Event
			ts          int64
			compliance  string
			userGroups  string
			groupsTrunc int
		)
		if err := rows.Scan(&e.ProxyID, &ts, &e.Domain, &e.Port, &e.Protocol, &e.Method,
			&e.URL, &e.Decision, &e.ResponseStatus, &e.SecretRef, &e.JudgeReason, &e.Tool, &e.Reason,
			&e.CostUSD, &e.Provider, &compliance,
			&e.UserSub, &e.UserEmail, &userGroups, &groupsTrunc, &e.UserSID, &e.IdentityStatus, &e.IdentityReason); err != nil {
			return nil, fmt.Errorf("analytics: fleet scan: %w", err)
		}
		e.Compliance = decodeCompliance(compliance)
		e.UserGroups = DecodeGroups(userGroups)
		e.UserGroupsTruncated = groupsTrunc != 0
		e.Timestamp = time.Unix(0, ts).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: fleet rows: %w", err)
	}
	return out, nil
}

// GetAggregatedEvents returns aggregated events matching filter, newest first,
// with ProxyID and AgentID populated. It additionally filters by agent_id.
func (s *FleetSQLiteStore) GetAggregatedEvents(filter AggregatedFilter) ([]AggregatedEvent, error) {
	q := `SELECT proxy_id, agent_id, ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance,
                 user_sub, user_email, user_groups, user_groups_truncated, user_sid, identity_status, identity_reason
          FROM events WHERE 1=1`
	var args []any
	if filter.Domain != "" {
		q += " AND domain = ?"
		args = append(args, filter.Domain)
	}
	if filter.Decision != "" {
		q += " AND decision = ?"
		args = append(args, filter.Decision)
	}
	if filter.Protocol != "" {
		q += " AND protocol = ?"
		args = append(args, filter.Protocol)
	}
	if filter.Tool != "" {
		q += " AND tool = ?"
		args = append(args, filter.Tool)
	}
	// ProxyID may come from either the embedded EventFilter or the AggregatedFilter.
	proxyID := filter.ProxyID
	if proxyID == "" {
		proxyID = filter.EventFilter.ProxyID
	}
	if proxyID != "" {
		q += " AND proxy_id = ?"
		args = append(args, proxyID)
	}
	if filter.AgentID != "" {
		q += " AND agent_id = ?"
		args = append(args, filter.AgentID)
	}
	if filter.User != "" {
		q += userFilterSQL
		args = append(args, filter.User, filter.User)
	}
	if !filter.Since.IsZero() {
		q += " AND ts >= ?"
		args = append(args, filter.Since.UnixNano())
	}
	q += " ORDER BY id DESC"
	if filter.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("analytics: fleet agg query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AggregatedEvent
	for rows.Next() {
		var (
			a           AggregatedEvent
			ts          int64
			compliance  string
			userGroups  string
			groupsTrunc int
		)
		if err := rows.Scan(&a.ProxyID, &a.AgentID, &ts, &a.Domain, &a.Port, &a.Protocol, &a.Method,
			&a.URL, &a.Decision, &a.ResponseStatus, &a.SecretRef, &a.JudgeReason, &a.Tool, &a.Reason,
			&a.CostUSD, &a.Provider, &compliance,
			&a.UserSub, &a.UserEmail, &userGroups, &groupsTrunc, &a.UserSID, &a.IdentityStatus, &a.IdentityReason); err != nil {
			return nil, fmt.Errorf("analytics: fleet agg scan: %w", err)
		}
		a.Compliance = decodeCompliance(compliance)
		a.UserGroups = DecodeGroups(userGroups)
		a.UserGroupsTruncated = groupsTrunc != 0
		a.Timestamp = time.Unix(0, ts).UTC()
		// Surface the originating proxy on the embedded Event as well, matching
		// CentralStore's GetEvents behavior.
		a.Event.ProxyID = a.ProxyID
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: fleet agg rows: %w", err)
	}
	return out, nil
}

// Close releases both database handles.
func (s *FleetSQLiteStore) Close() error {
	if s.sharedRO {
		return s.db.Close()
	}
	errRO := s.ro.Close()
	errDB := s.db.Close()
	if errDB != nil {
		return errDB
	}
	return errRO
}

// Query runs a validated, timeout-bounded, read-only SELECT against the ro
// handle and returns a bounded, JSON-friendly result set. The guard + runner
// are shared with SQLiteStore (query.go).
func (s *FleetSQLiteStore) Query(ctx context.Context, sqlText string, maxRows int) (QueryResult, error) {
	return runReadOnlyQuery(ctx, s.ro, sqlText, maxRows)
}

// Schema reports the queryable schema for the dashboard's query builder. It
// covers only the events table, read via PRAGMA table_info(events).
func (s *FleetSQLiteStore) Schema() SchemaInfo {
	return eventsTableSchema(s.db)
}
