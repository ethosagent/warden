// Package analytics defines the AnalyticsStore interface and a pure-Go SQLite
// implementation (modernc.org/sqlite — never a CGo driver). It records one
// event per proxied decision.
//
// Logging hygiene is a core invariant: events carry headers/metadata and a
// secret-by-reference only. There is deliberately NO request/response body
// field on Event, so full bodies cannot be persisted.
package analytics

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
)

// AnalyticsStore records and queries proxy decision events.
type AnalyticsStore interface {
	StoreEvent(e Event) error
	GetEvents(filter EventFilter) ([]Event, error)
}

// Event is a single recorded proxy decision. It intentionally has no body
// field: phase-1 logging is headers/metadata only, never full bodies.
type Event struct {
	Timestamp      time.Time
	Domain         string
	Port           int
	Protocol       string
	Method         string
	URL            string
	Decision       string
	ResponseStatus int
	// SecretRef references the secret used by hash/last-4/version — never the
	// raw value.
	SecretRef string
	// JudgeReason is the LLM judge's natural-language rationale for an allow/deny
	// verdict, recorded for audit. It is metadata only — never a request body or
	// secret value. Empty for statically decided events.
	JudgeReason string
}

// EventFilter narrows a GetEvents query. Zero-valued fields are ignored.
type EventFilter struct {
	Domain   string
	Decision string
	Since    time.Time
	// Limit caps the number of rows returned (0 = no cap).
	Limit int
}

// defaultMaxEvents is the retention cap when none is supplied.
const defaultMaxEvents = 100_000

// SQLiteStore is a pure-Go SQLite-backed AnalyticsStore with size-capped
// retention: when the row count exceeds maxEvents, the oldest events are
// pruned first.
type SQLiteStore struct {
	db        *sql.DB
	maxEvents int
}

var _ AnalyticsStore = (*SQLiteStore)(nil)

// NewSQLiteStore opens (or creates) a SQLite database at dsn and ensures the
// schema. Use ":memory:" for tests. maxEvents <= 0 uses the default cap.
func NewSQLiteStore(dsn string, maxEvents int) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("analytics: open sqlite: %w", err)
	}
	// A single connection avoids cross-connection visibility issues for an
	// in-memory DSN and is sufficient for a single-node proxy.
	db.SetMaxOpenConns(1)

	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	s := &SQLiteStore{db: db, maxEvents: maxEvents}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate creates the events table. Note there is no body column by design.
func (s *SQLiteStore) migrate() error {
	const ddl = `
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    domain          TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    url             TEXT    NOT NULL,
    decision        TEXT    NOT NULL,
    response_status INTEGER NOT NULL,
    secret_ref      TEXT    NOT NULL,
    judge_reason    TEXT    NOT NULL DEFAULT ''
);`
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("analytics: migrate: %w", err)
	}
	// Additive migration for databases created before judge_reason existed.
	// SQLite has no "ADD COLUMN IF NOT EXISTS"; ignore the duplicate-column
	// error so re-running migrate is idempotent.
	if _, err := s.db.Exec(`ALTER TABLE events ADD COLUMN judge_reason TEXT NOT NULL DEFAULT ''`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("analytics: migrate add judge_reason: %w", err)
		}
	}
	return nil
}

// Close releases the database handle.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// StoreEvent persists an event and enforces the retention cap, pruning the
// oldest events first when over the cap.
func (s *SQLiteStore) StoreEvent(e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	const ins = `INSERT INTO events
        (ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(ins,
		e.Timestamp.UnixNano(), e.Domain, e.Port, e.Protocol, e.Method,
		e.URL, e.Decision, e.ResponseStatus, e.SecretRef, e.JudgeReason)
	if err != nil {
		return fmt.Errorf("analytics: insert event: %w", err)
	}
	return s.prune()
}

// prune deletes oldest events while the row count exceeds maxEvents.
func (s *SQLiteStore) prune() error {
	const del = `DELETE FROM events WHERE id IN (
        SELECT id FROM events ORDER BY id ASC
        LIMIT MAX(0, (SELECT COUNT(*) FROM events) - ?)
    )`
	if _, err := s.db.Exec(del, s.maxEvents); err != nil {
		return fmt.Errorf("analytics: prune: %w", err)
	}
	return nil
}

// GetEvents returns events matching filter, newest first.
func (s *SQLiteStore) GetEvents(filter EventFilter) ([]Event, error) {
	q := `SELECT ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason
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
		return nil, fmt.Errorf("analytics: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Event
	for rows.Next() {
		var (
			e  Event
			ts int64
		)
		if err := rows.Scan(&ts, &e.Domain, &e.Port, &e.Protocol, &e.Method,
			&e.URL, &e.Decision, &e.ResponseStatus, &e.SecretRef, &e.JudgeReason); err != nil {
			return nil, fmt.Errorf("analytics: scan: %w", err)
		}
		e.Timestamp = time.Unix(0, ts).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: rows: %w", err)
	}
	return out, nil
}

// count returns the current number of stored events (test helper / internal).
func (s *SQLiteStore) count() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// GetOldestEventIDs returns the IDs and events of the oldest N events.
func (s *SQLiteStore) GetOldestEventIDs(limit int) ([]int64, []Event, error) {
	const q = `SELECT id, ts, domain, port, protocol, method, url, decision, response_status, secret_ref
	            FROM events ORDER BY id ASC LIMIT ?`
	rows, err := s.db.Query(q, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("analytics: oldest event IDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	var out []Event
	for rows.Next() {
		var (
			id int64
			e  Event
			ts int64
		)
		if err := rows.Scan(&id, &ts, &e.Domain, &e.Port, &e.Protocol, &e.Method,
			&e.URL, &e.Decision, &e.ResponseStatus, &e.SecretRef); err != nil {
			return nil, nil, fmt.Errorf("analytics: scan oldest IDs: %w", err)
		}
		e.Timestamp = time.Unix(0, ts).UTC()
		ids = append(ids, id)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("analytics: rows oldest IDs: %w", err)
	}
	return ids, out, nil
}

// DeleteEventsByID removes events with the given IDs.
func (s *SQLiteStore) DeleteEventsByID(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	// Build placeholders: (?, ?, ?)
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	query := "DELETE FROM events WHERE id IN (" + strings.Join(placeholders, ", ") + ")"
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("analytics: delete events by ID: %w", err)
	}
	return nil
}
