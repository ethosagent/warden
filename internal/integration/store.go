package integration

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
)

// Store is the Alert system-of-record: a pure-Go SQLite database holding the
// deduped alerts table and a dead-letter log. It owns two tables and a single
// connection (SetMaxOpenConns(1)), matching internal/analytics' style.
type Store struct {
	db        *sql.DB
	closeOnce sync.Once
	closeErr  error
}

// NewStore opens (or creates) a SQLite database at dbPath and migrates the
// schema. Use a temp-file path in tests (not ":memory:", which is not shared
// across connections).
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("integration: open sqlite: %w", err)
	}
	// A single connection is sufficient for the alert pipeline and avoids
	// cross-connection visibility surprises.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate creates the alerts + dead_letters tables. Timestamps are unix millis.
func (s *Store) migrate() error {
	const ddl = `
CREATE TABLE IF NOT EXISTS alerts (
    id             TEXT    PRIMARY KEY,
    dedup_key      TEXT    NOT NULL,
    category       TEXT    NOT NULL DEFAULT '',
    severity       INTEGER NOT NULL DEFAULT 0,
    subject_domain TEXT    NOT NULL DEFAULT '',
    subject_tool   TEXT    NOT NULL DEFAULT '',
    subject_agent  TEXT    NOT NULL DEFAULT '',
    subject_worker TEXT    NOT NULL DEFAULT '',
    summary        TEXT    NOT NULL DEFAULT '',
    evidence       TEXT    NOT NULL DEFAULT '',
    status         TEXT    NOT NULL DEFAULT 'firing',
    count          INTEGER NOT NULL DEFAULT 0,
    first_seen     INTEGER NOT NULL DEFAULT 0,
    last_seen      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dead_letters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    TEXT    NOT NULL,
    integration TEXT    NOT NULL,
    error       TEXT    NOT NULL,
    ts          INTEGER NOT NULL
);`
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("integration: migrate: %w", err)
	}
	return nil
}

// UpsertAlert inserts a new alert or, on ID conflict, escalates it: severity
// becomes max(existing, new), count increments, and last_seen/status/summary/
// evidence take the new values. first_seen is preserved (set only on insert).
func (s *Store) UpsertAlert(a Alert) error {
	const q = `INSERT INTO alerts
        (id, dedup_key, category, severity, subject_domain, subject_tool, subject_agent, subject_worker, summary, evidence, status, count, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            count     = count + 1,
            severity  = max(severity, excluded.severity),
            last_seen = excluded.last_seen,
            status    = excluded.status,
            summary   = excluded.summary,
            evidence  = excluded.evidence`
	if _, err := s.db.Exec(q,
		a.ID, a.DedupKey, a.Category, int(a.Severity),
		a.Subject.Domain, a.Subject.Tool, a.Subject.Agent, a.Subject.Worker,
		a.Summary, string(a.Evidence), string(a.Status), a.Count,
		a.FirstSeen.UnixMilli(), a.LastSeen.UnixMilli()); err != nil {
		return fmt.Errorf("integration: upsert alert: %w", err)
	}
	return nil
}

// alertColumns is the shared SELECT projection for the alerts table.
const alertColumns = `id, dedup_key, category, severity, subject_domain, subject_tool, subject_agent, subject_worker, summary, evidence, status, count, first_seen, last_seen`

// rowScanner abstracts *sql.Row and *sql.Rows for scanAlert.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAlert(sc rowScanner) (Alert, error) {
	var (
		a                   Alert
		sev                 int
		firstSeen, lastSeen int64
		evidence, status    string
	)
	if err := sc.Scan(&a.ID, &a.DedupKey, &a.Category, &sev,
		&a.Subject.Domain, &a.Subject.Tool, &a.Subject.Agent, &a.Subject.Worker,
		&a.Summary, &evidence, &status, &a.Count, &firstSeen, &lastSeen); err != nil {
		return Alert{}, err
	}
	a.Severity = Severity(sev)
	a.Evidence = Evidence(evidence)
	a.Status = Status(status)
	a.FirstSeen = time.UnixMilli(firstSeen).UTC()
	a.LastSeen = time.UnixMilli(lastSeen).UTC()
	return a, nil
}

// ListAlerts returns alerts newest-first (by last_seen). limit <= 0 returns all.
func (s *Store) ListAlerts(limit int) ([]Alert, error) {
	q := `SELECT ` + alertColumns + ` FROM alerts ORDER BY last_seen DESC, id ASC`
	var args []any
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("integration: list alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, fmt.Errorf("integration: scan alert: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("integration: list alerts rows: %w", err)
	}
	return out, nil
}

// GetAlert returns the alert with the given ID; the bool is false when absent.
func (s *Store) GetAlert(id string) (Alert, bool, error) {
	q := `SELECT ` + alertColumns + ` FROM alerts WHERE id = ?`
	a, err := scanAlert(s.db.QueryRow(q, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, false, nil
	}
	if err != nil {
		return Alert{}, false, fmt.Errorf("integration: get alert: %w", err)
	}
	return a, true, nil
}

// RecordDeadLetter appends a dead-letter row: an alert that a given integration
// failed to deliver after retries.
func (s *Store) RecordDeadLetter(alertID, integrationName, errMsg string, ts time.Time) error {
	const q = `INSERT INTO dead_letters (alert_id, integration, error, ts) VALUES (?, ?, ?, ?)`
	if _, err := s.db.Exec(q, alertID, integrationName, errMsg, ts.UnixMilli()); err != nil {
		return fmt.Errorf("integration: record dead letter: %w", err)
	}
	return nil
}

// Close releases the database handle. It is idempotent (Manager.Stop may call it
// after callers already have).
func (s *Store) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.db.Close() })
	return s.closeErr
}
