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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
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
	// Tool is the MCP tool name (from ParseToolCall); "" for non-MCP events.
	// It powers per-tool call counts in the dashboard. A tool name is an
	// operator/server-defined identifier — metadata, not a body or secret — so it
	// is allowed in the store. It is deliberately NOT used as a metric label
	// (unbounded cardinality lives only here).
	Tool string
	// Reason is a short, bounded decision reason for the MCP path
	// (e.g. "mcp_tool_denied", "mcp_poisoning", "mcp_schema_drift"). It is a
	// separate field from JudgeReason: bounded enum metadata, never content.
	Reason string
	// CostUSD is the estimated cost of this call in US dollars, derived
	// heuristically from observed request/response byte sizes and a known
	// provider's pricing (see internal/cost). Zero for non-LLM-provider traffic
	// or when cost tracking is disabled. It is an estimate, never billing-grade.
	CostUSD float64
	// Provider is the LLM provider this call was attributed to for cost
	// estimation (e.g. "openai", "anthropic"); "" when no provider matched.
	Provider string
	// Compliance holds the framework control IDs this event maps to
	// (e.g. "mitre:T1048", "owasp:LLM01"), tagged by internal/audit's Mapper.
	// Bounded framework identifiers only — never content. Nil when compliance
	// tagging is disabled or no control applies.
	Compliance []string
	// ProxyID identifies the worker that produced this event in a fleet view. It
	// is populated only by an aggregating store (CentralStore) at read time; the
	// local SQLite store leaves it empty (single node) and never persists it.
	ProxyID string
}

// encodeCompliance joins compliance control IDs into a single comma-separated
// column value. Control IDs are bounded framework identifiers (e.g.
// "mitre:T1048") that never contain commas, so a comma join round-trips safely.
func encodeCompliance(ids []string) string {
	return strings.Join(ids, ",")
}

// decodeCompliance splits a stored compliance column back into control IDs.
// An empty column yields a nil slice (no mappings), not a one-element slice.
func decodeCompliance(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// EventFilter narrows a GetEvents query. Zero-valued fields are ignored.
type EventFilter struct {
	Domain   string
	Decision string
	// Protocol filters by transport/protocol (e.g. "mcp", "https") so the
	// dashboard can scope to MCP-only events.
	Protocol string
	// Tool filters by MCP tool name for per-tool drill-down.
	Tool  string
	Since time.Time
	// ProxyID filters to events from one worker in a fleet view. Honored by the
	// aggregating CentralStore; ignored by the local SQLite store (single node).
	ProxyID string
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

var (
	_ AnalyticsStore = (*SQLiteStore)(nil)
	// SQLiteStore also persists the MCP gateway's inventory + observed schema.
	_ gateway.Store = (*SQLiteStore)(nil)
)

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
    judge_reason    TEXT    NOT NULL DEFAULT '',
    tool            TEXT    NOT NULL DEFAULT '',
    reason          TEXT    NOT NULL DEFAULT '',
    cost_usd        REAL    NOT NULL DEFAULT 0,
    provider        TEXT    NOT NULL DEFAULT '',
    compliance      TEXT    NOT NULL DEFAULT ''
);`
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("analytics: migrate: %w", err)
	}
	// Additive, forward-only migrations for databases created before a column
	// existed. The recipes persist warden.db across restarts, so these ALTERs
	// must never drop data — they only add absent columns. addColumnIfAbsent is
	// guarded by PRAGMA table_info so re-running migrate is idempotent.
	for _, c := range []struct{ name, ddl string }{
		{"judge_reason", `ALTER TABLE events ADD COLUMN judge_reason TEXT NOT NULL DEFAULT ''`},
		{"tool", `ALTER TABLE events ADD COLUMN tool TEXT NOT NULL DEFAULT ''`},
		{"reason", `ALTER TABLE events ADD COLUMN reason TEXT NOT NULL DEFAULT ''`},
		{"cost_usd", `ALTER TABLE events ADD COLUMN cost_usd REAL NOT NULL DEFAULT 0`},
		{"provider", `ALTER TABLE events ADD COLUMN provider TEXT NOT NULL DEFAULT ''`},
		{"compliance", `ALTER TABLE events ADD COLUMN compliance TEXT NOT NULL DEFAULT ''`},
	} {
		if err := s.addColumnIfAbsent(c.name, c.ddl); err != nil {
			return err
		}
	}
	// MCP persistence tables: the gateway's tool inventory and observed schema
	// profiles. CREATE TABLE IF NOT EXISTS keeps this additive and idempotent on a
	// pre-existing warden.db (the recipes persist it across restarts).
	const mcpDDL = `
CREATE TABLE IF NOT EXISTS mcp_tools (
    name            TEXT PRIMARY KEY,
    has_description INTEGER NOT NULL DEFAULT 0,
    schema_hash     TEXT    NOT NULL DEFAULT '',
    first_seen      INTEGER NOT NULL DEFAULT 0,
    last_seen       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS mcp_tool_schema (
    key          TEXT PRIMARY KEY,
    profile_json TEXT    NOT NULL,
    updated_at   INTEGER NOT NULL DEFAULT 0
);`
	if _, err := s.db.Exec(mcpDDL); err != nil {
		return fmt.Errorf("analytics: migrate mcp tables: %w", err)
	}
	return nil
}

// addColumnIfAbsent runs an ALTER TABLE ADD COLUMN only when the column is not
// already present, checked via PRAGMA table_info(events). This keeps migration
// idempotent and forward-only without dropping data on persisted databases.
func (s *SQLiteStore) addColumnIfAbsent(name, ddl string) error {
	rows, err := s.db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		return fmt.Errorf("analytics: migrate table_info: %w", err)
	}
	present := false
	for rows.Next() {
		var (
			cid        int
			colName    string
			colType    string
			notNull    int
			dflt       sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &primaryKey); err != nil {
			_ = rows.Close()
			return fmt.Errorf("analytics: migrate scan table_info: %w", err)
		}
		if colName == name {
			present = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("analytics: migrate table_info rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("analytics: migrate table_info close: %w", err)
	}
	if present {
		return nil
	}
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("analytics: migrate add %s: %w", name, err)
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
	_, err := s.db.Exec(`INSERT INTO events `+insertColumns,
		e.Timestamp.UnixNano(), e.Domain, e.Port, e.Protocol, e.Method,
		e.URL, e.Decision, e.ResponseStatus, e.SecretRef, e.JudgeReason, e.Tool, e.Reason,
		e.CostUSD, e.Provider, encodeCompliance(e.Compliance))
	if err != nil {
		return fmt.Errorf("analytics: insert event: %w", err)
	}
	return s.Prune()
}

// insertColumns is the shared column list + placeholder tuple for an events
// INSERT, used by both StoreEvent and StoreEventsBatch so the two paths can
// never drift.
const insertColumns = `(ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// StoreEventsBatch inserts every event in a single transaction — one fsync for
// the whole batch instead of one per event — setting any zero timestamp to now,
// identical per-event handling to StoreEvent. It deliberately does NOT prune:
// the async writer amortizes retention off the write path via Prune, so a batch
// insert pays one commit and no per-event SELECT COUNT/DELETE. An empty batch is
// a no-op. On any error the transaction is rolled back so a batch is all-or-
// nothing (no partial audit trail).
func (s *SQLiteStore) StoreEventsBatch(evs []Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("analytics: begin batch: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO events ` + insertColumns)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("analytics: prepare batch: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	now := time.Now()
	for _, e := range evs {
		ts := e.Timestamp
		if ts.IsZero() {
			ts = now
		}
		if _, err := stmt.Exec(
			ts.UnixNano(), e.Domain, e.Port, e.Protocol, e.Method,
			e.URL, e.Decision, e.ResponseStatus, e.SecretRef, e.JudgeReason, e.Tool, e.Reason,
			e.CostUSD, e.Provider, encodeCompliance(e.Compliance)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("analytics: insert batch event: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("analytics: commit batch: %w", err)
	}
	return nil
}

// Prune deletes oldest events while the row count exceeds maxEvents. The
// synchronous StoreEvent runs it inline (INSERT+prune, back-compat); the async
// writer calls it off the write path so per-insert cost drops to the INSERT
// alone.
func (s *SQLiteStore) Prune() error {
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
	q := `SELECT ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance
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
			e          Event
			ts         int64
			compliance string
		)
		if err := rows.Scan(&ts, &e.Domain, &e.Port, &e.Protocol, &e.Method,
			&e.URL, &e.Decision, &e.ResponseStatus, &e.SecretRef, &e.JudgeReason, &e.Tool, &e.Reason,
			&e.CostUSD, &e.Provider, &compliance); err != nil {
			return nil, fmt.Errorf("analytics: scan: %w", err)
		}
		e.Compliance = decodeCompliance(compliance)
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
	const q = `SELECT id, ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance
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
			id         int64
			e          Event
			ts         int64
			compliance string
		)
		if err := rows.Scan(&id, &ts, &e.Domain, &e.Port, &e.Protocol, &e.Method,
			&e.URL, &e.Decision, &e.ResponseStatus, &e.SecretRef, &e.JudgeReason, &e.Tool, &e.Reason,
			&e.CostUSD, &e.Provider, &compliance); err != nil {
			return nil, nil, fmt.Errorf("analytics: scan oldest IDs: %w", err)
		}
		e.Compliance = decodeCompliance(compliance)
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

// LoadMCPInventory returns the persisted MCP tool inventory. An empty store
// yields a nil slice and no error.
func (s *SQLiteStore) LoadMCPInventory() ([]gateway.InventoryItem, error) {
	const q = `SELECT name, has_description, schema_hash, first_seen, last_seen FROM mcp_tools`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("analytics: load mcp inventory: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []gateway.InventoryItem
	for rows.Next() {
		var (
			it        gateway.InventoryItem
			hasDesc   int
			firstSeen int64
			lastSeen  int64
		)
		if err := rows.Scan(&it.Name, &hasDesc, &it.InputSchemaHash, &firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("analytics: scan mcp inventory: %w", err)
		}
		it.HasDescription = hasDesc != 0
		it.FirstSeen = time.Unix(0, firstSeen).UTC()
		it.LastSeen = time.Unix(0, lastSeen).UTC()
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: rows mcp inventory: %w", err)
	}
	return out, nil
}

// SaveMCPInventory upserts the given inventory items by tool name. Existing rows
// are updated in place so the table converges on the gateway's live catalog.
func (s *SQLiteStore) SaveMCPInventory(items []gateway.InventoryItem) error {
	if len(items) == 0 {
		return nil
	}
	const up = `INSERT INTO mcp_tools (name, has_description, schema_hash, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            has_description = excluded.has_description,
            schema_hash     = excluded.schema_hash,
            first_seen      = excluded.first_seen,
            last_seen       = excluded.last_seen`
	for _, it := range items {
		hasDesc := 0
		if it.HasDescription {
			hasDesc = 1
		}
		if _, err := s.db.Exec(up, it.Name, hasDesc, it.InputSchemaHash,
			it.FirstSeen.UnixNano(), it.LastSeen.UnixNano()); err != nil {
			return fmt.Errorf("analytics: save mcp inventory: %w", err)
		}
	}
	return nil
}

// LoadMCPSchemas returns the persisted observed-schema profiles keyed by
// "tool\x00direction". An empty store yields an empty (non-nil) map.
func (s *SQLiteStore) LoadMCPSchemas() (map[string]mcp.ToolProfileView, error) {
	const q = `SELECT key, profile_json FROM mcp_tool_schema`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("analytics: load mcp schemas: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]mcp.ToolProfileView)
	for rows.Next() {
		var (
			key     string
			profile string
		)
		if err := rows.Scan(&key, &profile); err != nil {
			return nil, fmt.Errorf("analytics: scan mcp schema: %w", err)
		}
		var view mcp.ToolProfileView
		if err := json.Unmarshal([]byte(profile), &view); err != nil {
			return nil, fmt.Errorf("analytics: unmarshal mcp schema %q: %w", key, err)
		}
		out[key] = view
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: rows mcp schemas: %w", err)
	}
	return out, nil
}

// SaveMCPSchemas upserts each observed-schema profile by its key. The profile is
// stored as JSON; the structural view carries no field values.
func (s *SQLiteStore) SaveMCPSchemas(schemas map[string]mcp.ToolProfileView) error {
	if len(schemas) == 0 {
		return nil
	}
	const up = `INSERT INTO mcp_tool_schema (key, profile_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            profile_json = excluded.profile_json,
            updated_at   = excluded.updated_at`
	now := time.Now().UnixNano()
	for key, view := range schemas {
		blob, err := json.Marshal(view)
		if err != nil {
			return fmt.Errorf("analytics: marshal mcp schema %q: %w", key, err)
		}
		if _, err := s.db.Exec(up, key, string(blob), now); err != nil {
			return fmt.Errorf("analytics: save mcp schema %q: %w", key, err)
		}
	}
	return nil
}
