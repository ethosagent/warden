// Package analytics defines the AnalyticsStore interface and a pure-Go SQLite
// implementation (modernc.org/sqlite — never a CGo driver). It records one
// event per proxied decision.
//
// Logging hygiene is a core invariant: events carry headers/metadata and a
// secret-by-reference only. There is deliberately NO request/response body
// field on Event, so full bodies cannot be persisted.
package analytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	sqlite "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
	sqlite3 "modernc.org/sqlite/lib"
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
	// Reason is a short, bounded decision reason carried by EVERY deny event
	// (#409) — the one declared set in internal/denyreason (policy_no_match,
	// policy_denylist, rate_limited, time_window, method_not_allowed, …) plus
	// the MCP gateway's own bounded verdict reasons (mcp_tool_denied,
	// mcp_poisoning, mcp_schema_drift). It is a separate field from
	// JudgeReason: bounded enum metadata, never content — and never a raw
	// secret, body, or domain. Empty on allow events unless a monitor-mode
	// finding rode one (MCP/echo guard monitor reasons).
	Reason string
	// AddrClass is the bounded address class behind an SSRF dial refusal
	// ("loopback", "private", "link_local", "metadata", "multicast",
	// "reserved", "userinfo" — see proxy.SSRFError). It is set only on deny
	// events whose Reason is an ssrf_* enum, and never carries the resolved
	// address or the address list. Empty on every other event.
	AddrClass string
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

	// DataClasses holds the outbound-request DLP data classes detected in the
	// PRE-SWAP request body (the dotted taxonomy, e.g. "credentials", "pii.contact",
	// "source_code", "custom.<name>"). Bounded class names only — never matched
	// content, never offsets. Nil when DLP is off or found nothing.
	DataClasses []string
	// DLPAction is the DLP action for this request: allow/block/redact/monitor. In
	// monitor mode it is the WOULD-BE action (recorded but not enforced); in enforce
	// a block/redact rides the deny event. "monitor" also covers pure-observability
	// (no policy configured). "" when DLP is off. A small closed set — bounded
	// metadata, never content.
	DLPAction string
	// DLPRule is the bounded identifier of the DLP rule that decided this request
	// (e.g. "rule[1]", "classes[pii.contact]", "default"). "" when no policy applied.
	DLPRule string
	// DLPPartial flags that the request body was only partially scanned — an
	// over-cap body (first 1 MB scanned) or a non-scannable/binary content-type.
	// Honest coverage accounting: the bypass is recorded, never silent.
	DLPPartial bool
	// DLPEncoded flags a finding that appeared only in a decoded layer
	// (base64/URL) of the request body. Reserved for later phases; always false
	// in Phase 1.
	DLPEncoded bool

	// UID is a stable, content-free dedup identifier for central aggregation:
	// a truncated SHA-256 of (proxyID, local rowid), assigned by the worker's
	// SyncWorker just before a batch first leaves the node. Because it is
	// derived from the immutable local row id, the SAME event re-sent after a
	// lost ack carries the SAME UID, letting the control plane's fleet store
	// drop the duplicate — while two genuinely distinct events (even with
	// identical timestamp/domain/method) always get different UIDs. It is empty
	// for events that never cross the wire, for workers without a configured
	// proxy id, and for batches from pre-UID workers; empty UIDs are never
	// deduplicated. It is not persisted locally (it is recomputable from the
	// rowid) and is elided from JSON when empty, so signed receipts and
	// single-node APIs are unchanged.
	UID string `json:"event_uid,omitempty"`

	// LatencyMs is the total mediation latency in milliseconds for this request,
	// from request-read to response-relayed. It is a plain number — always-safe
	// metadata — and is populated on every event a request produces (allow and
	// deny alike), independent of whether DLP/swap were active.
	LatencyMs int64
	// SwappedRefs holds the PLACEHOLDER NAMES that were secret-swapped on this
	// request (e.g. "{{OPENAI_API_KEY}}"). These are the inert placeholder tokens
	// the agent already holds — NEVER secret values — so they are as safe to record
	// as Tool. Nil when nothing was swapped.
	SwappedRefs []string
	// Evidence holds bounded, MASKED evidence samples from scan/DLP findings, each
	// the value-free "••••<last4> (len N)" form scan's masker produces (opt-in via
	// scan.WithEvidence). It is NEVER the raw matched content, and the count is
	// capped upstream. Nil when evidence capture is off or nothing was found.
	Evidence []string

	// UserSub is the verified OIDC subject of the end user behind this request;
	// "" when the request was not attributed (identity mode off, or no token).
	// Stamped by the proxy (W-P1-VRFY-09); this package only stores it.
	UserSub string `json:"user_sub,omitempty"`
	// UserEmail is the verified email claim, "" when absent.
	UserEmail string `json:"user_email,omitempty"`
	// UserGroups are the verified group claims. Group names can contain commas
	// (LDAP DNs), so they are stored as a JSON array (EncodeGroups). Nil when none.
	UserGroups []string `json:"user_groups,omitempty"`
	// UserGroupsTruncated flags that UserGroups was cut at the verifier's cap.
	UserGroupsTruncated bool `json:"user_groups_truncated,omitempty"`
	// UserSID is the OIDC session id claim ("sid"), "" when absent.
	UserSID string `json:"user_sid,omitempty"`
	// IdentityStatus is the bounded verification status (e.g. "valid"); "" when
	// no token was presented. Bounded enum metadata, never token content.
	IdentityStatus string `json:"identity_status,omitempty"`
	// IdentityReason is the bounded reason behind a non-valid status. Never
	// token content.
	IdentityReason string `json:"identity_reason,omitempty"`
}

// EncodeGroups serialises a group list as a JSON array for a single column or
// field. A JSON array, never a comma join: LDAP DN group names contain commas.
// An empty list encodes to "". Shared with the fleet store (W-P1-VRFY-06).
func EncodeGroups(groups []string) string {
	if len(groups) == 0 {
		return ""
	}
	b, err := json.Marshal(groups)
	if err != nil { // a []string cannot fail to marshal
		return ""
	}
	return string(b)
}

// DecodeGroups parses an EncodeGroups value. "" or unparseable input yields a
// nil slice: an older or foreign row never errors a read.
func DecodeGroups(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil || len(out) == 0 {
		return nil
	}
	return out
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

// encodeDataClasses joins DLP data-class names into a single comma-separated
// column value. Class names are a small closed set (e.g. "credential_leak",
// "pii", "injection") that never contains a comma, so a comma join round-trips
// safely — the same convention encodeCompliance uses for control IDs.
func encodeDataClasses(classes []string) string {
	return strings.Join(classes, ",")
}

// decodeDataClasses splits a stored data_classes column back into class names.
// An empty column yields a nil slice (no classes), not a one-element slice.
func decodeDataClasses(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// encodeSwappedRefs joins swapped placeholder NAMES into a single comma-separated
// column value. Placeholder names are operator-defined tokens that by convention
// contain no comma (e.g. "{{OPENAI_API_KEY}}"), so a comma join round-trips safely —
// the same convention encodeDataClasses/encodeCompliance use. They are inert
// placeholder tokens the agent already holds, NEVER secret values.
func encodeSwappedRefs(names []string) string {
	return strings.Join(names, ",")
}

// decodeSwappedRefs splits a stored swapped_refs column back into placeholder
// names. An empty column yields a nil slice (nothing swapped), not a one-element
// slice.
func decodeSwappedRefs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// encodeEvidence joins bounded MASKED evidence samples into a single comma-
// separated column value. Each sample is the value-free "••••<last4> (len N)" form
// scan's masker produces — never raw matched content — and contains no comma, so a
// comma join round-trips safely. The number of samples is capped upstream.
func encodeEvidence(samples []string) string {
	return strings.Join(samples, ",")
}

// decodeEvidence splits a stored evidence column back into masked samples. An
// empty column yields a nil slice (no evidence), not a one-element slice.
func decodeEvidence(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// boolToInt maps a bool to the 0/1 INTEGER SQLite stores. modernc.org/sqlite
// (and database/sql) does not convert an INTEGER column into a *bool on scan, so
// bool event fields (DLPPartial/DLPEncoded) are persisted and read back through
// an int intermediate — never scanned directly into a bool.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
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
	// User narrows to one person: an exact user_sub match, or a case-insensitive
	// user_email match. Empty = no user filter. Always bound as a parameter.
	User string
	// ProxyID filters to events from one worker in a fleet view. Honored by the
	// aggregating CentralStore; ignored by the local SQLite store (single node).
	ProxyID string
	// Limit caps the number of rows returned (0 = no cap).
	Limit int
}

// userFilterSQL is the shared WHERE fragment for EventFilter.User; both SQLite
// stores bind the same value twice (sub, then email).
const userFilterSQL = " AND (user_sub = ? OR lower(user_email) = lower(?))"

// MatchesUser reports whether e belongs to f.User (true when no user filter is
// set). It is the in-memory twin of userFilterSQL, for stores and fakes that do
// not run SQL.
func (f EventFilter) MatchesUser(e Event) bool {
	if f.User == "" {
		return true
	}
	return e.UserSub == f.User || strings.EqualFold(e.UserEmail, f.User)
}

// defaultMaxEvents is the retention cap when none is supplied.
const defaultMaxEvents = 100_000

// SQLiteStore is a pure-Go SQLite-backed AnalyticsStore with size-capped
// retention: when the row count exceeds maxEvents, the oldest events are
// pruned first.
//
// Like FleetSQLiteStore it also exposes the read-only SQL query surface
// (AnalyticsQuery) that powers the dashboard's Explore tab on a worker. It
// holds two handles: the read/write handle for ingest/pruning (single
// connection, shared with the MCP gateway store via DB()), and a separate
// read-only handle (PRAGMA query_only = ON) used exclusively by Query — so
// ad-hoc SQL can never mutate the store and never contends with the async
// writer's single write connection on the request hot path.
type SQLiteStore struct {
	db        *sql.DB // read/write
	ro        *sql.DB // read-only query surface
	maxEvents int
	// sharedRO is true when ro aliases db (in-memory DSNs, where a separate ro
	// handle cannot see the same in-memory database). Close then closes db once.
	sharedRO bool
}

var (
	_ AnalyticsStore = (*SQLiteStore)(nil)
	_ AnalyticsQuery = (*SQLiteStore)(nil)
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
	// Read-only query handle (shared opener; see query.go), opened after migrate
	// so the database file exists. For in-memory DSNs it aliases the rw handle
	// (sharedRO=true).
	ro, shared, err := openReadOnlyDB(dsn, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	s.ro = ro
	s.sharedRO = shared
	return s, nil
}

// migrateBusyTimeout is the busy timeout migrate installs on the store's write
// handle: concurrent openers of one database file (a worker restart racing a
// sibling worker or a dashboard) queue on SQLite's lock instead of failing
// immediately. It is also the unit addColumnIfAbsent's retry budget is
// expressed in.
const migrateBusyTimeout = 5 * time.Second

// migrateMaxWait bounds the total time one migrate statement may keep retrying
// a busy database — several busy-timeout waits, so a flock of simultaneous
// openers drains instead of any single one of them giving up.
const migrateMaxWait = 3 * migrateBusyTimeout

// migrateRetryDelay spaces busy retries. The busy timeout does the real
// waiting inside SQLite; this just keeps the retry loop from spinning hot
// between waits.
const migrateRetryDelay = 50 * time.Millisecond

// migrate creates the events table. Note there is no body column by design.
func (s *SQLiteStore) migrate() error {
	// Serialize against concurrent openers before touching the schema (below).
	// The pragma itself takes no database lock, so it cannot fail busy.
	if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA busy_timeout = %d`, migrateBusyTimeout.Milliseconds())); err != nil {
		return fmt.Errorf("analytics: migrate busy_timeout: %w", err)
	}
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
    compliance      TEXT    NOT NULL DEFAULT '',
    data_classes    TEXT    NOT NULL DEFAULT '',
    dlp_action      TEXT    NOT NULL DEFAULT '',
    dlp_rule        TEXT    NOT NULL DEFAULT '',
    dlp_partial     INTEGER NOT NULL DEFAULT 0,
    dlp_encoded     INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    swapped_refs    TEXT    NOT NULL DEFAULT '',
    evidence        TEXT    NOT NULL DEFAULT '',
    addr_class      TEXT    NOT NULL DEFAULT '',
    user_sub        TEXT    NOT NULL DEFAULT '',
    user_email      TEXT    NOT NULL DEFAULT '',
    user_groups     TEXT    NOT NULL DEFAULT '',
    user_groups_truncated INTEGER NOT NULL DEFAULT 0,
    user_sid        TEXT    NOT NULL DEFAULT '',
    identity_status TEXT    NOT NULL DEFAULT '',
    identity_reason TEXT    NOT NULL DEFAULT ''
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
		{"data_classes", `ALTER TABLE events ADD COLUMN data_classes TEXT NOT NULL DEFAULT ''`},
		{"dlp_action", `ALTER TABLE events ADD COLUMN dlp_action TEXT NOT NULL DEFAULT ''`},
		{"dlp_rule", `ALTER TABLE events ADD COLUMN dlp_rule TEXT NOT NULL DEFAULT ''`},
		{"dlp_partial", `ALTER TABLE events ADD COLUMN dlp_partial INTEGER NOT NULL DEFAULT 0`},
		{"dlp_encoded", `ALTER TABLE events ADD COLUMN dlp_encoded INTEGER NOT NULL DEFAULT 0`},
		{"latency_ms", `ALTER TABLE events ADD COLUMN latency_ms INTEGER NOT NULL DEFAULT 0`},
		{"swapped_refs", `ALTER TABLE events ADD COLUMN swapped_refs TEXT NOT NULL DEFAULT ''`},
		{"evidence", `ALTER TABLE events ADD COLUMN evidence TEXT NOT NULL DEFAULT ''`},
		{"addr_class", `ALTER TABLE events ADD COLUMN addr_class TEXT NOT NULL DEFAULT ''`},
		{"user_sub", `ALTER TABLE events ADD COLUMN user_sub TEXT NOT NULL DEFAULT ''`},
		{"user_email", `ALTER TABLE events ADD COLUMN user_email TEXT NOT NULL DEFAULT ''`},
		{"user_groups", `ALTER TABLE events ADD COLUMN user_groups TEXT NOT NULL DEFAULT ''`},
		{"user_groups_truncated", `ALTER TABLE events ADD COLUMN user_groups_truncated INTEGER NOT NULL DEFAULT 0`},
		{"user_sid", `ALTER TABLE events ADD COLUMN user_sid TEXT NOT NULL DEFAULT ''`},
		{"identity_status", `ALTER TABLE events ADD COLUMN identity_status TEXT NOT NULL DEFAULT ''`},
		{"identity_reason", `ALTER TABLE events ADD COLUMN identity_reason TEXT NOT NULL DEFAULT ''`},
	} {
		if err := s.addColumnIfAbsent(c.name, c.ddl); err != nil {
			return err
		}
	}
	// The index needs user_sub to exist, so it comes after the column loop.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_user_sub_ts ON events (user_sub, ts)`); err != nil {
		return fmt.Errorf("analytics: migrate user index: %w", err)
	}
	return nil
}

// addColumnIfAbsent runs an ALTER TABLE ADD COLUMN only when the column is not
// already present, checked via PRAGMA table_info(events). This keeps migration
// idempotent and forward-only without dropping data on persisted databases.
//
// Two processes can open the same database at once (a worker restart racing a
// sibling worker or the dashboard): each may see the column absent and race to
// ALTER. Losing that race is the migration already done, so for EVERY column —
// the pre-#391 ones a very old database migrates through included — a
// "duplicate column name" failure re-checks table_info and returns nil, and a
// busy database is retried with a bounded backoff under the handle's busy
// timeout (migrate sets it) instead of surfaced.
func (s *SQLiteStore) addColumnIfAbsent(name, ddl string) error {
	deadline := time.Now().Add(migrateMaxWait)
	for {
		present, err := s.columnPresent(name)
		if err != nil {
			return err
		}
		if present {
			return nil
		}
		if _, err = s.db.Exec(ddl); err == nil {
			return nil
		}
		var se *sqlite.Error
		switch {
		case isBusyErr(err):
			// Another opener holds the write lock; wait it out and retry the
			// whole check+ALTER, bounded by migrateMaxWait.
			if time.Now().After(deadline) {
				return fmt.Errorf("analytics: migrate add %s: %w", name, err)
			}
			time.Sleep(migrateRetryDelay)
		case errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_ERROR:
			// "duplicate column name: <name>" — a concurrent opener ALTERed
			// between our table_info and this statement. The column existing
			// IS the migration's goal: confirm by re-checking rather than by
			// matching the error text, and succeed if it is there.
			if present, perr := s.columnPresent(name); perr == nil && present {
				return nil
			}
			return fmt.Errorf("analytics: migrate add %s: %w", name, err)
		default:
			return fmt.Errorf("analytics: migrate add %s: %w", name, err)
		}
	}
}

// columnPresent reports whether the events table has the given column, read
// via PRAGMA table_info(events). A busy database — a concurrent opener holding
// the write lock — is retried under the same bounded backoff as the ALTER.
func (s *SQLiteStore) columnPresent(name string) (present bool, err error) {
	deadline := time.Now().Add(migrateMaxWait)
	for {
		present, err = s.columnPresentOnce(name)
		if err == nil || !isBusyErr(err) || time.Now().After(deadline) {
			return present, err
		}
		time.Sleep(migrateRetryDelay)
	}
}

// columnPresentOnce is one table_info read for columnPresent.
func (s *SQLiteStore) columnPresentOnce(name string) (bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		return false, fmt.Errorf("analytics: migrate table_info: %w", err)
	}
	defer func() { _ = rows.Close() }()
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
			return false, fmt.Errorf("analytics: migrate scan table_info: %w", err)
		}
		if colName == name {
			present = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("analytics: migrate table_info rows: %w", err)
	}
	return present, nil
}

// isBusyErr reports whether err is SQLite's busy/locked family — a lock held
// by a concurrent opener — extended codes included.
func isBusyErr(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() & 0xff {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
		return true
	}
	return false
}

// Close releases both database handles.
func (s *SQLiteStore) Close() error {
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
// are shared with FleetSQLiteStore (query.go), so both stores enforce the same
// safety properties: SELECT/WITH-only, single statement, no mutating keywords,
// a dedicated read-only connection, a query timeout, and a row cap.
func (s *SQLiteStore) Query(ctx context.Context, sqlText string, maxRows int) (QueryResult, error) {
	return runReadOnlyQuery(ctx, s.ro, sqlText, maxRows)
}

// Schema reports the queryable schema for the dashboard's query builder. It
// covers only the events table, read via PRAGMA table_info(events), so it
// reflects the LOCAL events columns (which differ from the fleet table).
func (s *SQLiteStore) Schema() SchemaInfo {
	return eventsTableSchema(s.db)
}

// StoreEvent persists an event and enforces the retention cap, pruning the
// oldest events first when over the cap.
func (s *SQLiteStore) StoreEvent(e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO events `+insertColumns,
		e.Timestamp.UnixNano(), e.Domain, e.Port, e.Protocol, e.Method,
		e.URL, e.Decision, e.ResponseStatus, e.SecretRef, e.JudgeReason, e.Tool, e.Reason,
		e.CostUSD, e.Provider, encodeCompliance(e.Compliance),
		encodeDataClasses(e.DataClasses), e.DLPAction, e.DLPRule,
		boolToInt(e.DLPPartial), boolToInt(e.DLPEncoded),
		e.LatencyMs, encodeSwappedRefs(e.SwappedRefs), encodeEvidence(e.Evidence),
		e.AddrClass,
		e.UserSub, e.UserEmail, EncodeGroups(e.UserGroups), boolToInt(e.UserGroupsTruncated),
		e.UserSID, e.IdentityStatus, e.IdentityReason)
	if err != nil {
		return fmt.Errorf("analytics: insert event: %w", err)
	}
	return s.Prune()
}

// insertColumns is the shared column list + placeholder tuple for an events
// INSERT, used by both StoreEvent and StoreEventsBatch so the two paths can
// never drift.
const insertColumns = `(ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance, data_classes, dlp_action, dlp_rule, dlp_partial, dlp_encoded, latency_ms, swapped_refs, evidence, addr_class, user_sub, user_email, user_groups, user_groups_truncated, user_sid, identity_status, identity_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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
			e.CostUSD, e.Provider, encodeCompliance(e.Compliance),
			encodeDataClasses(e.DataClasses), e.DLPAction, e.DLPRule,
			boolToInt(e.DLPPartial), boolToInt(e.DLPEncoded),
			e.LatencyMs, encodeSwappedRefs(e.SwappedRefs), encodeEvidence(e.Evidence),
			e.AddrClass,
			e.UserSub, e.UserEmail, EncodeGroups(e.UserGroups), boolToInt(e.UserGroupsTruncated),
			e.UserSID, e.IdentityStatus, e.IdentityReason); err != nil {
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
	q := `SELECT ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance, data_classes, dlp_action, dlp_rule, dlp_partial, dlp_encoded, latency_ms, swapped_refs, evidence, addr_class, user_sub, user_email, user_groups, user_groups_truncated, user_sid, identity_status, identity_reason
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
		return nil, fmt.Errorf("analytics: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Event
	for rows.Next() {
		var (
			e           Event
			ts          int64
			compliance  string
			dataClasses string
			dlpPartial  int
			dlpEncoded  int
			swappedRefs string
			evidence    string
			userGroups  string
			groupsTrunc int
		)
		if err := rows.Scan(&ts, &e.Domain, &e.Port, &e.Protocol, &e.Method,
			&e.URL, &e.Decision, &e.ResponseStatus, &e.SecretRef, &e.JudgeReason, &e.Tool, &e.Reason,
			&e.CostUSD, &e.Provider, &compliance,
			&dataClasses, &e.DLPAction, &e.DLPRule, &dlpPartial, &dlpEncoded,
			&e.LatencyMs, &swappedRefs, &evidence, &e.AddrClass,
			&e.UserSub, &e.UserEmail, &userGroups, &groupsTrunc, &e.UserSID, &e.IdentityStatus, &e.IdentityReason); err != nil {
			return nil, fmt.Errorf("analytics: scan: %w", err)
		}
		e.Compliance = decodeCompliance(compliance)
		e.DataClasses = decodeDataClasses(dataClasses)
		e.DLPPartial = dlpPartial != 0
		e.DLPEncoded = dlpEncoded != 0
		e.SwappedRefs = decodeSwappedRefs(swappedRefs)
		e.Evidence = decodeEvidence(evidence)
		e.UserGroups = DecodeGroups(userGroups)
		e.UserGroupsTruncated = groupsTrunc != 0
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
	const q = `SELECT id, ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason, tool, reason, cost_usd, provider, compliance, data_classes, dlp_action, dlp_rule, dlp_partial, dlp_encoded, latency_ms, swapped_refs, evidence, addr_class, user_sub, user_email, user_groups, user_groups_truncated, user_sid, identity_status, identity_reason
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
			id          int64
			e           Event
			ts          int64
			compliance  string
			dataClasses string
			dlpPartial  int
			dlpEncoded  int
			swappedRefs string
			evidence    string
			userGroups  string
			groupsTrunc int
		)
		if err := rows.Scan(&id, &ts, &e.Domain, &e.Port, &e.Protocol, &e.Method,
			&e.URL, &e.Decision, &e.ResponseStatus, &e.SecretRef, &e.JudgeReason, &e.Tool, &e.Reason,
			&e.CostUSD, &e.Provider, &compliance,
			&dataClasses, &e.DLPAction, &e.DLPRule, &dlpPartial, &dlpEncoded,
			&e.LatencyMs, &swappedRefs, &evidence, &e.AddrClass,
			&e.UserSub, &e.UserEmail, &userGroups, &groupsTrunc, &e.UserSID, &e.IdentityStatus, &e.IdentityReason); err != nil {
			return nil, nil, fmt.Errorf("analytics: scan oldest IDs: %w", err)
		}
		e.Compliance = decodeCompliance(compliance)
		e.DataClasses = decodeDataClasses(dataClasses)
		e.DLPPartial = dlpPartial != 0
		e.DLPEncoded = dlpEncoded != 0
		e.SwappedRefs = decodeSwappedRefs(swappedRefs)
		e.Evidence = decodeEvidence(evidence)
		e.UserGroups = DecodeGroups(userGroups)
		e.UserGroupsTruncated = groupsTrunc != 0
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

// DB exposes the underlying SQLite handle so a sibling store can share the same
// single connection (SetMaxOpenConns(1)) instead of opening a competing second
// read-write handle to the same file. This is the "small provider" the
// hot-path-scalability plan sanctions for the analytics/MCP layering split:
// internal/mcp/gateway.NewSQLiteStore takes this handle to own MCP persistence,
// so internal/analytics stays events-only and imports nothing under
// internal/mcp. The caller must build the analytics (events) store first — its
// tables exist before the gateway store migrates its MCP tables on the shared
// handle — and must not Close the DB out from under the borrower (the analytics
// store owns the handle's lifecycle).
func (s *SQLiteStore) DB() *sql.DB { return s.db }
