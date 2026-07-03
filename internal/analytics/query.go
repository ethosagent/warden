package analytics

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// This file is the SHARED read-only SQL query surface (AnalyticsQuery) used by
// both SQLite-backed stores: FleetSQLiteStore on the control plane and the
// worker's local SQLiteStore. There is exactly ONE copy of the safety-critical
// pieces — the SELECT/WITH-only guard, the forbidden-keyword filter, the
// read-only connection opener, and the bounded query runner — so the two
// stores can never drift on safety properties.

// maxQueryRows is the hard upper bound on rows returned by Query, regardless of
// the caller-requested cap.
const maxQueryRows = 5000

// defaultQueryRows is the default row cap when Query is called with maxRows <= 0.
const defaultQueryRows = 1000

// queryTimeout bounds a single read-only query's execution time.
const queryTimeout = 5 * time.Second

// isMemoryDSN reports whether path names an in-memory SQLite database. A
// separate read-only connection cannot see another connection's in-memory DB,
// so for these we alias the rw handle for reads.
func isMemoryDSN(path string) bool {
	return path == ":memory:" || strings.HasPrefix(path, "file::memory:") ||
		strings.Contains(path, "mode=memory")
}

// readOnlyDSN derives the mode=ro DSN for a store's path, which callers hand
// us either as a plain filesystem path or as an existing "file:" URI (with or
// without query parameters).
func readOnlyDSN(path string) string {
	if strings.HasPrefix(path, "file:") {
		if strings.Contains(path, "?") {
			return path + "&mode=ro"
		}
		return path + "?mode=ro"
	}
	return "file:" + path + "?mode=ro"
}

// openReadOnlyDB opens the dedicated read-only query handle for the SQLite
// database at path (PRAGMA query_only = ON), used exclusively by Query so
// ad-hoc SQL can never mutate the store and never contends with the writer's
// single connection. For in-memory DSNs a separate ro handle would open a
// distinct, empty database, so it returns (rw, true) — the rw handle aliased,
// shared=true so Close knows not to close it twice. Even then, Query is
// guarded by isReadOnlySelect, so it cannot mutate the store.
func openReadOnlyDB(path string, rw *sql.DB) (ro *sql.DB, shared bool, err error) {
	if isMemoryDSN(path) {
		return rw, true, nil
	}
	ro, err = sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return nil, false, fmt.Errorf("analytics: open sqlite (ro): %w", err)
	}
	ro.SetMaxOpenConns(1)
	if _, err := ro.Exec(`PRAGMA query_only = ON;`); err != nil {
		_ = ro.Close()
		return nil, false, fmt.Errorf("analytics: sqlite query_only: %w", err)
	}
	return ro, false, nil
}

// forbiddenKeyword matches any mutating/side-effecting SQL keyword on a word
// boundary, case-insensitively. Query rejects statements containing any of these.
var forbiddenKeyword = regexp.MustCompile(`(?i)\b(ATTACH|PRAGMA|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|VACUUM|REINDEX)\b`)

// isReadOnlySelect validates that sqlText is a single read-only SELECT/WITH
// statement. It strips leading line (--) and block (/* */) comments, rejects any
// non-trailing ';' (single statement only), requires the first keyword to be
// SELECT or WITH, and rejects any forbidden mutating keyword. It returns a clear
// error describing the first rule violated.
func isReadOnlySelect(sqlText string) error {
	s := strings.TrimSpace(sqlText)
	// Strip leading line and block comments (repeatedly, since they can stack).
	for {
		if strings.HasPrefix(s, "--") {
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = strings.TrimSpace(s[i+1:])
				continue
			}
			s = ""
			break
		}
		if strings.HasPrefix(s, "/*") {
			if i := strings.Index(s, "*/"); i >= 0 {
				s = strings.TrimSpace(s[i+2:])
				continue
			}
			return fmt.Errorf("analytics: query rejected: unterminated block comment")
		}
		break
	}
	if s == "" {
		return fmt.Errorf("analytics: query rejected: empty statement")
	}
	// Single statement only: a ';' is allowed only as the trailing character.
	if i := strings.IndexByte(s, ';'); i >= 0 && i != len(s)-1 {
		return fmt.Errorf("analytics: query rejected: only a single statement is allowed")
	}
	// First keyword must be SELECT or WITH (case-insensitive).
	upper := strings.ToUpper(s)
	if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
		return fmt.Errorf("analytics: query rejected: only SELECT/WITH queries are allowed")
	}
	// No mutating keywords anywhere in the statement.
	if m := forbiddenKeyword.FindString(s); m != "" {
		return fmt.Errorf("analytics: query rejected: forbidden keyword %q", strings.ToUpper(m))
	}
	return nil
}

// runReadOnlyQuery runs a validated, timeout-bounded, read-only SELECT against
// ro (a handle from openReadOnlyDB) and returns a bounded, JSON-friendly result
// set. It is the single implementation behind every store's Query method.
func runReadOnlyQuery(ctx context.Context, ro *sql.DB, sqlText string, maxRows int) (QueryResult, error) {
	start := time.Now()
	if maxRows <= 0 {
		maxRows = defaultQueryRows
	}
	if maxRows > maxQueryRows {
		maxRows = maxQueryRows
	}
	if err := isReadOnlySelect(sqlText); err != nil {
		return QueryResult{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	rows, err := ro.QueryContext(ctx, sqlText)
	if err != nil {
		return QueryResult{}, fmt.Errorf("analytics: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return QueryResult{}, fmt.Errorf("analytics: query columns: %w", err)
	}

	res := QueryResult{Columns: cols, Rows: [][]any{}}
	// Read up to maxRows+1 rows so a maxRows+1th row flags truncation.
	for rows.Next() {
		if len(res.Rows) >= maxRows {
			res.Truncated = true
			break
		}
		scan := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range scan {
			ptrs[i] = &scan[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return QueryResult{}, fmt.Errorf("analytics: query scan: %w", err)
		}
		for i, v := range scan {
			// Convert []byte (RawBytes/text/blob) to string so JSON is readable.
			if b, ok := v.([]byte); ok {
				scan[i] = string(b)
			}
		}
		res.Rows = append(res.Rows, scan)
	}
	if err := rows.Err(); err != nil {
		return QueryResult{}, fmt.Errorf("analytics: query rows: %w", err)
	}
	res.ElapsedMs = time.Since(start).Milliseconds()
	return res, nil
}

// eventsTableSchema reports the queryable schema for the dashboard's query
// builder: only the events table, read live via PRAGMA table_info(events), so
// it always reflects THIS store's real columns (the local and fleet events
// tables differ).
func eventsTableSchema(db *sql.DB) SchemaInfo {
	info := SchemaInfo{Dialect: "sqlite"}
	rows, err := db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		return info
	}
	defer func() { _ = rows.Close() }()

	table := TableSchema{Name: "events"}
	for rows.Next() {
		var (
			cid        int
			name       string
			colType    string
			notNull    int
			dflt       sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &primaryKey); err != nil {
			return info
		}
		table.Columns = append(table.Columns, ColumnSchema{Name: name, Type: colType})
	}
	if err := rows.Err(); err != nil {
		return info
	}
	info.Tables = []TableSchema{table}
	return info
}
