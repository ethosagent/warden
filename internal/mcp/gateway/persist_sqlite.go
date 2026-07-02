package gateway

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/mcp"
	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
)

// SQLiteStore persists the MCP gateway's tool inventory and observed schema
// profiles in SQLite so they survive a proxy restart. It implements the
// gateway.Store interface and is OWNED by this package — the gateway no longer
// borrows the analytics store for persistence, which keeps analytics
// events-only and removes the layering inversion (analytics importing mcp).
//
// It does not own the *sql.DB: the handle is SHARED with the analytics events
// store (a single modernc SQLite connection, SetMaxOpenConns(1)) and passed in
// at construction. Opening a competing second read-write handle to the same
// file would fight that single connection, so the caller wires the one handle
// through both stores (events store built first so its tables exist, then this
// store migrates its MCP tables on the same handle). Closing the DB is the
// analytics store's responsibility; this type deliberately has no Close.
type SQLiteStore struct {
	db *sql.DB
}

var _ Store = (*SQLiteStore)(nil)

// NewSQLiteStore wraps a shared *sql.DB and ensures the MCP persistence tables
// exist. The handle must be the same one the analytics events store uses (see
// analytics.SQLiteStore.DB). migrate is idempotent (CREATE TABLE IF NOT
// EXISTS), so constructing over a database that already holds the tables is a
// no-op and safe on a persisted warden.db.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// migrate creates the MCP persistence tables. CREATE TABLE IF NOT EXISTS keeps
// this additive and idempotent on a pre-existing warden.db (the recipes persist
// it across restarts); it never touches the analytics events table, which the
// analytics store owns on the same handle.
func (s *SQLiteStore) migrate() error {
	const ddl = `
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
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("gateway: migrate mcp tables: %w", err)
	}
	return nil
}

// LoadMCPInventory returns the persisted MCP tool inventory. An empty store
// yields a nil slice and no error.
func (s *SQLiteStore) LoadMCPInventory() ([]InventoryItem, error) {
	const q = `SELECT name, has_description, schema_hash, first_seen, last_seen FROM mcp_tools`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("gateway: load mcp inventory: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []InventoryItem
	for rows.Next() {
		var (
			it        InventoryItem
			hasDesc   int
			firstSeen int64
			lastSeen  int64
		)
		if err := rows.Scan(&it.Name, &hasDesc, &it.InputSchemaHash, &firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("gateway: scan mcp inventory: %w", err)
		}
		it.HasDescription = hasDesc != 0
		it.FirstSeen = time.Unix(0, firstSeen).UTC()
		it.LastSeen = time.Unix(0, lastSeen).UTC()
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("gateway: rows mcp inventory: %w", err)
	}
	return out, nil
}

// SaveMCPInventory upserts the given inventory items by tool name. Existing rows
// are updated in place so the table converges on the gateway's live catalog.
func (s *SQLiteStore) SaveMCPInventory(items []InventoryItem) error {
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
			return fmt.Errorf("gateway: save mcp inventory: %w", err)
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
		return nil, fmt.Errorf("gateway: load mcp schemas: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]mcp.ToolProfileView)
	for rows.Next() {
		var (
			key     string
			profile string
		)
		if err := rows.Scan(&key, &profile); err != nil {
			return nil, fmt.Errorf("gateway: scan mcp schema: %w", err)
		}
		var view mcp.ToolProfileView
		if err := json.Unmarshal([]byte(profile), &view); err != nil {
			return nil, fmt.Errorf("gateway: unmarshal mcp schema %q: %w", key, err)
		}
		out[key] = view
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("gateway: rows mcp schemas: %w", err)
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
			return fmt.Errorf("gateway: marshal mcp schema %q: %w", key, err)
		}
		if _, err := s.db.Exec(up, key, string(blob), now); err != nil {
			return fmt.Errorf("gateway: save mcp schema %q: %w", key, err)
		}
	}
	return nil
}
