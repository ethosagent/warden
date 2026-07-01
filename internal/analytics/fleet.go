package analytics

import (
	"context"
	"fmt"
)

// FleetStore is the control plane's persistent analytics store: it ingests
// aggregated (multi-worker) events and serves the dashboard's read view.
type FleetStore interface {
	StoreAggregatedEvent(AggregatedEvent) error
	// GetEvents honors the filter (including ProxyID), returns newest first, and
	// sets Event.ProxyID on each returned event.
	GetEvents(EventFilter) ([]Event, error)
	Close() error
}

// AnalyticsQuery is the read-only SQL query surface. It is an optional
// capability: only SQL-backed stores implement it (the in-memory CentralStore
// does not).
type AnalyticsQuery interface {
	Query(ctx context.Context, sql string, maxRows int) (QueryResult, error)
	Schema() SchemaInfo
}

// QueryResult is a bounded, JSON-friendly result set from a read-only query.
type QueryResult struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Truncated bool     `json:"truncated"`
	ElapsedMs int64    `json:"elapsedMs"`
}

// SchemaInfo describes the queryable tables for the dashboard's query builder.
type SchemaInfo struct {
	Dialect string        `json:"dialect"` // "sqlite"
	Tables  []TableSchema `json:"tables"`
}

// TableSchema is one queryable table and its columns.
type TableSchema struct {
	Name    string         `json:"name"`
	Columns []ColumnSchema `json:"columns"`
}

// ColumnSchema is one column's name and declared type.
type ColumnSchema struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// FleetConfig selects and configures the fleet store.
type FleetConfig struct {
	// Provider is "memory" | "sqlite" (default "sqlite"). "postgres" returns a
	// "not yet implemented" error.
	Provider string
	// SQLitePath is the database path for the sqlite provider.
	SQLitePath string
	// RetentionDays prunes events older than this many days (0 = keep forever).
	RetentionDays int
	// MaxEvents is a hard row cap (0 = a sane default, reuses defaultMaxEvents).
	MaxEvents int
}

// NewFleetStore builds the store selected by cfg.Provider. "memory" returns an
// in-memory CentralStore; "sqlite" (the default when Provider is "") returns a
// FleetSQLiteStore; "postgres" is not yet implemented.
func NewFleetStore(cfg FleetConfig) (FleetStore, error) {
	switch cfg.Provider {
	case "memory":
		return NewCentralStore(cfg.MaxEvents), nil
	case "", "sqlite":
		return NewFleetSQLiteStore(cfg.SQLitePath, cfg.RetentionDays, cfg.MaxEvents)
	case "postgres":
		return nil, fmt.Errorf("analytics: provider %q not yet implemented", cfg.Provider)
	default:
		return nil, fmt.Errorf("analytics: unknown provider %q", cfg.Provider)
	}
}
