package analytics

import (
	"context"
	"fmt"
	"time"
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
	// Now is the store's clock (the usage rollup's day clamp and prune); nil
	// means time.Now. The control plane passes its injected clock.
	Now func() time.Time
}

// NewFleetStore builds the store selected by cfg.Provider. "memory" returns an
// in-memory CentralStore; "sqlite" (the default when Provider is "") returns a
// FleetSQLiteStore; "postgres" is not yet implemented.
func NewFleetStore(cfg FleetConfig) (FleetStore, error) {
	switch cfg.Provider {
	case "memory":
		c := NewCentralStore(cfg.MaxEvents)
		if cfg.Now != nil {
			c.now = cfg.Now
		}
		return c, nil
	case "", "sqlite":
		st, err := NewFleetSQLiteStore(cfg.SQLitePath, cfg.RetentionDays, cfg.MaxEvents)
		if err != nil {
			return nil, err
		}
		if cfg.Now != nil {
			st.now = cfg.Now
		}
		return st, nil
	case "postgres":
		return nil, fmt.Errorf("analytics: provider %q not yet implemented", cfg.Provider)
	default:
		return nil, fmt.Errorf("analytics: unknown provider %q", cfg.Provider)
	}
}

// ReplayScanner is an optional FleetStore capability: it streams the events a
// policy replay needs, newest first, in bounded pages on the store's read-only
// handle, so a large replay never holds the ingest connection. Events carry only
// ts, domain, port, protocol, method, decision and the user columns: no URL,
// header or secret reference. At most limit events are delivered; fn returning
// an error stops the scan with that error.
type ReplayScanner interface {
	ScanReplayEvents(ctx context.Context, since time.Time, limit int, fn func(Event) error) error
}

// ScanReplay delivers up to limit events at or after since, newest first, to
// fn: through the store's ReplayScanner when it has one, else one GetEvents.
func ScanReplay(ctx context.Context, s FleetStore, since time.Time, limit int, fn func(Event) error) error {
	if rs, ok := s.(ReplayScanner); ok {
		return rs.ScanReplayEvents(ctx, since, limit, fn)
	}
	events, err := s.GetEvents(EventFilter{Since: since, Limit: limit})
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Match ScanReplayEvents: MCP rows are not replayed and no URL is read.
		if e.Protocol == "mcp" {
			continue
		}
		e.URL = ""
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}
