package analytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// newFileStore builds a FILE-backed local SQLiteStore so the dedicated
// read-only query handle (a second sql.DB on the same file) is exercised,
// mirroring how a worker runs in production.
func newFileStore(t *testing.T, max int) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.db")
	s, err := NewSQLiteStore(path, max)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func localEvent(domain, decision string, ts time.Time) Event {
	return Event{
		Timestamp: ts,
		Domain:    domain,
		Port:      443,
		Protocol:  "https",
		Decision:  decision,
	}
}

func TestSQLiteStore_Query_Count(t *testing.T) {
	s := newFileStore(t, 0)
	now := time.Now()
	if err := s.StoreEvent(localEvent("d.example.com", "allow", now)); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := s.StoreEvent(localEvent("d.example.com", "deny", now)); err != nil {
		t.Fatalf("store: %v", err)
	}

	res, err := s.Query(context.Background(), "SELECT count(*) AS n FROM events", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Columns) != 1 || res.Columns[0] != "n" {
		t.Fatalf("columns = %v", res.Columns)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
	if got, ok := res.Rows[0][0].(int64); !ok || got != 2 {
		t.Fatalf("count = %v (%T), want 2", res.Rows[0][0], res.Rows[0][0])
	}
	if res.Truncated {
		t.Fatal("count query should not be truncated")
	}
}

func TestSQLiteStore_Query_Truncation(t *testing.T) {
	s := newFileStore(t, 0)
	now := time.Now()
	for i := 0; i < 10; i++ {
		if err := s.StoreEvent(localEvent("d.example.com", "allow", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	res, err := s.Query(context.Background(), "SELECT id FROM events", 3)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Rows) != 3 {
		t.Fatalf("rows = %d, want 3 (capped)", len(res.Rows))
	}
	if !res.Truncated {
		t.Fatal("expected Truncated=true")
	}
}

func TestSQLiteStore_Query_TextReadable(t *testing.T) {
	s := newFileStore(t, 0)
	if err := s.StoreEvent(localEvent("text.example.com", "allow", time.Now())); err != nil {
		t.Fatalf("store: %v", err)
	}
	res, err := s.Query(context.Background(), "SELECT domain FROM events", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
	if got, ok := res.Rows[0][0].(string); !ok || got != "text.example.com" {
		t.Fatalf("domain = %v (%T), want string text.example.com", res.Rows[0][0], res.Rows[0][0])
	}
}

func TestSQLiteStore_Query_RejectsMutations(t *testing.T) {
	s := newFileStore(t, 0)
	now := time.Now()
	if err := s.StoreEvent(localEvent("d.example.com", "allow", now)); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := s.StoreEvent(localEvent("d.example.com", "deny", now)); err != nil {
		t.Fatalf("store: %v", err)
	}

	before, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents before: %v", err)
	}

	bad := []string{
		"DELETE FROM events",
		"DROP TABLE events",
		"PRAGMA table_info(events)",
		"ATTACH DATABASE 'x.db' AS x",
		"SELECT 1; DELETE FROM events",
		"UPDATE events SET decision = 'allow'",
		"INSERT INTO events (ts) VALUES (1)",
		"REPLACE INTO events (ts) VALUES (1)",
		"VACUUM",
		"", // empty
		"-- just a comment",
	}
	for _, q := range bad {
		if _, err := s.Query(context.Background(), q, 0); err == nil {
			t.Errorf("Query(%q) = nil error, want rejection", q)
		}
	}

	// Prove read-only: row count unchanged after all rejected queries.
	after, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents after: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("row count changed: before=%d after=%d", len(before), len(after))
	}
}

func TestSQLiteStore_Query_AllowsWith(t *testing.T) {
	s := newFileStore(t, 0)
	if err := s.StoreEvent(localEvent("d.example.com", "allow", time.Now())); err != nil {
		t.Fatalf("store: %v", err)
	}
	res, err := s.Query(context.Background(), "WITH x AS (SELECT id FROM events) SELECT count(*) FROM x", 0)
	if err != nil {
		t.Fatalf("Query(WITH): %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
}

// TestSQLiteStore_Query_InMemory exercises the sharedRO path (in-memory DSN
// aliases the rw handle): queries still run and mutations are still rejected.
func TestSQLiteStore_Query_InMemory(t *testing.T) {
	s := newStore(t, 0) // ":memory:" helper from analytics_test.go
	if err := s.StoreEvent(localEvent("mem.example.com", "allow", time.Now())); err != nil {
		t.Fatalf("store: %v", err)
	}
	res, err := s.Query(context.Background(), "SELECT domain FROM events", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
	if _, err := s.Query(context.Background(), "DELETE FROM events", 0); err == nil {
		t.Fatal("in-memory Query(DELETE) = nil error, want rejection")
	}
}

// TestSQLiteStore_Schema asserts the schema endpoint reflects the LOCAL events
// table: worker-only columns (data_classes, dlp_action, latency_ms, ...) are
// present, and fleet-only columns (proxy_id, agent_id, event_uid) are NOT.
func TestSQLiteStore_Schema(t *testing.T) {
	s := newFileStore(t, 0)
	info := s.Schema()
	if info.Dialect != "sqlite" {
		t.Fatalf("dialect = %q, want sqlite", info.Dialect)
	}
	if len(info.Tables) != 1 || info.Tables[0].Name != "events" {
		t.Fatalf("tables = %+v, want single events table", info.Tables)
	}
	cols := map[string]bool{}
	for _, c := range info.Tables[0].Columns {
		cols[c.Name] = true
	}
	for _, want := range []string{"id", "ts", "domain", "decision", "compliance",
		"data_classes", "dlp_action", "dlp_rule", "latency_ms", "swapped_refs", "evidence"} {
		if !cols[want] {
			t.Errorf("schema missing local column %q", want)
		}
	}
	for _, fleetOnly := range []string{"proxy_id", "agent_id", "event_uid"} {
		if cols[fleetOnly] {
			t.Errorf("local schema unexpectedly reports fleet column %q", fleetOnly)
		}
	}
}

// TestSQLiteStore_Query_SeesWriterRows proves the dedicated read-only handle
// reads rows committed through the read/write handle (same file, two handles),
// the arrangement the worker dashboard relies on while the async writer owns
// the rw connection.
func TestSQLiteStore_Query_SeesWriterRows(t *testing.T) {
	s := newFileStore(t, 0)
	for i := 0; i < 3; i++ {
		if err := s.StoreEvent(localEvent("rw.example.com", "allow", time.Now())); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	res, err := s.Query(context.Background(), "SELECT count(*) FROM events", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got, ok := res.Rows[0][0].(int64); !ok || got != 3 {
		t.Fatalf("ro handle sees %v rows, want 3", res.Rows[0][0])
	}
}
