package analytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newFleetStore(t *testing.T, retentionDays, maxEvents int) *FleetSQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet.db")
	s, err := NewFleetSQLiteStore(path, retentionDays, maxEvents)
	if err != nil {
		t.Fatalf("NewFleetSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func aggEvent(proxyID, agentID, domain, decision string, ts time.Time) AggregatedEvent {
	return AggregatedEvent{
		Event: Event{
			Timestamp: ts,
			Domain:    domain,
			Port:      443,
			Protocol:  "https",
			Decision:  decision,
		},
		ProxyID: proxyID,
		AgentID: agentID,
	}
}

func TestFleetSQLite_StoreAndGet_ProxyFilter(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	now := time.Now()
	if err := s.StoreAggregatedEvent(aggEvent("proxy-a", "agent-1", "a.example.com", "allow", now)); err != nil {
		t.Fatalf("store a: %v", err)
	}
	if err := s.StoreAggregatedEvent(aggEvent("proxy-b", "agent-2", "b.example.com", "deny", now)); err != nil {
		t.Fatalf("store b: %v", err)
	}

	all, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents(all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("GetEvents(all) len = %d, want 2", len(all))
	}
	// Newest first, ProxyID populated.
	if all[0].ProxyID == "" {
		t.Fatal("expected ProxyID to be set on returned events")
	}

	only, err := s.GetEvents(EventFilter{ProxyID: "proxy-a"})
	if err != nil {
		t.Fatalf("GetEvents(proxy-a): %v", err)
	}
	if len(only) != 1 {
		t.Fatalf("GetEvents(proxy-a) len = %d, want 1", len(only))
	}
	if only[0].ProxyID != "proxy-a" || only[0].Domain != "a.example.com" {
		t.Fatalf("proxy-a filter returned %+v", only[0])
	}
}

func TestFleetSQLite_GetAggregatedEvents_AgentFilter(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	now := time.Now()
	_ = s.StoreAggregatedEvent(aggEvent("proxy-a", "agent-1", "a.example.com", "allow", now))
	_ = s.StoreAggregatedEvent(aggEvent("proxy-a", "agent-2", "b.example.com", "allow", now))

	got, err := s.GetAggregatedEvents(AggregatedFilter{AgentID: "agent-2"})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("agent-2 filter len = %d, want 1", len(got))
	}
	if got[0].AgentID != "agent-2" || got[0].ProxyID != "proxy-a" {
		t.Fatalf("agent filter returned %+v", got[0])
	}
	if got[0].Event.ProxyID != "proxy-a" {
		t.Fatalf("expected embedded Event.ProxyID set, got %q", got[0].Event.ProxyID)
	}
}

func TestFleetSQLite_Retention_Age(t *testing.T) {
	s := newFleetStore(t, 7, 0) // 7-day retention
	old := time.Now().Add(-10 * 24 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	if err := s.StoreAggregatedEvent(aggEvent("p", "a", "old.example.com", "allow", old)); err != nil {
		t.Fatalf("store old: %v", err)
	}
	if err := s.StoreAggregatedEvent(aggEvent("p", "a", "recent.example.com", "allow", recent)); err != nil {
		t.Fatalf("store recent: %v", err)
	}
	if err := s.PruneExpired(); err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}

	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("after age prune len = %d, want 1", len(got))
	}
	if got[0].Domain != "recent.example.com" {
		t.Fatalf("retained wrong event: %q", got[0].Domain)
	}
}

func TestFleetSQLite_Retention_KeepForever(t *testing.T) {
	s := newFleetStore(t, 0, 0) // retentionDays=0 keeps all
	old := time.Now().Add(-3650 * 24 * time.Hour)
	if err := s.StoreAggregatedEvent(aggEvent("p", "a", "ancient.example.com", "allow", old)); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := s.PruneExpired(); err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("retentionDays=0 pruned an event: len = %d, want 1", len(got))
	}
}

func TestFleetSQLite_MaxEventsCap(t *testing.T) {
	s := newFleetStore(t, 0, 3)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		ev := aggEvent("p", "a", "d.example.com", "allow", base.Add(time.Duration(i)*time.Second))
		ev.Method = string(rune('A' + i)) // distinguish
		if err := s.StoreAggregatedEvent(ev); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("cap=3 kept %d events, want 3", len(got))
	}
	// The newest three (methods C, D, E) should remain; A and B pruned.
	kept := map[string]bool{}
	for _, e := range got {
		kept[e.Method] = true
	}
	if kept["A"] || kept["B"] {
		t.Fatalf("oldest events not pruned: %v", kept)
	}
}

func TestFleetSQLite_Query_Count(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	now := time.Now()
	_ = s.StoreAggregatedEvent(aggEvent("p", "a", "d.example.com", "allow", now))
	_ = s.StoreAggregatedEvent(aggEvent("p", "a", "d.example.com", "deny", now))

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
	// count(*) scans as int64.
	if got, ok := res.Rows[0][0].(int64); !ok || got != 2 {
		t.Fatalf("count = %v (%T), want 2", res.Rows[0][0], res.Rows[0][0])
	}
	if res.Truncated {
		t.Fatal("count query should not be truncated")
	}
}

func TestFleetSQLite_Query_Truncation(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	now := time.Now()
	for i := 0; i < 10; i++ {
		_ = s.StoreAggregatedEvent(aggEvent("p", "a", "d.example.com", "allow", now.Add(time.Duration(i)*time.Second)))
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

func TestFleetSQLite_Query_TextReadable(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	_ = s.StoreAggregatedEvent(aggEvent("proxy-x", "a", "d.example.com", "allow", time.Now()))
	res, err := s.Query(context.Background(), "SELECT proxy_id FROM events", 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
	if got, ok := res.Rows[0][0].(string); !ok || got != "proxy-x" {
		t.Fatalf("proxy_id = %v (%T), want string proxy-x", res.Rows[0][0], res.Rows[0][0])
	}
}

func TestFleetSQLite_Query_RejectsMutations(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	now := time.Now()
	_ = s.StoreAggregatedEvent(aggEvent("p", "a", "d.example.com", "allow", now))
	_ = s.StoreAggregatedEvent(aggEvent("p", "a", "d.example.com", "deny", now))

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

func TestFleetSQLite_Query_AllowsWith(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	_ = s.StoreAggregatedEvent(aggEvent("p", "a", "d.example.com", "allow", time.Now()))
	res, err := s.Query(context.Background(), "WITH x AS (SELECT id FROM events) SELECT count(*) FROM x", 0)
	if err != nil {
		t.Fatalf("Query(WITH): %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
}

func TestFleetSQLite_Schema(t *testing.T) {
	s := newFleetStore(t, 0, 0)
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
	for _, want := range []string{"id", "event_uid", "proxy_id", "agent_id", "ts", "domain", "decision"} {
		if !cols[want] {
			t.Errorf("schema missing column %q", want)
		}
	}
}

func TestIsReadOnlySelect_StripsComments(t *testing.T) {
	ok := []string{
		"SELECT 1",
		"select id from events",
		"-- comment\nSELECT 1",
		"/* block */ SELECT 1",
		"SELECT 1;", // trailing semicolon allowed
		"WITH x AS (SELECT 1) SELECT * FROM x",
	}
	for _, q := range ok {
		if err := isReadOnlySelect(q); err != nil {
			t.Errorf("isReadOnlySelect(%q) = %v, want nil", q, err)
		}
	}
	bad := []string{
		"SELECT 1; SELECT 2",
		"DELETE FROM events",
		"select * from events where id in (delete from events)",
	}
	for _, q := range bad {
		if err := isReadOnlySelect(q); err == nil {
			t.Errorf("isReadOnlySelect(%q) = nil, want rejection", q)
		}
	}
}
