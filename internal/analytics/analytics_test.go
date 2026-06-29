package analytics

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T, max int) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(":memory:", max)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStoreAndGet_RoundTrip(t *testing.T) {
	s := newStore(t, 0)
	e := Event{
		Timestamp:      time.Unix(1000, 0).UTC(),
		Domain:         "api.openai.com",
		Port:           443,
		Protocol:       "https",
		Method:         "POST",
		URL:            "https://api.openai.com/v1/chat",
		Decision:       "allow",
		ResponseStatus: 200,
		SecretRef:      "sha256:abc last4:1234 len:20",
	}
	if err := s.StoreEvent(e); err != nil {
		t.Fatalf("StoreEvent: %v", err)
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if !reflect.DeepEqual(got[0], e) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got[0], e)
	}
}

func TestStoreEvent_FillsTimestamp(t *testing.T) {
	s := newStore(t, 0)
	if err := s.StoreEvent(Event{Domain: "x", Decision: "deny"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetEvents(EventFilter{})
	if got[0].Timestamp.IsZero() {
		t.Error("expected StoreEvent to fill a zero timestamp")
	}
}

func TestGetEvents_Filters(t *testing.T) {
	s := newStore(t, 0)
	base := time.Unix(2000, 0).UTC()
	_ = s.StoreEvent(Event{Timestamp: base, Domain: "a.com", Decision: "allow"})
	_ = s.StoreEvent(Event{Timestamp: base.Add(time.Second), Domain: "b.com", Decision: "deny"})
	_ = s.StoreEvent(Event{Timestamp: base.Add(2 * time.Second), Domain: "a.com", Decision: "deny"})

	byDomain, _ := s.GetEvents(EventFilter{Domain: "a.com"})
	if len(byDomain) != 2 {
		t.Errorf("domain filter len = %d, want 2", len(byDomain))
	}
	byDecision, _ := s.GetEvents(EventFilter{Decision: "deny"})
	if len(byDecision) != 2 {
		t.Errorf("decision filter len = %d, want 2", len(byDecision))
	}
	since, _ := s.GetEvents(EventFilter{Since: base.Add(2 * time.Second)})
	if len(since) != 1 {
		t.Errorf("since filter len = %d, want 1", len(since))
	}
	limited, _ := s.GetEvents(EventFilter{Limit: 1})
	if len(limited) != 1 {
		t.Errorf("limit len = %d, want 1", len(limited))
	}
	// Newest first.
	all, _ := s.GetEvents(EventFilter{})
	if all[0].Domain != "a.com" || all[0].Decision != "deny" {
		t.Errorf("ordering: first = %+v, want newest (a.com/deny)", all[0])
	}
}

// Retention: oldest events pruned first when over the cap.
func TestStoreEvent_PrunesOldestFirst(t *testing.T) {
	s := newStore(t, 3)
	base := time.Unix(3000, 0).UTC()
	for i := 0; i < 5; i++ {
		if err := s.StoreEvent(Event{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Domain:    "d.com",
			URL:       string(rune('A' + i)),
			Decision:  "allow",
		}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("count = %d, want 3 (capped)", n)
	}
	got, _ := s.GetEvents(EventFilter{})
	// Newest three are URLs E, D, C (oldest A, B pruned).
	want := []string{"E", "D", "C"}
	for i, w := range want {
		if got[i].URL != w {
			t.Errorf("row %d url = %q, want %q (oldest should be pruned)", i, got[i].URL, w)
		}
	}
}

// Invariant: Event has no body field — full bodies cannot be persisted.
func TestEvent_HasNoBodyField(t *testing.T) {
	tp := reflect.TypeOf(Event{})
	for i := 0; i < tp.NumField(); i++ {
		name := strings.ToLower(tp.Field(i).Name)
		if strings.Contains(name, "body") || strings.Contains(name, "payload") {
			t.Fatalf("Event must not carry a body/payload field; found %q", tp.Field(i).Name)
		}
	}
}

func TestNewSQLiteStore_BadDSN(t *testing.T) {
	// A path under a nonexistent directory cannot be opened/migrated.
	if _, err := NewSQLiteStore("/nonexistent-dir-xyz/warden.db", 0); err == nil {
		t.Fatal("expected error for unopenable DSN")
	}
}

// MCP metadata fields (Tool, Reason) round-trip through the store. Both are
// bounded, content-free identifiers — not bodies, not secrets.
func TestStoreAndGet_MCPFields_RoundTrip(t *testing.T) {
	s := newStore(t, 0)
	e := Event{
		Timestamp: time.Unix(4000, 0).UTC(),
		Domain:    "mcp.internal",
		Port:      8080,
		Protocol:  "mcp",
		Method:    "tools/call",
		URL:       "mcp://mcp.internal/tools/call",
		Decision:  "deny",
		Tool:      "read_file",
		Reason:    "mcp_tool_denied",
	}
	if err := s.StoreEvent(e); err != nil {
		t.Fatalf("StoreEvent: %v", err)
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Tool != "read_file" {
		t.Errorf("Tool = %q, want %q", got[0].Tool, "read_file")
	}
	if got[0].Reason != "mcp_tool_denied" {
		t.Errorf("Reason = %q, want %q", got[0].Reason, "mcp_tool_denied")
	}
	if !reflect.DeepEqual(got[0], e) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got[0], e)
	}
}

// The dashboard aggregates MCP events by protocol and per-tool; the filter must
// support both protocol="mcp" and an optional tool filter.
func TestGetEvents_ProtocolAndToolFilters(t *testing.T) {
	s := newStore(t, 0)
	base := time.Unix(5000, 0).UTC()
	_ = s.StoreEvent(Event{Timestamp: base, Protocol: "mcp", Tool: "read_file", Decision: "allow"})
	_ = s.StoreEvent(Event{Timestamp: base.Add(time.Second), Protocol: "mcp", Tool: "exec_cmd", Decision: "deny"})
	_ = s.StoreEvent(Event{Timestamp: base.Add(2 * time.Second), Protocol: "https", Decision: "allow"})

	byProto, _ := s.GetEvents(EventFilter{Protocol: "mcp"})
	if len(byProto) != 2 {
		t.Errorf("protocol filter len = %d, want 2", len(byProto))
	}
	byTool, _ := s.GetEvents(EventFilter{Protocol: "mcp", Tool: "read_file"})
	if len(byTool) != 1 {
		t.Errorf("tool filter len = %d, want 1", len(byTool))
	}
	if len(byTool) == 1 && byTool[0].Tool != "read_file" {
		t.Errorf("tool filter returned %q, want read_file", byTool[0].Tool)
	}
}

// Migration path: a DB created with the pre-MCP-columns schema must gain the
// tool/reason columns via additive ALTER TABLE without error and without
// dropping existing rows. Re-running migrate must stay idempotent.
func TestMigrate_AddsMCPColumns_PreservesData(t *testing.T) {
	// Open a raw DB and create the OLD schema (no tool/reason columns), then
	// insert a row the way an older Warden would have.
	dsn := "file:" + t.TempDir() + "/warden.db"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	const oldDDL = `
CREATE TABLE events (
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
	if _, err := db.Exec(oldDDL); err != nil {
		t.Fatalf("old ddl: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO events
        (ts, domain, port, protocol, method, url, decision, response_status, secret_ref, judge_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Unix(6000, 0).UnixNano(), "old.example", 443, "https", "GET",
		"https://old.example/", "allow", 200, "", ""); err != nil {
		t.Fatalf("insert old row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	// Now open through NewSQLiteStore, which runs migrate() and must ADD the
	// new columns to the existing table without wiping the old row.
	s, err := NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatalf("NewSQLiteStore (migrate existing): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Existing row survived and the new columns default to "".
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (existing row must survive migration)", len(got))
	}
	if got[0].Domain != "old.example" {
		t.Errorf("Domain = %q, want old.example", got[0].Domain)
	}
	if got[0].Tool != "" || got[0].Reason != "" {
		t.Errorf("migrated row Tool/Reason = %q/%q, want empty defaults", got[0].Tool, got[0].Reason)
	}

	// New writes carry the new columns.
	if err := s.StoreEvent(Event{Protocol: "mcp", Tool: "list_dir", Reason: "mcp_poisoning", Decision: "deny"}); err != nil {
		t.Fatalf("StoreEvent after migrate: %v", err)
	}
	mcp, _ := s.GetEvents(EventFilter{Protocol: "mcp"})
	if len(mcp) != 1 || mcp[0].Tool != "list_dir" || mcp[0].Reason != "mcp_poisoning" {
		t.Fatalf("post-migrate mcp row = %+v, want tool=list_dir reason=mcp_poisoning", mcp)
	}

	// Idempotent: running migrate again (re-open) must not error.
	if err := s.migrate(); err != nil {
		t.Fatalf("re-running migrate must be idempotent: %v", err)
	}
}
