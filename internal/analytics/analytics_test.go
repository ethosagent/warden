package analytics

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
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

func TestMCPInventory_RoundTrip(t *testing.T) {
	s := newStore(t, 0)

	first := time.Unix(1000, 0).UTC()
	last := time.Unix(2000, 0).UTC()
	in := []gateway.InventoryItem{
		{Name: "read_file", HasDescription: true, InputSchemaHash: "abc123", FirstSeen: first, LastSeen: last},
		{Name: "send_email", HasDescription: false, InputSchemaHash: "", FirstSeen: first, LastSeen: last},
	}
	if err := s.SaveMCPInventory(in); err != nil {
		t.Fatalf("SaveMCPInventory: %v", err)
	}

	got, err := s.LoadMCPInventory()
	if err != nil {
		t.Fatalf("LoadMCPInventory: %v", err)
	}
	byName := map[string]gateway.InventoryItem{}
	for _, it := range got {
		byName[it.Name] = it
	}
	if len(byName) != 2 {
		t.Fatalf("loaded %d items, want 2: %+v", len(byName), got)
	}
	rf := byName["read_file"]
	if !rf.HasDescription || rf.InputSchemaHash != "abc123" {
		t.Fatalf("read_file = %+v, want HasDescription + hash abc123", rf)
	}
	if !rf.FirstSeen.Equal(first) || !rf.LastSeen.Equal(last) {
		t.Fatalf("read_file timestamps = %v/%v, want %v/%v", rf.FirstSeen, rf.LastSeen, first, last)
	}
	if byName["send_email"].HasDescription {
		t.Fatalf("send_email should have HasDescription=false")
	}

	// Upsert: re-save read_file with new metadata; row updates in place.
	newLast := time.Unix(3000, 0).UTC()
	if err := s.SaveMCPInventory([]gateway.InventoryItem{
		{Name: "read_file", HasDescription: true, InputSchemaHash: "def456", FirstSeen: first, LastSeen: newLast},
	}); err != nil {
		t.Fatalf("upsert SaveMCPInventory: %v", err)
	}
	got2, _ := s.LoadMCPInventory()
	if len(got2) != 2 {
		t.Fatalf("after upsert want 2 rows, got %d", len(got2))
	}
	for _, it := range got2 {
		if it.Name == "read_file" && (it.InputSchemaHash != "def456" || !it.LastSeen.Equal(newLast)) {
			t.Fatalf("upsert did not update read_file: %+v", it)
		}
	}
}

func TestMCPSchemas_RoundTrip(t *testing.T) {
	s := newStore(t, 0)

	in := map[string]mcp.ToolProfileView{
		"read_file\x00request": {Fields: map[string]mcp.FieldProfileView{
			"params.path": {Types: []string{"string"}, SeenCount: 3, Sensitivity: []string{"pii"}},
			"params.n":    {Types: []string{"number", "string"}, SeenCount: 5},
		}},
		"send_email\x00response": {Fields: map[string]mcp.FieldProfileView{
			"result.ok": {Types: []string{"bool"}, SeenCount: 1},
		}},
	}
	if err := s.SaveMCPSchemas(in); err != nil {
		t.Fatalf("SaveMCPSchemas: %v", err)
	}

	got, err := s.LoadMCPSchemas()
	if err != nil {
		t.Fatalf("LoadMCPSchemas: %v", err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("schema round-trip mismatch:\n got=%#v\nwant=%#v", got, in)
	}

	// Upsert one key; the other is untouched.
	in["read_file\x00request"].Fields["params.path"] = mcp.FieldProfileView{Types: []string{"string"}, SeenCount: 9}
	if err := s.SaveMCPSchemas(map[string]mcp.ToolProfileView{
		"read_file\x00request": in["read_file\x00request"],
	}); err != nil {
		t.Fatalf("upsert SaveMCPSchemas: %v", err)
	}
	got2, _ := s.LoadMCPSchemas()
	if got2["read_file\x00request"].Fields["params.path"].SeenCount != 9 {
		t.Fatalf("upsert did not update schema: %+v", got2["read_file\x00request"])
	}
	if _, ok := got2["send_email\x00response"]; !ok {
		t.Fatalf("upsert dropped an untouched key")
	}
}

func TestMCPPersistence_EmptyIsRobust(t *testing.T) {
	s := newStore(t, 0)

	// Loads on an empty store must not error.
	inv, err := s.LoadMCPInventory()
	if err != nil {
		t.Fatalf("LoadMCPInventory (empty): %v", err)
	}
	if len(inv) != 0 {
		t.Fatalf("empty inventory expected, got %+v", inv)
	}
	sch, err := s.LoadMCPSchemas()
	if err != nil {
		t.Fatalf("LoadMCPSchemas (empty): %v", err)
	}
	if len(sch) != 0 {
		t.Fatalf("empty schemas expected, got %+v", sch)
	}

	// Saving empty/nil is a no-op, not an error.
	if err := s.SaveMCPInventory(nil); err != nil {
		t.Fatalf("SaveMCPInventory(nil): %v", err)
	}
	if err := s.SaveMCPSchemas(nil); err != nil {
		t.Fatalf("SaveMCPSchemas(nil): %v", err)
	}
}

func TestMigrate_MCPTablesAdditiveAndIdempotent(t *testing.T) {
	// Start from an EXISTING events-only DB (no MCP tables) the way a pre-upgrade
	// Warden would have, then verify NewSQLiteStore adds the MCP tables without
	// disturbing the events row, and that re-running migrate is idempotent.
	dsn := "file:" + t.TempDir() + "/warden.db"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	const eventsOnly = `
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
    judge_reason    TEXT    NOT NULL DEFAULT '',
    tool            TEXT    NOT NULL DEFAULT '',
    reason          TEXT    NOT NULL DEFAULT ''
);`
	if _, err := db.Exec(eventsOnly); err != nil {
		t.Fatalf("events-only ddl: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO events
        (ts, domain, port, protocol, method, url, decision, response_status, secret_ref)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Unix(7000, 0).UnixNano(), "old.example", 443, "https", "GET",
		"https://old.example/", "allow", 200, ""); err != nil {
		t.Fatalf("insert old row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	s, err := NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatalf("NewSQLiteStore (migrate existing events DB): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Existing events row survived the additive migration.
	evs, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(evs) != 1 || evs[0].Domain != "old.example" {
		t.Fatalf("events row not preserved across MCP migration: %+v", evs)
	}

	// The new MCP tables exist and are usable.
	if err := s.SaveMCPInventory([]gateway.InventoryItem{
		{Name: "read_file", HasDescription: true, FirstSeen: time.Unix(1, 0).UTC(), LastSeen: time.Unix(2, 0).UTC()},
	}); err != nil {
		t.Fatalf("SaveMCPInventory after migrate: %v", err)
	}
	inv, _ := s.LoadMCPInventory()
	if len(inv) != 1 {
		t.Fatalf("MCP inventory not usable after migrate: %+v", inv)
	}

	// Idempotent: re-running migrate must not error or drop the data just saved.
	if err := s.migrate(); err != nil {
		t.Fatalf("re-running migrate must be idempotent: %v", err)
	}
	inv2, _ := s.LoadMCPInventory()
	if len(inv2) != 1 {
		t.Fatalf("re-migrate dropped MCP data: %+v", inv2)
	}
}
