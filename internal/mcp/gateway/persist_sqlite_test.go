package gateway

import (
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/mcp"
)

// newMCPStore opens an in-memory SQLite DB (single shared connection, matching
// the production handle the analytics events store owns) and constructs a
// gateway MCP store over it.
func newMCPStore(t *testing.T) *SQLiteStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return s
}

func TestMCPInventory_RoundTrip(t *testing.T) {
	s := newMCPStore(t)

	first := time.Unix(1000, 0).UTC()
	last := time.Unix(2000, 0).UTC()
	in := []InventoryItem{
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
	byName := map[string]InventoryItem{}
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
	if err := s.SaveMCPInventory([]InventoryItem{
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
	s := newMCPStore(t)

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
	s := newMCPStore(t)

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

// TestMCPMigrate_AdditiveAndIdempotent starts from an events-only DB (the way a
// pre-upgrade Warden, or the analytics events store, leaves the shared handle),
// then verifies NewSQLiteStore adds the MCP tables on that same handle without
// disturbing the events row, and that constructing again (re-running migrate) is
// idempotent and preserves saved MCP data.
func TestMCPMigrate_AdditiveAndIdempotent(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/warden.db"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	// The analytics events store owns this table on the shared handle; simulate it.
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
    secret_ref      TEXT    NOT NULL
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

	// Construct the gateway MCP store over the SAME handle: it adds the MCP tables.
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore (migrate existing events DB): %v", err)
	}

	// Existing events row survived the additive migration.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if n != 1 {
		t.Fatalf("events row not preserved across MCP migration: count=%d", n)
	}

	// The new MCP tables exist and are usable.
	if err := s.SaveMCPInventory([]InventoryItem{
		{Name: "read_file", HasDescription: true, FirstSeen: time.Unix(1, 0).UTC(), LastSeen: time.Unix(2, 0).UTC()},
	}); err != nil {
		t.Fatalf("SaveMCPInventory after migrate: %v", err)
	}
	inv, _ := s.LoadMCPInventory()
	if len(inv) != 1 {
		t.Fatalf("MCP inventory not usable after migrate: %+v", inv)
	}

	// Idempotent: constructing again (re-runs migrate) must not error or drop the
	// data just saved.
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("re-running migrate must be idempotent: %v", err)
	}
	inv2, _ := s.LoadMCPInventory()
	if len(inv2) != 1 {
		t.Fatalf("re-migrate dropped MCP data: %+v", inv2)
	}
}
