package analytics

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// legacyEventsSchemaDDL is the events table EXACTLY as main created it before
// #391 added addr_class — the schema of commit c1c1010 ("fix: six audit bugs —
// alerts, explore, webhook signing, dedup, dashboard"), the last commit to
// touch the events DDL before this change. It is copied verbatim from that
// commit's migrate() so the migration tests below exercise the real upgrade
// path of an existing deployment, not a hand-waved approximation.
const legacyEventsSchemaDDL = `
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
    evidence        TEXT    NOT NULL DEFAULT ''
);`

// createLegacyEventsDB builds a database holding only the pre-#391 schema and
// one legacy row the way that Warden version would have written it.
func createLegacyEventsDB(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(legacyEventsSchemaDDL); err != nil {
		t.Fatalf("legacy ddl: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO events
        (ts, domain, port, protocol, method, url, decision, response_status, secret_ref)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Unix(6000, 0).UnixNano(), "legacy.example", 443, "https", "GET",
		"https://legacy.example/", "allow", 200, ""); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}
}

// The SSRF address class (#391) persists and reads back through the local
// SQLite store, and stays empty on events that are not dial refusals.
func TestSQLiteStore_AddrClassRoundTrip(t *testing.T) {
	store, err := NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()

	in := Event{
		Domain:    "loopback.test",
		Port:      443,
		Protocol:  "https",
		Decision:  "deny",
		Reason:    "ssrf_blocked",
		AddrClass: "loopback",
	}
	if err := store.StoreEvent(in); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := store.StoreEvent(Event{Domain: "api.openai.com", Protocol: "https", Decision: "allow"}); err != nil {
		t.Fatalf("store plain: %v", err)
	}

	got, err := store.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	// Newest first: [0] is the plain allow, [1] the refusal.
	if got[1].AddrClass != "loopback" || got[1].Reason != "ssrf_blocked" {
		t.Fatalf("refusal round-trip = reason %q, addr class %q", got[1].Reason, got[1].AddrClass)
	}
	if got[0].AddrClass != "" {
		t.Fatalf("non-refusal event grew an addr class: %q", got[0].AddrClass)
	}

	// The sync path (GetOldestEventIDs) reads the same column back.
	ids, evs, err := store.GetOldestEventIDs(2)
	if err != nil {
		t.Fatalf("oldest: %v", err)
	}
	if len(ids) != 2 || evs[0].AddrClass != "loopback" {
		t.Fatalf("oldest-event read lost the addr class: %+v", evs[0])
	}
}

// An existing database created by the pre-#391 schema (no addr_class column)
// must open cleanly through NewSQLiteStore: the additive migration adds the
// column, the old rows survive with an empty AddrClass, and new refusal events
// round-trip the class. The recipes persist warden.db across restarts, so this
// is the upgrade path every real deployment takes.
func TestSQLiteStore_LegacyDBMigratesPreservesRows(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "warden.db")
	createLegacyEventsDB(t, dsn)

	s, err := NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatalf("NewSQLiteStore (migrate legacy db): %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// The legacy row survived migration and reads back with an empty AddrClass.
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (the legacy row must survive migration)", len(got))
	}
	if got[0].Domain != "legacy.example" {
		t.Errorf("Domain = %q, want legacy.example", got[0].Domain)
	}
	if got[0].AddrClass != "" {
		t.Errorf("migrated row AddrClass = %q, want empty default", got[0].AddrClass)
	}

	// A new refusal event carries its class through both read paths.
	in := Event{
		Domain:    "loopback.test",
		Port:      443,
		Protocol:  "https",
		Decision:  "deny",
		Reason:    "ssrf_blocked",
		AddrClass: "loopback",
	}
	if err := s.StoreEvent(in); err != nil {
		t.Fatalf("StoreEvent after migrate: %v", err)
	}
	got, err = s.GetEvents(EventFilter{Decision: "deny"})
	if err != nil {
		t.Fatalf("GetEvents (deny): %v", err)
	}
	if len(got) != 1 || got[0].AddrClass != "loopback" || got[0].Reason != "ssrf_blocked" {
		t.Fatalf("post-migrate refusal = %+v, want addr_class=loopback reason=ssrf_blocked", got)
	}
	_, evs, err := s.GetOldestEventIDs(2)
	if err != nil {
		t.Fatalf("GetOldestEventIDs: %v", err)
	}
	if len(evs) != 2 || evs[0].AddrClass != "" || evs[1].AddrClass != "loopback" {
		t.Fatalf("oldest-event read across the migration boundary: %+v", evs)
	}
}

// Two processes can open the same database at once (a worker restart racing a
// dashboard or a sibling worker): each sees the column absent via PRAGMA
// table_info and races to ALTER. Every opener must succeed — a loser's
// "duplicate column name" is the winner already having done the migration, not
// a failure, and a busy database is waited out, not surfaced.
func TestSQLiteStore_ConcurrentOpenLegacyDB(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "warden.db")
	createLegacyEventsDB(t, dsn)

	const openers = 8
	errs := make([]error, openers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			s, err := NewSQLiteStore(dsn, 0)
			if err != nil {
				errs[i] = fmt.Errorf("open: %w", err)
				return
			}
			defer func() { _ = s.Close() }()
			// Every opener must be able to WRITE the new column too, not just
			// survive the migrate: the migration is pointless otherwise.
			if err := s.StoreEvent(Event{
				Domain:    fmt.Sprintf("opener-%d.test", i),
				Protocol:  "https",
				Decision:  "deny",
				Reason:    "ssrf_blocked",
				AddrClass: "loopback",
			}); err != nil {
				errs[i] = fmt.Errorf("store after migrate: %w", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("opener %d: %v", i, err)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	// One final opener reads it all back: the legacy row (empty class) and one
	// refusal per opener (their own class).
	s, err := NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != openers+1 {
		t.Fatalf("len = %d, want %d (legacy row + one per opener)", len(got), openers+1)
	}
	legacy := got[len(got)-1] // oldest last
	if legacy.Domain != "legacy.example" || legacy.AddrClass != "" {
		t.Fatalf("legacy row = %+v, want legacy.example with empty addr class", legacy)
	}
	for _, e := range got[:len(got)-1] {
		if e.Reason != "ssrf_blocked" || e.AddrClass != "loopback" {
			t.Fatalf("opener event = %+v, want ssrf_blocked/loopback", e)
		}
	}
}
