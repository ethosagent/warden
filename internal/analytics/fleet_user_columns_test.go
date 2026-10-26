package analytics

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// createLegacyFleetDB writes a fleet DB as it was before the user columns: the
// original events table plus one row.
func createLegacyFleetDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	_, err = db.Exec(`
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_uid TEXT,
    proxy_id TEXT NOT NULL DEFAULT '', agent_id TEXT NOT NULL DEFAULT '',
    ts INTEGER NOT NULL, domain TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL DEFAULT '', response_status INTEGER NOT NULL DEFAULT 0,
    secret_ref TEXT NOT NULL DEFAULT '', judge_reason TEXT NOT NULL DEFAULT '',
    tool TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '',
    cost_usd REAL NOT NULL DEFAULT 0, provider TEXT NOT NULL DEFAULT '',
    compliance TEXT NOT NULL DEFAULT '');
INSERT INTO events (event_uid, proxy_id, ts, domain, decision) VALUES ('u1', 'proxy-a', 5000, 'legacy.example', 'allow');`)
	if err != nil {
		t.Fatal(err)
	}
}

func fleetColumns(t *testing.T, s *FleetSQLiteStore) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, c := range userColumns {
		ok, err := s.columnPresent(c)
		if err != nil {
			t.Fatal(err)
		}
		out[c] = ok
	}
	return out
}

// An old fleet DB with rows opens with the user columns and index added, rows
// intact, and a second open is a no-op.
func TestFleetMigrateUserColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.db")
	createLegacyFleetDB(t, path)

	s, err := NewFleetSQLiteStore(path, 0, 0)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	for c, ok := range fleetColumns(t, s) {
		if !ok {
			t.Errorf("column %s not added", c)
		}
	}
	var idx int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_events_user_sub_ts'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("index count=%d err=%v", idx, err)
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil || len(got) != 1 {
		t.Fatalf("legacy row lost: %v %v", got, err)
	}
	if got[0].Domain != "legacy.example" || got[0].UserSub != "" || got[0].UserGroups != nil ||
		got[0].UserGroupsTruncated || got[0].IdentityStatus != "" {
		t.Fatalf("legacy defaults wrong: %+v", got[0])
	}
	if err := s.StoreAggregatedEvent(AggregatedEvent{Event: attributedEvent(), ProxyID: "proxy-a"}); err != nil {
		t.Fatalf("store after migrate: %v", err)
	}
	_ = s.Close()

	s2, err := NewFleetSQLiteStore(path, 0, 0)
	if err != nil {
		t.Fatalf("second open must be a no-op: %v", err)
	}
	defer func() { _ = s2.Close() }()
	got, err = s2.GetEvents(EventFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("rows after reopen: %d %v", len(got), err)
	}
	if err := s2.addColumnIfAbsent("user_sub", `ALTER TABLE events ADD COLUMN user_sub TEXT`); err != nil {
		t.Fatalf("addColumnIfAbsent on present column: %v", err)
	}
}

// addColumnIfAbsent surfaces a failing ALTER that did not add the column.
func TestFleetAddColumnIfAbsentBadDDL(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	if err := s.addColumnIfAbsent("nope", `ALTER TABLE missing ADD COLUMN nope TEXT`); err == nil {
		t.Fatal("expected error from bad DDL")
	}
}

// An attributed event goes SyncWorker -> HTTP -> ingest handler ->
// FleetSQLiteStore and reads back from GetEvents and GetAggregatedEvents with
// identical user fields, including a comma-bearing DN group.
func TestSyncIdentityFields(t *testing.T) {
	local := newTestStore(t, 0)
	want := attributedEvent()
	if err := local.StoreEvent(want); err != nil {
		t.Fatal(err)
	}
	fleet := newFleetStore(t, 0, 0)
	srv := newIngestServer(t, NewIngestHandler(fleet, ""))
	rs, err := NewHTTPRemoteStore(srv.URL, "", "proxy-1", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewSyncWorker(local, rs, "proxy-1", 5, 100, time.Hour).SyncOnce(); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	got, err := fleet.GetEvents(EventFilter{})
	if err != nil || len(got) != 1 {
		t.Fatalf("GetEvents: %v %v", got, err)
	}
	agg, err := fleet.GetAggregatedEvents(AggregatedFilter{})
	if err != nil || len(agg) != 1 {
		t.Fatalf("GetAggregatedEvents: %v %v", agg, err)
	}
	for name, e := range map[string]Event{"GetEvents": got[0], "GetAggregatedEvents": agg[0].Event} {
		if e.UserSub != want.UserSub || e.UserEmail != want.UserEmail || e.UserSID != want.UserSID ||
			e.IdentityStatus != want.IdentityStatus || e.IdentityReason != want.IdentityReason ||
			e.UserGroupsTruncated != want.UserGroupsTruncated {
			t.Errorf("%s lost identity fields: %+v", name, e)
		}
		if !reflect.DeepEqual(e.UserGroups, []string{dnGroup, "plain"}) {
			t.Errorf("%s UserGroups = %q", name, e.UserGroups)
		}
	}
}

// A worker that predates identity sends none; the CP stores and reads empty
// user fields without error.
func TestFleetEventWithoutIdentity(t *testing.T) {
	fleet := newFleetStore(t, 0, 0)
	if err := fleet.StoreAggregatedEvent(aggEvent("proxy-a", "a", "x.com", "allow", time.Now())); err != nil {
		t.Fatal(err)
	}
	got, err := fleet.GetEvents(EventFilter{})
	if err != nil || len(got) != 1 {
		t.Fatalf("GetEvents: %v %v", got, err)
	}
	if got[0].UserSub != "" || got[0].UserEmail != "" || got[0].UserGroups != nil ||
		got[0].UserGroupsTruncated || got[0].UserSID != "" || got[0].IdentityStatus != "" || got[0].IdentityReason != "" {
		t.Fatalf("unexpected identity: %+v", got[0])
	}
}
