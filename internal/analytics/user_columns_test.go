package analytics

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const dnGroup = "cn=eng,ou=groups,dc=corp"

var userColumns = []string{"user_sub", "user_email", "user_groups", "user_groups_truncated", "user_sid", "identity_status", "identity_reason"}

func attributedEvent() Event {
	return Event{
		Timestamp: time.Unix(7000, 0).UTC(),
		Domain:    "api.openai.com", Port: 443, Protocol: "https", Method: "GET",
		URL: "https://api.openai.com/", Decision: "allow",
		UserSub: "sub-1", UserEmail: "a@corp.example",
		UserGroups:          []string{dnGroup, "plain"},
		UserGroupsTruncated: true,
		UserSID:             "sid-1", IdentityStatus: "valid", IdentityReason: "ok",
	}
}

func hasColumn(t *testing.T, s *SQLiteStore, name string) bool {
	t.Helper()
	ok, err := s.columnPresent(name)
	if err != nil {
		t.Fatalf("columnPresent(%s): %v", name, err)
	}
	return ok
}

// An old warden.db with rows opens with the user columns added, old rows keep
// their defaults, and a second open is a no-op.
func TestMigrateUserColumns(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "warden.db")
	createLegacyEventsDB(t, dsn)

	s, err := NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	for _, c := range userColumns {
		if !hasColumn(t, s, c) {
			t.Errorf("column %s not added", c)
		}
	}
	var idx int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_events_user_sub_ts'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("index idx_events_user_sub_ts count=%d err=%v", idx, err)
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil || len(got) != 1 {
		t.Fatalf("legacy row lost: %v %v", got, err)
	}
	if got[0].Domain != "legacy.example" || got[0].UserSub != "" || got[0].UserGroups != nil ||
		got[0].UserGroupsTruncated || got[0].IdentityStatus != "" {
		t.Fatalf("legacy row defaults wrong: %+v", got[0])
	}
	if err := s.StoreEvent(attributedEvent()); err != nil {
		t.Fatalf("store after migrate: %v", err)
	}
	_ = s.Close()

	s2, err := NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatalf("second open must be a no-op: %v", err)
	}
	defer func() { _ = s2.Close() }()
	got, err = s2.GetEvents(EventFilter{})
	if err != nil || len(got) != 2 {
		t.Fatalf("rows after reopen: %d %v", len(got), err)
	}
}

// A group name with commas survives every write and read path unchanged.
func TestUserGroupsRoundTrip(t *testing.T) {
	want := attributedEvent()

	check := func(t *testing.T, got Event) {
		t.Helper()
		if !reflect.DeepEqual(got.UserGroups, want.UserGroups) {
			t.Errorf("UserGroups = %q, want %q", got.UserGroups, want.UserGroups)
		}
		if got.UserSub != want.UserSub || got.UserEmail != want.UserEmail || got.UserSID != want.UserSID ||
			got.IdentityStatus != want.IdentityStatus || got.IdentityReason != want.IdentityReason ||
			got.UserGroupsTruncated != want.UserGroupsTruncated {
			t.Errorf("identity fields lost: %+v", got)
		}
	}

	for name, store := range map[string]func(*SQLiteStore) error{
		"StoreEvent":       func(s *SQLiteStore) error { return s.StoreEvent(want) },
		"StoreEventsBatch": func(s *SQLiteStore) error { return s.StoreEventsBatch([]Event{want}) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t, 0)
			if err := store(s); err != nil {
				t.Fatal(err)
			}
			got, err := s.GetEvents(EventFilter{})
			if err != nil || len(got) != 1 {
				t.Fatalf("GetEvents: %v %v", got, err)
			}
			check(t, got[0])
			_, oldest, err := s.GetOldestEventIDs(10)
			if err != nil || len(oldest) != 1 {
				t.Fatalf("GetOldestEventIDs: %v %v", oldest, err)
			}
			check(t, oldest[0])
		})
	}
}

// An unattributed event reads back with nil groups and zero identity fields.
func TestUserFieldsEmptyByDefault(t *testing.T) {
	s := newTestStore(t, 0)
	if err := s.StoreEvent(Event{Domain: "x.com", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetEvents(EventFilter{})
	if len(got) != 1 || got[0].UserGroups != nil || got[0].UserSub != "" || got[0].UserGroupsTruncated {
		t.Fatalf("unexpected identity on plain event: %+v", got)
	}
}

// SyncWorker reads the user fields out of GetOldestEventIDs and the HTTP
// remote carries them to an ingest endpoint.
func TestSyncWorkerCarriesIdentity(t *testing.T) {
	s := newTestStore(t, 0)
	if err := s.StoreEvent(attributedEvent()); err != nil {
		t.Fatal(err)
	}

	mock := &mockRemote{}
	w := NewSyncWorker(s, mock, "proxy-1", 5, 100, time.Hour)
	if err := w.SyncOnce(); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(mock.batches) != 1 || len(mock.batches[0]) != 1 {
		t.Fatalf("batches = %v", mock.batches)
	}
	e := mock.batches[0][0]
	if e.UserSub != "sub-1" || e.IdentityStatus != "valid" || !reflect.DeepEqual(e.UserGroups, []string{dnGroup, "plain"}) {
		t.Fatalf("SyncWorker dropped identity: %+v", e)
	}

	// Over the wire: worker HTTP remote -> ingest handler.
	cs := NewCentralStore(0)
	h := NewIngestHandler(cs, StaticTokenAuthorizer(""))
	var seen []Event
	h.SetOnEvents(func(_ string, evs []Event) { seen = evs })
	srv := newIngestServer(t, h)
	rs, err := NewHTTPRemoteStore(srv.URL, "", "proxy-1", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StoreEvent(attributedEvent()); err != nil {
		t.Fatal(err)
	}
	if err := NewSyncWorker(s, rs, "proxy-1", 5, 100, time.Hour).SyncOnce(); err != nil {
		t.Fatalf("SyncOnce http: %v", err)
	}
	if len(seen) != 1 || seen[0].UserSub != "sub-1" || seen[0].UserEmail != "a@corp.example" ||
		seen[0].UserSID != "sid-1" || !seen[0].UserGroupsTruncated || seen[0].IdentityReason != "ok" ||
		!reflect.DeepEqual(seen[0].UserGroups, []string{dnGroup, "plain"}) {
		t.Fatalf("ingest endpoint did not receive identity: %+v", seen)
	}
}

func newIngestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}
