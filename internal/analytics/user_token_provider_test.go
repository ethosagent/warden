package analytics

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An event with UserTokenProvider round-trips through both stores on every
// write and read path, and a neighbouring event without it keeps empty
// defaults (W-P3-PUS-10).
func TestUserTokenProviderColumn(t *testing.T) {
	now := time.Now()
	with := Event{Timestamp: now, Domain: "gmail.googleapis.com", Decision: "allow",
		Provider: "openai", UserTokenProvider: "google", UserTokenRetried: true}
	plain := Event{Timestamp: now.Add(time.Second), Domain: "plain.example", Decision: "allow"}
	check := func(name string, evs []Event) {
		t.Helper()
		if len(evs) != 2 {
			t.Fatalf("%s: %d events, want 2", name, len(evs))
		}
		for _, e := range evs {
			switch e.Domain {
			case "gmail.googleapis.com":
				if e.UserTokenProvider != "google" || !e.UserTokenRetried || e.Provider != "openai" {
					t.Errorf("%s: lost per-user fields or touched Provider: %+v", name, e)
				}
			case "plain.example":
				if e.UserTokenProvider != "" || e.UserTokenRetried {
					t.Errorf("%s: plain event picked up fields: %+v", name, e)
				}
			}
		}
	}

	t.Run("sqlite", func(t *testing.T) {
		s := newTestStore(t, 0)
		if err := s.StoreEvent(with); err != nil {
			t.Fatal(err)
		}
		if err := s.StoreEventsBatch([]Event{plain}); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetEvents(EventFilter{})
		if err != nil {
			t.Fatal(err)
		}
		check("GetEvents", got)
		_, oldest, err := s.GetOldestEventIDs(10)
		if err != nil {
			t.Fatal(err)
		}
		check("GetOldestEventIDs", oldest)
	})

	t.Run("fleet", func(t *testing.T) {
		s := newFleetStore(t, 0, 0)
		for _, e := range []Event{with, plain} {
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e, ProxyID: "p1", AgentID: "a1"}); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.GetEvents(EventFilter{})
		if err != nil {
			t.Fatal(err)
		}
		check("fleet GetEvents", got)
		agg, err := s.GetAggregatedEvents(AggregatedFilter{})
		if err != nil {
			t.Fatal(err)
		}
		check("fleet GetAggregatedEvents", []Event{agg[0].Event, agg[1].Event})
	})

	t.Run("ingest", func(t *testing.T) {
		fleet := newFleetStore(t, 0, 0)
		srv := newIngestServer(t, NewIngestHandler(fleet, StaticTokenAuthorizer("")))
		rs, err := NewHTTPRemoteStore(srv.URL, "", "proxy-1", srv.Client())
		if err != nil {
			t.Fatal(err)
		}
		local := newTestStore(t, 0)
		for _, e := range []Event{with, plain} {
			if err := local.StoreEvent(e); err != nil {
				t.Fatal(err)
			}
		}
		if err := NewSyncWorker(local, rs, "proxy-1", 5, 100, time.Hour).SyncOnce(); err != nil {
			t.Fatalf("SyncOnce: %v", err)
		}
		got, err := fleet.GetEvents(EventFilter{})
		if err != nil {
			t.Fatal(err)
		}
		check("ingest", got)
	})
}

// Databases created before the columns existed gain them without losing rows,
// on both stores; a second open is a no-op.
func TestUserTokenProviderMigration(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		dsn := "file:" + filepath.Join(t.TempDir(), "warden.db")
		createLegacyEventsDB(t, dsn)
		s, err := NewSQLiteStore(dsn, 0)
		if err != nil {
			t.Fatalf("open legacy: %v", err)
		}
		for _, c := range []string{"user_token_provider", "user_token_retried"} {
			if !hasColumn(t, s, c) {
				t.Errorf("column %s not added", c)
			}
		}
		got, err := s.GetEvents(EventFilter{})
		if err != nil || len(got) != 1 || got[0].UserTokenProvider != "" || got[0].UserTokenRetried {
			t.Fatalf("legacy row lost or wrong defaults: %+v %v", got, err)
		}
		_ = s.Close()
		s2, err := NewSQLiteStore(dsn, 0)
		if err != nil {
			t.Fatalf("second open must be a no-op: %v", err)
		}
		_ = s2.Close()
	})
	t.Run("fleet", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fleet.db")
		createLegacyFleetDB(t, path)
		s, err := NewFleetSQLiteStore(path, 0, 0)
		if err != nil {
			t.Fatalf("open legacy: %v", err)
		}
		defer func() { _ = s.Close() }()
		for _, c := range []string{"user_token_provider", "user_token_retried"} {
			if ok, err := s.columnPresent(c); err != nil || !ok {
				t.Errorf("column %s not added (err %v)", c, err)
			}
		}
		got, err := s.GetEvents(EventFilter{})
		if err != nil || len(got) != 1 || got[0].UserTokenProvider != "" {
			t.Fatalf("legacy row lost or wrong defaults: %+v %v", got, err)
		}
	})
}

// An event without a per-user swap marshals without the new keys.
func TestUserTokenProviderOmittedWhenEmpty(t *testing.T) {
	b, err := json.Marshal(Event{Domain: "x.com", Decision: "allow", Provider: "openai"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "user_token") {
		t.Errorf("event without a per-user swap carries the new keys: %s", b)
	}
	b, _ = json.Marshal(Event{UserTokenProvider: "google", UserTokenRetried: true})
	if !strings.Contains(string(b), `"user_token_provider":"google"`) || !strings.Contains(string(b), `"user_token_retried":true`) {
		t.Errorf("set fields missing from JSON: %s", b)
	}
}
