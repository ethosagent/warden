package analytics

import (
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
