package analytics

import (
	"reflect"
	"testing"
)

// The 3 dashboard "Activity" columns (latency_ms, swapped_refs, evidence) persist
// and read back through the local SQLite store — the same round-trip discipline as
// the DLP columns.
func TestSQLiteStore_ActivityFieldsRoundTrip(t *testing.T) {
	store, err := NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()

	in := Event{
		Domain:      "api.openai.com",
		Port:        443,
		Protocol:    "https",
		Method:      "POST",
		URL:         "https://api.openai.com/v1/chat",
		Decision:    "allow",
		LatencyMs:   42,
		SwappedRefs: []string{"{{OPENAI_API_KEY}}", "{{ORG_ID}}"},
		Evidence:    []string{"••••abcd (len 20)", "••••1234 (len 16)"},
	}
	if err := store.StoreEvent(in); err != nil {
		t.Fatalf("store: %v", err)
	}

	got, err := store.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.LatencyMs != 42 {
		t.Fatalf("LatencyMs = %d, want 42", ev.LatencyMs)
	}
	if !reflect.DeepEqual(ev.SwappedRefs, []string{"{{OPENAI_API_KEY}}", "{{ORG_ID}}"}) {
		t.Fatalf("SwappedRefs round-trip = %v", ev.SwappedRefs)
	}
	if !reflect.DeepEqual(ev.Evidence, []string{"••••abcd (len 20)", "••••1234 (len 16)"}) {
		t.Fatalf("Evidence round-trip = %v", ev.Evidence)
	}

	// GetOldestEventIDs (the retention/read path) must decode the new columns too.
	_, oldest, err := store.GetOldestEventIDs(10)
	if err != nil {
		t.Fatalf("oldest: %v", err)
	}
	if len(oldest) != 1 || oldest[0].LatencyMs != 42 ||
		!reflect.DeepEqual(oldest[0].SwappedRefs, []string{"{{OPENAI_API_KEY}}", "{{ORG_ID}}"}) ||
		!reflect.DeepEqual(oldest[0].Evidence, []string{"••••abcd (len 20)", "••••1234 (len 16)"}) {
		t.Fatalf("GetOldestEventIDs round-trip = %+v", oldest)
	}
}

// The batch insert path persists the new columns identically to StoreEvent.
func TestSQLiteStore_ActivityFieldsBatchRoundTrip(t *testing.T) {
	store, err := NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.StoreEventsBatch([]Event{{
		Domain: "api.openai.com", Port: 443, Protocol: "https", Method: "POST",
		URL: "https://api.openai.com/v1/chat", Decision: "allow",
		LatencyMs: 7, SwappedRefs: []string{"{{OPENAI_API_KEY}}"},
		Evidence: []string{"••••wxyz (len 30)"},
	}}); err != nil {
		t.Fatalf("batch store: %v", err)
	}
	got, err := store.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 1 || got[0].LatencyMs != 7 ||
		!reflect.DeepEqual(got[0].SwappedRefs, []string{"{{OPENAI_API_KEY}}"}) ||
		!reflect.DeepEqual(got[0].Evidence, []string{"••••wxyz (len 30)"}) {
		t.Fatalf("batch round-trip = %+v", got)
	}
}

// An event with no activity data reads back with zero/empty new fields (back-compat:
// a pre-Activity event, or any request that swapped nothing and found nothing, is
// unaffected — nil slices, zero latency).
func TestSQLiteStore_NoActivityDataReadsBackEmpty(t *testing.T) {
	store, err := NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.StoreEvent(Event{
		Domain: "example.com", Port: 443, Protocol: "https", Method: "GET",
		URL: "https://example.com/", Decision: "allow",
	}); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := store.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.LatencyMs != 0 || len(ev.SwappedRefs) != 0 || len(ev.Evidence) != 0 {
		t.Fatalf("expected empty activity fields, got %+v", ev)
	}
}
