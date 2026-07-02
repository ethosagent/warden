package analytics

import (
	"reflect"
	"testing"
)

// The 5 DLP columns persist and read back through the local SQLite store.
func TestSQLiteStore_DLPFieldsRoundTrip(t *testing.T) {
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
		DataClasses: []string{"credential_leak", "pii"},
		DLPAction:   "monitor",
		DLPRule:     "",
		DLPPartial:  true,
		DLPEncoded:  false,
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
	if !reflect.DeepEqual(ev.DataClasses, []string{"credential_leak", "pii"}) {
		t.Fatalf("DataClasses round-trip = %v", ev.DataClasses)
	}
	if ev.DLPAction != "monitor" {
		t.Fatalf("DLPAction = %q, want monitor", ev.DLPAction)
	}
	if !ev.DLPPartial {
		t.Fatalf("DLPPartial = false, want true")
	}
	if ev.DLPEncoded {
		t.Fatalf("DLPEncoded = true, want false")
	}
}

// An event with no DLP data reads back with empty/false DLP fields (back-compat:
// a pre-DLP event, or any non-DLP request, is unaffected).
func TestSQLiteStore_NoDLPDataReadsBackEmpty(t *testing.T) {
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
	if len(ev.DataClasses) != 0 || ev.DLPAction != "" || ev.DLPRule != "" || ev.DLPPartial || ev.DLPEncoded {
		t.Fatalf("expected empty DLP fields, got %+v", ev)
	}
}
