package integration

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alerts.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleAlert(id, dedup string, sev Severity, ts time.Time) Alert {
	return Alert{
		ID:        id,
		DedupKey:  dedup,
		Category:  "reliability",
		Severity:  sev,
		Subject:   Subject{Domain: "api.foo.com", Tool: "search", Agent: "a1", Worker: "w1"},
		Summary:   "summary",
		Evidence:  "rate=7.2%",
		Status:    StatusFiring,
		Count:     1,
		FirstSeen: ts,
		LastSeen:  ts,
	}
}

func TestStoreUpsertInsertThenConflict(t *testing.T) {
	s := newTestStore(t)
	t0 := time.UnixMilli(1_000)
	t1 := time.UnixMilli(2_000)

	first := sampleAlert("id1", "error_rate:api.foo.com", SevMedium, t0)
	if err := s.UpsertAlert(first); err != nil {
		t.Fatalf("upsert insert: %v", err)
	}

	got, ok, err := s.GetAlert("id1")
	if err != nil || !ok {
		t.Fatalf("GetAlert: ok=%v err=%v", ok, err)
	}
	if got.Count != 1 || got.Severity != SevMedium {
		t.Errorf("after insert: count=%d sev=%v", got.Count, got.Severity)
	}

	// Re-fire with higher severity and later last_seen.
	refire := sampleAlert("id1", "error_rate:api.foo.com", SevCritical, t1)
	refire.Summary = "escalated"
	refire.Evidence = "rate=20%"
	if err := s.UpsertAlert(refire); err != nil {
		t.Fatalf("upsert conflict: %v", err)
	}

	got, ok, err = s.GetAlert("id1")
	if err != nil || !ok {
		t.Fatalf("GetAlert after conflict: ok=%v err=%v", ok, err)
	}
	if got.Count != 2 {
		t.Errorf("count = %d, want 2 (incremented)", got.Count)
	}
	if got.Severity != SevCritical {
		t.Errorf("severity = %v, want escalated to critical", got.Severity)
	}
	if !got.LastSeen.Equal(t1.UTC()) {
		t.Errorf("last_seen = %v, want %v", got.LastSeen, t1.UTC())
	}
	if !got.FirstSeen.Equal(t0.UTC()) {
		t.Errorf("first_seen = %v, want preserved %v", got.FirstSeen, t0.UTC())
	}
	if got.Summary != "escalated" || string(got.Evidence) != "rate=20%" {
		t.Errorf("summary/evidence not updated: %q %q", got.Summary, got.Evidence)
	}

	// Re-fire with LOWER severity must not de-escalate.
	lower := sampleAlert("id1", "error_rate:api.foo.com", SevLow, time.UnixMilli(3_000))
	if err := s.UpsertAlert(lower); err != nil {
		t.Fatalf("upsert lower: %v", err)
	}
	got, _, _ = s.GetAlert("id1")
	if got.Severity != SevCritical {
		t.Errorf("severity de-escalated to %v, want critical (max wins)", got.Severity)
	}
	if got.Count != 3 {
		t.Errorf("count = %d, want 3", got.Count)
	}
}

func TestStoreListAlertsOrdering(t *testing.T) {
	s := newTestStore(t)
	older := sampleAlert("a", "k:a", SevLow, time.UnixMilli(1_000))
	newer := sampleAlert("b", "k:b", SevLow, time.UnixMilli(5_000))
	if err := s.UpsertAlert(older); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAlert(newer); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListAlerts(0)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].ID != "b" {
		t.Errorf("newest-first ordering broken: got %q first", list[0].ID)
	}

	limited, err := s.ListAlerts(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 1 || limited[0].ID != "b" {
		t.Errorf("limit=1 should return newest only, got %+v", limited)
	}
}

func TestStoreGetAlertMissing(t *testing.T) {
	s := newTestStore(t)
	_, ok, err := s.GetAlert("nope")
	if err != nil {
		t.Fatalf("GetAlert missing err: %v", err)
	}
	if ok {
		t.Error("missing alert should return ok=false")
	}
}

func TestStoreRecordDeadLetter(t *testing.T) {
	s := newTestStore(t)
	if err := s.RecordDeadLetter("id1", "sec-hook", "boom", time.UnixMilli(1_000)); err != nil {
		t.Fatalf("RecordDeadLetter: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM dead_letters WHERE alert_id = ? AND integration = ?`, "id1", "sec-hook").Scan(&n); err != nil {
		t.Fatalf("count dead_letters: %v", err)
	}
	if n != 1 {
		t.Errorf("dead_letters rows = %d, want 1", n)
	}
}

func TestStoreReopenPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	s1, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.UpsertAlert(sampleAlert("keep", "k:keep", SevHigh, time.UnixMilli(1_000))); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	// Close is idempotent.
	if err := s1.Close(); err != nil {
		t.Errorf("second Close should be nil, got %v", err)
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	got, ok, err := s2.GetAlert("keep")
	if err != nil || !ok {
		t.Fatalf("reopened GetAlert: ok=%v err=%v", ok, err)
	}
	if got.Severity != SevHigh {
		t.Errorf("persisted severity = %v, want high", got.Severity)
	}
}
