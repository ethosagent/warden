package analytics

import (
	"fmt"
	"testing"
	"time"
)

type mockRemote struct {
	batches [][]Event
	err     error
}

func (m *mockRemote) SendBatch(events []Event) error {
	if m.err != nil {
		return m.err
	}
	m.batches = append(m.batches, events)
	return nil
}

func newTestStore(t *testing.T, max int) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(":memory:", max)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func storeN(t *testing.T, s *SQLiteStore, n int) {
	t.Helper()
	base := time.Unix(5000, 0).UTC()
	for i := 0; i < n; i++ {
		if err := s.StoreEvent(Event{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Domain:    fmt.Sprintf("d%d.com", i),
			Decision:  "allow",
		}); err != nil {
			t.Fatalf("StoreEvent[%d]: %v", i, err)
		}
	}
}

func TestSyncOnce_SendsAndPrunes(t *testing.T) {
	s := newTestStore(t, 0)
	storeN(t, s, 5)

	mock := &mockRemote{}
	w := NewSyncWorker(s, mock, "proxy-1", 5, 100, time.Hour)

	if err := w.SyncOnce(); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(mock.batches) != 1 {
		t.Fatalf("batches = %d, want 1", len(mock.batches))
	}
	if len(mock.batches[0]) != 5 {
		t.Fatalf("batch size = %d, want 5", len(mock.batches[0]))
	}
	n, err := s.count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("remaining events = %d, want 0", n)
	}
}

func TestSyncOnce_RemoteFailure_PreservesEvents(t *testing.T) {
	s := newTestStore(t, 0)
	storeN(t, s, 3)

	mock := &mockRemote{err: fmt.Errorf("network down")}
	w := NewSyncWorker(s, mock, "proxy-1", 10, 100, time.Hour)

	if err := w.SyncOnce(); err == nil {
		t.Fatal("expected error from SyncOnce")
	}
	n, err := s.count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("events = %d, want 3 (preserved after failure)", n)
	}
}

func TestSyncOnce_BufferCap_PrunesOldest(t *testing.T) {
	s := newTestStore(t, 0)
	storeN(t, s, 10)

	mock := &mockRemote{err: fmt.Errorf("network down")}
	w := NewSyncWorker(s, mock, "proxy-1", 5, 6, time.Hour)

	if err := w.SyncOnce(); err == nil {
		t.Fatal("expected error from SyncOnce")
	}
	n, err := s.count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Errorf("events = %d, want 6 (pruned to bufferCap)", n)
	}

	// The remaining events should be the newest 6.
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	// GetEvents returns newest first, so first should be d9.com.
	if got[0].Domain != "d9.com" {
		t.Errorf("newest event = %s, want d9.com", got[0].Domain)
	}
	if got[len(got)-1].Domain != "d4.com" {
		t.Errorf("oldest remaining = %s, want d4.com", got[len(got)-1].Domain)
	}
}

// recordingRemote records every batch it is offered, INCLUDING failed attempts,
// so tests can compare what a retry re-sends against the original attempt.
type recordingRemote struct {
	batches [][]Event
	err     error
}

func (r *recordingRemote) SendBatch(events []Event) error {
	// Copy: SyncOnce may reuse/restamp the slice on the next attempt.
	cp := make([]Event, len(events))
	copy(cp, events)
	r.batches = append(r.batches, cp)
	return r.err
}

// storeIdenticalN inserts n events with IDENTICAL semantic fields (same
// timestamp, domain, method) — the legitimate-collision case a dedup key must
// never conflate.
func storeIdenticalN(t *testing.T, s *SQLiteStore, n int) {
	t.Helper()
	ts := time.Unix(5000, 0).UTC()
	for i := 0; i < n; i++ {
		if err := s.StoreEvent(Event{Timestamp: ts, Domain: "same.com", Method: "GET", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent[%d]: %v", i, err)
		}
	}
}

func TestSyncOnce_UIDs_StableAcrossRetries_UniquePerEvent(t *testing.T) {
	s := newTestStore(t, 0)
	storeIdenticalN(t, s, 2)

	remote := &recordingRemote{err: fmt.Errorf("ack lost")}
	w := NewSyncWorker(s, remote, "proxy-1", 10, 100, time.Hour)

	// First attempt fails (simulating a lost ack) — events preserved locally.
	if err := w.SyncOnce(); err == nil {
		t.Fatal("expected error from first SyncOnce")
	}
	// Retry succeeds.
	remote.err = nil
	if err := w.SyncOnce(); err != nil {
		t.Fatalf("retry SyncOnce: %v", err)
	}
	if len(remote.batches) != 2 {
		t.Fatalf("batches = %d, want 2", len(remote.batches))
	}
	first, second := remote.batches[0], remote.batches[1]
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("batch sizes = %d, %d, want 2, 2", len(first), len(second))
	}

	// Stability: the retry re-sends the SAME UIDs the first attempt carried.
	for i := range first {
		if first[i].UID == "" {
			t.Fatalf("event[%d] UID empty, want assigned before first send", i)
		}
		if len(first[i].UID) != 24 {
			t.Errorf("event[%d] UID length = %d, want 24 hex chars", i, len(first[i].UID))
		}
		if first[i].UID != second[i].UID {
			t.Errorf("event[%d] UID changed across retry: %q then %q", i, first[i].UID, second[i].UID)
		}
	}
	// Uniqueness: semantically identical events still get distinct UIDs.
	if first[0].UID == first[1].UID {
		t.Errorf("distinct events share UID %q", first[0].UID)
	}
}

func TestSyncOnce_NoProxyID_LeavesUIDsEmpty(t *testing.T) {
	s := newTestStore(t, 0)
	storeN(t, s, 2)

	remote := &recordingRemote{}
	w := NewSyncWorker(s, remote, "", 10, 100, time.Hour)
	if err := w.SyncOnce(); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	for i, e := range remote.batches[0] {
		if e.UID != "" {
			t.Errorf("event[%d] UID = %q, want empty without a proxy id", i, e.UID)
		}
	}
}

func TestEventUID_Deterministic(t *testing.T) {
	if got, again := eventUID("p1", 42), eventUID("p1", 42); got != again {
		t.Errorf("eventUID not deterministic: %q vs %q", got, again)
	}
	if eventUID("p1", 42) == eventUID("p1", 43) {
		t.Error("different rowids produced the same UID")
	}
	if eventUID("p1", 42) == eventUID("p2", 42) {
		t.Error("different proxy ids produced the same UID")
	}
}

func TestSyncOnce_EmptyStore_NoOp(t *testing.T) {
	s := newTestStore(t, 0)

	mock := &mockRemote{}
	w := NewSyncWorker(s, mock, "proxy-1", 10, 100, time.Hour)

	if err := w.SyncOnce(); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(mock.batches) != 0 {
		t.Errorf("batches = %d, want 0", len(mock.batches))
	}
}
