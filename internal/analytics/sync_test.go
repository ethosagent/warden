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
	w := NewSyncWorker(s, mock, 5, 100, time.Hour)

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
	w := NewSyncWorker(s, mock, 10, 100, time.Hour)

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
	w := NewSyncWorker(s, mock, 5, 6, time.Hour)

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

func TestSyncOnce_EmptyStore_NoOp(t *testing.T) {
	s := newTestStore(t, 0)

	mock := &mockRemote{}
	w := NewSyncWorker(s, mock, 10, 100, time.Hour)

	if err := w.SyncOnce(); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if len(mock.batches) != 0 {
		t.Errorf("batches = %d, want 0", len(mock.batches))
	}
}
