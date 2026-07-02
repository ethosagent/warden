package integration

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// seqStore records the order (a global sequence tick) in which UpsertAlert is
// called, and can be made to fail.
type seqStore struct {
	mu       sync.Mutex
	seq      *int
	upsertAt int
	calls    int
	fail     error
	last     Alert
}

func (s *seqStore) UpsertAlert(a Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	*s.seq++
	s.upsertAt = *s.seq
	s.last = a
	return s.fail
}

// seqRouter records when Deliver is called relative to the shared sequence.
type seqRouter struct {
	mu        sync.Mutex
	seq       *int
	deliverAt int
	calls     int
	last      Alert
}

func (r *seqRouter) Deliver(a Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	*r.seq++
	r.deliverAt = *r.seq
	r.last = a
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAlertManagerIngestPersistsBeforeDeliver(t *testing.T) {
	seq := 0
	store := &seqStore{seq: &seq}
	router := &seqRouter{seq: &seq}
	am := &AlertManager{store: store, router: router, logger: quietLogger(), now: func() time.Time { return time.UnixMilli(42) }}

	am.Ingest(Finding{
		RuleID:   "error_rate",
		Category: "reliability",
		Severity: SevHigh,
		Subject:  Subject{Domain: "api.foo.com"},
		Summary:  "boom",
		Evidence: "rate=9%",
		DedupKey: "error_rate:api.foo.com",
	})

	if store.calls != 1 || router.calls != 1 {
		t.Fatalf("calls: store=%d router=%d, want 1/1", store.calls, router.calls)
	}
	if store.upsertAt >= router.deliverAt {
		t.Errorf("persist must precede deliver: upsertAt=%d deliverAt=%d", store.upsertAt, router.deliverAt)
	}

	// Derived alert shape.
	got := router.last
	if got.ID != alertID("error_rate:api.foo.com") {
		t.Errorf("alert ID not derived from dedup key: %q", got.ID)
	}
	if got.Status != StatusFiring || got.Count != 1 {
		t.Errorf("status/count = %q/%d", got.Status, got.Count)
	}
	if !got.FirstSeen.Equal(time.UnixMilli(42)) {
		t.Errorf("zero Ts should default to now(): %v", got.FirstSeen)
	}
}

func TestAlertManagerIngestBoundsFields(t *testing.T) {
	seq := 0
	store := &seqStore{seq: &seq}
	router := &seqRouter{seq: &seq}
	am := &AlertManager{store: store, router: router, logger: quietLogger(), now: time.Now}

	huge := make([]byte, maxSummaryBytes+100)
	for i := range huge {
		huge[i] = 'x'
	}
	am.Ingest(Finding{DedupKey: "k:x", Summary: string(huge), Evidence: Evidence(huge)})

	if len(router.last.Summary) > maxSummaryBytes {
		t.Errorf("summary not bounded: %d", len(router.last.Summary))
	}
	if len(router.last.Evidence) > maxEvidenceBytes {
		t.Errorf("evidence not bounded: %d", len(router.last.Evidence))
	}
	if err := assertEgressSafe(router.last); err != nil {
		t.Errorf("bounded alert should pass egress check: %v", err)
	}
}

func TestAlertManagerFailOpenOnStoreError(t *testing.T) {
	seq := 0
	store := &seqStore{seq: &seq, fail: errors.New("db down")}
	router := &seqRouter{seq: &seq}
	am := &AlertManager{store: store, router: router, logger: quietLogger(), now: time.Now}

	// Must not panic despite the store error.
	am.Ingest(Finding{DedupKey: "k:x", Summary: "s"})

	// Delivery still attempted best-effort (fail-open notification).
	if router.calls != 1 {
		t.Errorf("router.calls = %d, want 1 (deliver best-effort after store error)", router.calls)
	}
}

func TestAlertManagerIngestUsesFindingTs(t *testing.T) {
	seq := 0
	store := &seqStore{seq: &seq}
	router := &seqRouter{seq: &seq}
	am := &AlertManager{store: store, router: router, logger: quietLogger(), now: func() time.Time { return time.UnixMilli(999) }}

	ts := time.UnixMilli(1234)
	am.Ingest(Finding{DedupKey: "k:x", Ts: ts})
	if !router.last.FirstSeen.Equal(ts) || !router.last.LastSeen.Equal(ts) {
		t.Errorf("finding Ts should be used: first=%v last=%v", router.last.FirstSeen, router.last.LastSeen)
	}
}

func TestNewAlertManagerNilLogger(t *testing.T) {
	am := NewAlertManager(nil, nil, nil)
	if am.logger == nil {
		t.Error("nil logger should default to non-nil")
	}
}
