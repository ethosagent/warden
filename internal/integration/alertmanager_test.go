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
// called, and can be made to fail. When merged is set, UpsertAlert returns it
// (simulating the store's post-merge row); otherwise it echoes the input.
type seqStore struct {
	mu       sync.Mutex
	seq      *int
	upsertAt int
	calls    int
	fail     error
	last     Alert
	merged   *Alert
}

func (s *seqStore) UpsertAlert(a Alert) (Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	*s.seq++
	s.upsertAt = *s.seq
	s.last = a
	if s.fail != nil {
		return Alert{}, s.fail
	}
	if s.merged != nil {
		return *s.merged, nil
	}
	return a, nil
}

// ListAlerts satisfies the alertStore interface; the Ingest tests never sweep, so
// a no-op is sufficient (the resolve sweep is exercised against a real *Store).
func (s *seqStore) ListAlerts(int) ([]Alert, error) { return nil, nil }

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

// captureRouter records every delivered Alert (seqRouter keeps only the last).
type captureRouter struct {
	mu     sync.Mutex
	alerts []Alert
}

func (r *captureRouter) Deliver(a Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
}

func (r *captureRouter) all() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Alert(nil), r.alerts...)
}

// TestAlertManagerIngestDeliversStoreMergedState proves Ingest hands the
// store's post-merge row to the router, not the pre-merge Count=1 construct.
func TestAlertManagerIngestDeliversStoreMergedState(t *testing.T) {
	seq := 0
	merged := Alert{
		ID:        alertID("k:x"),
		DedupKey:  "k:x",
		Severity:  SevCritical, // escalated by the store merge
		Status:    StatusFiring,
		Count:     42,
		FirstSeen: time.UnixMilli(5), // preserved from the first insert
		LastSeen:  time.UnixMilli(1234),
	}
	store := &seqStore{seq: &seq, merged: &merged}
	router := &seqRouter{seq: &seq}
	am := &AlertManager{store: store, router: router, logger: quietLogger(), now: time.Now}

	am.Ingest(Finding{DedupKey: "k:x", Severity: SevLow, Ts: time.UnixMilli(1234)})

	got := router.last
	if got.Count != 42 {
		t.Errorf("delivered Count = %d, want store-merged 42", got.Count)
	}
	if got.Severity != SevCritical {
		t.Errorf("delivered Severity = %v, want store-merged critical", got.Severity)
	}
	if !got.FirstSeen.Equal(time.UnixMilli(5)) {
		t.Errorf("delivered FirstSeen = %v, want store-preserved %v", got.FirstSeen, time.UnixMilli(5))
	}
}

// TestAlertManagerIngestDeliversRisingCount drives Ingest against a REAL Store:
// the first ingest delivers Count=1, and each duplicate (same DedupKey) delivers
// the true merged count (2, then 3) with FirstSeen preserved and severity
// escalated — the state sinks render, not a Count=1-forever snapshot.
func TestAlertManagerIngestDeliversRisingCount(t *testing.T) {
	s := newTestStore(t)
	router := &captureRouter{}
	am := &AlertManager{store: s, router: router, logger: quietLogger(), now: time.Now}

	f := Finding{
		RuleID:   "error_rate",
		Category: "reliability",
		Severity: SevMedium,
		Subject:  Subject{Domain: "api.foo.com"},
		Summary:  "boom",
		Evidence: "rate=9%",
		DedupKey: "error_rate:api.foo.com",
	}

	f.Ts = time.UnixMilli(1_000)
	am.Ingest(f)
	f.Ts = time.UnixMilli(2_000)
	f.Severity = SevHigh
	am.Ingest(f)
	f.Ts = time.UnixMilli(3_000)
	f.Severity = SevLow
	am.Ingest(f)

	delivered := router.all()
	if len(delivered) != 3 {
		t.Fatalf("delivered %d alerts, want 3", len(delivered))
	}
	for i, want := range []int{1, 2, 3} {
		if delivered[i].Count != want {
			t.Errorf("delivery #%d Count = %d, want %d", i+1, delivered[i].Count, want)
		}
	}
	// FirstSeen rides the merge: preserved from the first insert.
	for i, a := range delivered {
		if !a.FirstSeen.Equal(time.UnixMilli(1_000).UTC()) {
			t.Errorf("delivery #%d FirstSeen = %v, want preserved %v", i+1, a.FirstSeen, time.UnixMilli(1_000).UTC())
		}
	}
	// Severity escalation (max wins) rides the merge too: the third, lower-severity
	// re-fire still delivers the escalated high.
	if delivered[1].Severity != SevHigh || delivered[2].Severity != SevHigh {
		t.Errorf("delivered severities = %v/%v, want high/high (max wins)", delivered[1].Severity, delivered[2].Severity)
	}
	// LastSeen tracks each re-fire.
	if !delivered[2].LastSeen.Equal(time.UnixMilli(3_000).UTC()) {
		t.Errorf("delivery #3 LastSeen = %v, want %v", delivered[2].LastSeen, time.UnixMilli(3_000).UTC())
	}
}

// TestAlertManagerConcurrentIngestCounts fires N concurrent duplicate ingests at
// a real Store and asserts the delivered counts are exactly {1..N} — each upsert
// is atomic (single statement with RETURNING on one connection), so no two
// deliveries can observe the same count and none is skipped.
func TestAlertManagerConcurrentIngestCounts(t *testing.T) {
	s := newTestStore(t)
	router := &captureRouter{}
	am := &AlertManager{store: s, router: router, logger: quietLogger(), now: time.Now}

	const n = 24
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			am.Ingest(Finding{DedupKey: "k:conc", Summary: "s", Ts: time.UnixMilli(1_000)})
		}()
	}
	wg.Wait()

	delivered := router.all()
	if len(delivered) != n {
		t.Fatalf("delivered %d alerts, want %d", len(delivered), n)
	}
	seen := make(map[int]bool, n)
	for _, a := range delivered {
		if a.Count < 1 || a.Count > n {
			t.Fatalf("delivered Count %d out of range [1,%d]", a.Count, n)
		}
		if seen[a.Count] {
			t.Fatalf("Count %d delivered twice — upsert+read not atomic", a.Count)
		}
		seen[a.Count] = true
	}
	row, ok, err := s.GetAlert(alertID("k:conc"))
	if err != nil || !ok {
		t.Fatalf("GetAlert: ok=%v err=%v", ok, err)
	}
	if row.Count != n {
		t.Errorf("store Count = %d, want %d", row.Count, n)
	}
}
