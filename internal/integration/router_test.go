package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// --- test integrations ---

type baseIntegration struct{ typ string }

func (b baseIntegration) Type() string                                { return b.typ }
func (b baseIntegration) Start(context.Context, System, Config) error { return nil }
func (b baseIntegration) Stop(context.Context) error                  { return nil }

// recordingAlerter records every Alert it receives and signals a channel.
type recordingAlerter struct {
	baseIntegration
	mu   sync.Mutex
	got  []Alert
	recv chan Alert
	err  error // returned by Alert when non-nil
}

func newRecordingAlerter(typ string) *recordingAlerter {
	return &recordingAlerter{baseIntegration: baseIntegration{typ: typ}, recv: make(chan Alert, 64)}
}

func (r *recordingAlerter) Alert(_ context.Context, a Alert) error {
	r.mu.Lock()
	r.got = append(r.got, a)
	err := r.err
	r.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case r.recv <- a:
	default:
	}
	return nil
}

func (r *recordingAlerter) received() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Alert(nil), r.got...)
}

// eventStreamerOnly implements Integration + EventStreamer but NOT Alerter.
type eventStreamerOnly struct{ baseIntegration }

func (e eventStreamerOnly) OnEvent(context.Context, Event) error { return nil }

// blockingAlerter blocks until its context is cancelled, then returns ctx.Err.
type blockingAlerter struct {
	baseIntegration
	mu    sync.Mutex
	fired int
}

func (b *blockingAlerter) Alert(ctx context.Context, _ Alert) error {
	b.mu.Lock()
	b.fired++
	b.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func (b *blockingAlerter) attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fired
}

func qlen(b *binding) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.order)
}

// --- binding queue semantics (deterministic, no goroutines) ---

func TestBindingCoalesceByDedupKey(t *testing.T) {
	b := &binding{name: "x", pending: map[string]Alert{}, signal: make(chan struct{}, 1)}

	b.enqueue(Alert{DedupKey: "k", Count: 1, Summary: "first"}, 10, quietLogger())
	b.enqueue(Alert{DedupKey: "k", Count: 2, Summary: "second"}, 10, quietLogger())

	if qlen(b) != 1 {
		t.Fatalf("coalesce: queue len = %d, want 1", qlen(b))
	}
	a, ok := b.dequeue()
	if !ok {
		t.Fatal("expected one queued alert")
	}
	if a.Summary != "second" || a.Count != 2 {
		t.Errorf("dequeue should return freshest state, got %+v", a)
	}
	if _, ok := b.dequeue(); ok {
		t.Error("queue should be empty after single coalesced dequeue")
	}
}

func TestBindingDropOldestOnOverflow(t *testing.T) {
	b := &binding{name: "x", pending: map[string]Alert{}, signal: make(chan struct{}, 1)}
	const depth = 3

	for _, k := range []string{"k0", "k1", "k2"} {
		b.enqueue(Alert{DedupKey: k}, depth, quietLogger())
	}
	// Overflow: k3 pushes out oldest k0.
	b.enqueue(Alert{DedupKey: "k3"}, depth, quietLogger())

	if qlen(b) != depth {
		t.Fatalf("queue len = %d, want %d", qlen(b), depth)
	}
	if b.dropped != 1 {
		t.Errorf("dropped = %d, want 1", b.dropped)
	}
	first, _ := b.dequeue()
	if first.DedupKey != "k1" {
		t.Errorf("oldest (k0) should have been dropped; first now %q", first.DedupKey)
	}
}

// --- router delivery routing ---

func TestRouterDeliverMatchGating(t *testing.T) {
	store := newTestStore(t)
	r := NewRouter(store, NewBus(), quietLogger(), RouterOptions{})

	match := newRecordingAlerter("match")
	nomatch := newRecordingAlerter("nomatch")
	r.Bind("match", []MatchClause{{Severity: "high"}}, match)
	r.Bind("nomatch", []MatchClause{{Severity: "low"}}, nomatch)

	// Not started: enqueued but not drained, so we inspect the queues directly.
	r.Deliver(Alert{ID: "a", DedupKey: "k:a", Severity: SevHigh, Summary: "s"})

	if got := qlen(r.bindings[0]); got != 1 {
		t.Errorf("matching binding queue = %d, want 1", got)
	}
	if got := qlen(r.bindings[1]); got != 0 {
		t.Errorf("non-matching binding queue = %d, want 0", got)
	}
}

func TestRouterDeliverEgressUnsafeDropped(t *testing.T) {
	store := newTestStore(t)
	r := NewRouter(store, NewBus(), quietLogger(), RouterOptions{})
	rec := newRecordingAlerter("rec")
	r.Bind("rec", []MatchClause{{Severity: "high"}}, rec)

	big := make([]byte, maxSummaryBytes+10)
	for i := range big {
		big[i] = 'x'
	}
	// Oversized summary bypassing the AlertManager bounding — router must drop.
	r.Deliver(Alert{ID: "a", DedupKey: "k:a", Severity: SevHigh, Summary: string(big)})

	if got := qlen(r.bindings[0]); got != 0 {
		t.Errorf("egress-unsafe alert should be dropped, queue = %d", got)
	}
}

func TestRouterBindEventStreamerOnlyNotBound(t *testing.T) {
	store := newTestStore(t)
	r := NewRouter(store, NewBus(), quietLogger(), RouterOptions{})

	// EventStreamer-only implements no wired capability in M1 ⇒ not bound.
	r.Bind("streamer", []MatchClause{{Severity: "high"}}, eventStreamerOnly{baseIntegration{typ: "streamer"}})
	if len(r.bindings) != 0 {
		t.Errorf("EventStreamer-only instance should not be bound, bindings=%d", len(r.bindings))
	}

	// An Alerter that also happens to be an EventStreamer IS bound (as Alerter).
	both := &alerterAndStreamer{recordingAlerter: newRecordingAlerter("both")}
	r.Bind("both", []MatchClause{{Severity: "high"}}, both)
	if len(r.bindings) != 1 {
		t.Errorf("Alerter+EventStreamer should be bound once, bindings=%d", len(r.bindings))
	}
}

type alerterAndStreamer struct {
	*recordingAlerter
}

func (a *alerterAndStreamer) OnEvent(context.Context, Event) error { return nil }

func TestRouterDroppedCountUnknownInstance(t *testing.T) {
	store := newTestStore(t)
	r := NewRouter(store, NewBus(), quietLogger(), RouterOptions{})
	if got := r.DroppedCount("nope"); got != 0 {
		t.Errorf("DroppedCount for unknown instance = %d, want 0", got)
	}
}

// --- async delivery: retry, dead-letter, integration_down, self-loop guard ---

func waitAlert(t *testing.T, ch chan Alert, d time.Duration) Alert {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(d):
		t.Fatal("timed out waiting for alert delivery")
		return Alert{}
	}
}

func TestRouterRetryDeadLetterSelfLoopGuard(t *testing.T) {
	store := newTestStore(t)
	bus := NewBus()
	logger := quietLogger()
	r := NewRouter(store, bus, logger, RouterOptions{Timeout: time.Second, MaxRetries: 1, QueueDepth: 16})
	r.backoffBase = time.Millisecond
	am := NewAlertManager(store, r, logger)
	bus.SetAlertManager(am)

	// A: always fails. Matches the original alert (high severity). Also would
	// match the integration_down alert (also high) — the self-loop guard must
	// stop the down alert routing back to A.
	failing := newRecordingAlerter("A")
	failing.err = errors.New("sink down")
	r.Bind("A", []MatchClause{{Severity: "high"}}, failing)

	// B: healthy. Only matches category "integration" (the integration_down
	// self-alert), NOT the original (category "reliability").
	observer := newRecordingAlerter("B")
	r.Bind("B", []MatchClause{{Category: "integration"}}, observer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	// Publish the original finding through the bus → alert manager → router.
	bus.PublishFinding(Finding{
		RuleID:   "error_rate",
		Category: "reliability",
		Severity: SevHigh,
		Subject:  Subject{Domain: "api.foo.com"},
		Summary:  "boom",
		DedupKey: "error_rate:api.foo.com",
	})

	// B should receive the integration_down self-alert emitted after A's
	// retries are exhausted.
	down := waitAlert(t, observer.recv, 3*time.Second)
	if down.DedupKey != integrationDownPrefix+"A" {
		t.Errorf("observer got %q, want integration_down for A", down.DedupKey)
	}

	if err := r.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}

	// A must have been retried (>= 2 attempts for the ORIGINAL alert).
	aGot := failing.received()
	if len(aGot) < 2 {
		t.Errorf("failing sink attempts = %d, want >= 2 (retry)", len(aGot))
	}
	// Self-loop guard: A must NEVER have been handed the integration_down alert.
	for _, a := range aGot {
		if a.DedupKey == integrationDownPrefix+"A" {
			t.Error("self-loop guard failed: integration_down routed back to failing instance A")
		}
	}

	// Dead-letter recorded for A.
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM dead_letters WHERE integration = ?`, "A").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Errorf("dead_letters for A = %d, want >= 1", n)
	}
}

func TestRouterDeliveryTimeout(t *testing.T) {
	store := newTestStore(t)
	bus := NewBus()
	logger := quietLogger()
	r := NewRouter(store, bus, logger, RouterOptions{Timeout: 20 * time.Millisecond, MaxRetries: 1, QueueDepth: 8})
	r.backoffBase = time.Millisecond
	am := NewAlertManager(store, r, logger)
	bus.SetAlertManager(am)

	blocker := &blockingAlerter{baseIntegration: baseIntegration{typ: "slow"}}
	r.Bind("slow", []MatchClause{{Severity: "high"}}, blocker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	bus.PublishFinding(Finding{Severity: SevHigh, Category: "reliability", DedupKey: "slow:x", Summary: "s"})

	// Each attempt times out at 20ms; with MaxRetries=1 there are 2 attempts.
	// Poll for the dead-letter row that follows exhaustion.
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM dead_letters WHERE integration = ?`, "slow").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for dead-letter after delivery timeouts")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if blocker.attempts() < 2 {
		t.Errorf("timeout sink attempts = %d, want >= 2", blocker.attempts())
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestRouterStopIdempotentAndNotStarted(t *testing.T) {
	store := newTestStore(t)
	r := NewRouter(store, NewBus(), quietLogger(), RouterOptions{})
	// Stop before Start is a no-op.
	if err := r.Stop(context.Background()); err != nil {
		t.Errorf("Stop before Start: %v", err)
	}
	r.Start(context.Background())
	// Second Start is idempotent (no panic / no extra goroutines observable).
	r.Start(context.Background())
	if err := r.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Errorf("second Stop should be nil: %v", err)
	}
}

func TestRouterEndToEndDelivery(t *testing.T) {
	store := newTestStore(t)
	bus := NewBus()
	logger := quietLogger()
	r := NewRouter(store, bus, logger, RouterOptions{QueueDepth: 8})
	am := NewAlertManager(store, r, logger)
	bus.SetAlertManager(am)

	sink := newRecordingAlerter("sink")
	r.Bind("sink", []MatchClause{{Category: "reliability"}}, sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	bus.PublishFinding(Finding{Category: "reliability", Severity: SevMedium, DedupKey: "error_rate:x", Summary: "hi"})
	got := waitAlert(t, sink.recv, 2*time.Second)
	if got.DedupKey != "error_rate:x" {
		t.Errorf("delivered dedup = %q", got.DedupKey)
	}
	// Persisted before fan-out.
	if _, ok, _ := store.GetAlert(got.ID); !ok {
		t.Error("alert should be persisted in the store")
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
}
