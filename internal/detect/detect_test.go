package detect

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// base is a fixed wall-clock-free anchor; all tests advance from it explicitly.
var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	testDomain   = "api.foo.com"
	testWorker   = "worker-1"
	testProvider = "openai"

	// Planted value-bearing strings. Detectors never read URL / JudgeReason /
	// Reason, so a Finding must never contain any of these. assertClean asserts it.
	leakURL    = "https://api.foo.com/v1/secret?token=PLANTED_SECRET_TOKEN"
	leakReason = "PLANTED_JUDGE_FREETEXT_reason"
	leakEnum   = "PLANTED_bounded_reason"
)

// mkEvent builds an event that always carries planted value-bearing fields, so
// every detector's Finding is checked structurally for egress hygiene.
func mkEvent(ts time.Time, domain string, status int) analytics.Event {
	return analytics.Event{
		Timestamp:      ts,
		Domain:         domain,
		ResponseStatus: status,
		ProxyID:        testWorker,
		URL:            leakURL,
		JudgeReason:    leakReason,
		Reason:         leakEnum,
	}
}

// assertClean fails if s contains any planted value-bearing token — the egress
// hygiene invariant for Summary and Evidence.
func assertClean(t *testing.T, label, s string) {
	t.Helper()
	for _, bad := range []string{
		"PLANTED_SECRET_TOKEN", "PLANTED_JUDGE", "PLANTED_bounded",
		"/v1/secret", "token=", "https://", "?",
	} {
		if strings.Contains(s, bad) {
			t.Fatalf("egress hygiene: %s leaked %q: %q", label, bad, s)
		}
	}
}

// assertFindingClean runs the hygiene check over a Finding's operator-facing
// strings.
func assertFindingClean(t *testing.T, f integration.Finding) {
	t.Helper()
	assertClean(t, "summary", f.Summary)
	assertClean(t, "evidence", string(f.Evidence))
}

// findByRule returns the first finding whose RuleID matches, or ok=false.
func findByRule(fs []integration.Finding, rule string) (integration.Finding, bool) {
	for _, f := range fs {
		if f.RuleID == rule {
			return f, true
		}
	}
	return integration.Finding{}, false
}

func TestDurLabel(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Minute, "5m"},
		{time.Hour, "1h"},
		{30 * time.Second, "30s"},
		{90 * time.Second, "90s"}, // not a whole minute -> falls to the seconds label
	}
	for _, c := range cases {
		if got := durLabel(c.d); got != c.want {
			t.Errorf("durLabel(%s) = %q, want %q", c.d, got, c.want)
		}
	}
}

// TestSlidingWindowRingPruneCompacts drives the ring's prune past the
// half-dead-prefix compaction trigger and asserts the live view and backing
// array stay correct and bounded.
func TestSlidingWindowRingPruneCompacts(t *testing.T) {
	w := slidingWindow[int]{window: 10 * time.Second}
	// 20 samples, one per second.
	for i := 0; i < 20; i++ {
		w.add(base.Add(time.Duration(i)*time.Second), i)
	}
	if w.len() != 20 {
		t.Fatalf("len before prune = %d, want 20", w.len())
	}
	// At t=15s, cutoff=5s: samples i=0..5 (six) are pruned. The dead prefix (6) is
	// below half of 20, so the head advances WITHOUT compacting the backing array.
	w.prune(base.Add(15 * time.Second))
	if got := w.len(); got != 14 {
		t.Fatalf("len after first prune = %d, want 14", got)
	}
	if w.start != 6 || len(w.samples) != 20 {
		t.Errorf("expected head advance without compaction: start=%d backing=%d", w.start, len(w.samples))
	}
	// At t=20s, cutoff=10s: samples i=0..10 (eleven) are dead. The prefix now
	// dominates, so prune compacts and resets the head.
	w.prune(base.Add(20 * time.Second))
	if got := w.len(); got != 9 {
		t.Fatalf("len after second prune = %d, want 9", got)
	}
	if w.start != 0 || len(w.samples) != 9 {
		t.Errorf("expected compaction to reset head and reclaim backing: start=%d backing=%d", w.start, len(w.samples))
	}
	// The live view holds exactly the surviving samples (i=11..19), in order.
	live := w.live()
	if len(live) != 9 || live[0].v != 11 || live[8].v != 19 {
		t.Errorf("live view wrong: len=%d first=%d last=%d", len(live), live[0].v, live[8].v)
	}
	// Aging everything out empties the window.
	w.prune(base.Add(100 * time.Second))
	if w.len() != 0 {
		t.Errorf("expected empty window after full expiry, got %d", w.len())
	}
}

func TestDefaultConfigEnablesAll(t *testing.T) {
	e := NewEngine(DefaultConfig(), func() time.Time { return base })
	got := e.Detectors()
	want := []string{"error_rate", "auth_fail_burst", "cost_anomaly", "response_time"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Detectors() = %v, want %v", got, want)
	}
}

func TestNilClockDefaultsToNow(t *testing.T) {
	e := NewEngine(DefaultConfig(), nil)
	if e.now == nil {
		t.Fatal("nil clock should default to time.Now")
	}
	// Smoke: Evaluate must not panic with the default clock.
	_ = e.Evaluate()
}

// TestEngineFansToAllEnabled feeds a single event stream that trips several
// detectors and asserts Evaluate aggregates findings from each.
func TestEngineFansToAllEnabled(t *testing.T) {
	now := base
	e := NewEngine(DefaultConfig(), func() time.Time { return now })

	// tripStream builds a stream stamped at ts that trips all four detectors:
	// 5xx errors, 401 auth failures, provider spend, and (with latencyMs) slow
	// responses.
	tripStream := func(ts time.Time, latencyMs int64) []analytics.Event {
		var events []analytics.Event
		for i := 0; i < 30; i++ {
			ev := mkEvent(ts, testDomain, 200)
			if i < 15 {
				ev.ResponseStatus = 500
			}
			ev.LatencyMs = latencyMs
			events = append(events, ev)
		}
		for i := 0; i < 12; i++ {
			events = append(events, mkEvent(ts, "auth.foo.com", 401))
		}
		for i := 0; i < 6; i++ {
			ev := mkEvent(ts, testDomain, 200)
			ev.CostUSD = 10
			ev.Provider = testProvider
			events = append(events, ev)
		}
		return events
	}

	// Round 1 at base: a calm-latency stream seeds the response_time baseline.
	e.Observe(tripStream(base, 200))
	_ = e.Evaluate()

	// Round 2 in a later, isolated window: a slow-latency stream trips everything.
	now = base.Add(6 * time.Minute)
	e.Observe(tripStream(now, 1500))
	findings := e.Evaluate()

	for _, rule := range []string{"error_rate", "auth_fail_burst", "cost_anomaly", "response_time"} {
		f, ok := findByRule(findings, rule)
		if !ok {
			t.Errorf("expected a %s finding, got %d findings", rule, len(findings))
			continue
		}
		assertFindingClean(t, f)
	}
}

// TestDisabledDetectorEmitsNothing enables only error_rate and verifies no other
// detector runs or emits.
func TestDisabledDetectorEmitsNothing(t *testing.T) {
	cfg := Config{ErrorRate: DefaultErrorRateConfig(), MaxKeys: 16}
	now := base
	e := NewEngine(cfg, func() time.Time { return now })

	if names := e.Detectors(); len(names) != 1 || names[0] != "error_rate" {
		t.Fatalf("expected only error_rate enabled, got %v", names)
	}

	// A pure cost/auth stream must yield nothing (those detectors are off) and the
	// error_rate detector sees no 5xx.
	var events []analytics.Event
	for i := 0; i < 30; i++ {
		ev := mkEvent(base, testDomain, 200)
		ev.CostUSD = 100
		ev.Provider = testProvider
		events = append(events, ev)
		events = append(events, mkEvent(base, testDomain, 401))
	}
	e.Observe(events)
	if fs := e.Evaluate(); len(fs) != 0 {
		t.Fatalf("expected no findings from a healthy 2xx stream, got %v", fs)
	}
}

// TestCardinalityCapEvictsLRU drives keyedWindows past its cap and asserts the
// tracked-key set stays bounded and the least-recently-observed keys are evicted.
func TestCardinalityCapEvictsLRU(t *testing.T) {
	const maxKeys = 4
	k := newKeyedWindows(maxKeys, func() *errorRateState {
		return &errorRateState{w: slidingWindow[bool]{window: time.Minute}}
	})
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("d%d", i)
		k.observe(key, base.Add(time.Duration(i)*time.Second), func(*errorRateState) {})
	}
	if got := k.len(); got != maxKeys {
		t.Fatalf("tracked keys = %d, want %d", got, maxKeys)
	}
	if got := k.Evictions(); got != 6 {
		t.Fatalf("evictions = %d, want 6", got)
	}
	// The 4 most-recently-observed keys survive; the oldest are gone.
	for i := 0; i <= 5; i++ {
		if _, ok := k.entries[fmt.Sprintf("d%d", i)]; ok {
			t.Errorf("expected LRU key d%d to be evicted", i)
		}
	}
	for i := 6; i <= 9; i++ {
		if _, ok := k.entries[fmt.Sprintf("d%d", i)]; !ok {
			t.Errorf("expected recent key d%d to survive", i)
		}
	}
}

// TestEngineCardinalityCapCounted verifies the engine surfaces eviction counts
// from its detectors when driven past the cap.
func TestEngineCardinalityCapCounted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxKeys = 8
	e := NewEngine(cfg, func() time.Time { return base })
	var events []analytics.Event
	for i := 0; i < 50; i++ {
		events = append(events, mkEvent(base, fmt.Sprintf("d%d.foo.com", i), 500))
	}
	e.Observe(events)
	if e.Evictions() == 0 {
		t.Fatal("expected the engine to report cardinality-cap evictions")
	}
}

// TestConcurrentObserveEvaluateRaceClean exercises the concurrency contract:
// many goroutines Observe while another Evaluates. Run under -race.
func TestConcurrentObserveEvaluateRaceClean(t *testing.T) {
	var mu sync.Mutex
	now := base
	e := NewEngine(DefaultConfig(), func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Ingest goroutines.
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				select {
				case <-stop:
					return
				default:
				}
				ev := mkEvent(base.Add(time.Duration(i)*time.Millisecond),
					fmt.Sprintf("d%d.foo.com", i%16), 500)
				ev.LatencyMs = 1500
				ev.CostUSD = 1
				ev.Provider = testProvider
				e.Observe([]analytics.Event{ev})
			}
		}(g)
	}

	// Tick goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			mu.Lock()
			now = now.Add(time.Second)
			mu.Unlock()
			_ = e.Evaluate()
		}
	}()

	wg.Wait()
	close(stop)
}
