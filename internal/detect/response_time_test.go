package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/integration"
)

// feedLatency observes n same-latency samples for testDomain at time ts.
func feedLatency(d *responseTimeDetector, ts time.Time, n int, latencyMs int64) {
	for i := 0; i < n; i++ {
		ev := mkEvent(ts, testDomain, 200)
		ev.LatencyMs = latencyMs
		d.Observe(ev)
	}
}

// TestResponseTimeSpikeTrips establishes a calm baseline, then a sudden sustained
// jump (in a fresh window) trips the detector.
func TestResponseTimeSpikeTrips(t *testing.T) {
	cfg := DefaultResponseTimeConfig()
	d := newResponseTimeDetector(cfg, 16)

	// Window 0: calm 250ms baseline; first evaluate SEEDS baseline, never trips.
	feedLatency(d, base, cfg.MinSamples, 250)
	if fs := d.Evaluate(base); len(fs) != 0 {
		t.Fatalf("baseline-establishing evaluate must not trip, got %v", fs)
	}

	// Window 1 (past the window, old samples pruned): sudden 1500ms spike.
	t1 := base.Add(cfg.Window + time.Minute)
	feedLatency(d, t1, cfg.MinSamples, 1500)
	f, ok := findByRule(d.Evaluate(t1), "response_time")
	if !ok {
		t.Fatalf("expected a response_time finding on the spike")
	}
	if f.Category != "reliability" {
		t.Errorf("category = %q, want reliability", f.Category)
	}
	// 1500 >= 5x baseline(250) -> High.
	if f.Severity != integration.SevHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if f.DedupKey != "response_time:"+testDomain {
		t.Errorf("dedupKey = %q", f.DedupKey)
	}
	if f.Subject.Domain != testDomain || f.Subject.Worker != testWorker {
		t.Errorf("subject = %+v", f.Subject)
	}
	for _, want := range []string{"1500ms", "5m", testDomain, "baseline 250ms"} {
		if !strings.Contains(f.Summary, want) {
			t.Errorf("summary %q missing %q", f.Summary, want)
		}
	}
	assertFindingClean(t, f)
}

// TestResponseTimeMediumSeverity: a jump above floor and >=3x but <5x baseline.
func TestResponseTimeMediumSeverity(t *testing.T) {
	cfg := DefaultResponseTimeConfig()
	d := newResponseTimeDetector(cfg, 16)
	feedLatency(d, base, cfg.MinSamples, 250) // baseline 250
	d.Evaluate(base)

	t1 := base.Add(cfg.Window + time.Minute)
	feedLatency(d, t1, cfg.MinSamples, 900) // 900 >= 800 floor, 3.6x, < 5x(1250)
	f, ok := findByRule(d.Evaluate(t1), "response_time")
	if !ok {
		t.Fatal("expected finding")
	}
	if f.Severity != integration.SevMedium {
		t.Errorf("severity = %v, want medium", f.Severity)
	}
}

// TestResponseTimeBelowFloorNeverTrips: a huge relative jump that is still below
// the absolute floor does not trip (guards fast endpoints).
func TestResponseTimeBelowFloorNeverTrips(t *testing.T) {
	cfg := DefaultResponseTimeConfig()
	d := newResponseTimeDetector(cfg, 16)
	feedLatency(d, base, cfg.MinSamples, 50) // baseline 50ms
	d.Evaluate(base)

	t1 := base.Add(cfg.Window + time.Minute)
	feedLatency(d, t1, cfg.MinSamples, 400) // 8x baseline but < 800ms floor
	if fs := d.Evaluate(t1); len(fs) != 0 {
		t.Fatalf("expected no trip below the absolute floor, got %v", fs)
	}
}

// TestResponseTimeBelowMinSamplesNeverTrips: fewer than MinSamples means no
// average is computed and no baseline is established.
func TestResponseTimeBelowMinSamplesNeverTrips(t *testing.T) {
	cfg := DefaultResponseTimeConfig()
	d := newResponseTimeDetector(cfg, 16)
	feedLatency(d, base, cfg.MinSamples-1, 5000) // huge latency but too few samples
	if fs := d.Evaluate(base); len(fs) != 0 {
		t.Fatalf("expected no trip below min samples, got %v", fs)
	}
}

// TestResponseTimeGradualRiseDoesNotFalselyTrip: a slow rise that the baseline
// tracks (each window < 3x the current baseline) never trips, even as absolute
// latency climbs past the floor. This is the intended relative-degradation
// behavior: only a jump large RELATIVE to the domain's own recent norm alerts.
func TestResponseTimeGradualRiseDoesNotFalselyTrip(t *testing.T) {
	cfg := DefaultResponseTimeConfig()
	d := newResponseTimeDetector(cfg, 16)

	// Each latency is <1.25x the previous, so it never reaches 3x the (tracking)
	// baseline. The sequence climbs from 250ms to 1000ms, well past the 800 floor.
	latencies := []int64{250, 300, 350, 420, 500, 600, 720, 860, 1000}
	for i, l := range latencies {
		ts := base.Add(time.Duration(i) * (cfg.Window + time.Minute))
		feedLatency(d, ts, cfg.MinSamples, l)
		if fs := d.Evaluate(ts); len(fs) != 0 {
			t.Fatalf("gradual rise falsely tripped at step %d (latency %dms): %v", i, l, fs)
		}
	}
}

// TestResponseTimeBaselineNotChasedByPersistentSpike: while tripped the baseline
// must stay put, so a sustained spike keeps re-emitting (level-triggered) rather
// than the baseline creeping up to mask it.
func TestResponseTimeBaselineNotChasedByPersistentSpike(t *testing.T) {
	cfg := DefaultResponseTimeConfig()
	d := newResponseTimeDetector(cfg, 16)
	feedLatency(d, base, cfg.MinSamples, 250) // baseline 250
	d.Evaluate(base)

	// Three consecutive spike windows all re-emit with the same baseline (250).
	for i := 1; i <= 3; i++ {
		ts := base.Add(time.Duration(i) * (cfg.Window + time.Minute))
		feedLatency(d, ts, cfg.MinSamples, 1500)
		f, ok := findByRule(d.Evaluate(ts), "response_time")
		if !ok {
			t.Fatalf("spike window %d: expected a finding", i)
		}
		if !strings.Contains(f.Summary, "baseline 250ms") {
			t.Errorf("spike window %d: baseline drifted: %q", i, f.Summary)
		}
	}
}

func TestResponseTimeWindowExpiryStopsTripping(t *testing.T) {
	cfg := DefaultResponseTimeConfig()
	d := newResponseTimeDetector(cfg, 16)
	feedLatency(d, base, cfg.MinSamples, 250)
	d.Evaluate(base)

	t1 := base.Add(cfg.Window + time.Minute)
	feedLatency(d, t1, cfg.MinSamples, 1500)
	if _, ok := findByRule(d.Evaluate(t1), "response_time"); !ok {
		t.Fatal("expected the spike to trip")
	}
	// After the spike samples age out, there is nothing to average -> no trip.
	t2 := t1.Add(cfg.Window + time.Minute)
	if fs := d.Evaluate(t2); len(fs) != 0 {
		t.Fatalf("expected no trip once the spike window aged out, got %v", fs)
	}
}
