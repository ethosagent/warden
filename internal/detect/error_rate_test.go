package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// feedErrorRate observes total events for testDomain at base, the first
// errCount of which are 5xx, and returns the detector's Evaluate output at base.
func feedErrorRate(t *testing.T, d *errorRateDetector, total, errCount int) []integration.Finding {
	t.Helper()
	for i := 0; i < total; i++ {
		status := 200
		if i < errCount {
			status = 500
		}
		d.Observe(mkEvent(base, testDomain, status))
	}
	return d.Evaluate(base)
}

func TestErrorRateTripsAtThreshold(t *testing.T) {
	d := newErrorRateDetector(DefaultErrorRateConfig(), 16)
	fs := feedErrorRate(t, d, 50, 6) // 12% over 5m, 50 >= 20 samples

	f, ok := findByRule(fs, "error_rate")
	if !ok {
		t.Fatalf("expected error_rate finding, got %v", fs)
	}
	if f.Category != "reliability" {
		t.Errorf("category = %q, want reliability", f.Category)
	}
	if f.Severity != integration.SevMedium {
		t.Errorf("severity = %v, want medium", f.Severity)
	}
	if f.DedupKey != "error_rate:"+testDomain {
		t.Errorf("dedupKey = %q", f.DedupKey)
	}
	if f.Subject.Domain != testDomain || f.Subject.Worker != testWorker {
		t.Errorf("subject = %+v", f.Subject)
	}
	if f.RuleID != "error_rate" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
	if !f.Ts.Equal(base) {
		t.Errorf("ts = %v, want %v", f.Ts, base)
	}
	for _, want := range []string{"12.0%", "5m", "(6/50)", testDomain} {
		if !strings.Contains(f.Summary, want) {
			t.Errorf("summary %q missing %q", f.Summary, want)
		}
	}
	assertFindingClean(t, f)
}

func TestErrorRateBelowRateThresholdDoesNotTrip(t *testing.T) {
	d := newErrorRateDetector(DefaultErrorRateConfig(), 16)
	fs := feedErrorRate(t, d, 50, 4) // 8% < 10%
	if len(fs) != 0 {
		t.Fatalf("expected no finding below rate threshold, got %v", fs)
	}
}

func TestErrorRateBelowMinSamplesDoesNotTrip(t *testing.T) {
	d := newErrorRateDetector(DefaultErrorRateConfig(), 16)
	fs := feedErrorRate(t, d, 10, 5) // 50% rate but only 10 < 20 samples
	if len(fs) != 0 {
		t.Fatalf("expected no finding below min samples, got %v", fs)
	}
}

func TestErrorRateEscalatesToHigh(t *testing.T) {
	d := newErrorRateDetector(DefaultErrorRateConfig(), 16)
	// 24% >= 2x threshold (20%) -> High.
	fs := feedErrorRate(t, d, 50, 12)
	f, ok := findByRule(fs, "error_rate")
	if !ok {
		t.Fatalf("expected finding, got %v", fs)
	}
	if f.Severity != integration.SevHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
}

func TestErrorRateEscalatesAtHalf(t *testing.T) {
	// Exactly 50% error rate (with the same threshold=0.10) also escalates.
	d := newErrorRateDetector(DefaultErrorRateConfig(), 16)
	fs := feedErrorRate(t, d, 40, 20)
	f, ok := findByRule(fs, "error_rate")
	if !ok {
		t.Fatalf("expected finding, got %v", fs)
	}
	if f.Severity != integration.SevHigh {
		t.Errorf("severity = %v, want high at 50%%", f.Severity)
	}
}

func TestErrorRateWindowExpiryStopsTripping(t *testing.T) {
	cfg := DefaultErrorRateConfig()
	d := newErrorRateDetector(cfg, 16)
	// A burst at base trips immediately...
	if fs := feedErrorRate(t, d, 50, 20); len(fs) == 0 {
		t.Fatal("expected the burst to trip")
	}
	// ...but after the whole window ages out, nothing remains to trip on.
	later := base.Add(cfg.Window + time.Second)
	if fs := d.Evaluate(later); len(fs) != 0 {
		t.Fatalf("expected the aged-out burst to stop tripping, got %v", fs)
	}
}

func TestErrorRateIgnoresPreResponseEvents(t *testing.T) {
	d := newErrorRateDetector(DefaultErrorRateConfig(), 16)
	// Pre-response blocks (status 0) and domain-less events carry no signal.
	for i := 0; i < 50; i++ {
		d.Observe(mkEvent(base, testDomain, 0))
		d.Observe(mkEvent(base, "", 500))
	}
	if fs := d.Evaluate(base); len(fs) != 0 {
		t.Fatalf("expected no finding from pre-response/domain-less events, got %v", fs)
	}
}

func TestErrorRateLevelTriggeredReEmits(t *testing.T) {
	d := newErrorRateDetector(DefaultErrorRateConfig(), 16)
	for i := 0; i < 50; i++ {
		status := 200
		if i < 20 {
			status = 500
		}
		d.Observe(mkEvent(base, testDomain, status))
	}
	// Two consecutive Evaluates within the window both emit (level-triggered);
	// the AlertManager dedups and bumps Count downstream.
	if fs := d.Evaluate(base); len(fs) != 1 {
		t.Fatalf("first evaluate: want 1 finding, got %d", len(fs))
	}
	if fs := d.Evaluate(base.Add(time.Minute)); len(fs) != 1 {
		t.Fatalf("second evaluate: want 1 finding while still tripped, got %d", len(fs))
	}
}

// Guard: the detector never reads value-bearing fields, so a Finding is clean
// regardless of what the events carried.
func TestErrorRateEgressHygiene(t *testing.T) {
	d := newErrorRateDetector(DefaultErrorRateConfig(), 16)
	ev := analytics.Event{
		Timestamp:      base,
		Domain:         testDomain,
		ResponseStatus: 500,
		URL:            leakURL,
		JudgeReason:    leakReason,
		Reason:         leakEnum,
		ProxyID:        testWorker,
	}
	for i := 0; i < 30; i++ {
		d.Observe(ev)
	}
	f, ok := findByRule(d.Evaluate(base), "error_rate")
	if !ok {
		t.Fatal("expected finding")
	}
	assertFindingClean(t, f)
}
