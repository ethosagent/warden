package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// feedCost observes n events of unit cost for the given provider at base.
func feedCost(d *costAnomalyDetector, provider string, n int, unit float64) {
	for i := 0; i < n; i++ {
		d.Observe(analytics.Event{
			Timestamp: base,
			Domain:    testDomain,
			Provider:  provider,
			CostUSD:   unit,
			ProxyID:   testWorker,
			URL:       leakURL,
			Reason:    leakEnum,
		})
	}
}

func TestCostAnomalyTripsAtBudget(t *testing.T) {
	d := newCostAnomalyDetector(DefaultCostAnomalyConfig(), 16)
	feedCost(d, testProvider, 6, 5.0) // $30 >= $25 budget, < 2x
	f, ok := findByRule(d.Evaluate(base), "cost_anomaly")
	if !ok {
		t.Fatal("expected cost_anomaly finding")
	}
	if f.Category != "cost" {
		t.Errorf("category = %q, want cost", f.Category)
	}
	if f.Severity != integration.SevMedium {
		t.Errorf("severity = %v, want medium", f.Severity)
	}
	if f.DedupKey != "cost_anomaly:"+testProvider {
		t.Errorf("dedupKey = %q", f.DedupKey)
	}
	if f.Subject.Worker != testWorker {
		t.Errorf("subject.worker = %q, want %q", f.Subject.Worker, testWorker)
	}
	for _, want := range []string{"$30.00", "1h", testProvider, "budget $25.00"} {
		if !strings.Contains(f.Summary, want) {
			t.Errorf("summary %q missing %q", f.Summary, want)
		}
	}
	assertFindingClean(t, f)
}

func TestCostAnomalyBelowBudgetDoesNotTrip(t *testing.T) {
	d := newCostAnomalyDetector(DefaultCostAnomalyConfig(), 16)
	feedCost(d, testProvider, 4, 5.0) // $20 < $25
	if fs := d.Evaluate(base); len(fs) != 0 {
		t.Fatalf("expected no finding below budget, got %v", fs)
	}
}

func TestCostAnomalyEscalatesToHigh(t *testing.T) {
	d := newCostAnomalyDetector(DefaultCostAnomalyConfig(), 16)
	feedCost(d, testProvider, 7, 10.0) // $70 >= 2x budget ($50)
	f, ok := findByRule(d.Evaluate(base), "cost_anomaly")
	if !ok {
		t.Fatal("expected finding")
	}
	if f.Severity != integration.SevHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
}

func TestCostAnomalyBucketsEmptyProviderAsUnknown(t *testing.T) {
	d := newCostAnomalyDetector(DefaultCostAnomalyConfig(), 16)
	feedCost(d, "", 6, 5.0) // $30, no provider
	f, ok := findByRule(d.Evaluate(base), "cost_anomaly")
	if !ok {
		t.Fatal("expected finding for unknown-provider spend")
	}
	if f.DedupKey != "cost_anomaly:"+unknownProvider {
		t.Errorf("dedupKey = %q, want unknown bucket", f.DedupKey)
	}
	if !strings.Contains(f.Summary, unknownProvider) {
		t.Errorf("summary %q missing unknown provider", f.Summary)
	}
}

func TestCostAnomalyIgnoresZeroCost(t *testing.T) {
	d := newCostAnomalyDetector(DefaultCostAnomalyConfig(), 16)
	feedCost(d, testProvider, 1000, 0) // zero-cost events carry no spend
	if fs := d.Evaluate(base); len(fs) != 0 {
		t.Fatalf("expected zero-cost events to be ignored, got %v", fs)
	}
}

func TestCostAnomalyWindowExpiry(t *testing.T) {
	cfg := DefaultCostAnomalyConfig()
	d := newCostAnomalyDetector(cfg, 16)
	feedCost(d, testProvider, 6, 5.0)
	if _, ok := findByRule(d.Evaluate(base), "cost_anomaly"); !ok {
		t.Fatal("expected initial trip")
	}
	later := base.Add(cfg.Window + time.Second)
	if fs := d.Evaluate(later); len(fs) != 0 {
		t.Fatalf("expected spend to age out of the window, got %v", fs)
	}
}
