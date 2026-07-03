package detect

import (
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// unknownProvider is the bucket for cost-bearing events with no attributed
// provider, so spend is never silently dropped.
const unknownProvider = "unknown"

// CostAnomalyConfig configures the cost_anomaly detector (category "cost").
type CostAnomalyConfig struct {
	// Enabled turns the detector on.
	Enabled bool
	// Window is the sliding window over which per-provider spend is summed.
	Window time.Duration
	// BudgetUSD is the in-window spend (US dollars) at or above which the detector
	// trips.
	BudgetUSD float64
}

// DefaultCostAnomalyConfig: 1h window, $25 budget.
func DefaultCostAnomalyConfig() CostAnomalyConfig {
	return CostAnomalyConfig{
		Enabled:   true,
		Window:    time.Hour,
		BudgetUSD: 25.0,
	}
}

// costState is one provider's window of per-event cost samples (US dollars).
type costState struct {
	w       slidingWindow[float64]
	proxyID string
}

// costAnomalyDetector trips when a provider's summed in-window spend meets the
// budget — a runaway-agent / cost-exfiltration tripwire.
type costAnomalyDetector struct {
	cfg CostAnomalyConfig
	win *keyedWindows[costState]
}

func newCostAnomalyDetector(cfg CostAnomalyConfig, maxKeys int) *costAnomalyDetector {
	window := cfg.Window
	return &costAnomalyDetector{
		cfg: cfg,
		win: newKeyedWindows(maxKeys, func() *costState {
			return &costState{w: slidingWindow[float64]{window: window}}
		}),
	}
}

func (d *costAnomalyDetector) Name() string { return "cost_anomaly" }

// Evictions exposes the cardinality-cap eviction count.
func (d *costAnomalyDetector) Evictions() uint64 { return d.win.Evictions() }

// Observe records positive-cost events, keyed by provider (empty provider is
// bucketed as "unknown" so spend is never dropped). Zero/negative-cost events
// carry no spend signal and are ignored.
func (d *costAnomalyDetector) Observe(e analytics.Event) {
	if e.CostUSD <= 0 {
		return
	}
	provider := e.Provider
	if provider == "" {
		provider = unknownProvider
	}
	cost := e.CostUSD
	proxyID := e.ProxyID
	ts := e.Timestamp
	d.win.observe(provider, ts, func(s *costState) {
		if proxyID != "" {
			s.proxyID = proxyID
		}
		s.w.prune(ts)
		s.w.add(ts, cost)
	})
}

// Evaluate emits, for each provider whose in-window spend meets BudgetUSD, a
// Medium finding — escalated to High at 2× budget. Provider is carried in the
// DedupKey and Summary (Subject has no provider field); Subject.Worker records
// the reporting worker.
func (d *costAnomalyDetector) Evaluate(now time.Time) []integration.Finding {
	var findings []integration.Finding
	d.win.evaluate(func(provider string, s *costState) {
		s.w.prune(now)
		if s.w.len() == 0 {
			return
		}
		var sum float64
		for _, sample := range s.w.live() {
			sum += sample.v
		}
		if sum < d.cfg.BudgetUSD {
			return
		}
		sev := integration.SevMedium
		if sum >= 2*d.cfg.BudgetUSD {
			sev = integration.SevHigh
		}
		win := durLabel(d.cfg.Window)
		findings = append(findings, integration.Finding{
			RuleID:   d.Name(),
			Category: "cost",
			Severity: sev,
			Subject:  integration.Subject{Worker: s.proxyID},
			Summary: fmt.Sprintf("$%.2f spend in %s on %s (budget $%.2f)",
				sum, win, provider, d.cfg.BudgetUSD),
			Evidence: integration.Evidence(fmt.Sprintf(
				"spend=%.2f budget=%.2f window=%s", sum, d.cfg.BudgetUSD, win)),
			DedupKey: d.Name() + ":" + provider,
			Ts:       now,
		})
	}, func(s *costState) bool { return s.w.len() == 0 })
	return findings
}
