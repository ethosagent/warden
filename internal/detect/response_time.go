package detect

import (
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// ResponseTimeConfig configures the response_time detector (category
// "reliability").
type ResponseTimeConfig struct {
	// Enabled turns the detector on.
	Enabled bool
	// Window is the sliding window over which latency samples are averaged.
	Window time.Duration
	// MinSamples is the minimum number of in-window samples before an average is
	// meaningful.
	MinSamples int
	// FloorMs is an absolute latency floor (milliseconds): below it, a spike is
	// never reported however large the relative jump — avoids alerting on a fast
	// endpoint that merely doubled from a trivially low baseline.
	FloorMs float64
	// DegradeFactor is the multiple of the rolling baseline the window average
	// must reach to trip.
	DegradeFactor float64
	// BaselineAlpha is the EWMA weight (0..1] applied to a fresh window average
	// when updating the baseline. Higher tracks faster.
	BaselineAlpha float64
}

// DefaultResponseTimeConfig: 5m window, ≥10 samples, 800ms floor, 3× baseline,
// 0.3 EWMA weight.
func DefaultResponseTimeConfig() ResponseTimeConfig {
	return ResponseTimeConfig{
		Enabled:       true,
		Window:        5 * time.Minute,
		MinSamples:    10,
		FloorMs:       800,
		DegradeFactor: 3.0,
		BaselineAlpha: 0.3,
	}
}

// responseTimeState is one domain's window of latency samples plus a rolling
// baseline. baseline is the EWMA of past NON-tripped window averages; baseline
// <= 0 means "not yet established".
type responseTimeState struct {
	w        slidingWindow[int64]
	baseline float64
	proxyID  string
}

// responseTimeDetector trips when a domain's window-average latency both clears
// an absolute floor AND is a large multiple of its own rolling baseline. The
// baseline updates ONLY on non-tripped evaluations, so it does not chase a spike
// (a spike would otherwise raise the baseline and mask itself). A gradual rise
// the baseline can track never reaches DegradeFactor× and does not falsely trip;
// a sudden sustained jump above a settled baseline does.
type responseTimeDetector struct {
	cfg ResponseTimeConfig
	win *keyedWindows[responseTimeState]
}

func newResponseTimeDetector(cfg ResponseTimeConfig, maxKeys int) *responseTimeDetector {
	if cfg.BaselineAlpha <= 0 || cfg.BaselineAlpha > 1 {
		cfg.BaselineAlpha = 0.3
	}
	window := cfg.Window
	return &responseTimeDetector{
		cfg: cfg,
		win: newKeyedWindows(maxKeys, func() *responseTimeState {
			return &responseTimeState{w: slidingWindow[int64]{window: window}}
		}),
	}
}

func (d *responseTimeDetector) Name() string { return "response_time" }

// Evictions exposes the cardinality-cap eviction count.
func (d *responseTimeDetector) Evictions() uint64 { return d.win.Evictions() }

// Observe records the latency of each event that reached an upstream response
// (ResponseStatus >= 100) for a domain. Domain-less or pre-response events carry
// no latency signal and are ignored.
func (d *responseTimeDetector) Observe(e analytics.Event) {
	if e.Domain == "" || e.ResponseStatus < 100 || e.LatencyMs < 0 {
		return
	}
	latency := e.LatencyMs
	proxyID := e.ProxyID
	ts := e.Timestamp
	d.win.observe(e.Domain, ts, func(s *responseTimeState) {
		if proxyID != "" {
			s.proxyID = proxyID
		}
		s.w.prune(ts)
		s.w.add(ts, latency)
	})
}

// Evaluate emits a Medium finding (escalated to High at 5× baseline) for each
// domain whose window average clears FloorMs and is at least DegradeFactor× a
// positive established baseline. On a non-trip with enough samples it advances
// the EWMA baseline; on a trip it deliberately leaves the baseline untouched.
func (d *responseTimeDetector) Evaluate(now time.Time) []integration.Finding {
	var findings []integration.Finding
	d.win.evaluate(func(domain string, s *responseTimeState) {
		s.w.prune(now)
		n := s.w.len()
		if n < d.cfg.MinSamples {
			return
		}
		var sum int64
		for _, sample := range s.w.live() {
			sum += sample.v
		}
		avg := float64(sum) / float64(n)

		// Establish the baseline on the first sufficiently-sampled window; never
		// trip before there is a baseline to compare against. avg <= 0 cannot seed
		// a meaningful baseline, so wait for real latency.
		if s.baseline <= 0 {
			if avg > 0 {
				s.baseline = avg
			}
			return
		}

		tripped := avg >= d.cfg.FloorMs && avg >= d.cfg.DegradeFactor*s.baseline
		if !tripped {
			// Track the baseline only while healthy so it follows a genuine drift
			// but cannot chase a spike.
			s.baseline = d.cfg.BaselineAlpha*avg + (1-d.cfg.BaselineAlpha)*s.baseline
			return
		}

		sev := integration.SevMedium
		if avg >= 5*s.baseline {
			sev = integration.SevHigh
		}
		win := durLabel(d.cfg.Window)
		findings = append(findings, integration.Finding{
			RuleID:   d.Name(),
			Category: "reliability",
			Severity: sev,
			Subject:  integration.Subject{Domain: domain, Worker: s.proxyID},
			Summary: fmt.Sprintf("latency %dms avg over %s → %s (baseline %dms)",
				int64(avg), win, domain, int64(s.baseline)),
			Evidence: integration.Evidence(fmt.Sprintf(
				"avg_ms=%d baseline_ms=%d samples=%d window=%s",
				int64(avg), int64(s.baseline), n, win)),
			DedupKey: d.Name() + ":" + domain,
			Ts:       now,
		})
	}, func(s *responseTimeState) bool {
		// Drop only a fully-idle key with no baseline worth preserving.
		return s.w.len() == 0 && s.baseline <= 0
	})
	return findings
}
