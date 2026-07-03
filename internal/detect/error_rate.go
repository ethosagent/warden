package detect

import (
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// ErrorRateConfig configures the error_rate detector (category "reliability").
type ErrorRateConfig struct {
	// Enabled turns the detector on.
	Enabled bool
	// Window is the sliding window over which requests/errors are counted.
	Window time.Duration
	// MinSamples is the minimum number of in-window requests before a rate is
	// meaningful (gates against tiny-denominator noise).
	MinSamples int
	// RateThreshold is the errors/total fraction (0..1) at or above which the
	// detector trips.
	RateThreshold float64
}

// DefaultErrorRateConfig: 5m window, ≥20 requests, ≥10% error rate.
func DefaultErrorRateConfig() ErrorRateConfig {
	return ErrorRateConfig{
		Enabled:       true,
		Window:        5 * time.Minute,
		MinSamples:    20,
		RateThreshold: 0.10,
	}
}

// errorRateState is one domain's window of request outcomes: each sample's value
// is true when the response was a 5xx.
type errorRateState struct {
	w       slidingWindow[bool]
	proxyID string
}

// errorRateDetector trips when a domain's in-window 5xx rate meets the threshold.
type errorRateDetector struct {
	cfg ErrorRateConfig
	win *keyedWindows[errorRateState]
}

func newErrorRateDetector(cfg ErrorRateConfig, maxKeys int) *errorRateDetector {
	window := cfg.Window
	return &errorRateDetector{
		cfg: cfg,
		win: newKeyedWindows(maxKeys, func() *errorRateState {
			return &errorRateState{w: slidingWindow[bool]{window: window}}
		}),
	}
}

func (d *errorRateDetector) Name() string { return "error_rate" }

// Evictions exposes the cardinality-cap eviction count.
func (d *errorRateDetector) Evictions() uint64 { return d.win.Evictions() }

// Observe counts one request per event that reached an upstream response
// (ResponseStatus >= 100), flagging 5xx as an error. Events with no domain or no
// upstream response (e.g. a pre-response block, status 0) are ignored: they are
// not upstream-reliability signal.
func (d *errorRateDetector) Observe(e analytics.Event) {
	if e.Domain == "" || e.ResponseStatus < 100 {
		return
	}
	isErr := e.ResponseStatus >= 500
	proxyID := e.ProxyID
	ts := e.Timestamp
	d.win.observe(e.Domain, ts, func(s *errorRateState) {
		if proxyID != "" {
			s.proxyID = proxyID
		}
		s.w.prune(ts)
		s.w.add(ts, isErr)
	})
}

// Evaluate emits, for each domain with total >= MinSamples and rate >=
// RateThreshold, a Medium finding — escalated to High when the rate is at least
// 2× the threshold or at least 50%.
func (d *errorRateDetector) Evaluate(now time.Time) []integration.Finding {
	var findings []integration.Finding
	d.win.evaluate(func(domain string, s *errorRateState) {
		s.w.prune(now)
		total := s.w.len()
		if total < d.cfg.MinSamples {
			return
		}
		errors := 0
		for _, sample := range s.w.live() {
			if sample.v {
				errors++
			}
		}
		rate := float64(errors) / float64(total)
		if rate < d.cfg.RateThreshold {
			return
		}
		sev := integration.SevMedium
		if rate >= 2*d.cfg.RateThreshold || rate >= 0.5 {
			sev = integration.SevHigh
		}
		win := durLabel(d.cfg.Window)
		findings = append(findings, integration.Finding{
			RuleID:   d.Name(),
			Category: "reliability",
			Severity: sev,
			Subject:  integration.Subject{Domain: domain, Worker: s.proxyID},
			Summary: fmt.Sprintf("error rate %.1f%% over %s (%d/%d) → %s",
				rate*100, win, errors, total, domain),
			Evidence: integration.Evidence(fmt.Sprintf(
				"total=%d errors=%d rate=%.3f window=%s", total, errors, rate, win)),
			DedupKey: d.Name() + ":" + domain,
			Ts:       now,
		})
	}, func(s *errorRateState) bool { return s.w.len() == 0 })
	return findings
}
