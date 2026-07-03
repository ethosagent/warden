package detect

import (
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// AuthFailBurstConfig configures the auth_fail_burst detector (category
// "security").
type AuthFailBurstConfig struct {
	// Enabled turns the detector on.
	Enabled bool
	// Window is the sliding window over which auth failures are counted.
	Window time.Duration
	// CountThreshold is the number of 401/403 responses in-window at or above
	// which the detector trips.
	CountThreshold int
}

// DefaultAuthFailBurstConfig: 5m window, ≥10 auth failures.
func DefaultAuthFailBurstConfig() AuthFailBurstConfig {
	return AuthFailBurstConfig{
		Enabled:        true,
		Window:         5 * time.Minute,
		CountThreshold: 10,
	}
}

// authFailState is one domain's window of auth-failure timestamps. The sample
// value is unused (struct{}); the count is len(window).
type authFailState struct {
	w       slidingWindow[struct{}]
	proxyID string
}

// authFailBurstDetector trips when a domain accumulates a burst of 401/403
// responses within the window — a signal of credential stuffing / a broken or
// rotated credential hammering an upstream.
type authFailBurstDetector struct {
	cfg AuthFailBurstConfig
	win *keyedWindows[authFailState]
}

func newAuthFailBurstDetector(cfg AuthFailBurstConfig, maxKeys int) *authFailBurstDetector {
	window := cfg.Window
	return &authFailBurstDetector{
		cfg: cfg,
		win: newKeyedWindows(maxKeys, func() *authFailState {
			return &authFailState{w: slidingWindow[struct{}]{window: window}}
		}),
	}
}

func (d *authFailBurstDetector) Name() string { return "auth_fail_burst" }

// Evictions exposes the cardinality-cap eviction count.
func (d *authFailBurstDetector) Evictions() uint64 { return d.win.Evictions() }

// Observe records one sample per 401/403 response for a domain. All other
// statuses (and domain-less events) are ignored.
func (d *authFailBurstDetector) Observe(e analytics.Event) {
	if e.Domain == "" {
		return
	}
	if e.ResponseStatus != 401 && e.ResponseStatus != 403 {
		return
	}
	proxyID := e.ProxyID
	ts := e.Timestamp
	d.win.observe(e.Domain, ts, func(s *authFailState) {
		if proxyID != "" {
			s.proxyID = proxyID
		}
		s.w.prune(ts)
		s.w.add(ts, struct{}{})
	})
}

// Evaluate emits a High finding for each domain whose in-window auth-failure
// count meets CountThreshold.
func (d *authFailBurstDetector) Evaluate(now time.Time) []integration.Finding {
	var findings []integration.Finding
	d.win.evaluate(func(domain string, s *authFailState) {
		s.w.prune(now)
		count := s.w.len()
		if count < d.cfg.CountThreshold {
			return
		}
		win := durLabel(d.cfg.Window)
		findings = append(findings, integration.Finding{
			RuleID:   d.Name(),
			Category: "security",
			Severity: integration.SevHigh,
			Subject:  integration.Subject{Domain: domain, Worker: s.proxyID},
			Summary: fmt.Sprintf("%d auth failures (401/403) in %s → %s",
				count, win, domain),
			Evidence: integration.Evidence(fmt.Sprintf(
				"count=%d window=%s", count, win)),
			DedupKey: d.Name() + ":" + domain,
			Ts:       now,
		})
	}, func(s *authFailState) bool { return s.w.len() == 0 })
	return findings
}
