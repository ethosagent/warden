package offboard

import (
	"sort"
	"sync"
	"time"
)

// Metric names. The counters are in-memory until W-P5-RETN-06 exports them;
// no label carries a subject.
const (
	MetricRefreshTotal = "warden_cp_offboarding_refresh_total"
	MetricLastRun      = "warden_cp_offboarding_last_run_timestamp_seconds"
)

// Metrics holds the job's counters. A nil *Metrics ignores every call.
type Metrics struct {
	mu      sync.Mutex
	refresh map[string]uint64
	lastRun time.Time
}

// NewMetrics returns empty counters.
func NewMetrics() *Metrics { return &Metrics{refresh: map[string]uint64{}} }

func (m *Metrics) incRefresh(outcome string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[outcome]++
}

func (m *Metrics) setLastRun(t time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastRun = t
}

// Refresh returns warden_cp_offboarding_refresh_total{outcome}.
func (m *Metrics) Refresh(outcome string) uint64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refresh[outcome]
}

// Outcomes returns the outcomes counted so far, sorted.
func (m *Metrics) Outcomes() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.refresh))
	for k := range m.refresh {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LastRun returns warden_cp_offboarding_last_run_timestamp_seconds (0 before
// the first run).
func (m *Metrics) LastRun() float64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastRun.IsZero() {
		return 0
	}
	return float64(m.lastRun.UnixMilli()) / 1000
}
