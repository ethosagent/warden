package tokensvc

import (
	"sort"
	"sync"
	"time"
)

// Metric names, for the exporter W-P5-RETN-06 adds.
const (
	MetricIssued   = "warden_cp_tokens_issued_total"
	MetricDenied   = "warden_cp_tokens_denied_total"
	MetricDuration = "warden_cp_token_exchange_seconds"
)

const (
	// UnknownAgent is the agent label of a token that cannot be attributed to
	// a registered agent. The claimed iss of an unverified assertion is never
	// a label: any caller can send any id.
	UnknownAgent = "unknown"
	// OtherAgent is the label past maxAgentLabels distinct agents, so the
	// label set stays bounded even if the registry grows without limit.
	OtherAgent     = "other"
	maxAgentLabels = 1024
)

// durationBuckets are the upper bounds of the histogram, in seconds.
var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Metrics keeps the token service's counters in memory until the control plane
// has a /metrics endpoint (W-P5-RETN-06). Every method is safe on a nil
// receiver and for concurrent use, so callers never check for it. The only
// labels are a closed Reason and a registered agent id: never a subject, an
// email, an IP or a request value.
type Metrics struct {
	mu     sync.Mutex
	issued map[string]int64
	denied map[Reason]int64
	counts []int64 // per bucket, not cumulative
	sum    float64
	n      int64
}

// NewMetrics returns an empty Metrics with every Reason present at zero.
func NewMetrics() *Metrics {
	m := &Metrics{
		issued: map[string]int64{}, denied: map[Reason]int64{},
		counts: make([]int64, len(durationBuckets)+1),
	}
	for _, r := range AllReasons() {
		m.denied[r] = 0
	}
	return m
}

// Issued counts one issued token for agent, which must be an agent whose
// assertion verified. An empty id counts as UnknownAgent.
func (m *Metrics) Issued(agent string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case agent == "":
		agent = UnknownAgent
	case m.issued[agent] == 0 && len(m.issued) >= maxAgentLabels:
		agent = OtherAgent
	}
	m.issued[agent]++
}

// Denied counts one refusal. A reason outside the closed enum is counted as
// ReasonMalformed, so the label set cannot grow from a request.
func (m *Metrics) Denied(r Reason) {
	if m == nil {
		return
	}
	if !KnownReason(r) {
		r = ReasonMalformed
	}
	m.mu.Lock()
	m.denied[r]++
	m.mu.Unlock()
}

// Observe records one exchange duration.
func (m *Metrics) Observe(d time.Duration) {
	if m == nil {
		return
	}
	s := d.Seconds()
	if s < 0 {
		s = 0
	}
	i := sort.SearchFloat64s(durationBuckets, s)
	m.mu.Lock()
	m.counts[i]++
	m.sum += s
	m.n++
	m.mu.Unlock()
}

// IssuedTotal returns warden_cp_tokens_issued_total{agent}.
func (m *Metrics) IssuedTotal(agent string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issued[agent]
}

// IssuedSnapshot copies warden_cp_tokens_issued_total by agent.
func (m *Metrics) IssuedSnapshot() map[string]int64 {
	out := map[string]int64{}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.issued {
		out[k] = v
	}
	return out
}

// DeniedTotal returns warden_cp_tokens_denied_total{reason}.
func (m *Metrics) DeniedTotal(r Reason) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denied[r]
}

// DeniedSnapshot copies warden_cp_tokens_denied_total by reason. Its keys are
// exactly AllReasons.
func (m *Metrics) DeniedSnapshot() map[Reason]int64 {
	out := map[Reason]int64{}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.denied {
		out[k] = v
	}
	return out
}

// Histogram is a snapshot of warden_cp_token_exchange_seconds: Counts[i] is
// the number of observations at most Bounds[i] seconds (not cumulative), and
// the last element counts the rest.
type Histogram struct {
	Bounds []float64
	Counts []int64
	Sum    float64
	Count  int64
}

// Duration returns a snapshot of the exchange duration histogram.
func (m *Metrics) Duration() Histogram {
	h := Histogram{Bounds: append([]float64(nil), durationBuckets...)}
	if m == nil {
		h.Counts = make([]int64, len(durationBuckets)+1)
		return h
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	h.Counts = append([]int64(nil), m.counts...)
	h.Sum, h.Count = m.sum, m.n
	return h
}
