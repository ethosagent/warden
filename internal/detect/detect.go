// Package detect is Warden's temporal detection engine: a set of windowed
// detectors that consume the analytics event stream and emit
// integration.Findings for temporal conditions (error spikes, auth-failure
// bursts, cost anomalies, latency degradation) that a single event can never
// reveal.
//
// The engine is deliberately self-contained: it imports only internal/analytics
// (the Event it consumes) and internal/integration (the Finding it produces).
// Neither imports detect, so there is no cycle. Phase 2 wires the engine into
// the control plane / worker (Observe from the ingest goroutine, Evaluate on a
// tick); this package is importable and fully testable in isolation with an
// injected clock.
//
// Concurrency model: a detector's Observe (called from the ingest goroutine) and
// Evaluate (called from the tick goroutine) may run concurrently. Each detector
// guards its per-key windowed state with a mutex (see keyedWindows), so the
// engine is safe to drive from separate goroutines.
//
// Level-triggered emit: a detector emits a Finding on EACH Evaluate while its
// condition holds — never per event. The downstream AlertManager dedups by
// DedupKey and bumps Count, so an alert's Count reflects the number of detection
// windows the condition persisted (its LastSeen stays fresh while it re-fires).
//
// EGRESS HYGIENE (hard invariant): a Finding's Summary and Evidence cross
// Warden's trust boundary (the router pushes the derived Alert to webhooks /
// Slack). They carry ONLY bounded metadata — a domain, a provider, and numeric
// counts / rates / latency / cost. NEVER a URL, a request/response body, a
// free-text reason, or a raw value. The detectors here never read URL / Reason /
// JudgeReason, so hygiene is structural: Summaries are domain-or-provider plus
// numbers, and nothing else.
//
// TODO(m3-phase-later): the complex correlation detectors — "suspicious
// sequences" (ordered multi-tool patterns) and "cross-MCP correlation" (a
// finding that spans several MCP servers) — are intentionally NOT built here.
// This phase ships the initial solid set (error_rate, auth_fail_burst,
// cost_anomaly, response_time); the correlation detectors are a later phase.
package detect

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// defaultMaxKeys caps the number of distinct keys (domains/providers) a single
// detector tracks. Domains and providers are unbounded attacker/agent-controlled
// dimensions, so an uncapped per-key map is a memory leak. When a detector is at
// the cap and observes a new key, it evicts the least-recently-observed key.
const defaultMaxKeys = 1024

// Detector observes events and, on Evaluate (a tick), emits Findings for tripped
// temporal conditions. Implementations are concurrency-safe: Observe is called
// from the ingest goroutine and Evaluate from the tick goroutine, possibly
// concurrently.
type Detector interface {
	// Name is the stable detector identifier (also the DedupKey rule-id prefix).
	Name() string
	// Observe folds one event into the detector's windowed state. It must be
	// cheap and allocation-light; it never emits.
	Observe(e analytics.Event)
	// Evaluate is called on each tick with the engine clock's current time. It
	// prunes expired samples and returns a Finding for every key whose condition
	// currently holds (level-triggered — emits again next tick if still tripped).
	Evaluate(now time.Time) []integration.Finding
}

// evictionCounter is implemented by detectors that track bounded per-key state;
// the engine sums it so operators can see how often cardinality caps evict keys.
type evictionCounter interface {
	Evictions() uint64
}

// Config holds the engine's per-detector sub-configs plus the shared cardinality
// cap. Each detector reads ONLY its own sub-config.
type Config struct {
	ErrorRate     ErrorRateConfig
	AuthFailBurst AuthFailBurstConfig
	CostAnomaly   CostAnomalyConfig
	ResponseTime  ResponseTimeConfig
	// MaxKeys caps the number of distinct keys each detector tracks (bounded
	// cardinality). 0 uses defaultMaxKeys.
	MaxKeys int
}

// DefaultConfig returns a not-noisy, works-out-of-box configuration: every
// detector enabled with conservative thresholds and the default cardinality cap.
func DefaultConfig() Config {
	return Config{
		ErrorRate:     DefaultErrorRateConfig(),
		AuthFailBurst: DefaultAuthFailBurstConfig(),
		CostAnomaly:   DefaultCostAnomalyConfig(),
		ResponseTime:  DefaultResponseTimeConfig(),
		MaxKeys:       defaultMaxKeys,
	}
}

// Engine fans each observed event to every enabled detector and aggregates their
// Findings on Evaluate. It holds no mutable shared state beyond the detectors
// (which guard their own state), so Observe and Evaluate are safe to call from
// separate goroutines.
type Engine struct {
	now       func() time.Time
	detectors []Detector
}

// NewEngine builds an engine with the enabled detectors from cfg. now defaults to
// time.Now when nil (tests inject a fake clock). Only detectors whose sub-config
// Enabled is true are constructed.
func NewEngine(cfg Config, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	maxKeys := cfg.MaxKeys
	if maxKeys <= 0 {
		maxKeys = defaultMaxKeys
	}
	var ds []Detector
	if cfg.ErrorRate.Enabled {
		ds = append(ds, newErrorRateDetector(cfg.ErrorRate, maxKeys))
	}
	if cfg.AuthFailBurst.Enabled {
		ds = append(ds, newAuthFailBurstDetector(cfg.AuthFailBurst, maxKeys))
	}
	if cfg.CostAnomaly.Enabled {
		ds = append(ds, newCostAnomalyDetector(cfg.CostAnomaly, maxKeys))
	}
	if cfg.ResponseTime.Enabled {
		ds = append(ds, newResponseTimeDetector(cfg.ResponseTime, maxKeys))
	}
	return &Engine{now: now, detectors: ds}
}

// Observe fans each event to every enabled detector.
func (e *Engine) Observe(events []analytics.Event) {
	for _, ev := range events {
		for _, d := range e.detectors {
			d.Observe(ev)
		}
	}
}

// Evaluate calls each detector's Evaluate at the engine clock's current time and
// concatenates their Findings.
func (e *Engine) Evaluate() []integration.Finding {
	now := e.now()
	var out []integration.Finding
	for _, d := range e.detectors {
		out = append(out, d.Evaluate(now)...)
	}
	return out
}

// Detectors returns the names of the enabled detectors, in construction order.
func (e *Engine) Detectors() []string {
	names := make([]string, len(e.detectors))
	for i, d := range e.detectors {
		names[i] = d.Name()
	}
	return names
}

// Evictions returns the total number of cardinality-cap evictions across all
// detectors that track bounded per-key state.
func (e *Engine) Evictions() uint64 {
	var total uint64
	for _, d := range e.detectors {
		if c, ok := d.(evictionCounter); ok {
			total += c.Evictions()
		}
	}
	return total
}

// stamped is a single time-tagged sample in a sliding window.
type stamped[T any] struct {
	t time.Time
	v T
}

// slidingWindow is a prune-on-demand window of time-tagged samples of one type,
// keeping only samples strictly newer than now-window.
//
// It is a ring: expired samples are dropped by advancing a head index (start)
// rather than filtering the whole slice, so pruning is amortized O(1) per sample
// — pruning on every Observe stays cheap even for a hot key that sees thousands
// of events per window (an O(n) filter-per-Observe would be O(n²) per window).
// The backing array is compacted when its dead prefix reaches half its length,
// so a burst that ages out frees memory.
//
// Samples are appended in observation order, which for the analytics event
// stream IS time order; prune therefore drops the expired PREFIX. A rare
// out-of-order straggler is retained at most one extra window (a benign
// over-count for a heuristic detector), never dropped early.
type slidingWindow[T any] struct {
	window  time.Duration
	samples []stamped[T]
	start   int // samples[:start] are pruned (dead); samples[start:] are live
}

// add appends a sample at time t. Callers prune before/after as appropriate.
func (w *slidingWindow[T]) add(t time.Time, v T) {
	w.samples = append(w.samples, stamped[T]{t: t, v: v})
}

// prune advances past every sample at or before now-window (keeping t strictly
// after the cutoff), then compacts the backing array once its dead prefix
// dominates so aged-out samples are collectable.
func (w *slidingWindow[T]) prune(now time.Time) {
	cutoff := now.Add(-w.window)
	for w.start < len(w.samples) && !w.samples[w.start].t.After(cutoff) {
		w.samples[w.start] = stamped[T]{} // release any reference for GC
		w.start++
	}
	if w.start > 0 && w.start*2 >= len(w.samples) {
		n := copy(w.samples, w.samples[w.start:])
		for i := n; i < len(w.samples); i++ {
			w.samples[i] = stamped[T]{}
		}
		w.samples = w.samples[:n]
		w.start = 0
	}
}

// live returns the currently-in-window samples (call prune first for an exact
// windowed view).
func (w *slidingWindow[T]) live() []stamped[T] { return w.samples[w.start:] }

// len reports the number of live samples (call prune first for a windowed count).
func (w *slidingWindow[T]) len() int { return len(w.samples) - w.start }

// keyEntry is one tracked key's state plus its recency for LRU eviction.
type keyEntry[S any] struct {
	state   *S
	lastObs time.Time
}

// keyedWindows maps a key (domain or provider) to per-key detector state with a
// bounded cardinality cap and least-recently-observed eviction. It owns the
// mutex that makes a detector concurrency-safe: observe (ingest goroutine) and
// evaluate (tick goroutine) both take it.
type keyedWindows[S any] struct {
	mu        sync.Mutex
	entries   map[string]*keyEntry[S]
	maxKeys   int
	newState  func() *S
	evictions uint64
}

// newKeyedWindows builds a keyed store capped at maxKeys, using newState to
// lazily create a key's state on first observation.
func newKeyedWindows[S any](maxKeys int, newState func() *S) *keyedWindows[S] {
	if maxKeys <= 0 {
		maxKeys = defaultMaxKeys
	}
	return &keyedWindows[S]{
		entries:  make(map[string]*keyEntry[S]),
		maxKeys:  maxKeys,
		newState: newState,
	}
}

// observe resolves (or creates) the state for key, bumps its recency to obsTime,
// and runs fn against it under the lock. On creating a new key while at the cap
// it first evicts the least-recently-observed key.
func (k *keyedWindows[S]) observe(key string, obsTime time.Time, fn func(*S)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.entries[key]
	if !ok {
		if len(k.entries) >= k.maxKeys {
			k.evictLRULocked()
		}
		e = &keyEntry[S]{state: k.newState()}
		k.entries[key] = e
	}
	if obsTime.After(e.lastObs) {
		e.lastObs = obsTime
	}
	fn(e.state)
}

// evaluate runs fn for every tracked key (in sorted key order for deterministic
// Finding ordering) under the lock. When stale is non-nil and reports true for a
// key's state after fn, that key is deleted — so an idle key whose window has
// fully aged out does not occupy a cardinality slot forever.
func (k *keyedWindows[S]) evaluate(fn func(key string, s *S), stale func(*S) bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	keys := make([]string, 0, len(k.entries))
	for key := range k.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		e := k.entries[key]
		fn(key, e.state)
		if stale != nil && stale(e.state) {
			delete(k.entries, key)
		}
	}
}

// evictLRULocked removes the least-recently-observed key. Caller holds the lock.
func (k *keyedWindows[S]) evictLRULocked() {
	var (
		oldestKey string
		oldestTs  time.Time
		found     bool
	)
	for key, e := range k.entries {
		if !found || e.lastObs.Before(oldestTs) {
			oldestKey, oldestTs, found = key, e.lastObs, true
		}
	}
	if found {
		delete(k.entries, oldestKey)
		k.evictions++
	}
}

// Evictions returns how many keys this store has evicted for the cardinality cap.
func (k *keyedWindows[S]) Evictions() uint64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.evictions
}

// len returns the number of currently tracked keys (test/introspection helper).
func (k *keyedWindows[S]) len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.entries)
}

// durLabel renders a window duration compactly ("5m", "1h", "30s") for Summaries.
func durLabel(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	case d%time.Second == 0:
		return fmt.Sprintf("%ds", d/time.Second)
	default:
		return d.String()
	}
}
