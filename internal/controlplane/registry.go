package controlplane

import (
	"sort"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/dashboard"
)

// staleAfter is how long without contact before a worker is considered offline.
// Workers poll policy (default 15s) and forward analytics (every few seconds),
// so ~45s tolerates a couple of missed beats before flipping to offline.
const staleAfter = 45 * time.Second

// WorkerRegistry tracks the data-plane workers the control plane has heard from,
// via policy pulls and analytics ingest, for the "connected workers" view. It is
// in-memory (workers re-announce on their next poll) and safe for concurrent use.
type WorkerRegistry struct {
	mu      sync.Mutex
	workers map[string]*workerState
	now     func() time.Time
}

type workerState struct {
	firstSeen       time.Time
	lastSeen        time.Time
	lastPolicyPull  time.Time
	eventsForwarded int64
	policyETag      string // the worker's current policy version (from heartbeat)
}

// NewWorkerRegistry returns an empty registry.
func NewWorkerRegistry() *WorkerRegistry {
	return &WorkerRegistry{workers: make(map[string]*workerState), now: time.Now}
}

// SeenPolicyPull records that the named worker fetched policy. A blank proxyID
// (worker without a configured id) is ignored — it can't be tracked distinctly.
func (r *WorkerRegistry) SeenPolicyPull(proxyID string) {
	if proxyID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	w := r.touch(proxyID, now)
	w.lastPolicyPull = now
}

// SeenIngest records that the named worker forwarded n analytics events.
func (r *WorkerRegistry) SeenIngest(proxyID string, n int) {
	if proxyID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	w := r.touch(proxyID, now)
	if n > 0 {
		w.eventsForwarded += int64(n)
	}
}

// SeenHeartbeat records a heartbeat and the worker's current policy ETag, so the
// dashboard can flag workers that are a policy version behind.
func (r *WorkerRegistry) SeenHeartbeat(proxyID, policyETag string) {
	if proxyID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.touch(proxyID, r.now())
	if policyETag != "" {
		w.policyETag = policyETag
	}
}

// touch returns the worker's state, creating it on first contact. Caller holds mu.
func (r *WorkerRegistry) touch(proxyID string, now time.Time) *workerState {
	w, ok := r.workers[proxyID]
	if !ok {
		w = &workerState{firstSeen: now}
		r.workers[proxyID] = w
	}
	w.lastSeen = now
	return w
}

// Views returns the registry as dashboard rows, online-first then by id. Online
// is computed against staleAfter so it stays correct between dashboard refreshes.
func (r *WorkerRegistry) Views() []dashboard.WorkerView {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]dashboard.WorkerView, 0, len(r.workers))
	for id, w := range r.workers {
		v := dashboard.WorkerView{
			ProxyID:         id,
			FirstSeen:       w.firstSeen.UTC().Format(time.RFC3339),
			LastSeen:        w.lastSeen.UTC().Format(time.RFC3339),
			EventsForwarded: w.eventsForwarded,
			PolicyETag:      w.policyETag,
			Online:          now.Sub(w.lastSeen) < staleAfter,
		}
		if !w.lastPolicyPull.IsZero() {
			v.LastPolicyPull = w.lastPolicyPull.UTC().Format(time.RFC3339)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online // online first
		}
		return out[i].ProxyID < out[j].ProxyID
	})
	return out
}
