package controlplane

import (
	"slices"
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
	policyETag      string   // the worker's current policy version (from heartbeat)
	caps            []string // capabilities of the latest heartbeat (replaced, not merged)

	// How the worker last authenticated (recordAuth). tokenID/tokenName are set
	// only for kind token; legacy and none ids are unverified headers.
	authKind  WorkerKind
	tokenID   string
	tokenName string
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
// dashboard can flag workers that are a policy version behind. caps replaces the
// stored set: a worker that stops advertising a capability loses it.
func (r *WorkerRegistry) SeenHeartbeat(proxyID, policyETag string, caps []string) {
	if proxyID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.touch(proxyID, r.now())
	if policyETag != "" {
		w.policyETag = policyETag
	}
	w.caps = append([]string(nil), caps...)
}

// maxWorkersWithoutCap bounds the WorkersWithoutCap result.
const maxWorkersWithoutCap = 100

// WorkersWithoutCap returns the ids of connected (online) workers that do not
// advertise cap, sorted and capped at 100.
func (r *WorkerRegistry) WorkersWithoutCap(cap string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []string
	for id, w := range r.workers {
		if now.Sub(w.lastSeen) >= staleAfter || slices.Contains(w.caps, cap) {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > maxWorkersWithoutCap {
		out = out[:maxWorkersWithoutCap]
	}
	return out
}

// recordAuth notes how the worker behind p last authenticated. A principal
// without a proxy id (a legacy or anonymous caller with no header) is ignored,
// like the Seen* methods.
func (r *WorkerRegistry) recordAuth(p WorkerPrincipal) {
	if p.ProxyID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.touch(p.ProxyID, r.now())
	w.authKind, w.tokenID, w.tokenName = p.Kind, p.TokenID, p.TokenName
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
			Caps:            append([]string(nil), w.caps...),
			Online:          now.Sub(w.lastSeen) < staleAfter,
			AuthKind:        string(w.authKind),
			TokenName:       w.tokenName,
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
