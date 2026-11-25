package controlplane

import (
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/config"
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
	agentID         string   // the agent the worker says it serves (latest heartbeat; valid or empty)
	identityMode    string   // the identity mode the worker says it runs (latest heartbeat; enum or empty)
	bundle          WorkerBundle
	// loggedReject is the rejection reason last logged for the worker and
	// aheadLogged whether the ahead-of-head ERROR was logged, so each is
	// logged once per change, not once per heartbeat (NoteBundleSignals).
	loggedReject string
	aheadLogged  bool

	// How the worker last authenticated (recordAuth). tokenID/tokenName are set
	// only for kind token; legacy and none ids are unverified headers.
	authKind  WorkerKind
	tokenID   string
	tokenName string
	// certSerial and certNotAfter describe the certificate of the latest cert
	// authentication (kind cert only).
	certSerial   string
	certNotAfter time.Time
	// seenSerials are the last few certificate serials the worker authenticated
	// with, oldest first. Renewal's lineage rule asks whether a successor was
	// ever used; the latest alone would be overwritten by the predecessor's own
	// renewal request.
	seenSerials []string
}

// maxSeenSerials bounds workerState.seenSerials.
const maxSeenSerials = 8

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

// WorkerBundle is the signed-bundle state of a worker's latest heartbeat
// (W-P2-SBND-05), already validated by the control plane (validWorkerBundle):
// times are RFC 3339 UTC, kids are well-formed, and RejectReason is in the
// closed set. The zero value is a worker that reports nothing.
type WorkerBundle struct {
	Seq          int64
	KID          string
	IssuedAt     string
	PinnedKIDs   []string
	Stale        bool
	RejectReason string
	RejectAt     string
}

// SeenHeartbeat records a heartbeat and the worker's current policy ETag, so the
// dashboard can flag workers that are a policy version behind. caps replaces the
// stored set: a worker that stops advertising a capability loses it. bundle
// replaces the stored bundle state the same way.
//
// agentID and identityMode (W-P2-AREG-03) replace the stored values too, under
// the same lock, so a view never pairs new caps with an old agent binding. The
// caller has already validated them (validAgentBinding); a worker is never trusted.
func (r *WorkerRegistry) SeenHeartbeat(proxyID, policyETag string, caps []string, agentID, identityMode string, bundle WorkerBundle) {
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
	w.agentID = agentID
	w.identityMode = identityMode
	bundle.PinnedKIDs = append([]string(nil), bundle.PinnedKIDs...)
	w.bundle = bundle
}

// NoteBundleSignals reports whether a heartbeat of proxyID is the first to show
// a new rejection reason (rejectChanged) or the first to put the worker above
// the control plane's head seq (aheadNew). Each is true once per change, so the
// caller logs once per (worker, reason) and once per worker while ahead. A
// worker that stops being rejected or ahead re-arms, so a later one logs again.
func (r *WorkerRegistry) NoteBundleSignals(proxyID, reason string, ahead bool) (rejectChanged, aheadNew bool) {
	if proxyID == "" {
		return false, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.workers[proxyID]
	if !ok {
		return false, false
	}
	rejectChanged = reason != "" && reason != w.loggedReject
	w.loggedReject = reason
	aheadNew = ahead && !w.aheadLogged
	w.aheadLogged = ahead
	return rejectChanged, aheadNew
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

// FlagBundleState sets Behind and BundleSeqAhead on every view of a worker that
// verifies signed bundles (advertises bundle/v1), from the seq it reports. Such
// a worker's heartbeat ETag is the signed envelope's, which never equals the
// legacy wire's ETag the control plane serves, so comparing ETags would show
// every pinned worker as behind. headSeq is the control plane's newest signed
// seq (0 = it serves no bundle: nothing to compare, so neither flag is set).
// A worker without the cap keeps the ETag comparison done by the caller.
func FlagBundleState(views []dashboard.WorkerView, headSeq int64) {
	for i := range views {
		v := &views[i]
		if !slices.Contains(v.Caps, config.CapBundleV1) {
			continue
		}
		v.Behind = headSeq > 0 && v.BundleSeq < headSeq
		v.BundleSeqAhead = headSeq > 0 && v.BundleSeq > headSeq
	}
}

// FlagNoGroupPolicy sets NoGroupPolicy on every view whose caps lack
// grouppolicy/v1 when the served policy has scopedEntries > 0. A legacy worker
// (no caps) is flagged too.
func FlagNoGroupPolicy(views []dashboard.WorkerView, scopedEntries int) {
	if scopedEntries <= 0 {
		return
	}
	for i := range views {
		views[i].NoGroupPolicy = !slices.Contains(views[i].Caps, config.CapGroupPolicyV1)
	}
}

// FlagNoIdentityChallenge sets NoIdentityChallenge on every view whose caps lack
// identity/challenge-v1 while the served settings turn challenge mode on. Such
// a worker rejects the unknown mode and keeps allowing; a legacy worker (no
// caps) is flagged too.
func FlagNoIdentityChallenge(views []dashboard.WorkerView, challengeServed bool) {
	if !challengeServed {
		return
	}
	for i := range views {
		views[i].NoIdentityChallenge = !slices.Contains(views[i].Caps, config.CapIdentityChallengeV1)
	}
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
	w.certSerial, w.certNotAfter = p.CertSerial, p.NotAfter
	if p.Kind == KindCert && !slices.Contains(w.seenSerials, p.CertSerial) {
		if len(w.seenSerials) >= maxSeenSerials {
			w.seenSerials = w.seenSerials[1:]
		}
		w.seenSerials = append(w.seenSerials, p.CertSerial)
	}
}

// certSeen reports whether the worker authenticated with the certificate of
// this serial since the control plane started (among its last few).
func (r *WorkerRegistry) certSeen(proxyID, serial string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.workers[proxyID]
	return ok && slices.Contains(w.seenSerials, serial)
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
			AgentID:         w.agentID,
			IdentityMode:    w.identityMode,
			Online:          now.Sub(w.lastSeen) < staleAfter,
			AuthKind:        string(w.authKind),
			TokenName:       w.tokenName,

			BundleSeq:        w.bundle.Seq,
			BundleKID:        w.bundle.KID,
			BundleIssuedAt:   w.bundle.IssuedAt,
			PinnedKIDs:       append([]string(nil), w.bundle.PinnedKIDs...),
			BundleStale:      w.bundle.Stale,
			LastRejectReason: w.bundle.RejectReason,
			LastRejectAt:     w.bundle.RejectAt,
		}
		if w.authKind == KindCert {
			v.CertSerial = w.certSerial
			v.CertNotAfter = w.certNotAfter.UTC().Format(time.RFC3339)
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
