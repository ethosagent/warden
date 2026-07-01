package controlplane

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// PolicyServer is the policy-serving seam: it serves the ETag-versioned
// allow/deny + settings long-poll and reloads the served policy on demand.
// ServePolicy is the /policy long-poll handler (one of the exactly-three
// worker→CP interactions); Refresh re-reads the policy file and bumps the ETag,
// waking any blocked waiters. Last-known-good is preserved on a reload error.
type PolicyServer interface {
	// ServePolicy handles GET /policy with ETag-based long-poll.
	ServePolicy(w http.ResponseWriter, r *http.Request)
	// Refresh re-reads the policy file and wakes long-poll waiters when the ETag
	// changes. A read/parse error keeps the last-known-good policy.
	Refresh()
}

// policyServer is the concrete PolicyServer. It owns the cohesive serving state
// (the policyWatch plus the load/refresh/etag/serve cluster) so policy serving
// is understandable and fakeable in isolation. It records policy-pull activity
// against the worker registry, exactly as before.
type policyServer struct {
	policyPath string
	token      string
	logger     *slog.Logger
	registry   *WorkerRegistry
	watch      *policyWatch
}

// newPolicyServer constructs the policy-serving component and performs the
// initial load so /policy and the dashboard have policy immediately. registry
// receives SeenPolicyPull on each poll; token gates access when non-empty.
func newPolicyServer(policyPath, token string, logger *slog.Logger, registry *WorkerRegistry) *policyServer {
	ps := &policyServer{
		policyPath: policyPath,
		token:      token,
		logger:     logger,
		registry:   registry,
		watch:      newPolicyWatch(),
	}
	ps.Refresh() // initial load so /policy and the dashboard have policy immediately
	return ps
}

// policyWatch holds the current served policy + its ETag and broadcasts to
// blocked long-poll waiters when it changes. The broadcast is a close-and-replace
// channel: waiters grab the current channel, and a change closes it.
type policyWatch struct {
	mu   sync.Mutex
	wire policyWire
	etag string
	ok   bool // a good policy has been loaded at least once
	ch   chan struct{}
}

func newPolicyWatch() *policyWatch { return &policyWatch{ch: make(chan struct{})} }

// set updates the watched policy and wakes waiters only when the ETag changes.
func (w *policyWatch) set(wire policyWire, etag string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ok && etag == w.etag {
		return
	}
	w.wire, w.etag, w.ok = wire, etag, true
	close(w.ch)
	w.ch = make(chan struct{})
}

// snapshot returns the current policy, ETag, whether one has loaded, and a
// channel that closes when the policy next changes.
func (w *policyWatch) snapshot() (policyWire, string, bool, <-chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.wire, w.etag, w.ok, w.ch
}

// Refresh re-reads the policy file and updates the watch. On a read/parse error
// it logs and keeps the last good policy, so a mid-edit malformed file never
// breaks workers.
func (ps *policyServer) Refresh() {
	wire, err := ps.loadPolicy()
	if err != nil {
		ps.logger.Warn("control plane: policy reload failed; keeping last-known-good", "error", err)
		return
	}
	ps.watch.set(wire, etagFor(wire))
}

// etagFor is a short, stable content hash of the served policy. Because Settings
// is part of policyWire, the ETag automatically covers behavioral settings too:
// any settings change alters the marshaled bytes → a new ETag → long-poll wake.
func etagFor(wire policyWire) string {
	b, _ := json.Marshal(wire)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]) // 16 hex chars
}

// currentETag returns the ETag of the policy currently served (for the dashboard
// "version behind" hint). Empty until the first successful load.
func (ps *policyServer) currentETag() string {
	_, etag, _, _ := ps.watch.snapshot()
	return etag
}

// snapshot exposes the watch snapshot to the owning Server (dashboard live views).
func (ps *policyServer) snapshot() (policyWire, string, bool, <-chan struct{}) {
	return ps.watch.snapshot()
}

// loadPolicy re-reads and validates the policy file, returning the allow/deny
// wire view. Re-reading per call keeps served policy fresh without a watcher.
func (ps *policyServer) loadPolicy() (policyWire, error) {
	prov, err := config.NewLocalYAMLProvider(ps.policyPath)
	if err != nil {
		return policyWire{}, err
	}
	p, err := prov.GetPolicy()
	if err != nil {
		return policyWire{}, err
	}
	// SettingsWireFromPolicy projects only the secret-free behavioral blocks and
	// returns nil when the config is pure allow/deny, so the "settings" key stays
	// absent in that case (back-compat).
	return policyWire{
		Allowlist: p.Allowlist,
		Denylist:  p.Denylist,
		Settings:  config.SettingsWireFromPolicy(p),
	}, nil
}

// ServePolicy serves the current allow/deny policy with ETag-based long-poll.
// A worker sends its current ETag in If-None-Match and an optional ?wait=:
//   - ETag differs   -> 200 with the new policy + ETag (immediate).
//   - ETag matches    -> block up to ?wait for a change, then 200 (changed) or
//     304 Not Modified (timeout). wait==0/absent returns immediately (plain poll).
//
// This is one of the ONLY three worker→CP interactions; the CP never calls the
// worker. A bad mid-edit file never breaks workers: the watch keeps last-good.
func (ps *policyServer) ServePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ps.token != "" {
		want := "Bearer " + ps.token
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	// Register the worker as connected (it announces its id on the pull).
	ps.registry.SeenPolicyPull(r.Header.Get(analytics.ProxyIDHeader))

	inm := trimETag(r.Header.Get("If-None-Match"))
	wait := parseWait(r.URL.Query().Get("wait"))

	for {
		wire, etag, ok, ch := ps.watch.snapshot()
		if !ok {
			// No good policy has ever loaded (e.g. unreadable file at startup).
			http.Error(w, "policy unavailable", http.StatusInternalServerError)
			return
		}
		if etag != inm {
			w.Header().Set("ETag", `"`+etag+`"`)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(wire)
			return
		}
		if wait <= 0 {
			w.Header().Set("ETag", `"`+etag+`"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		timer := time.NewTimer(wait)
		select {
		case <-ch:
			timer.Stop() // policy changed — loop re-evaluates and serves it
		case <-timer.C:
			w.Header().Set("ETag", `"`+etag+`"`)
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			timer.Stop()
			return
		}
	}
}

// parseWait parses the ?wait= long-poll duration, clamped to [min,max]; an
// absent/zero/invalid value means "respond immediately" (plain poll).
func parseWait(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0
	}
	if d < minLongPollWait {
		d = minLongPollWait
	}
	if d > maxLongPollWait {
		d = maxLongPollWait
	}
	return d
}

// trimETag normalizes an If-None-Match value to the bare tag (no quotes / weak prefix).
func trimETag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "W/")
	return strings.Trim(s, `"`)
}
