package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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

	// overlays are applied in order by loadPolicy after the base wire is built.
	// overlayMu guards appends; sealed is set by the first Refresh or ServePolicy,
	// after which overlays never changes and is read without the lock.
	overlayMu sync.Mutex
	overlays  []wireOverlay
	sealed    atomic.Bool
}

// wireOverlay merges serve-time data into the served wire: data that must reach
// workers but must never be stored in a policy version, because a rollback
// would otherwise restore it (the AWS credential, the block list). apply runs
// on every Refresh (writes and the reload ticker), never per /policy request,
// and may run concurrently with itself. It returns an opaque fingerprint of
// what it contributed ("" = nothing); an error fails the whole load, so the
// last-known-good wire keeps being served.
type wireOverlay struct {
	name  string
	apply func(ctx context.Context, w *policyWire) (fingerprint string, err error)
}

// maxOverlayErrLen bounds an overlay error in the reload-failure log line.
const maxOverlayErrLen = 256

// newPolicyServer constructs the policy-serving component. It does not load:
// the owner registers overlays (addOverlay) and then calls Refresh once, so
// /policy and the dashboard have policy immediately. registry receives
// SeenPolicyPull on each poll; token gates access when non-empty.
func newPolicyServer(policyPath, token string, logger *slog.Logger, registry *WorkerRegistry) *policyServer {
	return &policyServer{
		policyPath: policyPath,
		token:      token,
		logger:     logger,
		registry:   registry,
		watch:      newPolicyWatch(),
	}
}

// addOverlay registers o to run after the overlays already registered. It is
// for wiring only: after the first Refresh or ServePolicy it returns an error,
// as it does for an empty or duplicate name or a nil apply.
func (ps *policyServer) addOverlay(o wireOverlay) error {
	ps.overlayMu.Lock()
	defer ps.overlayMu.Unlock()
	if ps.sealed.Load() {
		return fmt.Errorf("controlplane: overlay %q registered after the policy server started", o.name)
	}
	if o.name == "" {
		return errors.New("controlplane: overlay name is empty")
	}
	if o.apply == nil {
		return fmt.Errorf("controlplane: overlay %q has no apply func", o.name)
	}
	for _, have := range ps.overlays {
		if have.name == o.name {
			return fmt.Errorf("controlplane: overlay %q already registered", o.name)
		}
	}
	ps.overlays = append(ps.overlays, o)
	return nil
}

// sealOverlays ends overlay registration and returns the final list. Taking
// overlayMu orders every earlier append before the caller's reads.
func (ps *policyServer) sealOverlays() []wireOverlay {
	ps.overlayMu.Lock()
	defer ps.overlayMu.Unlock()
	ps.sealed.Store(true)
	return ps.overlays
}

// overlayFingerprints returns a copy of the overlay fingerprints (overlay name
// to opaque string) of the last successful load. Empty before the first load
// and when no overlay is registered.
func (ps *policyServer) overlayFingerprints() map[string]string {
	return ps.watch.fingerprints()
}

// policyWatch holds the current served policy + its ETag and broadcasts to
// blocked long-poll waiters when it changes. The broadcast is a close-and-replace
// channel: waiters grab the current channel, and a change closes it.
type policyWatch struct {
	mu   sync.Mutex
	wire policyWire
	etag string
	fps  map[string]string // overlay fingerprints of the load that produced wire
	ok   bool              // a good policy has been loaded at least once
	ch   chan struct{}
}

func newPolicyWatch() *policyWatch { return &policyWatch{ch: make(chan struct{})} }

// set updates the watched policy and wakes waiters only when the ETag changes.
// The overlay fingerprints are always replaced: an overlay's fingerprint can
// change while the served bytes do not, and that must not wake waiters.
func (w *policyWatch) set(wire policyWire, etag string, fps map[string]string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fps = fps
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

// fingerprints returns a copy of the overlay fingerprints of the last
// successful load.
func (w *policyWatch) fingerprints() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return maps.Clone(w.fps)
}

// Refresh re-reads the policy file and updates the watch. On a read/parse error
// it logs and keeps the last good policy, so a mid-edit malformed file never
// breaks workers.
func (ps *policyServer) Refresh() {
	wire, fps, err := ps.loadPolicy(context.Background())
	if err != nil {
		var oe *overlayError
		if errors.As(err, &oe) {
			ps.logger.Warn("control plane: policy overlay failed; keeping last-known-good",
				"overlay", oe.name, "error", boundedErr(oe.err))
			return
		}
		ps.logger.Warn("control plane: policy reload failed; keeping last-known-good", "error", err)
		return
	}
	ps.watch.set(wire, etagFor(wire), fps)
}

// overlayError names the overlay whose apply failed a load.
type overlayError struct {
	name string
	err  error
}

func (e *overlayError) Error() string { return "overlay " + e.name + ": " + e.err.Error() }
func (e *overlayError) Unwrap() error { return e.err }

// boundedErr is err's message cut to maxOverlayErrLen bytes, so a verbose
// backend error cannot flood the log.
func boundedErr(err error) string {
	s := err.Error()
	if len(s) <= maxOverlayErrLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxOverlayErrLen], "") + "...(truncated)"
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

// loadPolicy builds the served wire: the base wire from the policy file, then
// every overlay in registration order. It returns each overlay's fingerprint;
// any overlay error fails the load (an *overlayError). It seals overlay
// registration.
func (ps *policyServer) loadPolicy(ctx context.Context) (policyWire, map[string]string, error) {
	overlays := ps.sealOverlays()
	wire, err := ps.loadBase()
	if err != nil {
		return policyWire{}, nil, err
	}
	fps := make(map[string]string, len(overlays))
	for _, o := range overlays {
		fp, err := o.apply(ctx, &wire)
		if err != nil {
			return policyWire{}, nil, &overlayError{name: o.name, err: err}
		}
		fps[o.name] = fp
	}
	return wire, fps, nil
}

// loadBase re-reads and validates the policy file, returning the allow/deny
// wire view with no overlay applied. Re-reading per call keeps served policy
// fresh without a watcher.
func (ps *policyServer) loadBase() (policyWire, error) {
	prov, err := config.NewLocalYAMLProvider(ps.policyPath)
	if err != nil {
		return policyWire{}, err
	}
	p, err := prov.GetPolicy()
	if err != nil {
		return policyWire{}, err
	}
	// The console API is the only source of the served block list (merged from
	// the CP store); a YAML list is ignored, loudly, and never echoed.
	if len(p.BlockedUsers) > 0 {
		ps.logger.Warn("control plane: policy file contains blockedUsers; ignored (manage the block list from the console)",
			"entries", len(p.BlockedUsers))
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
	if !ps.sealed.Load() {
		ps.sealOverlays() // first request ends overlay registration
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
