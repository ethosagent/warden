package controlplane

import (
	"context"
	"crypto/sha256"
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
	auth       *WorkerAuthenticator
	logger     *slog.Logger
	registry   *WorkerRegistry
	watch      *policyWatch
	// lintWarned holds the per-user limit lint warnings already logged, so a
	// reload logs each distinct one once.
	lintWarned sync.Map

	// overlays are applied in order by loadPolicy after the base wire is built.
	// overlayMu guards appends; sealed is set by the first Refresh or ServePolicy,
	// after which overlays never changes and is read without the lock.
	overlayMu sync.Mutex
	overlays  []wireOverlay
	sealed    atomic.Bool

	// versions is the versioned policy store (--policy-store=versioned), nil in
	// file mode. When its head is above 0 the base wire is the head doc instead
	// of the YAML. Set once at wiring time, before the first Refresh.
	versions PolicyVersionStore
	// headMu guards the cached head: headVer and the doc JSON it was decoded
	// from, so a Refresh with an unchanged head reads only the head version.
	headMu  sync.Mutex
	headVer int64
	headDoc []byte
	// pubMu guards pubVer/pubETag: the head version and served ETag last
	// confirmed in the publish log, so a Refresh that serves the same pair
	// again skips the store.
	pubMu   sync.Mutex
	pubVer  int64
	pubETag string

	// bundles is the signed-bundle publisher (--bundles=offer|require), nil
	// when bundles are off: then none of the fields below is ever touched and
	// /policy is the code it was before bundles existed. Set once at wiring
	// time, before the first Refresh.
	bundles *bundlePublisher
	// now is the clock the envelope's expiry is checked against.
	now func() time.Time
	// refreshMu serializes Refresh end to end (load, publish-log append, sign,
	// swap), so a seq is never built from two interleaved loads. It guards the
	// last good load below and the publisher's state.
	refreshMu sync.Mutex
	loaded    bool
	lastWire  policyWire
	lastETag  string
	lastHead  int64
}

// Publish-log values of an ETag change without a new version.
const (
	publishActorSystem    = "system"
	publishReasonExternal = "external"
	// publishReasonTokenJWKS marks a row appended because the token JWKS
	// changed while the served policy did not; publishReasonRestore marks the
	// row --bundle-seq-floor appends.
	publishReasonTokenJWKS = "token_jwks"
	// publishReasonTokenIssuer marks a row appended because the signed token
	// issuer changed (tokenService.issuer edited, or the service switched on
	// or off) while the served policy did not.
	publishReasonTokenIssuer = "token_issuer"
	publishReasonRestore     = "restore"
)

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
// SeenPolicyPull on each poll; token is the shared token the default
// authenticator checks (empty = open). New replaces the authenticator with the
// control plane's own (worker tokens, mode, counters) before serving.
func newPolicyServer(policyPath, token string, logger *slog.Logger, registry *WorkerRegistry) *policyServer {
	return &policyServer{
		policyPath: policyPath,
		auth:       NewWorkerAuthenticator(WorkerAuthConfig{Legacy: token, Registry: registry, Logger: logger}),
		logger:     logger,
		registry:   registry,
		watch:      newPolicyWatch(),
		now:        time.Now,
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
	// bundle is the newest signed envelope (nil until one is signed or with
	// bundles off). It shares ch with the legacy wire: a change to either
	// wakes every waiter, and each waiter re-checks its own format's ETag.
	bundle *signedBundle
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

// setBundle installs a newly signed envelope and wakes the waiters. An older
// seq, or the same seq with an issuedAt that is not newer, is ignored, so a
// slow build can never move the served envelope backwards.
func (w *policyWatch) setBundle(b *signedBundle) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cur := w.bundle; cur != nil && (b.seq < cur.seq || (b.seq == cur.seq && !b.issuedAt.After(cur.issuedAt))) {
		return
	}
	w.bundle = b
	close(w.ch)
	w.ch = make(chan struct{})
}

// bundleSnapshot returns the current envelope (nil if none) and a channel
// that closes when the policy or the envelope next changes.
func (w *policyWatch) bundleSnapshot() (*signedBundle, <-chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bundle, w.ch
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
// breaks workers. In versioned mode it first records a served-ETag change
// without a new version in the publish log, so a worker on the new ETag maps
// to a version from the moment it can fetch it.
func (ps *policyServer) Refresh() { ps.refresh(false) }

// refresh is Refresh with the option to re-sign the bundle even when its
// content is unchanged (the re-sign ticker and a bundle key change). Under
// refreshMu, a forced re-sign whose reload fails still re-signs the last good
// content, so a mid-edit policy file cannot let the envelope expire.
func (ps *policyServer) refresh(resign bool) {
	ps.refreshMu.Lock()
	defer ps.refreshMu.Unlock()
	ctx := context.Background()
	wire, fps, head, err := ps.loadPolicy(ctx)
	if err != nil {
		var oe *overlayError
		if errors.As(err, &oe) {
			ps.logger.Warn("control plane: policy overlay failed; keeping last-known-good",
				"overlay", oe.name, "error", boundedErr(oe.err))
		} else {
			ps.logger.Warn("control plane: policy reload failed; keeping last-known-good", "error", err)
		}
		if resign && ps.loaded {
			ps.publishBundle(ctx, ps.lastWire, ps.lastETag, ps.lastHead, true)
		}
		return
	}
	if head > 0 {
		// File mode lints the loaded file (loadFile); a versioned head is
		// linted here, when it is applied.
		ps.lintServed(wire)
	}
	etag := etagFor(wire)
	ps.recordPublish(ctx, head, etag, fps)
	ps.watch.set(wire, etag, fps)
	ps.loaded, ps.lastWire, ps.lastETag, ps.lastHead = true, wire, etag, head
	ps.publishBundle(ctx, wire, etag, head, resign)
}

// recordPublish appends a publish-log row when the served ETag of head (0 =
// file mode or an empty store: nothing to map) is not the newest row. A Create
// has already appended its own row, so after a head move this appends
// nothing; the store re-checks under its transaction. A store error is logged
// and retried on the next Refresh; serving never waits on it.
func (ps *policyServer) recordPublish(ctx context.Context, head int64, etag string, fps map[string]string) {
	if ps.versions == nil || head == 0 {
		return
	}
	ps.pubMu.Lock()
	defer ps.pubMu.Unlock()
	if head == ps.pubVer && etag == ps.pubETag {
		return
	}
	reason := ps.publishReason(fps)
	appended, err := ps.versions.AppendPublish(ctx, head, etag, reason, publishActorSystem)
	if err != nil {
		ps.logger.Warn("control plane: policy publish log append failed", "version", head, "error", boundedErr(err))
		return
	}
	ps.pubVer, ps.pubETag = head, etag
	if appended {
		ps.logger.Info("policy publish logged", "version", head, "etag", etag, "reason", reason)
	}
}

// publishReason names the first overlay, in registration order, whose
// fingerprint differs from the last load's, or "external" when none does or
// nothing has loaded yet (a restart cannot tell what changed while down).
func (ps *policyServer) publishReason(fps map[string]string) string {
	if _, _, ok, _ := ps.watch.snapshot(); !ok {
		return publishReasonExternal
	}
	prev := ps.watch.fingerprints()
	for _, o := range ps.sealOverlays() {
		if fps[o.name] != prev[o.name] {
			return o.name
		}
	}
	return publishReasonExternal
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
//
// It hashes the projected wire (projectScoped), the exact shape served, so the
// ETag of a stored doc equals the ETag of the body workers receive.
func etagFor(wire policyWire) string {
	b, _ := json.Marshal(projectScoped(wire))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]) // 16 hex chars
}

// bundleHeadSeq is the seq of the newest signed bundle the control plane
// serves, 0 when it serves none (bundles off, or nothing signed yet).
func (ps *policyServer) bundleHeadSeq() int64 {
	b, _ := ps.watch.bundleSnapshot()
	if b == nil {
		return 0
	}
	return b.seq
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

// loadPolicy builds the served wire: the base wire, then every overlay in
// registration order. It returns each overlay's fingerprint and the head
// version the base came from (0 = the policy file); any overlay error fails
// the load (an *overlayError). It seals overlay registration.
func (ps *policyServer) loadPolicy(ctx context.Context) (policyWire, map[string]string, int64, error) {
	ps.sealOverlays() // even a failed first load ends registration
	wire, head, err := ps.loadBaseHead(ctx)
	if err != nil {
		return policyWire{}, nil, 0, err
	}
	fps, err := ps.applyOverlays(ctx, &wire)
	if err != nil {
		return policyWire{}, nil, 0, err
	}
	return wire, fps, head, nil
}

// applyOverlays runs every overlay on wire in registration order and returns
// their fingerprints; an overlay error is an *overlayError. It seals overlay
// registration.
func (ps *policyServer) applyOverlays(ctx context.Context, wire *policyWire) (map[string]string, error) {
	overlays := ps.sealOverlays()
	fps := make(map[string]string, len(overlays))
	for _, o := range overlays {
		fp, err := o.apply(ctx, wire)
		if err != nil {
			return nil, &overlayError{name: o.name, err: err}
		}
		fps[o.name] = fp
	}
	return fps, nil
}

// servedETag is the /policy ETag doc would be served with: the hash of doc
// with the overlays applied. doc is not modified. The versioned store records
// it in the publish log.
func (ps *policyServer) servedETag(ctx context.Context, doc policyWire) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	var wire policyWire
	if err := json.Unmarshal(b, &wire); err != nil {
		return "", err
	}
	if _, err := ps.applyOverlays(ctx, &wire); err != nil {
		return "", err
	}
	return etagFor(wire), nil
}

// loadBase returns the served wire with no overlay applied: the head doc of the
// versioned store when it has one, otherwise the policy file, re-read and
// validated per call so served policy stays fresh without a watcher.
func (ps *policyServer) loadBase(ctx context.Context) (policyWire, error) {
	wire, _, err := ps.loadBaseHead(ctx)
	return wire, err
}

// loadBaseHead is loadBase plus the head version the wire came from (0 = the
// policy file).
func (ps *policyServer) loadBaseHead(ctx context.Context) (policyWire, int64, error) {
	if ps.versions != nil {
		wire, head, err := ps.loadHead(ctx)
		if err != nil {
			return policyWire{}, 0, err
		}
		if head > 0 {
			return wire, head, nil
		}
	}
	wire, err := ps.loadFile()
	return wire, 0, err
}

// loadHead returns the head doc of the versioned store and its version, or
// version 0 when the store is empty. It reads only the head version unless the head
// moved, in which case it fetches the new doc (checked against doc_sha256).
// Each call decodes a fresh copy, so overlays can modify it freely.
func (ps *policyServer) loadHead(ctx context.Context) (policyWire, int64, error) {
	head, err := ps.versions.Head(ctx)
	if err != nil {
		return policyWire{}, 0, err
	}
	if head == 0 {
		return policyWire{}, 0, nil
	}
	ps.headMu.Lock()
	defer ps.headMu.Unlock()
	if head != ps.headVer {
		v, err := ps.versions.Get(ctx, head)
		if err != nil {
			return policyWire{}, 0, err
		}
		b, err := json.Marshal(v.Doc)
		if err != nil {
			return policyWire{}, 0, fmt.Errorf("policy store: encode head v%d: %w", head, err)
		}
		ps.headVer, ps.headDoc = head, b
	}
	var wire policyWire
	if err := json.Unmarshal(ps.headDoc, &wire); err != nil {
		return policyWire{}, 0, fmt.Errorf("policy store: decode head v%d: %w", head, err)
	}
	return wire, head, nil
}

// loadFile re-reads and validates the policy file, returning the allow/deny
// wire view with no overlay applied.
func (ps *policyServer) loadFile() (policyWire, error) {
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
	for _, msg := range config.LintUserLimits(p) {
		if _, dup := ps.lintWarned.LoadOrStore(msg, struct{}{}); !dup {
			ps.logger.Warn("control plane: " + msg)
		}
	}
	// SettingsWireFromPolicy projects only the secret-free behavioral blocks and
	// returns nil when the config is pure allow/deny, so the "settings" key stays
	// absent in that case (back-compat).
	return policyWireOfPolicy(p), nil
}

// lintServed logs config.LintUserLimits for a served versioned head, each
// distinct warning once. The identity modes come from the head's settings.
// Whether a worker has a CA is known only to that worker, which lints its own
// effective config, so the CA warning is not raised here.
func (ps *policyServer) lintServed(w policyWire) {
	if len(w.UserLimits) == 0 && w.DefaultUserLimit == nil && w.AnonymousLimit == nil {
		return
	}
	for _, msg := range config.LintUserLimits(lintPolicyOfWire(w)) {
		if _, dup := ps.lintWarned.LoadOrStore(msg, struct{}{}); !dup {
			ps.logger.Warn("control plane: " + msg)
		}
	}
}

// lintPolicyOfWire is the policy LintUserLimits needs from a served wire: the
// limit rules plus the agents' and the default identity modes.
func lintPolicyOfWire(w policyWire) config.Policy {
	p := policyOfWire(w)
	// A non-empty CA path only switches off the per-worker CA warning (see
	// lintServed); nothing reads the value.
	p.TLS.CACert = "per-worker"
	if w.Settings != nil {
		if w.Settings.Identity != nil {
			p.Identity = *w.Settings.Identity
		}
		for _, a := range w.Settings.Agents {
			p.Agents = append(p.Agents, config.AgentPolicy{ID: a.ID, Policy: a.Policy, Identity: a.Identity})
		}
	}
	return p
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
	principal, err := ps.auth.Authenticate(r)
	if err != nil {
		WriteWorkerAuthError(w, err)
		return
	}
	if !ps.sealed.Load() {
		ps.sealOverlays() // first request ends overlay registration
	}
	// Register the worker as connected under the authenticated id: a token's
	// bound proxy id, never the raw header.
	ps.registry.SeenPolicyPull(principal.ProxyID)

	inm := trimETag(r.Header.Get("If-None-Match"))
	wait := parseWait(r.URL.Query().Get("wait"))

	// Signed bundles (--bundles=offer|require). With bundles off ps.bundles is
	// nil and this is skipped: the legacy path below is all there is.
	if b := ps.bundles; b != nil {
		if acceptsBundle(r) {
			ps.longPoll(w, r, principal, inm, wait, ps.bundleView)
			return
		}
		if b.cfg.Mode == BundlesRequire {
			writeBundleError(w, http.StatusNotAcceptable, "signed_bundle_required")
			return
		}
	}
	ps.longPoll(w, r, principal, inm, wait, ps.legacyView)
}

// policyView is one format's current state for the long poll: its ETag, the
// channel that closes when anything changes, whether it can be served at all
// and how to write the 200 and the "unavailable" reply.
type policyView struct {
	etag        string
	ch          <-chan struct{}
	ok          bool
	write       func(http.ResponseWriter)
	unavailable func(http.ResponseWriter)
}

// legacyView is the unsigned policyWire view.
func (ps *policyServer) legacyView() policyView {
	wire, etag, ok, ch := ps.watch.snapshot()
	return policyView{
		etag: etag, ch: ch, ok: ok,
		write: func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			// The watch holds the real rules (dashboard, audit and diff read
			// them); the fail-closed projection happens here, on the way out.
			_ = json.NewEncoder(w).Encode(projectScoped(wire))
		},
		// No good policy has ever loaded (e.g. unreadable file at startup).
		unavailable: func(w http.ResponseWriter) { http.Error(w, "policy unavailable", http.StatusInternalServerError) },
	}
}

// bundleView is the signed envelope view. An envelope past its expiresAt is
// not served: a worker would only reject it as expired.
func (ps *policyServer) bundleView() policyView {
	sb, ch := ps.watch.bundleSnapshot()
	if sb == nil || !ps.now().Before(sb.expiresAt) {
		return policyView{ch: ch, unavailable: func(w http.ResponseWriter) {
			writeBundleError(w, http.StatusServiceUnavailable, "signed_bundle_unavailable")
		}}
	}
	return policyView{
		etag: sb.etag, ch: ch, ok: true,
		write: func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", BundleMediaType)
			_, _ = w.Write(sb.env)
		},
	}
}

// longPoll serves one format of the policy with ETag long-poll semantics.
func (ps *policyServer) longPoll(w http.ResponseWriter, r *http.Request, principal WorkerPrincipal, inm string, wait time.Duration, current func() policyView) {
	// A token's held request registers lazily when it first parks and is
	// released when the handler returns.
	var revoked <-chan struct{}
	release := func() {}
	defer func() { release() }()

	for {
		v := current()
		if !v.ok {
			v.unavailable(w)
			return
		}
		if v.etag != inm {
			// Re-authenticate before any write: a token revoked while this
			// request waited never receives the new policy.
			if !ps.stillAuthorized(w, principal) {
				return
			}
			w.Header().Set("ETag", `"`+v.etag+`"`)
			v.write(w)
			return
		}
		if wait <= 0 {
			w.Header().Set("ETag", `"`+v.etag+`"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if revoked == nil {
			revoked, release = ps.auth.WatchRevoke(principal)
		}
		// Register first, then check: a revoke between the initial
		// authentication and the park is seen here, never missed.
		if !ps.stillAuthorized(w, principal) {
			return
		}
		timer := time.NewTimer(wait)
		select {
		case <-v.ch:
			timer.Stop() // policy changed — loop re-evaluates and serves it
		case <-revoked:
			timer.Stop()
			WriteWorkerAuthError(w, ErrUnauthorized)
			return
		case <-timer.C:
			if !ps.stillAuthorized(w, principal) {
				return
			}
			w.Header().Set("ETag", `"`+v.etag+`"`)
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			timer.Stop()
			return
		}
	}
}

// stillAuthorized re-authenticates p from the in-memory index and writes 401
// when its credential is no longer valid.
func (ps *policyServer) stillAuthorized(w http.ResponseWriter, p WorkerPrincipal) bool {
	if err := ps.auth.Reauthenticate(p); err != nil {
		WriteWorkerAuthError(w, err)
		return false
	}
	return true
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
