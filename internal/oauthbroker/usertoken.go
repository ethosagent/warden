package oauthbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// This file is the control plane's user-token refresh engine (W-P3-PUS-03):
// it turns a stored grant into a usable access token. The control plane is the
// only refresh authority, so a rotated refresh token cannot race across
// workers and refresh tokens and client secrets never leave it. There is no
// HTTP route here; W-P3-PUS-07 exposes Engine.Token over the worker mTLS
// mint endpoint.

// The engine's typed errors. Every error Token returns is exactly one of these
// (possibly wrapped), so the mint endpoint maps them to the four outcomes:
// grant_missing, scope_insufficient and reconsent_required send the user to
// consent (s.authRequired); ErrTokenUnavailable is a 503 with Retry-After that
// never sends the user to re-consent.
var (
	// ErrScopeInsufficient: the grant does not hold every required scope.
	ErrScopeInsufficient = errors.New("oauthbroker: granted scopes are insufficient")
	// ErrReconsentRequired: the provider rejected the refresh token (or the
	// stored token cannot be refreshed). The grant row is kept in state
	// reconsent_required; offboarding is never triggered by it.
	ErrReconsentRequired = errors.New("oauthbroker: reconsent required")
	// ErrTokenUnavailable: a store error, provider 5xx or timeout, an
	// unconfigured provider or a grant mid-reconnect. The grant is untouched.
	ErrTokenUnavailable = errors.New("oauthbroker: user token unavailable")
)

// Outcome labels of warden.cp.user_token.refresh.total{provider,outcome} and
// the closed status words of oauth_grants.last_refresh_status.
const (
	UserTokenCache     = "cache"     // served from the in-memory cache
	UserTokenStored    = "stored"    // served from the stored record, no provider call
	UserTokenRefreshed = "refreshed" // a provider refresh ran
	UserTokenMissing   = "grant_missing"
	UserTokenScope     = "scope_insufficient"
	UserTokenReconsent = "reconsent_required"
	UserTokenUnavail   = "unavailable"

	RefreshStatusOK              = "ok"
	RefreshStatusInvalidGrant    = "invalid_grant"
	RefreshStatusError           = "error"
	RefreshStatusWritebackFailed = "writeback_failed"

	// FindingWritebackFailed is the DedupKey prefix and rule id of the finding
	// published when a rotated refresh token could not be persisted.
	FindingWritebackFailed = "user_token_writeback_failed"
)

// ValidRefreshStatus reports whether s is one of the closed status words.
func ValidRefreshStatus(s string) bool {
	switch s {
	case RefreshStatusOK, RefreshStatusInvalidGrant, RefreshStatusError, RefreshStatusWritebackFailed:
		return true
	}
	return false
}

// Engine tuning.
const (
	// TokenMinTTL is the shortest remaining life a stored or cached access token
	// may have and still be handed out.
	TokenMinTTL = 60 * time.Second
	// ForceWindow is the least time between two forced refreshes of one key.
	ForceWindow = 30 * time.Second
	// maxEntries bounds the cache; an entry holding an unpersisted rotated
	// refresh token is never evicted.
	maxEntries = 10000
	// opTimeout bounds the store and metadata calls of one flight.
	opTimeout = 10 * time.Second
	// nonExpiringTTL is the ExpiresIn reported for a record that never expires
	// (a GitHub OAuth-app token); the worker caches it for at most its own TTL.
	nonExpiringTTL = 3600
)

// writebackBackoff is the wait before each retry of a failed write-back: the
// first attempt plus three retries.
var writebackBackoff = [...]time.Duration{100 * time.Millisecond, 400 * time.Millisecond, 1600 * time.Millisecond}

// Minted is one access token the engine hands out. It holds a live bearer
// token: callers must not log or %v it. Ref identifies this token without
// revealing it (the worker echoes it back as stale_ref).
type Minted struct {
	AccessToken string
	// ExpiresIn is the remaining life in seconds, relative to now: only
	// relative time crosses the wire, so clock skew does not matter.
	ExpiresIn  int64
	Scope      string
	GrantEpoch int64
	Ref        string
}

// String and GoString redact the token under every formatting verb.
func (m Minted) String() string {
	return "Minted{access_token=" + redacted + " expires_in=" + strconv.FormatInt(m.ExpiresIn, 10) + " ref=" + m.Ref + "}"
}
func (m Minted) GoString() string { return m.String() }

// LogValue keeps the token out of slog.
func (m Minted) LogValue() slog.Value {
	return slog.GroupValue(slog.String("ref", m.Ref), slog.Int64("expires_in", m.ExpiresIn))
}

// RefreshRecorder is the optional GrantStore extension that stamps the outcome
// of a refresh on the grant row (last_refresh_at, last_refresh_status). The
// SQLite store implements it; an engine over a store without it skips the
// stamp.
type RefreshRecorder interface {
	RecordRefresh(ctx context.Context, userKey, provider, grantID, status string, at time.Time) error
}

// EpochSource reads a user's grant epoch (the publish_log seq of the last
// revoke bump, W-P3-PUS-08). A nil source means every epoch is 0.
type EpochSource interface {
	GrantEpoch(ctx context.Context, userKey string) (int64, error)
}

// EngineMetrics are the CP instruments (*observability.Metrics implements it). provider is a registered id or
// "other"; there is no user or agent label. A nil EngineMetrics records nothing.
type EngineMetrics interface {
	RecordCPUserTokenRefresh(provider, outcome string)
	RecordCPUserTokenWritebackFailure()
}

// WritebackAlerter publishes the high user_token_writeback_failed finding. The
// opaque userKey and the provider are all it receives (never sub or email).
type WritebackAlerter interface {
	WritebackFailed(userKey, provider string)
}

// EngineConfig is what NewEngine needs. Registry, Grants, Records and Now are
// required.
type EngineConfig struct {
	Registry *Registry
	// Grants is the broker's grant metadata port (state, grant_id, scopes).
	Grants GrantStore
	// Records is the consent.store grant record port (TokenRecord + version).
	Records GrantRecords
	// Locks MUST be the single set shared with the connect callback, revoke and
	// offboarding (the control plane's Server.grantLocks).
	Locks   *GrantLocks
	Epochs  EpochSource
	Metrics EngineMetrics
	Alerter WritebackAlerter
	Now     func() time.Time
	Logger  *slog.Logger
	// Sleep waits d or until ctx ends; nil uses a timer. Tests inject it.
	Sleep func(ctx context.Context, d time.Duration)
}

// Engine mints user access tokens. It is safe for concurrent use.
type Engine struct {
	reg     *Registry
	grants  GrantStore
	records GrantRecords
	locks   *GrantLocks
	epochs  EpochSource
	metrics EngineMetrics
	alerter WritebackAlerter
	now     func() time.Time
	log     *slog.Logger
	sleep   func(ctx context.Context, d time.Duration)

	sf singleflight.Group

	mu      sync.Mutex
	entries map[string]*tokenEntry
	forceAt map[string]time.Time

	// testHook, when set, runs after the provider answered and before the
	// write-back (tests pause a refresh there).
	testHook func(userKey, provider string)
}

// tokenEntry is the cached current token of one (userKey, provider).
type tokenEntry struct {
	rec TokenRecord
	// unwritten: rec holds a rotated refresh token the store has not accepted
	// yet. It is flushed by the next flight, and the entry is never served from
	// the fast path nor evicted until then.
	unwritten bool
}

// NewEngine returns an Engine over cfg.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	switch {
	case cfg.Registry == nil:
		return nil, errors.New("oauthbroker: EngineConfig.Registry is required")
	case cfg.Grants == nil:
		return nil, errors.New("oauthbroker: EngineConfig.Grants is required")
	case cfg.Records == nil:
		return nil, errors.New("oauthbroker: EngineConfig.Records is required")
	case cfg.Now == nil:
		return nil, errors.New("oauthbroker: EngineConfig.Now is required")
	}
	e := &Engine{
		reg: cfg.Registry, grants: cfg.Grants, records: cfg.Records, locks: cfg.Locks,
		epochs: cfg.Epochs, metrics: cfg.Metrics, alerter: cfg.Alerter, now: cfg.Now,
		log: cfg.Logger, sleep: cfg.Sleep,
		entries: map[string]*tokenEntry{}, forceAt: map[string]time.Time{},
	}
	if e.locks == nil {
		e.locks = NewGrantLocks()
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	if e.sleep == nil {
		e.sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
			}
		}
	}
	return e, nil
}

func cacheKey(userKey, provider string) string { return userKey + "\x00" + provider }

// WithGrantLock runs fn holding the grant lock of (userKey, provider) and drops
// the engine's cache entry for the key first, so an in-flight refresh finishes
// before fn runs and nothing cached outlives fn's change. RevokeUserGrant and
// offboarding call it. fn must not call Token.
func (e *Engine) WithGrantLock(userKey, provider string, fn func() error) error {
	unlock := e.locks.Lock(userKey, provider)
	defer unlock()
	e.drop(cacheKey(userKey, provider))
	return fn()
}

func (e *Engine) drop(key string) {
	e.mu.Lock()
	delete(e.entries, key)
	delete(e.forceAt, key)
	e.mu.Unlock()
}

// flightResult is what one flight shares with every caller joined to it.
type flightResult struct {
	rec    TokenRecord
	grant  Grant
	epoch  int64
	source string // UserTokenCache | UserTokenStored | UserTokenRefreshed
}

// Token returns an access token for (userKey, provider) that carries every
// scope in need. It reuses the cached or stored token while it has more than
// TokenMinTTL left and otherwise refreshes it at the provider, persisting a
// rotated refresh token before returning. force is honoured only when the
// current token's Ref equals staleRef and at most once per ForceWindow per key;
// otherwise the current token is returned. The ctx bounds the caller's wait;
// the refresh itself runs detached under its own deadlines so a cancelled
// caller cannot strand a rotated refresh token.
func (e *Engine) Token(ctx context.Context, userKey, provider string, need []string, force bool, staleRef string) (Minted, error) {
	m, outcome, err := e.token(ctx, userKey, provider, need, force, staleRef)
	e.count(provider, outcomeOf(outcome, err))
	return m, err
}

func outcomeOf(source string, err error) string {
	switch {
	case err == nil:
		return source
	case errors.Is(err, ErrGrantMissing):
		return UserTokenMissing
	case errors.Is(err, ErrScopeInsufficient):
		return UserTokenScope
	case errors.Is(err, ErrReconsentRequired):
		return UserTokenReconsent
	default:
		return UserTokenUnavail
	}
}

func (e *Engine) count(provider, outcome string) {
	if e.metrics == nil {
		return
	}
	if _, err := e.reg.Get(provider); err != nil {
		provider = "other"
	}
	e.metrics.RecordCPUserTokenRefresh(provider, outcome)
}

func (e *Engine) token(ctx context.Context, userKey, provider string, need []string, force bool, staleRef string) (Minted, string, error) {
	key := cacheKey(userKey, provider)
	if !force {
		if res, ok, err := e.fastPath(ctx, key, userKey, provider); err != nil {
			return Minted{}, "", err
		} else if ok {
			return e.finish(res, need, UserTokenCache)
		}
	}
	res, err := e.flight(ctx, key, userKey, provider, force, staleRef)
	if err != nil {
		return Minted{}, "", err
	}
	return e.finish(res, need, res.source)
}

// finish applies the per-caller scope check and builds the Minted.
func (e *Engine) finish(res flightResult, need []string, source string) (Minted, string, error) {
	if _, missing := CapScopes(CanonicalScopes(need), grantedScopes(res)); len(missing) > 0 {
		return Minted{}, "", fmt.Errorf("%w", ErrScopeInsufficient)
	}
	exp := int64(nonExpiringTTL)
	if res.rec.Expiry > 0 {
		exp = res.rec.Expiry - e.now().Unix()
	}
	return Minted{
		AccessToken: res.rec.AccessToken, ExpiresIn: exp, Scope: res.rec.Scope,
		GrantEpoch: res.epoch, Ref: tokenRef(res.rec),
	}, source, nil
}

// grantedScopes is what the provider issued (the record), falling back to the
// grant row's scopes for a provider whose token response names none.
func grantedScopes(res flightResult) []string {
	if sc := res.rec.Scopes(); len(sc) > 0 {
		return sc
	}
	return res.grant.Scopes
}

// tokenRef names a token without revealing it: a truncated hash over the
// grant, receipt time and token. A refreshed token always gets a new ref.
func tokenRef(r TokenRecord) string {
	h := sha256.New()
	_, _ = h.Write([]byte(r.GrantID + "\x00" + strconv.FormatInt(r.ObtainedAt, 10) + "\x00" + strconv.FormatInt(r.Expiry, 10) + "\x00" + r.AccessToken))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// fresh reports whether rec can be handed out as stored without a refresh.
func (e *Engine) fresh(rec TokenRecord) bool {
	if rec.Expiry == 0 {
		return rec.RefreshToken == "" // a never-expiring token (GitHub OAuth app)
	}
	return time.Unix(rec.Expiry, 0).Sub(e.now()) > TokenMinTTL
}

// fastPath serves from the cache when the grant row still names the cached
// grant (a reconnect or revoke changes it) and the token is fresh.
func (e *Engine) fastPath(ctx context.Context, key, userKey, provider string) (flightResult, bool, error) {
	e.mu.Lock()
	ent := e.entries[key]
	var rec TokenRecord
	if ent != nil && !ent.unwritten {
		rec = ent.rec
	}
	e.mu.Unlock()
	if rec == (TokenRecord{}) || !e.fresh(rec) {
		return flightResult{}, false, nil
	}
	g, err := e.grantRow(ctx, userKey, provider)
	if err != nil || g.State != GrantActive || g.GrantID != rec.GrantID {
		return flightResult{}, false, nil // the slow path classifies it
	}
	epoch, err := e.epoch(ctx, userKey)
	if err != nil {
		return flightResult{}, false, fmt.Errorf("%w: epoch", ErrTokenUnavailable)
	}
	return flightResult{rec: rec, grant: g, epoch: epoch, source: UserTokenCache}, true, nil
}

func (e *Engine) epoch(ctx context.Context, userKey string) (int64, error) {
	if e.epochs == nil {
		return 0, nil
	}
	return e.epochs.GrantEpoch(ctx, userKey)
}

// grantRow reads the grant metadata row; no row is ErrGrantMissing.
func (e *Engine) grantRow(ctx context.Context, userKey, provider string) (Grant, error) {
	cctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	g, err := e.grants.GetGrant(cctx, userKey, provider)
	switch {
	case errors.Is(err, ErrNotFound):
		return Grant{}, ErrGrantMissing
	case err != nil:
		return Grant{}, fmt.Errorf("%w: grant row", ErrTokenUnavailable)
	}
	return g, nil
}

// flight coalesces concurrent callers of one key onto a single run of doFlight.
// The run is detached from the callers' contexts (a refresh that rotated a
// refresh token must reach its write-back) and each caller still honours its
// own ctx while waiting.
func (e *Engine) flight(ctx context.Context, key, userKey, provider string, force bool, staleRef string) (flightResult, error) {
	sfKey := key
	if force {
		sfKey += "\x00force"
	}
	dctx := context.WithoutCancel(ctx)
	ch := e.sf.DoChan(sfKey, func() (any, error) {
		return e.doFlight(dctx, key, userKey, provider, force, staleRef)
	})
	select {
	case r := <-ch:
		if r.Err != nil {
			return flightResult{}, r.Err
		}
		return r.Val.(flightResult), nil
	case <-ctx.Done():
		return flightResult{}, fmt.Errorf("%w: %w", ErrTokenUnavailable, ctx.Err())
	}
}

// doFlight runs under the grant lock from the first read of the grant to the
// write-back, on every backend: versioned compare-and-swap is only defence in
// depth against a delete-and-reconnect that restarts store versions.
func (e *Engine) doFlight(ctx context.Context, key, userKey, provider string, force bool, staleRef string) (flightResult, error) {
	unlock := e.locks.Lock(userKey, provider)
	defer unlock()

	// Two passes: a grant that changed under the refresh (ErrGrantChanged) is
	// re-read once; a second change is reported as unavailable.
	for pass := 0; pass < 2; pass++ {
		res, again, err := e.once(ctx, key, userKey, provider, force, staleRef)
		if err != nil || !again {
			return res, err
		}
	}
	return flightResult{}, fmt.Errorf("%w: grant kept changing", ErrTokenUnavailable)
}

func (e *Engine) once(ctx context.Context, key, userKey, provider string, force bool, staleRef string) (res flightResult, again bool, err error) {
	g, err := e.grantRow(ctx, userKey, provider)
	if err != nil {
		e.drop(key)
		return res, false, err
	}
	switch g.State {
	case GrantActive:
	case GrantReconsentRequired:
		e.drop(key)
		return res, false, ErrReconsentRequired
	case GrantConnecting:
		// A reconnect over an active grant keeps the earlier grant's record in
		// consent.store until the callback replaces it. Whether to serve it is
		// undecided by the product, so refuse transiently rather than send the
		// user to consent again; a first connect has nothing to serve yet.
		if g.PrevGrantID != "" {
			return res, false, fmt.Errorf("%w: grant is being reconnected", ErrTokenUnavailable)
		}
		return res, false, ErrGrantMissing
	default: // revoked
		e.drop(key)
		return res, false, ErrGrantMissing
	}

	cur, ver, err := e.load(ctx, userKey, provider)
	if err != nil {
		return res, false, err
	}
	if cur.GrantID != g.GrantID {
		// The record belongs to another grant than the active row (a crash
		// between the callback's write and its activation). Never serve it.
		e.drop(key)
		return res, false, fmt.Errorf("%w: stored grant does not match the active grant", ErrTokenUnavailable)
	}
	epoch, err := e.epoch(ctx, userKey)
	if err != nil {
		return res, false, fmt.Errorf("%w: epoch", ErrTokenUnavailable)
	}

	// A rotated refresh token the store has not accepted yet is the newest
	// credential: use it, and persist it before anything else.
	e.mu.Lock()
	ent := e.entries[key]
	var pending *TokenRecord
	if ent != nil && ent.unwritten && ent.rec.GrantID == cur.GrantID {
		p := ent.rec
		pending = &p
	}
	e.mu.Unlock()
	if pending != nil {
		if err := e.store(ctx, userKey, provider, *pending, ver, 0); err != nil {
			if errors.Is(err, ErrGrantChanged) {
				e.drop(key)
				return res, true, nil
			}
			return res, false, fmt.Errorf("%w: write-back pending", ErrTokenUnavailable)
		}
		cur = *pending
		e.setEntry(key, cur, false)
		if _, ver, err = e.load(ctx, userKey, provider); err != nil {
			return res, false, err
		}
	}

	if force && tokenRef(cur) == staleRef && e.forceAllowed(key) {
		if cur.RefreshToken == "" {
			// A never-expiring token the upstream rejected: nothing to refresh.
			e.markReconsent(ctx, key, userKey, provider, cur.GrantID, RefreshStatusInvalidGrant)
			return res, false, ErrReconsentRequired
		}
	} else if e.fresh(cur) {
		src := UserTokenStored
		e.setEntry(key, cur, false)
		return flightResult{rec: cur, grant: g, epoch: epoch, source: src}, false, nil
	}

	return e.refresh(ctx, key, userKey, provider, cur, ver, g, epoch)
}

// load reads the record. A missing key is ErrGrantMissing; every other store
// failure is ErrTokenUnavailable, never a missing grant.
func (e *Engine) load(ctx context.Context, userKey, provider string) (TokenRecord, GrantVersion, error) {
	cctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	rec, ver, err := e.records.LoadGrant(cctx, userKey, provider)
	switch {
	case errors.Is(err, ErrGrantMissing):
		e.drop(cacheKey(userKey, provider))
		return TokenRecord{}, GrantVersion{}, ErrGrantMissing
	case err != nil:
		return TokenRecord{}, GrantVersion{}, fmt.Errorf("%w: load grant", ErrTokenUnavailable)
	}
	return rec, ver, nil
}

func (e *Engine) forceAllowed(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if last, ok := e.forceAt[key]; ok && now.Sub(last) < ForceWindow {
		return false
	}
	if len(e.forceAt) >= maxEntries {
		for k, t := range e.forceAt {
			if now.Sub(t) >= ForceWindow {
				delete(e.forceAt, k)
			}
		}
	}
	e.forceAt[key] = now
	return true
}

func (e *Engine) setEntry(key string, rec TokenRecord, unwritten bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.entries[key]; !ok && len(e.entries) >= maxEntries {
		for k, v := range e.entries {
			if !v.unwritten {
				delete(e.entries, k)
				break
			}
		}
	}
	e.entries[key] = &tokenEntry{rec: rec, unwritten: unwritten}
}

// markReconsent records reconsent_required on the grant row (kept, never
// offboarded) and drops the cache entry.
func (e *Engine) markReconsent(ctx context.Context, key, userKey, provider, grantID, status string) {
	e.drop(key)
	cctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	if _, err := e.grants.MarkReconsentRequired(cctx, userKey, provider, grantID); err != nil {
		e.log.Warn("user token: could not mark the grant reconsent_required", "provider", provider, "user_key", userKey, "grant_id", grantID)
	}
	e.stamp(cctx, userKey, provider, grantID, status)
}

func (e *Engine) stamp(ctx context.Context, userKey, provider, grantID, status string) {
	if rr, ok := e.grants.(RefreshRecorder); ok {
		if err := rr.RecordRefresh(ctx, userKey, provider, grantID, status, e.now()); err != nil && !errors.Is(err, ErrNotFound) {
			e.log.Warn("user token: could not record the refresh status", "provider", provider, "status", status)
		}
	}
}

// refresh runs the provider refresh for cur and persists a rotated token.
func (e *Engine) refresh(ctx context.Context, key, userKey, provider string, cur TokenRecord, ver GrantVersion, g Grant, epoch int64) (flightResult, bool, error) {
	prov, err := e.reg.Get(provider)
	if err != nil {
		return flightResult{}, false, fmt.Errorf("%w: provider not configured", ErrTokenUnavailable)
	}
	secret, err := prov.ClientSecret(ctx)
	if err != nil {
		e.stamp(ctx, userKey, provider, g.GrantID, RefreshStatusError)
		return flightResult{}, false, fmt.Errorf("%w: client secret", ErrTokenUnavailable)
	}
	next, err := Refresh(ctx, prov, cur, secret)
	switch {
	case err == nil:
	case errors.Is(err, ErrRefreshInvalidGrant), errors.Is(err, ErrNotRefreshable):
		e.markReconsent(ctx, key, userKey, provider, g.GrantID, RefreshStatusInvalidGrant)
		return flightResult{}, false, ErrReconsentRequired
	default:
		// invalid_client, permanent, retryable, unconfigured, blocked: an
		// operator or provider problem, never the user's grant.
		e.stamp(ctx, userKey, provider, g.GrantID, RefreshStatusError)
		return flightResult{}, false, fmt.Errorf("%w: provider refresh", ErrTokenUnavailable)
	}
	if e.testHook != nil {
		e.testHook(userKey, provider)
	}

	// The grant must still be the one we refreshed: re-read the row and the
	// epoch before any write. Anything else is dropped, never written.
	g2, err := e.grantRow(ctx, userKey, provider)
	if err != nil {
		return flightResult{}, false, err
	}
	epoch2, err := e.epoch(ctx, userKey)
	if err != nil {
		return flightResult{}, false, fmt.Errorf("%w: epoch", ErrTokenUnavailable)
	}
	if g2.State != GrantActive || g2.GrantID != cur.GrantID || epoch2 != epoch {
		e.drop(key)
		return flightResult{}, true, nil
	}

	if next.RefreshToken != cur.RefreshToken {
		if err := e.store(ctx, userKey, provider, next, ver, len(writebackBackoff)); err != nil {
			if errors.Is(err, ErrGrantChanged) {
				e.drop(key)
				return flightResult{}, true, nil
			}
			// Keep the only copy of the rotated refresh token in memory and write
			// it again at the next flight. Do not hand out a token whose rotation
			// is not durable.
			e.setEntry(key, next, true)
			e.writebackFailed(ctx, userKey, provider, g2.GrantID)
			return flightResult{}, false, fmt.Errorf("%w: write-back", ErrTokenUnavailable)
		}
	}
	e.setEntry(key, next, false)
	e.stamp(ctx, userKey, provider, g2.GrantID, RefreshStatusOK)
	return flightResult{rec: next, grant: g2, epoch: epoch2, source: UserTokenRefreshed}, false, nil
}

// store writes rec with the version it was read at, retrying a failed write
// with the SAME read version (never re-read in between: a re-read could pick
// up a concurrent writer's version and let us overwrite it). ErrGrantChanged is
// final. retries is how many backed-off retries follow the first attempt.
func (e *Engine) store(ctx context.Context, userKey, provider string, rec TokenRecord, ver GrantVersion, retries int) error {
	var err error
	for attempt := 0; ; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, opTimeout)
		err = e.records.StoreRotated(cctx, userKey, provider, rec, ver)
		cancel()
		if err == nil || errors.Is(err, ErrGrantChanged) || attempt >= retries {
			return err
		}
		e.sleep(ctx, writebackBackoff[attempt])
	}
}

// writebackFailed records the failure on the row, the counter and a high
// finding. It never logs a token, only the opaque identifiers.
func (e *Engine) writebackFailed(ctx context.Context, userKey, provider, grantID string) {
	e.stamp(ctx, userKey, provider, grantID, RefreshStatusWritebackFailed)
	if e.metrics != nil {
		e.metrics.RecordCPUserTokenWritebackFailure()
	}
	if e.alerter != nil {
		e.alerter.WritebackFailed(userKey, provider)
	}
	e.log.Error("user token: rotated refresh token could not be persisted; it is held in memory only and a control plane restart before the next write forces re-consent",
		"provider", provider, "user_key", userKey, "grant_id", grantID)
}
