package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/apikeys/adapters/sqlitestore"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// API key authentication (W-P2-APIK-02), behind console.apiKeys.enabled.
//
// The authenticator sits outermost on the human routes that may carry a key,
// in the principal slot of the chain
//
//	api key (Principal) -> session -> request id -> admin audit -> authz -> handler
//
// A request that presents a `wak_` bearer is decided here and never falls
// through to another credential: a failed key is a uniform 401, a key together
// with a console cookie is a 400, and no session is looked up for it. A request
// without one passes through untouched, so session behaviour is unchanged.
// Invalid keys write no admin audit row (they are refused before the audit
// middleware); they are counted and logged, rate limited, without the token.
// Authorization (scope, owner role) is requireRoleKeys, inside the audit
// middleware, so a valid key's refusal is chained as denied like a session's.
//
// The middleware does no database I/O: Index.Authenticate is a map read, one
// sha256 and a constant-time compare, and last-use values are kept in memory.

// Outcomes of warden_cp_apikey_auth_total. The set is fixed and carries no
// per-key label, so the counter stays bounded (W-P5-RETN-06 will export it).
// IndexStale is not in the ticket's list: it is the fail-closed refusal of an
// Index that could not confirm itself current (apikeys.ReasonIndexStale), kept
// apart so a stalled Run is visible instead of looking like "unknown".
const (
	APIKeyOutcomeOK                = "ok"
	APIKeyOutcomeMalformed         = "malformed"
	APIKeyOutcomeUnknown           = "unknown"
	APIKeyOutcomeBadSecret         = "bad_secret"
	APIKeyOutcomeExpired           = "expired"
	APIKeyOutcomeRevoked           = "revoked"
	APIKeyOutcomeInsufficientScope = "insufficient_scope"
	APIKeyOutcomeRateLimited       = "rate_limited"
	APIKeyOutcomeIndexStale        = "index_stale"
)

var apiKeyOutcomes = []string{
	APIKeyOutcomeOK, APIKeyOutcomeMalformed, APIKeyOutcomeUnknown, APIKeyOutcomeBadSecret,
	APIKeyOutcomeExpired, APIKeyOutcomeRevoked, APIKeyOutcomeInsufficientScope,
	APIKeyOutcomeRateLimited, APIKeyOutcomeIndexStale,
}

const (
	// apiKeyRejectLogEvery is the per-address interval of apikey_auth_rejected.
	apiKeyRejectLogEvery = time.Minute
	apiKeyRejectLogAddrs = 4096
	// apiKeyBurstFactor is the token bucket's capacity as a multiple of
	// ratePerKey (a burst of 2x, refilled at ratePerKey per second).
	apiKeyBurstFactor = 2

	dashboardAPIPrefix = "/dashboard/api/"
	secretsPathPrefix  = "/central/secrets"
)

// apiKeyCounters counts authentication outcomes without locks or labels
// beyond the fixed set above. A nil *apiKeyCounters ignores every call, so
// code on the shared authz path needs no feature check.
type apiKeyCounters struct {
	n map[string]*atomic.Int64
}

func newAPIKeyCounters() *apiKeyCounters {
	c := &apiKeyCounters{n: make(map[string]*atomic.Int64, len(apiKeyOutcomes))}
	for _, o := range apiKeyOutcomes {
		c.n[o] = new(atomic.Int64)
	}
	return c
}

func (c *apiKeyCounters) inc(outcome string) {
	if c == nil {
		return
	}
	if v, ok := c.n[outcome]; ok {
		v.Add(1)
	}
}

func (c *apiKeyCounters) snapshot() map[string]int64 {
	out := make(map[string]int64, len(apiKeyOutcomes))
	if c == nil {
		return out
	}
	for o, v := range c.n {
		out[o] = v.Load()
	}
	return out
}

// APIKeyAuthCounts returns warden_cp_apikey_auth_total by outcome since start;
// empty when API keys are disabled.
func (s *Server) APIKeyAuthCounts() map[string]int64 { return s.apiKeyCounts.snapshot() }

// apiKeyAuth is the authenticator's state. One per Server, nil when
// console.apiKeys is disabled.
type apiKeyAuth struct {
	index      *apikeys.Index
	clk        clock.Clock
	logger     *slog.Logger
	cookieName string
	limiter    *sessionLimiter
	rejectLog  *addrLimiter
	counts     *apiKeyCounters
	trusted    []netip.Prefix
}

func newAPIKeyAuth(ix *apikeys.Index, cc config.ConsoleConfig, cookieName string, clk clock.Clock, logger *slog.Logger, counts *apiKeyCounters) *apiKeyAuth {
	rate := float64(cc.APIKeys.RatePerKey)
	return &apiKeyAuth{
		index: ix, clk: clk, logger: logger, cookieName: cookieName, counts: counts,
		limiter: &sessionLimiter{
			clk: clk, capacity: rate * apiKeyBurstFactor, perSec: rate, buckets: map[string]*bucket{},
		},
		rejectLog: newAddrLimiter(clk, apiKeyRejectLogEvery, apiKeyRejectLogAddrs),
		trusted:   trustedPrefixes(cc.TrustedProxies),
	}
}

// apiKeyReachable reports whether a request path may be authenticated with a
// key: the admin API, plus /central/secrets so that a valid key is refused
// there (403) rather than indistinguishable from no credential. Everything
// else that runs the human-session chain (/dashboard/ HTML, /auth/*) never
// runs the authenticator: a key there is a flat 401.
func apiKeyReachable(path string) bool {
	return strings.HasPrefix(path, dashboardAPIPrefix) || strings.HasPrefix(path, secretsPathPrefix)
}

// apiKeyWrap puts h behind the API key authenticator; it is the identity when
// API keys are disabled, so the handler tree is exactly as before.
func (s *Server) apiKeyWrap(h http.Handler) http.Handler {
	if s.apiKeys == nil {
		return h
	}
	return s.apiKeys.wrap(h)
}

// bearerToken returns the bearer credential of a request. The scheme is
// case-insensitive (RFC 7235).
func bearerToken(r *http.Request) (string, bool) {
	return bearerOf(r.Header.Get("Authorization"))
}

func bearerOf(h string) (string, bool) {
	const scheme = "bearer "
	h = strings.TrimSpace(h)
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", false
	}
	return strings.TrimSpace(h[len(scheme):]), true
}

// hasAPIKeyBearer reports whether ANY Authorization header value is a bearer
// that starts with wak_ (scheme matched case-insensitively, whitespace
// trimmed). The worker authenticator uses it so a key can never be hidden in a
// second header value or behind odd spacing.
func hasAPIKeyBearer(r *http.Request) bool {
	for _, h := range r.Header.Values("Authorization") {
		if tok, ok := bearerOf(h); ok && apikeys.LooksLikeKey(tok) {
			return true
		}
	}
	return false
}

// queryHasKey reports whether any query key or value looks like an API key. A
// key in a URL lands in proxy and access logs, so the request is refused.
func queryHasKey(r *http.Request) bool {
	for k, vs := range r.URL.Query() {
		if apikeys.LooksLikeKey(k) {
			return true
		}
		for _, v := range vs {
			if apikeys.LooksLikeKey(v) {
				return true
			}
		}
	}
	return false
}

func (a *apiKeyAuth) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if queryHasKey(r) {
			writeAuthzJSON(w, http.StatusBadRequest, map[string]string{"error": "api_key_in_query"})
			return
		}
		// One credential only: with several Authorization values a key could ride
		// next to something another layer would honour.
		if len(r.Header.Values("Authorization")) > 1 {
			writeAuthzJSON(w, http.StatusBadRequest, map[string]string{"error": "multiple_authorization"})
			return
		}
		tok, has := bearerToken(r)
		if !has || !apikeys.LooksLikeKey(tok) {
			// Not a key: the session path (or none) decides, exactly as before.
			next.ServeHTTP(w, r)
			return
		}
		// From here the request is a key request and nothing else.
		if a.cookieName != "" {
			if c, err := r.Cookie(a.cookieName); err == nil && c.Value != "" {
				writeAuthzJSON(w, http.StatusBadRequest, map[string]string{"error": "ambiguous_credentials"})
				return
			}
		}
		if !apiKeyReachable(r.URL.Path) {
			a.unauthorized(w)
			return
		}
		now := a.clk.Now()
		key, reason, err := a.index.Authenticate(tok, now)
		if err != nil {
			a.reject(w, r, tok, reason)
			return
		}
		if ok, wait := a.limiter.allow(key.ID); !ok {
			a.counts.inc(APIKeyOutcomeRateLimited)
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
			writeAuthzJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		a.index.MarkUsed(key.ID, now, clientIP(r, a.trusted))
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), keyPrincipal(key))))
	})
}

// keyPrincipal is the Principal of an authenticated key. Groups is the owner's
// snapshot from creation; the role is recomputed from it on every request.
func keyPrincipal(k apikeys.Key) Principal {
	return Principal{
		Kind: PrincipalAPIKey, Iss: k.OwnerIss, Sub: apiKeySubPrefix + k.ID, Email: k.OwnerEmail,
		Groups: k.OwnerGroups, AuthMethod: PrincipalAPIKey,
		KeyID: k.ID, Scopes: k.Scopes, OwnerSub: k.OwnerSub,
	}
}

// reject answers a failed key: one 401 for every reason, no session fallback.
// The reason is counted and logged, never sent.
func (a *apiKeyAuth) reject(w http.ResponseWriter, r *http.Request, tok string, reason apikeys.Reason) {
	outcome := APIKeyOutcomeUnknown
	switch reason {
	case apikeys.ReasonMalformed:
		outcome = APIKeyOutcomeMalformed
	case apikeys.ReasonBadSecret:
		outcome = APIKeyOutcomeBadSecret
	case apikeys.ReasonExpired:
		outcome = APIKeyOutcomeExpired
	case apikeys.ReasonRevoked:
		outcome = APIKeyOutcomeRevoked
	case apikeys.ReasonIndexStale:
		outcome = APIKeyOutcomeIndexStale
	}
	a.counts.inc(outcome)
	ip := clientIP(r, a.trusted)
	if a.rejectLog.allow(ip) {
		// The id is not secret (it is the key's public name); the secret and its
		// hash are never in the line.
		id := "malformed"
		if parsed, err := apikeys.Parse(tok); err == nil {
			id = parsed
		}
		a.logger.Warn("apikey_auth_rejected", "key_id", id, "reason", string(reason),
			"client_ip", ip, "method", r.Method, "path", r.URL.Path)
	}
	a.unauthorized(w)
}

func (a *apiKeyAuth) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeAuthzJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}

// keyAuthorized decides an API key Principal against a table row: the key must
// hold the row's scope (ScopeSelf: any valid key) and its owner's current role
// must cover the row. It returns the scope named in the refusal. A ScopeNone or
// unclassified row is never reachable.
func keyAuthorized(p Principal, row authzRow, role config.Role) (ok bool, need apikeys.Scope) {
	need = row.Scope
	switch need {
	case "", apikeys.ScopeNone:
		return false, apikeys.ScopeNone
	case apikeys.ScopeSelf:
		// Any valid key, but the owner's current role must still cover the row.
		return role >= row.MinRole, need
	}
	return p.hasScope(need) && role >= row.MinRole, need
}

// initAPIKeys builds the authenticator when console.apiKeys is enabled, an
// Index was supplied and console sessions are up (the cookie name it checks
// for ambiguous_credentials comes from them). Disabled, nothing is built and no
// route is wrapped.
func (s *Server) initAPIKeys() {
	cc := s.cfg.Console
	if !cc.APIKeys.Enabled || s.cfg.APIKeyIndex == nil {
		return
	}
	if s.sessions == nil {
		s.cfg.Logger.Error("control plane: api keys disabled (console sessions are not available)")
		return
	}
	s.apiKeyCounts = newAPIKeyCounters()
	s.apiKeys = newAPIKeyAuth(s.cfg.APIKeyIndex, cc, s.sessionCookie.Name, s.cfg.Clock, s.cfg.Logger, s.apiKeyCounts)
}

// newAPIKeyRegistry is the one scope registry of a control plane: the store,
// the authz table's coverage test and every later feature that registers a
// scope share it (never a second instance).
func newAPIKeyRegistry() *apikeys.Registry { return apikeys.NewP2Registry() }

// startAPIKeys opens the API key store on the state DB, builds the Index and
// starts Index.Run on a context derived from ctx. stop cancels Run and waits
// for it, including its final last-use flush, so call it before the state DB
// closes. The Index is returned only after Run has started: nothing can
// authenticate against an Index nobody is refreshing.
func startAPIKeys(ctx context.Context, state *cpstate.DB, reg *apikeys.Registry, clk clock.Clock, logger *slog.Logger) (apikeys.Store, *apikeys.Index, func(), error) {
	if state == nil {
		return nil, nil, nil, errors.New("control-plane: console.apiKeys.enabled needs --state-dir (API keys live in its database)")
	}
	store, err := sqlitestore.New(state, sqlitestore.Options{Registry: reg, Clock: clk})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("control-plane: api keys: %w", err)
	}
	// Loading is not cancellable: a shutdown signal during boot must not read as
	// a broken key table.
	ix, err := apikeys.NewIndex(context.WithoutCancel(ctx), store, apikeys.IndexOptions{
		Now: clk.Now, After: clk.After, Logger: logger,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("control-plane: api keys: %w", err)
	}
	// Run is cancelled only by the returned stop, never by ctx: stop is deferred,
	// so it runs after the HTTP server has drained, and last-use marks from
	// requests still in flight at shutdown reach Run's final flush.
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	go func() {
		defer close(done)
		ix.Run(runCtx)
	}()
	return store, ix, func() { cancel(); <-done }, nil
}

// keyOwnerBlocked reports whether an API key's owner is on the user block list.
// A blocked person's keys stop working at once, as their sessions do. It is an
// atomic snapshot read (no database I/O); a block list that has not loaded
// refuses, because the control plane cannot tell.
func (s *Server) keyOwnerBlocked(p Principal) bool {
	if s.blocks == nil {
		return false
	}
	if !s.blocks.Ready() {
		return true
	}
	return s.blocks.IsBlocked(p.OwnerSub, p.Email)
}

// APIKeyStore returns the API key store (nil with API keys disabled). Writes
// through it notify the Index, so they take effect on this process at once.
func (s *Server) APIKeyStore() apikeys.Store { return s.cfg.APIKeyStore }

// APIKeyRegistry returns the control plane's one scope registry (nil with API
// keys disabled).
func (s *Server) APIKeyRegistry() *apikeys.Registry { return s.cfg.APIKeyRegistry }
