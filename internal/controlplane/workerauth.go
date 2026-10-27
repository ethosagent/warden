package controlplane

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock"
)

// WorkerKind is how a worker request authenticated.
type WorkerKind string

const (
	// KindToken is a per-worker wwt_ token; its bound proxy id is authoritative.
	KindToken WorkerKind = "token"
	// KindLegacy is the shared Config.Token; the proxy id is the unverified header.
	KindLegacy WorkerKind = "legacy"
	// KindNone is an anonymous caller on an open control plane.
	KindNone WorkerKind = "none"
)

// WorkerPrincipal is the authenticated identity of a worker request. ProxyID is
// the id the registry, ingest store and every ingest callback record: the
// token's bound id for KindToken, the self-reported header otherwise.
type WorkerPrincipal struct {
	TokenID, TokenName, ProxyID string
	Kind                        WorkerKind
}

// Worker authentication errors. Both carry no detail on purpose: the reason
// goes only to the rate-limited rejection log.
var (
	// ErrUnauthorized is a missing, malformed, unknown, expired, revoked or wrong
	// credential (HTTP 401).
	ErrUnauthorized = errors.New("worker auth: unauthorized")
	// ErrProxyIDMismatch is a valid token presented with a proxy id other than the
	// one it is bound to (HTTP 403).
	ErrProxyIDMismatch = errors.New("worker auth: proxy id mismatch")
)

// workerAuthMode is resolved once at startup. strict (worker tokens only) is
// added by W-P1-WTOK-04 as one more case in resolveWorkerAuthMode and Authenticate.
type workerAuthMode string

const (
	modeOpen  workerAuthMode = "open"  // no shared token: anonymous accepted
	modeMixed workerAuthMode = "mixed" // shared token set: tokens or the shared token
)

func resolveWorkerAuthMode(legacy string) workerAuthMode {
	if legacy == "" {
		return modeOpen
	}
	return modeMixed
}

const (
	// maxLegacyIDs caps the per-proxy-id legacy request counter. The ids are
	// unverified headers, so the map must not grow without bound.
	maxLegacyIDs = 10_000
	// rejectLogEvery is the rate limit per (reason, remote address).
	rejectLogEvery = time.Minute
	// maxRejectKeys bounds the rejection-log rate-limit map.
	maxRejectKeys = 4096
)

// WorkerAuthConfig builds a WorkerAuthenticator.
type WorkerAuthConfig struct {
	// Legacy is the shared token (Config.Token); empty selects open mode.
	Legacy string
	// Tokens is the per-worker token store; nil means no wwt_ token is accepted.
	Tokens *WorkerTokenStore
	// Registry records Kind, TokenID and TokenName on the worker's entry.
	Registry *WorkerRegistry
	Logger   *slog.Logger
	Clock    clock.Clock
	// TLS reports whether the control plane serves TLS (for the startup warning).
	TLS bool
}

// WorkerAuthenticator authenticates the worker-plane routes (/policy,
// /control/heartbeat, /central/ingest). A wwt_ bearer goes only to the token
// store and never falls back to the shared token; any other bearer is compared
// with the shared token in constant time.
type WorkerAuthenticator struct {
	mode     workerAuthMode
	legacy   string
	tokens   *WorkerTokenStore
	registry *WorkerRegistry
	log      *slog.Logger
	clk      clock.Clock
	tls      bool

	mu         sync.Mutex
	counters   map[[2]string]int64 // {kind, outcome}: bounded labels, no proxy id
	legacyReqs map[string]int64    // per proxy id, capped at maxLegacyIDs
	rejectedAt map[string]time.Time

	// cancels holds one revoke channel per token id that has a parked
	// long-poll, shared by all of that token's waiters and removed when the
	// last one returns. Keyed by id so cert principals (W-P2-WCA-04) can key
	// it by worker id as well.
	cancelMu sync.Mutex
	cancels  map[string]*cancelEntry
}

type cancelEntry struct {
	ch      chan struct{}
	waiters int
}

// NewWorkerAuthenticator builds the authenticator and resolves the mode.
func NewWorkerAuthenticator(c WorkerAuthConfig) *WorkerAuthenticator {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Clock == nil {
		c.Clock = clock.Real()
	}
	a := &WorkerAuthenticator{
		mode: resolveWorkerAuthMode(c.Legacy), legacy: c.Legacy, tokens: c.Tokens,
		registry: c.Registry, log: c.Logger, clk: c.Clock, tls: c.TLS,
		counters:   map[[2]string]int64{},
		legacyReqs: map[string]int64{},
		rejectedAt: map[string]time.Time{},
		cancels:    map[string]*cancelEntry{},
	}
	if c.Tokens != nil {
		c.Tokens.OnRevoked(a.cancelToken)
	}
	return a
}

// WatchRevoke registers a parked long-poll of p and returns a channel closed
// when its credential is revoked, plus a release func to call when the poll
// returns. Only token principals have a per-credential identity: for legacy
// and none it returns a nil channel (never ready) and a no-op release.
func (a *WorkerAuthenticator) WatchRevoke(p WorkerPrincipal) (<-chan struct{}, func()) {
	if p.Kind != KindToken || p.TokenID == "" {
		return nil, func() {}
	}
	a.cancelMu.Lock()
	e := a.cancels[p.TokenID]
	if e == nil {
		e = &cancelEntry{ch: make(chan struct{})}
		a.cancels[p.TokenID] = e
	}
	e.waiters++
	a.cancelMu.Unlock()
	return e.ch, func() {
		a.cancelMu.Lock()
		defer a.cancelMu.Unlock()
		if e.waiters--; e.waiters == 0 && a.cancels[p.TokenID] == e {
			delete(a.cancels, p.TokenID)
		}
	}
}

// cancelToken is the OnRevoked hook: it wakes every parked long-poll of id.
func (a *WorkerAuthenticator) cancelToken(id string) {
	a.cancelMu.Lock()
	e := a.cancels[id]
	delete(a.cancels, id)
	a.cancelMu.Unlock()
	if e != nil {
		close(e.ch)
	}
}

// Reauthenticate re-checks p against the in-memory token index before a
// response is written after a wait. It does no DB I/O and does not count or
// mark the token used. Legacy and none principals always pass.
func (a *WorkerAuthenticator) Reauthenticate(p WorkerPrincipal) error {
	if p.Kind != KindToken {
		return nil
	}
	if a.tokens == nil || a.tokens.Valid(p.TokenID) != nil {
		return ErrUnauthorized
	}
	return nil
}

// LogMode logs the resolved mode once, with the open-mode and no-TLS warnings.
func (a *WorkerAuthenticator) LogMode() {
	a.log.Info("control plane worker auth", "auth_mode", string(a.mode), "worker_tokens", a.tokens != nil)
	if a.mode == modeOpen {
		a.log.Warn("worker auth is open: anonymous callers are accepted on /policy, /control/heartbeat and /central/ingest (set --token-env or issue worker tokens)")
	}
	if !a.tls && (a.mode != modeOpen || a.tokens != nil) {
		a.log.Warn("worker auth tokens are sent in clear text: the control plane has no TLS (set --ca-cert and --ca-key)")
	}
}

// bearer returns the presented bearer credential, if any.
func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	return h[len("Bearer "):], true
}

// hasWorkerTokenBearer reports whether r presents a wwt_ bearer. The human
// routes (secrets, dashboard writes) refuse it for every method.
func hasWorkerTokenBearer(r *http.Request) bool {
	tok, ok := bearer(r)
	return ok && strings.HasPrefix(tok, workerTokenPrefix)
}

// Authenticate resolves the caller of a worker-plane request. It counts the
// outcome, logs a rejection (rate-limited, never the credential) and, on
// success, records the worker's auth on the registry and marks the token used.
func (a *WorkerAuthenticator) Authenticate(r *http.Request) (WorkerPrincipal, error) {
	p, reason, tokenID, err := a.resolve(r)
	if err != nil {
		outcome := "unauthorized"
		if errors.Is(err, ErrProxyIDMismatch) {
			outcome = "forbidden"
		}
		a.count(p.Kind, outcome)
		a.logRejected(reason, tokenID, r)
		return WorkerPrincipal{}, err
	}
	a.count(p.Kind, "ok")
	switch p.Kind {
	case KindToken:
		a.tokens.MarkUsed(p.TokenID, a.clk.Now())
	case KindLegacy:
		a.countLegacy(p.ProxyID)
	}
	if a.registry != nil {
		a.registry.recordAuth(p)
	}
	return p, nil
}

// resolve authenticates without side effects. On error p.Kind names the
// credential family that was attempted (for the counter label).
func (a *WorkerAuthenticator) resolve(r *http.Request) (p WorkerPrincipal, reason, tokenID string, err error) {
	tok, has := bearer(r)
	if has && strings.HasPrefix(tok, workerTokenPrefix) {
		p.Kind = KindToken
		if a.tokens == nil {
			return p, "no_token_store", "", ErrUnauthorized
		}
		t, terr := a.tokens.Authenticate(tok)
		if terr != nil {
			switch {
			case errors.Is(terr, ErrRevoked):
				reason = "revoked"
			case errors.Is(terr, ErrExpired):
				reason = "expired"
			case errors.Is(terr, ErrMalformed):
				reason = "malformed"
			default:
				reason = "unknown"
			}
			// Revoked and expired tokens are known, so their id is safe to log.
			if errors.Is(terr, ErrRevoked) || errors.Is(terr, ErrExpired) {
				tokenID = a.tokenIDFor(tok)
			}
			return p, reason, tokenID, ErrUnauthorized
		}
		// The bound id is authoritative: a header that differs in any way is refused.
		for _, v := range r.Header.Values(analytics.ProxyIDHeader) {
			if v != "" && v != t.ProxyID {
				return p, "proxy_id_mismatch", t.ID, ErrProxyIDMismatch
			}
		}
		return WorkerPrincipal{Kind: KindToken, TokenID: t.ID, TokenName: t.Name, ProxyID: t.ProxyID}, "", "", nil
	}
	hdr := r.Header.Get(analytics.ProxyIDHeader)
	switch a.mode {
	case modeOpen:
		return WorkerPrincipal{Kind: KindNone, ProxyID: hdr}, "", "", nil
	default: // modeMixed
		if !has {
			p.Kind = KindNone
			return p, "missing", "", ErrUnauthorized
		}
		p.Kind = KindLegacy
		if subtle.ConstantTimeCompare([]byte(tok), []byte(a.legacy)) != 1 {
			return p, "bad_token", "", ErrUnauthorized
		}
		return WorkerPrincipal{Kind: KindLegacy, ProxyID: hdr}, "", "", nil
	}
}

// tokenIDFor finds the id of a revoked or expired token for the rejection log.
func (a *WorkerAuthenticator) tokenIDFor(plaintext string) string {
	return a.tokens.idFor(plaintext)
}

// idFor returns the id of the indexed token with this plaintext, or "".
func (s *WorkerTokenStore) idFor(plaintext string) string {
	return s.idx.Load().byHash[hashToken(plaintext)].ID
}

func (a *WorkerAuthenticator) count(k WorkerKind, outcome string) {
	a.mu.Lock()
	a.counters[[2]string{string(k), outcome}]++
	a.mu.Unlock()
}

// Count returns warden_cp_worker_auth_total{kind,outcome}, kept in memory for
// the later /metrics export (W-P5-RETN-06). Outcomes: ok, unauthorized, forbidden.
func (a *WorkerAuthenticator) Count(k WorkerKind, outcome string) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counters[[2]string{string(k), outcome}]
}

func (a *WorkerAuthenticator) countLegacy(proxyID string) {
	if proxyID == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.legacyReqs[proxyID]; !ok && len(a.legacyReqs) >= maxLegacyIDs {
		return
	}
	a.legacyReqs[proxyID]++
}

// LegacyRequests is how many shared-token requests proxyID made (the id is an
// unverified header; ids beyond the cap are not counted).
func (a *WorkerAuthenticator) LegacyRequests(proxyID string) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.legacyReqs[proxyID]
}

func (a *WorkerAuthenticator) legacyIDs() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.legacyReqs)
}

// logRejected logs one "worker auth rejected" line per reason and remote host
// per minute. The reason, token id (when known) and address are all it carries:
// never the Authorization header, the plaintext or the hash.
func (a *WorkerAuthenticator) logRejected(reason, tokenID string, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := a.clk.Now()
	key := reason + "|" + host
	a.mu.Lock()
	if at, ok := a.rejectedAt[key]; ok && now.Sub(at) < rejectLogEvery {
		a.mu.Unlock()
		return
	}
	if len(a.rejectedAt) >= maxRejectKeys {
		for k, at := range a.rejectedAt {
			if now.Sub(at) >= rejectLogEvery {
				delete(a.rejectedAt, k)
			}
		}
		for k := range a.rejectedAt { // still full: make room for the new key
			if len(a.rejectedAt) < maxRejectKeys {
				break
			}
			delete(a.rejectedAt, k)
		}
	}
	a.rejectedAt[key] = now
	a.mu.Unlock()
	attrs := []any{"reason", reason}
	if tokenID != "" {
		attrs = append(attrs, "token_id", tokenID)
	}
	attrs = append(attrs, "remote_addr", host)
	a.log.Warn("worker auth rejected", attrs...)
}

// WriteWorkerAuthError answers an Authenticate error: 401 "unauthorized" with
// WWW-Authenticate, or 403 "proxy id mismatch".
func WriteWorkerAuthError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrProxyIDMismatch) {
		http.Error(w, "proxy id mismatch", http.StatusForbidden)
		return
	}
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// IngestAuthorizer adapts the authenticator to the ingest handler's authorizer
// seam: the accepted proxy id is the principal's, and a refusal is 401 or 403.
func (a *WorkerAuthenticator) IngestAuthorizer() analytics.IngestAuthorizer {
	return func(r *http.Request) (string, int) {
		p, err := a.Authenticate(r)
		switch {
		case err == nil:
			return p.ProxyID, 0
		case errors.Is(err, ErrProxyIDMismatch):
			return "", http.StatusForbidden
		default:
			return "", http.StatusUnauthorized
		}
	}
}

// ingestAuthErrors makes the ingest handler's refusals match the other worker
// routes: 401 carries WWW-Authenticate and 403 says "proxy id mismatch".
func ingestAuthErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&authErrWriter{ResponseWriter: w}, r)
	})
}

type authErrWriter struct {
	http.ResponseWriter
	forbidden bool
}

func (w *authErrWriter) WriteHeader(code int) {
	switch code {
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", "Bearer")
	case http.StatusForbidden:
		w.forbidden = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *authErrWriter) Write(b []byte) (int, error) {
	if w.forbidden {
		w.forbidden = false
		if _, err := w.ResponseWriter.Write([]byte("proxy id mismatch\n")); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}
