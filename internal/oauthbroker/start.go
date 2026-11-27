package oauthbroker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// Codes of a refused start. The HTTP layer maps each to a status and answers
// {"error":"<code>"}; the text never carries a state, verifier, challenge or
// store error.
const (
	CodeInvalidRequest       = "invalid_request"
	CodeUnknownProvider      = "unknown_provider"
	CodeUserBlocked          = "user_blocked"
	CodeBlockListUnavailable = "block_list_unavailable"
	CodePendingNotFound      = "pending_not_found"
	CodePendingNotActive     = "pending_not_active"
	CodeScopeNotAllowed      = "scope_not_allowed"
	CodeRateLimited          = "rate_limited"
	CodeTooManyAttempts      = "too_many_attempts"
	CodeStoreUnavailable     = "store_unavailable"
	CodeInternal             = "internal"
)

// StartError is a refused start. Scopes lists the scope names outside the cap
// for CodeScopeNotAllowed; RetryAfter is set for CodeRateLimited.
type StartError struct {
	Code       string
	Scopes     []string
	RetryAfter time.Duration
}

func (e *StartError) Error() string {
	if len(e.Scopes) > 0 {
		return fmt.Sprintf("oauthbroker: start refused: %s (%s)", e.Code, strings.Join(e.Scopes, " "))
	}
	return "oauthbroker: start refused: " + e.Code
}

func startErr(code string) *StartError { return &StartError{Code: code} }

// StartRequest is one connect start. Iss, Sub and Email are the portal
// session's verified identity, never request data; Provider, Scopes and
// PendingID come from the form.
type StartRequest struct {
	Iss, Sub, Email string
	Provider        string
	// Scopes is the requested scope set; empty means the provider's defaults
	// (or the pending's scopes).
	Scopes    []string
	PendingID string
	// Ceiling is an extra cap for a start without a pending (the portal passes
	// the provider's allowed scopes intersected with the union of the
	// perUserSecrets mapping scopes, W-P3-PORT-03). It is honoured only with
	// HasCeiling, so an empty ceiling means "no scope" rather than "no cap".
	// It never comes from a request.
	Ceiling    []string
	HasCeiling bool
}

// StartResult is a started attempt: where to send the browser and the value of
// the __Host-warden_connect binding cookie to set on that response.
type StartResult struct {
	RedirectURL string
	// BrowserToken is the cookie value; only its SHA-256 is stored.
	BrowserToken string
	// CookieMaxAge is the cookie's lifetime (AttemptTTL).
	CookieMaxAge time.Duration
}

const (
	randBytes = 32 // state, verifier source and browser token entropy
	// maxPendingIDLog bounds the pending id written to a log line.
	maxPendingIDLog = 64
)

// Start checks the request and, when it passes, stores a single-use attempt
// (SHA-256 of the state, the PKCE verifier, the browser binding hash) and
// returns the provider authorization URL. It does no network I/O. The checks
// run in order: provider exists, user not blocked (fail closed), rate limit,
// pending ownership and status, scope cap, then the one row is written.
func (b *Broker) Start(ctx context.Context, req StartRequest) (StartResult, error) {
	st := startState{provider: UnknownProviderLabel}
	res, err := b.start(ctx, req, &st)
	b.recordStart(st, err)
	b.auditStartBlocked(ctx, req, st, err)
	return res, err
}

// auditStartBlocked writes the connect.denied row of a start refused because
// the user is blocked. Only that refusal is audited (the other start refusals
// are logged and counted): a blocked user retrying is the signal an operator
// wants. The row carries the provider and the fixed reason; a failed append is
// logged and never turns the refusal into an allow.
func (b *Broker) auditStartBlocked(ctx context.Context, req StartRequest, st startState, err error) {
	var se *StartError
	if b.audit == nil || !errors.As(err, &se) || se.Code != CodeUserBlocked {
		return
	}
	ev := AuditEvent{
		Action: AuditActionDenied, Outcome: OutcomeDenied, Reason: ReasonUserBlocked, Status: 403,
		Sub: req.Sub, Email: req.Email, Provider: st.provider,
	}
	if aerr := b.audit.Record(context.WithoutCancel(ctx), ev); aerr != nil {
		b.logger.Error("connect: audit append failed", "provider", st.provider, "action", ev.Action)
	}
}

// startState is what the log line and counter need, filled as checks pass.
type startState struct {
	provider  string // a configured id, else UnknownProviderLabel
	userKey   string
	pendingID string // only after ownership was verified
	scopes    int
}

func (b *Broker) start(ctx context.Context, req StartRequest, st *startState) (StartResult, error) {
	if req.Iss == "" || req.Sub == "" {
		return StartResult{}, startErr(CodeInternal)
	}
	userKey, err := b.userKey(req.Iss, req.Sub)
	if err != nil || userKey == "" {
		return StartResult{}, startErr(CodeInternal)
	}
	st.userKey = userKey

	if req.Provider == "" {
		return StartResult{}, startErr(CodeInvalidRequest)
	}
	prov, err := b.reg.Get(req.Provider)
	if err != nil {
		return StartResult{}, startErr(CodeUnknownProvider)
	}
	st.provider = prov.ID

	blocked, err := b.blocks.IsBlocked(ctx, req.Sub, req.Email)
	if err != nil {
		return StartResult{}, startErr(CodeBlockListUnavailable)
	}
	if blocked {
		return StartResult{}, startErr(CodeUserBlocked)
	}

	if b.limiter != nil {
		if ok, wait := b.limiter.Allow(st.userKey, b.now()); !ok {
			return StartResult{}, &StartError{Code: CodeRateLimited, RetryAfter: wait}
		}
	}

	var pending *Pending
	if req.PendingID != "" {
		p, err := b.store.GetPending(ctx, req.PendingID)
		switch {
		case errors.Is(err, ErrNotFound):
			return StartResult{}, startErr(CodePendingNotFound)
		case err != nil:
			return StartResult{}, startErr(CodeStoreUnavailable)
		}
		// Another user's pending is indistinguishable from an unknown one.
		if p.Iss != req.Iss || p.Sub != req.Sub {
			return StartResult{}, startErr(CodePendingNotFound)
		}
		st.pendingID = req.PendingID
		if len(st.pendingID) > maxPendingIDLog {
			st.pendingID = st.pendingID[:maxPendingIDLog]
		}
		if p.Provider != prov.ID {
			return StartResult{}, startErr(CodeInvalidRequest)
		}
		if p.Status != StatusPending {
			return StartResult{}, startErr(CodePendingNotActive)
		}
		pending = &p
	}

	capped, err := cappedScopes(prov, req, pending)
	if err != nil {
		return StartResult{}, err
	}

	// The provider is asked for the union of what the user already granted and
	// the new scopes, so a reconnect never narrows a working grant.
	want := capped
	switch g, err := b.store.GetGrant(ctx, st.userKey, prov.ID); {
	case err == nil:
		if g.State == GrantActive {
			// Re-cap what the grant already holds: a scope the operator has
			// since removed from allowedScopes (or a githubApp, which has none)
			// is dropped silently, never requested again.
			keep, _ := prov.CapScopes(g.Scopes)
			want = UnionScopes(keep, capped)
		}
	case errors.Is(err, ErrNotFound):
	default:
		return StartResult{}, startErr(CodeStoreUnavailable)
	}
	st.scopes = len(want)

	state, err := b.randToken()
	if err != nil {
		return StartResult{}, startErr(CodeInternal)
	}
	verifier, err := b.randToken()
	if err != nil {
		return StartResult{}, startErr(CodeInternal)
	}
	browser, err := b.randToken()
	if err != nil {
		return StartResult{}, startErr(CodeInternal)
	}
	location, err := b.authURL(prov, want, state, verifier)
	if err != nil {
		return StartResult{}, startErr(CodeInternal)
	}
	if _, err := b.store.CreateAttempt(ctx, Attempt{
		StateHash: HashState(state), PendingID: req.PendingID,
		Iss: req.Iss, Sub: req.Sub, UserKey: st.userKey, Provider: prov.ID,
		Scopes: want, Verifier: verifier, BrowserHash: HashBrowserBinding(browser),
	}); err != nil {
		if errors.Is(err, ErrTooMany) {
			return StartResult{}, startErr(CodeTooManyAttempts)
		}
		return StartResult{}, startErr(CodeStoreUnavailable)
	}
	return StartResult{RedirectURL: location, BrowserToken: browser, CookieMaxAge: AttemptTTL}, nil
}

// cappedScopes applies the provider cap, the pending's scopes and the caller's
// ceiling to the request. Scopes the caller named that fall outside any cap
// refuse the start (400 scope_not_allowed, before any row is written); when
// the caller named none, the defaults (or the pending's scopes) are narrowed
// to the caps instead, and the start is refused only when nothing is left.
func cappedScopes(prov *Provider, req StartRequest, pending *Pending) ([]string, error) {
	requested := normalizeScopes(req.Scopes)
	named := len(requested) > 0
	if !named {
		requested = prov.DefaultScopes
		if pending != nil && len(pending.Scopes) > 0 {
			requested = pending.Scopes
		}
	}
	// Never write to a shared slice: every cap builds a new one.
	capped, rejected := prov.CapScopes(requested)
	if pending != nil {
		out, rej := CapScopes(capped, pending.Scopes)
		capped, rejected = out, UnionScopes(rejected, rej)
	}
	if req.HasCeiling && pending == nil {
		out, rej := CapScopes(capped, req.Ceiling)
		capped, rejected = out, UnionScopes(rejected, rej)
	}
	if len(rejected) > 0 && (named || len(capped) == 0) {
		return nil, &StartError{Code: CodeScopeNotAllowed, Scopes: slices.Clone(rejected)}
	}
	return capped, nil
}

// broker-owned authorization parameters: neither the provider's authURL query
// nor extraAuthParams can set or replace one.
var reservedAuthParams = map[string]struct{}{
	"client_id": {}, "redirect_uri": {}, "response_type": {}, "scope": {},
	"state": {}, "code_challenge": {}, "code_challenge_method": {}, "nonce": {},
	"include_granted_scopes": {}, "request": {}, "request_uri": {},
	"response_mode": {}, "claims": {},
}

func reservedAuthParam(k string) bool {
	_, ok := reservedAuthParams[strings.ToLower(k)]
	return ok
}

// authURL builds the provider authorization URL: code flow, PKCE S256, the
// configured redirect_uri and the capped scopes. A githubApp sends no scope
// (its permissions come from the app).
func (b *Broker) authURL(p *Provider, scopes []string, state, verifier string) (string, error) {
	u, err := url.Parse(p.AuthURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k := range q {
		if reservedAuthParam(k) {
			q.Del(k)
		}
	}
	for k, v := range p.ExtraAuthParams {
		if !reservedAuthParam(k) {
			q.Set(k, v)
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", b.redir)
	q.Set("state", state)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	if p.Type != config.OAuthProviderGitHubApp && len(scopes) > 0 {
		q.Set("scope", JoinScopes(scopes))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// randToken returns 32 random bytes as unpadded base64url (43 characters, the
// shortest RFC 7636 verifier).
func (b *Broker) randToken() (string, error) {
	var buf [randBytes]byte
	if _, err := io.ReadFull(b.rand, buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// recordStart writes the oauth_connect_start log line and bumps the counter.
// It carries no state, verifier, challenge or code.
func (b *Broker) recordStart(st startState, err error) {
	outcome, reason := OutcomeOK, ""
	var se *StartError
	if errors.As(err, &se) {
		reason = se.Code
		switch se.Code {
		case CodeStoreUnavailable, CodeInternal, CodeBlockListUnavailable:
			outcome = OutcomeError
		default:
			outcome = OutcomeDenied
		}
	} else if err != nil {
		outcome, reason = OutcomeError, CodeInternal
	}
	b.metrics.inc(ConnectKey{Provider: st.provider, Stage: StageStart, Outcome: outcome})
	lvl := b.logger.Info
	if outcome != OutcomeOK {
		lvl = b.logger.Warn
	}
	lvl("oauth_connect_start",
		"provider", st.provider, "user_key", st.userKey, "pending_id", st.pendingID,
		"scopes_count", st.scopes, "outcome", outcome, "reason", reason)
}
