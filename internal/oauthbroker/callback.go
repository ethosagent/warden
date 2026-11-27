package oauthbroker

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"
)

// TokenVault is consent.store as the broker uses it: the CP-only user
// credential store behind secrets.SecretStore. Get reports an absent key with
// an error Config.NotFound recognises. Keys lists the logical keys (the hourly
// orphan pass reads the ones under users/).
type TokenVault interface {
	Get(ctx context.Context, key string) (string, error)
	Put(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
	Keys(ctx context.Context) ([]string, error)
}

// AuditEvent is one connect decision for the admin audit log. It never carries
// a token, code, state, verifier or secret reference.
type AuditEvent struct {
	// Action is AuditActionGranted or AuditActionDenied.
	Action string
	// Outcome is OutcomeOK, OutcomeDenied or OutcomeError.
	Outcome string
	// Reason is a fixed code ("" for a plain grant).
	Reason string
	Status int
	// Sub and Email are the portal session's identity (the actor).
	Sub, Email string
	Provider   string
	GrantID    string
	PendingID  string
	Scopes     []string
}

// Audit actions of connect.
const (
	AuditActionGranted = "connect.granted"
	AuditActionDenied  = "connect.denied"
)

// AuditSink records connect decisions. Ready reports whether a record could
// be written now (admin audit on and healthy); a nil sink means audit is off.
type AuditSink interface {
	Ready(ctx context.Context) error
	Record(ctx context.Context, ev AuditEvent) error
}

// Codes of a refused or failed callback. The HTTP layer renders each as a
// generic page (never provider text); Status gives its HTTP status.
const (
	CodeStateInvalid        = "state_invalid"
	CodeSessionMismatch     = "session_mismatch"
	CodeAuditUnavailable    = "admin_audit_unavailable"
	CodeExchangeFailed      = "exchange_failed"
	CodeProviderUnreachable = "provider_unreachable"
	CodeProviderConfig      = "provider_unavailable"
	CodeScopeExceeded       = "scope_exceeded"
	CodeSecretStoreDown     = "secret_store_unavailable"
)

// CallbackError is a refused or failed callback. Its text is the Code only.
type CallbackError struct {
	Code string
}

func (e *CallbackError) Error() string { return "oauthbroker: callback refused: " + e.Code }

func cbErr(code string) *CallbackError { return &CallbackError{Code: code} }

// Status is the HTTP status of the page that answers the error.
func (e *CallbackError) Status() int {
	switch e.Code {
	case CodeStateInvalid, CodeExchangeFailed, CodeInvalidRequest:
		return 400
	case CodeSessionMismatch, CodeUserBlocked, CodeScopeExceeded:
		return 403
	case CodeProviderUnreachable:
		return 502
	case CodeAuditUnavailable, CodeBlockListUnavailable, CodeStoreUnavailable, CodeSecretStoreDown, CodeProviderConfig:
		return 503
	default:
		return 500
	}
}

// CallbackRequest is one GET /connect/callback. Iss, Sub and Email are the
// portal session's identity, never request data; State, Code and ProviderError
// are the query parameters and BrowserToken is the connect cookie's value.
type CallbackRequest struct {
	Iss, Sub, Email string
	State, Code     string
	// ProviderError is the query's error parameter (error_description is never
	// read).
	ProviderError string
	BrowserToken  string
}

// Results of a callback that ran to a decision.
const (
	ResultGranted = "granted"
	ResultDenied  = "denied"
)

// CallbackResult says where the browser goes next. Provider is a configured
// provider id and PendingID a broker-issued id; Reason is a fixed code.
type CallbackResult struct {
	Result    string
	Reason    string
	Provider  string
	PendingID string
}

// writeTimeout bounds the lock-held write phase, which runs detached from the
// request so a client that hangs up after the code was spent cannot leave a
// half-written grant.
const writeTimeout = 30 * time.Second

// Reasons recorded on a pending completed by the callback.
const (
	ReasonAccessDenied      = "access_denied"
	ReasonScopeExceeded     = "scope_exceeded"
	ReasonInsufficientScope = "insufficient_scope"
	ReasonUserBlocked       = "user_blocked"
)

// identityScopes are granted on top of the cap: Google returns openid and email
// when the account identity is read, and they carry no API access.
var identityScopes = []string{"openid", "email"}

type callbackState struct {
	provider  string
	userKey   string
	pendingID string
	grantID   string
	scopes    []string
	reason    string
	// audited is set once the attempt was consumed: from then on the request
	// is attributable to the session user, so its outcome is audited.
	audited bool
}

// Callback consumes the attempt behind a provider redirect and, when every
// check passes, exchanges the code and stores the grant. The order is: audit
// health, single-use attempt, session user, browser binding, block list, the
// provider's own error, the code exchange, the scope cap, then the write under
// GrantLocks (grant connecting, TokenRecord in consent.store, grant active,
// block re-check, pending completed). A refusal before the exchange sends no
// request to the provider. A returned *CallbackError has Code and Status.
func (b *Broker) Callback(ctx context.Context, req CallbackRequest) (CallbackResult, error) {
	st := callbackState{provider: UnknownProviderLabel}
	res, err := b.callback(ctx, req, &st)
	b.recordCallback(ctx, req, st, res, err)
	return res, err
}

func (b *Broker) callback(ctx context.Context, req CallbackRequest, st *callbackState) (CallbackResult, error) {
	if b.vault == nil || b.grantKey == nil || b.exchanger == nil || req.Iss == "" || req.Sub == "" {
		return CallbackResult{}, cbErr(CodeInternal)
	}
	if req.State == "" {
		return CallbackResult{}, cbErr(CodeStateInvalid)
	}
	// Before the attempt is consumed, so a sick audit log costs the user a
	// retry, not a restart.
	if b.audit != nil {
		if err := b.audit.Ready(ctx); err != nil {
			return CallbackResult{}, cbErr(CodeAuditUnavailable)
		}
	}
	a, err := b.store.ConsumeAttempt(ctx, HashState(req.State))
	switch {
	case errors.Is(err, ErrNotFound):
		return CallbackResult{}, cbErr(CodeStateInvalid)
	case err != nil:
		return CallbackResult{}, cbErr(CodeStoreUnavailable)
	}
	st.audited = true
	st.userKey = a.UserKey
	st.pendingID = a.PendingID
	st.scopes = a.Scopes
	if len(st.pendingID) > maxPendingIDLog {
		st.pendingID = st.pendingID[:maxPendingIDLog]
	}
	prov, perr := b.reg.Get(a.Provider)
	if perr == nil {
		st.provider = prov.ID
	}

	// The portal user who finished the flow must be the one who started it.
	if a.Iss != req.Iss || a.Sub != req.Sub {
		return CallbackResult{}, cbErr(CodeSessionMismatch)
	}
	// And the same browser: the cookie set on the start response.
	want := []byte(a.BrowserHash)
	got := []byte(HashBrowserBinding(req.BrowserToken))
	if req.BrowserToken == "" || subtle.ConstantTimeCompare(got, want) != 1 {
		return CallbackResult{}, cbErr(CodeStateInvalid)
	}
	if perr != nil {
		return CallbackResult{}, cbErr(CodeStateInvalid)
	}
	if uk, err := b.userKey(req.Iss, req.Sub); err != nil || uk != a.UserKey {
		return CallbackResult{}, cbErr(CodeStateInvalid)
	}

	if err := b.checkBlocked(ctx, req); err != nil {
		b.completePending(ctx, a.PendingID, StatusDenied, ReasonUserBlocked)
		return CallbackResult{}, err
	}

	if req.ProviderError != "" {
		if SafeErrorCode(req.ProviderError) == ErrorCodeAccessDenied {
			return b.denied(ctx, a, prov, ReasonAccessDenied, st), nil
		}
		return CallbackResult{}, cbErr(CodeExchangeFailed)
	}
	if req.Code == "" {
		return CallbackResult{}, cbErr(CodeInvalidRequest)
	}

	secret, err := prov.ClientSecret(ctx)
	if err != nil {
		return CallbackResult{}, cbErr(CodeProviderConfig)
	}
	xctx, cancel := context.WithTimeout(ctx, ExchangeTimeout)
	started := b.now()
	tok, err := b.exchanger.Exchange(xctx, ExchangeRequest{
		TokenURL: prov.TokenURL, ClientID: prov.ClientID, ClientSecret: secret,
		Code: req.Code, Verifier: a.Verifier, RedirectURL: b.redir,
	})
	cancel()
	b.observeExchange(prov.ID, b.now().Sub(started))
	if err != nil {
		return b.exchangeFailed(ctx, a, prov, err, st)
	}
	if tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "bearer") {
		return CallbackResult{}, cbErr(CodeExchangeFailed)
	}

	// The cap is the operator's allowedScopes (plus the identity scopes), never
	// the attempt's own list: a provider can grant more than was asked.
	requested := CanonicalScopes(a.Scopes)
	granted := ParseScopes(tok.Scope)
	scopeSent := len(granted) > 0
	if !scopeSent {
		granted = requested
	}
	if _, outside := CapScopes(granted, UnionScopes(prov.AllowedScopes, identityScopes)); len(outside) > 0 {
		b.logger.Warn("oauth_connect_scope_exceeded", "provider", prov.ID, "user_key", a.UserKey, "outside_count", len(outside))
		b.completePending(ctx, a.PendingID, StatusDenied, ReasonScopeExceeded)
		return CallbackResult{}, cbErr(CodeScopeExceeded)
	}
	st.scopes = granted
	insufficient := false
	if scopeSent {
		_, missing := CapScopes(requested, granted)
		insufficient = len(missing) > 0
	}
	return b.writeGrant(ctx, req, a, prov, tok, granted, insufficient, st)
}

// writeGrant is the write phase, after the exchange succeeded and the scopes passed
// the cap. Everything here runs detached from the request, under GrantLocks.
func (b *Broker) writeGrant(ctx context.Context, req CallbackRequest, a Attempt, prov *Provider, tok TokenResponse, granted []string, insufficient bool, st *callbackState) (CallbackResult, error) {
	key, err := b.grantKey(a.UserKey, prov.ID)
	if err != nil {
		return CallbackResult{}, cbErr(CodeInternal)
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	unlock := b.locks.Lock(a.UserKey, prov.ID)
	defer unlock()

	grant, err := b.store.BeginGrant(wctx, GrantRef{UserKey: a.UserKey, Iss: a.Iss, Sub: a.Sub, Provider: prov.ID})
	if err != nil {
		return CallbackResult{}, cbErr(CodeStoreUnavailable)
	}
	st.grantID = grant.GrantID

	rec := TokenRecord{
		V: TokenRecordVersion, GrantID: grant.GrantID, Provider: prov.ID, ClientID: prov.ClientID,
		TokenType: tok.TokenType, AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken,
		Scope: JoinScopes(granted), ObtainedAt: b.now().Unix(),
	}
	if !tok.Expiry.IsZero() {
		rec.Expiry = tok.Expiry.UTC().Unix()
	}
	if !tok.RefreshExpiry.IsZero() {
		rec.RefreshExpiry = tok.RefreshExpiry.UTC().Unix()
	}
	if rec.RefreshToken == "" {
		// A reconnect often returns no refresh token (Google only sends one on
		// first consent); the stored one stays valid and must not be lost.
		prev, err := b.vault.Get(wctx, key)
		switch {
		case err == nil:
			if old, perr := ParseTokenRecord([]byte(prev)); perr == nil && old.RefreshToken != "" {
				rec.RefreshToken, rec.RefreshExpiry = old.RefreshToken, old.RefreshExpiry
			}
		case b.notFound(err):
		default:
			b.logger.Warn("oauth_connect_secret_store_failed", "provider", prov.ID, "user_key", a.UserKey, "op", "get")
			return CallbackResult{}, cbErr(CodeSecretStoreDown)
		}
	}
	data, err := rec.Marshal()
	if err != nil {
		return CallbackResult{}, cbErr(CodeInternal)
	}
	if err := b.vault.Put(wctx, key, string(data)); err != nil {
		// The token is dropped here; the grant stays connecting for the
		// reconciler, which restores the earlier grant or revokes this one.
		b.logger.Warn("oauth_connect_secret_store_failed", "provider", prov.ID, "user_key", a.UserKey, "op", "put")
		return CallbackResult{}, cbErr(CodeSecretStoreDown)
	}
	if _, err := b.store.ActivateGrant(wctx, grant.GrantID, granted, Account{}); err != nil {
		b.logger.Warn("oauth_connect_activate_failed", "provider", prov.ID, "user_key", a.UserKey)
		return CallbackResult{}, cbErr(CodeStoreUnavailable)
	}

	// A block that landed during the exchange: nothing the user connected may
	// outlive it.
	if err := b.checkBlocked(wctx, req); err != nil {
		if derr := b.vault.Delete(wctx, key); derr != nil {
			b.logger.Warn("oauth_connect_secret_store_failed", "provider", prov.ID, "user_key", a.UserKey, "op", "delete")
		}
		if _, rerr := b.store.RevokeGrant(wctx, a.UserKey, prov.ID, grant.GrantID); rerr != nil {
			b.logger.Warn("oauth_connect_revoke_failed", "provider", prov.ID, "user_key", a.UserKey)
		}
		b.completePending(wctx, a.PendingID, StatusDenied, ReasonUserBlocked)
		return CallbackResult{}, err
	}

	res := CallbackResult{Result: ResultGranted, Provider: prov.ID, PendingID: a.PendingID}
	if insufficient {
		// The grant holds what the provider gave; the pending ends denied so a
		// JIT caller stops retrying a request this grant can never satisfy.
		res.Result, res.Reason = ResultDenied, ReasonInsufficientScope
		st.reason = ReasonInsufficientScope
		b.completePending(wctx, a.PendingID, StatusDenied, ReasonInsufficientScope)
	} else {
		b.completePending(wctx, a.PendingID, StatusGranted, "")
	}
	return res, nil
}

// checkBlocked re-reads the block list; an unreadable list refuses like a
// blocked user (fail closed).
func (b *Broker) checkBlocked(ctx context.Context, req CallbackRequest) error {
	blocked, err := b.blocks.IsBlocked(ctx, req.Sub, req.Email)
	if err != nil {
		return cbErr(CodeBlockListUnavailable)
	}
	if blocked {
		return cbErr(CodeUserBlocked)
	}
	return nil
}

// denied completes the pending denied and reports a denial the user caused.
func (b *Broker) denied(ctx context.Context, a Attempt, prov *Provider, reason string, st *callbackState) CallbackResult {
	st.reason = reason
	b.completePending(ctx, a.PendingID, StatusDenied, reason)
	return CallbackResult{Result: ResultDenied, Reason: reason, Provider: prov.ID, PendingID: a.PendingID}
}

func (b *Broker) exchangeFailed(ctx context.Context, a Attempt, prov *Provider, err error, st *callbackState) (CallbackResult, error) {
	var xe *ExchangeError
	if !errors.As(err, &xe) {
		xe = &ExchangeError{Kind: ExchangeUnavailable}
	}
	switch xe.Kind {
	case ExchangeDenied:
		return b.denied(ctx, a, prov, ReasonAccessDenied, st), nil
	case ExchangeRejected:
		// Only this attempt fails; the pending stays open for a retry.
		st.reason = SafeErrorCode(xe.Code)
		return CallbackResult{}, cbErr(CodeExchangeFailed)
	default:
		st.reason = "unreachable"
		return CallbackResult{}, cbErr(CodeProviderUnreachable)
	}
}

// completePending ends the attempt's pending, if it has one. A pending that
// already ended (expired meanwhile) is not an error.
func (b *Broker) completePending(ctx context.Context, id string, status PendingStatus, reason string) {
	if id == "" {
		return
	}
	if err := b.store.CompletePending(context.WithoutCancel(ctx), id, status, reason); err != nil &&
		!errors.Is(err, ErrNotPending) && !errors.Is(err, ErrNotFound) {
		b.logger.Warn("oauth_connect_pending_not_completed", "pending_id", id, "status", string(status))
	}
}

func (b *Broker) observeExchange(provider string, d time.Duration) {
	b.metrics.mu.Lock()
	defer b.metrics.mu.Unlock()
	t := b.metrics.exchange[provider]
	if t == nil {
		t = &exchangeTiming{}
		b.metrics.exchange[provider] = t
	}
	t.count++
	t.sum += d
}

// ExchangeSeconds returns warden_cp_oauth_token_exchange_seconds{provider} as
// (observations, total seconds) per configured provider id. W-P5-RETN-06 adds
// it to the export list.
func (b *Broker) ExchangeSeconds() map[string][2]float64 {
	b.metrics.mu.Lock()
	defer b.metrics.mu.Unlock()
	out := make(map[string][2]float64, len(b.metrics.exchange))
	for k, v := range b.metrics.exchange {
		out[k] = [2]float64{float64(v.count), v.sum.Seconds()}
	}
	return out
}

// recordCallback bumps the counter, writes the connect log line and, once the
// attempt was consumed, the admin audit row. Nothing here sees a code, state,
// verifier or token.
func (b *Broker) recordCallback(ctx context.Context, req CallbackRequest, st callbackState, res CallbackResult, err error) {
	outcome, reason, status := OutcomeOK, st.reason, 303
	granted := err == nil && (res.Result == ResultGranted || res.Reason == ReasonInsufficientScope)
	var ce *CallbackError
	switch {
	case errors.As(err, &ce):
		reason, status = ce.Code, ce.Status()
		outcome = OutcomeDenied
		switch ce.Code {
		case CodeStoreUnavailable, CodeInternal, CodeBlockListUnavailable, CodeSecretStoreDown,
			CodeProviderUnreachable, CodeProviderConfig, CodeAuditUnavailable:
			outcome = OutcomeError
		}
	case err != nil:
		outcome, reason, status = OutcomeError, CodeInternal, 500
	case res.Result == ResultDenied:
		outcome = OutcomeDenied
		if reason == "" {
			reason = res.Reason
		}
	}
	b.metrics.inc(ConnectKey{Provider: st.provider, Stage: StageCallback, Outcome: outcome})
	lvl := b.logger.Info
	if outcome != OutcomeOK {
		lvl = b.logger.Warn
	}
	lvl("connect", "schema", "warden.consent.v1",
		"stage", StageCallback, "provider", st.provider, "user_key", st.userKey, "pending_id", st.pendingID,
		"grant_id", st.grantID, "scopes_count", len(st.scopes), "outcome", outcome, "reason", reason)

	if b.audit == nil || !st.audited {
		return
	}
	ev := AuditEvent{
		Action: AuditActionDenied, Outcome: outcome, Reason: reason, Status: status,
		Sub: req.Sub, Email: req.Email, Provider: st.provider, GrantID: st.grantID,
		PendingID: st.pendingID, Scopes: st.scopes,
	}
	if granted {
		ev.Action = AuditActionGranted
		ev.Outcome = OutcomeOK
	}
	if aerr := b.audit.Record(context.WithoutCancel(ctx), ev); aerr != nil {
		b.logger.Error("connect: audit append failed", "provider", st.provider, "action", ev.Action)
	}
}
