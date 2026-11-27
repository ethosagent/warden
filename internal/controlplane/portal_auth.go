package controlplane

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/internal/webauth"
)

// The consent portal's sign-in (W-P3-CSIG-02). Employees sign in through the
// dedicated consent.oidc client (warden-portal by default) and get a portal
// session, a separate type from the console's with no console privilege:
//
//	GET /portal/login    stores a purpose=portal pending row, sets the
//	                     __Host-warden_portal_login binding cookie, redirects to the IdP
//	GET /portal/callback consumes that row (purpose=portal only), exchanges the code,
//	                     verifies the ID token for the portal client, admits the
//	                     user and creates a portal_sessions row
//	GET /portal          a minimal no-store page (replaced by W-P3-PORT-01)
//
// The flow is webauth.Flow; this file adds the portal's admission (block
// list, allowedGroups, the IdP link's refresh token) and its session. The
// code, state, verifier, nonce, tokens and cookie values are never logged.

// portalSecretStoreUnavailable answers a callback whose IdP link could not be
// stored: no session, no row (fail closed).
const portalSecretStoreUnavailable = "secret_store_unavailable"

// portalSessionStoreUnavailable answers a callback whose portal_sessions
// insert failed (503, no session). An IdP link stored just before may exist
// without a session in that case.
const portalSessionStoreUnavailable = "session_store_unavailable"

// portalService is the portal's front door. A service whose flow could not be
// built (a bad issuer, say) stays mounted and answers 503 idp_unavailable.
type portalService struct {
	cfg      config.ConsentConfig
	provider *webauth.Provider
	flow     *webauth.Flow
	pending  *webauth.PendingStore
	sessions *PortalSessionStore
	// blocks is the block list; nil means none is kept.
	blocks *BlockStore
	// links stores the IdP link on login (W-P3-CSIG-03); nil until that
	// ticket wires the CP-only consent.store.
	links  portal.LinkWriter
	cookie webauth.Cookie
	logger *slog.Logger

	// audit records a callback's outcome in the admin audit log
	// (Server.recordPortalLogin); nil when admin audit is disabled.
	audit func(*http.Request, portalLoginResult)
}

// initPortal builds the portal when the consent block is enabled and a state
// DB is open; otherwise s.portal stays nil and no /portal route exists. It
// does no network I/O: discovery runs from Start.
func (s *Server) initPortal() {
	if s.cfg.Consent == nil || s.cfg.State == nil {
		return
	}
	cc := *s.cfg.Consent
	p := &portalService{cfg: cc, blocks: s.blocks, logger: s.cfg.Logger}
	s.portal = p
	cookie, err := webauth.NewCookie(cc.OIDC.RedirectURL, portal.SessionCookieBase)
	if err != nil {
		s.cfg.Logger.Error("control plane: portal login unavailable", "error", err)
		return
	}
	if !cookie.Secure {
		s.cfg.Logger.Warn("control plane: portal session cookie is not Secure (http loopback consent.oidc.redirectURL); use https outside development")
	}
	p.cookie = cookie
	p.sessions = NewPortalSessionStore(s.cfg.State.SQL(), cc.Session.Idle, cc.Session.Absolute, s.cfg.Now)
	client, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: cc.OIDC.Issuer, InternalIssuerURL: cc.OIDC.InternalIssuerURL})
	if err != nil {
		s.cfg.Logger.Error("control plane: portal login unavailable", "error", err)
		return
	}
	// Pinned to the portal client: Audience and AllowedAZP are its id, so a
	// console token (aud warden-console) or a data-plane one never signs in.
	verifier, err := oidc.NewIDTokenVerifier(oidc.IDTokenConfig{
		Issuer: cc.OIDC.Issuer, ClientID: cc.OIDC.ClientID,
		InternalIssuerURL: cc.OIDC.InternalIssuerURL, Now: s.cfg.Now,
	})
	if err != nil {
		s.cfg.Logger.Error("control plane: portal login unavailable", "error", err)
		return
	}
	p.provider = webauth.NewProvider(webauth.ProviderConfig{
		Name: "portal", Issuer: cc.OIDC.Issuer,
		OAuth: oauth2.Config{
			ClientID: cc.OIDC.ClientID, ClientSecret: s.cfg.ConsentClientSecret,
			RedirectURL: cc.OIDC.RedirectURL, Scopes: portal.Scopes(cc.IdPLink.Enabled),
		},
		Discover: func(ctx context.Context) (webauth.Endpoints, error) {
			ep, err := oidc.Discover(ctx, client, cc.OIDC.Issuer)
			return webauth.Endpoints{AuthURL: ep.AuthURL, TokenURL: ep.TokenURL}, err
		},
		HTTPContext: func(ctx context.Context) context.Context { return oidc.WithHTTPClient(ctx, client) },
		Logger:      s.cfg.Logger,
	})
	p.pending = webauth.NewPendingStore(s.cfg.State.SQL(), s.cfg.Now)
	prefixes := portal.NextPrefixes()
	p.flow = &webauth.Flow{
		Name: "portal", Provider: p.provider, Verifier: verifier, Pending: p.pending,
		Purpose: webauth.PurposePortal, LoginCookie: cookie.Named(portal.LoginCookieBase),
		AllowNext:   func(next string) bool { return webauth.SafeNext(next, prefixes...) },
		DefaultNext: portal.Home, Logger: s.cfg.Logger,
	}
}

// start runs discovery and the sweepers until ctx is done.
func (p *portalService) start(ctx context.Context) {
	if p.sessions != nil {
		go p.sweepSessions(ctx)
	}
	if p.flow != nil {
		go p.provider.Run(ctx)
		// One pending sweeper serves every purpose; a second (the console's)
		// is harmless.
		go p.pending.RunSweeper(ctx, p.logger)
	}
}

// ready reports whether discovery has succeeded.
func (p *portalService) ready() bool { return p.flow.Ready() }

// handleLogin starts a portal login.
func (p *portalService) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	if !p.ready() {
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	if p.blocks != nil && !p.blocks.Ready() {
		writeAuthError(w, http.StatusServiceUnavailable, loginBlockUnavailable)
		return
	}
	err := p.flow.Begin(w, r, r.URL.Query().Get("next"))
	switch {
	case err == nil:
		return
	case errors.Is(err, webauth.ErrUnavailable):
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	code, status := loginInternal, http.StatusInternalServerError
	if errors.Is(err, webauth.ErrPendingFull) {
		code, status = loginBusy, http.StatusServiceUnavailable
	}
	p.logger.Warn("portal_login", "result", "failed", "reason", code, "duration_ms", time.Since(start).Milliseconds())
	writeAuthError(w, status, code)
}

// portalLoginResult carries what the callback logs and records.
type portalLoginResult struct {
	reason string
	// sub is the token's subject for the log line, verified or not.
	sub string
	// consumed is true once a portal pending state was taken: only then is a
	// failure recorded in the admin audit log.
	consumed bool
	// actor comes only from a verified ID token; sessionHash is the new
	// session's id hash (never the raw id).
	actor       adminaudit.Actor
	sessionHash string
	status      int
}

// handleCallback finishes a portal login. A success redirects to the stored
// next; a refusal of the user or the token redirects to
// /portal?login_error=<code>; an unmet IdP-link or block-list precondition is
// a JSON error (502 offline_access_not_granted, 503 otherwise).
func (p *portalService) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	if !p.ready() {
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	login, err := p.flow.Complete(w, r)
	if errors.Is(err, webauth.ErrUnavailable) {
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	next, res := p.finishLogin(w, r, login, err)
	p.logger.Info("portal_login",
		"result", map[bool]string{true: "ok", false: "failed"}[res.reason == ""],
		"reason", res.reason, "sub", res.sub, "duration_ms", time.Since(start).Milliseconds())
	if p.audit != nil && (res.reason == "" || res.consumed) {
		p.audit(r, res)
	}
	switch res.reason {
	case "":
		http.Redirect(w, r, next, http.StatusFound)
	case portal.CodeOfflineAccessNotGranted, loginBlockUnavailable, portalSecretStoreUnavailable, portalSessionStoreUnavailable:
		writeAuthError(w, res.status, res.reason)
	default:
		http.Redirect(w, r, portal.Home+"?login_error="+url.QueryEscape(res.reason), http.StatusFound)
	}
}

// finishLogin turns the flow's outcome into the portal's: a failed flow keeps
// its code; a verified login is admitted and gets a session. Nothing is
// written for a refused login.
func (p *portalService) finishLogin(w http.ResponseWriter, r *http.Request, login webauth.Login, err error) (string, portalLoginResult) {
	if err != nil {
		var fe *webauth.Error
		if errors.As(err, &fe) {
			return "", portalLoginResult{reason: fe.Code, consumed: fe.Consumed, sub: fe.Sub, status: http.StatusFound}
		}
		return "", portalLoginResult{reason: loginStateInvalid, status: http.StatusFound}
	}
	ctx := r.Context()
	claims := login.Claims
	res := portalLoginResult{consumed: true, sub: claims.Sub, actor: adminaudit.Actor{Sub: claims.Sub, Email: claims.Email}, status: http.StatusFound}
	// Without a loaded block list the portal cannot tell who is blocked, so it
	// refuses.
	if p.blocks != nil && !p.blocks.Ready() {
		res.reason, res.status = loginBlockUnavailable, http.StatusServiceUnavailable
		return "", res
	}
	adm := portal.Admission{
		AllowedGroups:       p.cfg.AllowedGroups,
		RequireRefreshToken: p.cfg.IdPLink.Enabled,
	}
	if p.blocks != nil {
		adm.Blocks = p.blocks
	}
	groups := portal.CapGroups(claims.Groups)
	if code := adm.Admit(portal.Candidate{
		Sub: claims.Sub, Email: claims.Email, Groups: groups, HasRefreshToken: login.RefreshToken != "",
	}); code != "" {
		res.reason = code
		if code == portal.CodeOfflineAccessNotGranted {
			res.status = http.StatusBadGateway
		}
		return "", res
	}
	if p.links != nil && p.cfg.IdPLink.Enabled {
		if err := p.links.StoreLink(ctx, portal.Link{Iss: claims.Issuer, Sub: claims.Sub, Email: claims.Email, RefreshToken: login.RefreshToken}); err != nil {
			// Only the error's type is logged: a store error could echo what
			// it was asked to write.
			p.logger.Error("portal login: idp link store failed", "sub", claims.Sub, "reason", "idp_link_store_failed", "error_type", fmt.Sprintf("%T", err))
			res.reason, res.status = portalSecretStoreUnavailable, http.StatusServiceUnavailable
			return "", res
		}
	}
	rawID, sess, err := p.sessions.Create(ctx, webauth.SessionInput{
		Iss: claims.Issuer, Sub: claims.Sub, Email: claims.Email, Groups: groups,
	})
	if err != nil {
		// The IdP link, when one was written above, stays: it is the same
		// link the user's next successful login writes again.
		p.logger.Error("portal login: session create failed", "reason", "session_store_failed", "error", err)
		res.reason, res.status = portalSessionStoreUnavailable, http.StatusServiceUnavailable
		return "", res
	}
	// A portal cookie the request carried is never reused: its row is dropped
	// and the new id is minted server-side.
	if old, ok := p.cookie.From(r); ok {
		if err := p.sessions.Delete(ctx, old); err != nil {
			p.logger.Warn("portal login: old session delete failed", "error", err)
		}
	}
	http.SetCookie(w, p.cookie.New(rawID, p.sessions.Absolute()))
	res.sessionHash = sess.IDHash
	return login.Next, res
}

// session returns the live portal session the request's portal cookie names,
// with its raw id. Only the portal cookie and portal_sessions are read; a
// blocked principal, or any principal while no block list has loaded, has no
// session. Activity is recorded at most once a
// minute. W-P3-CSIG-04's RequireSession builds on it.
func (p *portalService) session(r *http.Request) (webauth.Session, string, bool) {
	if p.sessions == nil {
		return webauth.Session{}, "", false
	}
	rawID, ok := p.cookie.From(r)
	if !ok {
		return webauth.Session{}, "", false
	}
	sess, live, err := p.sessions.Lookup(r.Context(), rawID)
	if err != nil {
		p.logger.Error("portal session lookup failed", "error", err)
		return webauth.Session{}, "", false
	}
	if !live {
		return webauth.Session{}, "", false
	}
	// Without a loaded block list nobody can be told apart from a blocked
	// user, so no session authenticates (fail closed).
	if p.blocks != nil && (!p.blocks.Ready() || p.blocks.IsBlocked(sess.Sub, sess.Email)) {
		return webauth.Session{}, "", false
	}
	if webauth.TouchDue(sess, p.sessions.Now()) {
		if _, err := p.sessions.Touch(r.Context(), rawID); err != nil {
			p.logger.Warn("portal session touch failed", "session", shortHash(sess.IDHash), "error", err)
		}
	}
	return sess, rawID, true
}

// portalLoginMessages are the texts the stub page shows for a login_error;
// any other value is ignored, so the page never echoes the query.
var portalLoginMessages = map[string]string{
	webauth.CodeStateInvalid:   "The sign-in link expired or was used already. Please sign in again.",
	webauth.CodeNonceMismatch:  "The sign-in could not be verified. Please sign in again.",
	webauth.CodeTokenInvalid:   "The sign-in could not be verified. Please sign in again.",
	webauth.CodeExchangeFailed: "The identity provider did not complete the sign-in. Please try again.",
	webauth.CodeIDPError:       "The identity provider refused the sign-in.",
	webauth.CodeIDPUnavailable: "The identity provider is unavailable. Please try again later.",
	portal.CodeBlocked:         "Your account is blocked from the portal.",
	portal.CodeNotAllowed:      "Your account is not allowed to use the portal.",
}

var portalHomeTmpl = template.Must(template.New("portal").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Warden portal</title></head>
<body>
<h1>Warden portal</h1>
{{- if .Error}}
<p role="alert">{{.Error}}</p>
{{- end}}
{{- if .Email}}
<p>Signed in as <strong>{{.Email}}</strong>. Session ends {{.ExpiresAt}}.</p>
<form method="post" action="/portal/logout">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Sign out</button>
</form>
{{- else}}
<p><a href="/portal/login">Sign in</a></p>
{{- end}}
</body></html>
`))

// handleHome serves the minimal portal page: who is signed in and a sign-out
// form, or a sign-in link. W-P3-PORT-01 replaces it.
func (p *portalService) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	webauth.NoStore(w)
	data := struct{ Error, Email, ExpiresAt, CSRF string }{Error: portalLoginMessages[r.URL.Query().Get("login_error")]}
	if sess, rawID, ok := p.session(r); ok {
		data.Email = sess.Email
		if data.Email == "" {
			data.Email = sess.Sub
		}
		data.ExpiresAt = sess.ExpiresAt.UTC().Format(time.RFC3339)
		data.CSRF = webauth.CSRFToken([]byte(rawID), portal.CSRFLabel)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = portalHomeTmpl.Execute(w, data)
}

// recordPortalLogin records the outcome of one portal callback: portal.login
// for a success, portal.login_failed (rate-limited per address with its own
// limiter, separate from the console's) for a failure that consumed a portal
// state.
func (s *Server) recordPortalLogin(r *http.Request, res portalLoginResult) {
	a := s.audit
	in := adminaudit.Input{
		Actor: res.actor, AuthMethod: adminaudit.AuthMethodOIDC,
		Target: targetPortalSession, HTTPStatus: res.status,
		ClientIP: clientIP(r, a.trusted), RequestID: RequestIDFrom(r.Context()),
	}
	if res.reason == "" {
		in.Action, in.Outcome = actionPortalLogin, adminaudit.OutcomeOK
		in.TargetRef = shortHash(res.sessionHash)
	} else {
		if !a.portalLoginFailed.allow(in.ClientIP) {
			n := a.portalLoginFailedDropped.Add(1)
			if a.loginFailedLog.allow(in.ClientIP) {
				a.logger.Warn("admin_audit_portal_login_failed_rate_limited", "client_ip", in.ClientIP, "limit_per_minute", loginFailedPerMinute, "dropped", n)
			}
			return
		}
		in.Action, in.Outcome = actionPortalLoginFailed, portalLoginOutcome(res.reason)
		in.Details = map[string]string{detailReason: res.reason}
	}
	s.recordAuth(r.Context(), in)
}

const (
	actionPortalLogin       = "portal.login"
	actionPortalLoginFailed = "portal.login_failed"
	targetPortalSession     = "portal_session"
)

// portalLoginOutcome is denied for a refusal of the user or the token and
// error for an IdP, exchange or store failure.
func portalLoginOutcome(code string) string {
	switch code {
	case portal.CodeBlocked, portal.CodeNotAllowed, portal.CodeOfflineAccessNotGranted,
		loginStateInvalid, loginTokenInvalid, loginNonceMismatch:
		return adminaudit.OutcomeDenied
	}
	return adminaudit.OutcomeError
}
