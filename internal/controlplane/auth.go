package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
)

// Console login error codes. They are the whole vocabulary the browser ever
// sees (?login_error=<code>); IdP error text is never echoed.
const (
	loginStateInvalid   = "state_invalid"
	loginNonceMismatch  = "nonce_mismatch"
	loginTokenInvalid   = "token_invalid"
	loginExchangeFailed = "exchange_failed"
	loginIDPError       = "idp_error"
	loginNoRole         = "no_role"
	loginIDPUnavailable = "idp_unavailable"
	// loginBusy and loginInternal answer /auth/login itself (JSON, not a
	// redirect): the pending table is full, or storing the attempt failed.
	loginBusy     = "login_busy"
	loginInternal = "login_error"
)

const (
	loginCookieSecure = "__Host-warden_login"
	loginCookiePlain  = "warden_login"
	// dashboardHome is where a login lands without a usable next.
	dashboardHome = "/dashboard/"
	// maxNextBytes bounds the stored post-login path.
	maxNextBytes = 512

	discoveryBackoffMin = time.Second
	discoveryBackoffMax = 30 * time.Second
	discoveryTimeout    = 10 * time.Second
)

// authService is the console's OIDC login: /auth/login starts an
// authorization-code flow with S256 PKCE, /auth/callback finishes it and turns
// a verified ID token into a session. It stores no access, refresh or ID token.
type authService struct {
	cfg      config.ConsoleConfig
	oauth    oauth2.Config
	client   *http.Client
	verifier identity.Verifier
	pending  *pendingStore
	sessions *SessionStore
	cookie   SessionCookie
	logger   *slog.Logger

	loginCookieName string
	endpoints       atomic.Pointer[oidc.Endpoints]

	backoffMin, backoffMax time.Duration
}

// initAuth builds the login service when sessions are on. It does no network
// I/O: discovery runs from Start, so an unreachable IdP never delays startup.
func (s *Server) initAuth() {
	if s.sessions == nil {
		return
	}
	cc := s.cfg.Console
	// A client or verifier that cannot be built (a plain-http issuer without
	// internalIssuerURL, say) leaves the routes mounted but never ready: they
	// answer 503 idp_unavailable instead of silently vanishing.
	unavailable := func(err error) {
		s.cfg.Logger.Error("control plane: console login unavailable", "error", err)
		s.auth = &authService{logger: s.cfg.Logger}
	}
	client, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: cc.OIDC.Issuer, InternalIssuerURL: cc.OIDC.InternalIssuerURL})
	if err != nil {
		unavailable(err)
		return
	}
	verifier, err := oidc.NewIDTokenVerifier(oidc.IDTokenConfig{
		Issuer: cc.OIDC.Issuer, ClientID: cc.OIDC.ClientID,
		InternalIssuerURL: cc.OIDC.InternalIssuerURL, Now: s.cfg.Now,
	})
	if err != nil {
		unavailable(err)
		return
	}
	name := loginCookiePlain
	if s.sessionCookie.Secure {
		name = loginCookieSecure
	}
	s.auth = &authService{
		cfg: cc,
		oauth: oauth2.Config{
			ClientID: cc.OIDC.ClientID, ClientSecret: s.cfg.ClientSecret,
			RedirectURL: cc.OIDC.RedirectURL, Scopes: cc.OIDC.Scopes,
		},
		client:          client,
		verifier:        verifier,
		pending:         newPendingStore(s.cfg.State.SQL(), s.cfg.Now),
		sessions:        s.sessions,
		cookie:          s.sessionCookie,
		logger:          s.cfg.Logger,
		loginCookieName: name,
		backoffMin:      discoveryBackoffMin,
		backoffMax:      discoveryBackoffMax,
	}
}

// discover fetches the provider's endpoints, retrying with backoff until it
// succeeds or ctx is done. Until then both routes answer 503.
func (a *authService) discover(ctx context.Context) {
	if a.client == nil {
		return
	}
	wait := a.backoffMin
	for {
		dctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
		ep, err := oidc.Discover(dctx, a.client, a.cfg.OIDC.Issuer)
		cancel()
		if err == nil {
			a.endpoints.Store(&ep)
			a.logger.Info("control plane: console oidc discovery succeeded", "issuer", a.cfg.OIDC.Issuer)
			return
		}
		a.logger.Warn("control plane: console oidc discovery failed; login stays unavailable and will be retried",
			"issuer", a.cfg.OIDC.Issuer, "retry_in", wait.String(), "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, a.backoffMax)
	}
}

// sweep deletes expired pending logins every minute until ctx is done.
func (a *authService) sweep(ctx context.Context) {
	if a.pending == nil {
		return
	}
	t := time.NewTicker(pendingSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := a.pending.Sweep(ctx); err != nil {
			a.logger.Warn("control plane: pending login sweep failed", "error", err)
		}
	}
}

// ready returns the oauth config with the discovered endpoints, or false while
// discovery has not succeeded.
func (a *authService) ready() (oauth2.Config, bool) {
	ep := a.endpoints.Load()
	if ep == nil {
		return oauth2.Config{}, false
	}
	c := a.oauth
	c.Endpoint = oauth2.Endpoint{AuthURL: ep.AuthURL, TokenURL: ep.TokenURL, AuthStyle: oauth2.AuthStyleInHeader}
	return c, true
}

// handleLogin starts a login: it stores a pending row keyed by the state's
// hash, binds it to this browser with a cookie and redirects to the IdP.
func (a *authService) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	oc, ok := a.ready()
	if !ok {
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	state, nonce, browser := randomToken(32), randomToken(32), randomToken(32)
	verifier := oauth2.GenerateVerifier()
	err := a.pending.Put(r.Context(), pendingLogin{
		StateHash: sha256Hex(state), Nonce: nonce, Verifier: verifier,
		Next: sanitizeNext(r.URL.Query().Get("next")), BrowserHash: sha256Hex(browser),
	})
	if err != nil {
		code, status := loginInternal, http.StatusInternalServerError
		if errors.Is(err, errPendingFull) {
			code, status = loginBusy, http.StatusServiceUnavailable
		}
		a.logger.Warn("console_login", "result", "failed", "reason", code, "duration_ms", time.Since(start).Milliseconds())
		writeAuthError(w, status, code)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.loginCookieName, Value: browser, Path: "/", MaxAge: int(pendingTTL.Seconds()),
		Secure: a.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	noStore(w)
	http.Redirect(w, r, oc.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)), http.StatusFound)
}

// loginResult carries what the callback logs.
type loginResult struct {
	reason string
	sub    string
}

// handleCallback finishes a login. Every outcome redirects to the dashboard;
// a failure carries only a code from the fixed set above.
func (a *authService) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	oc, ok := a.ready()
	if !ok {
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	noStore(w)
	// The browser-binding cookie is single use whatever happens next.
	http.SetCookie(w, &http.Cookie{
		Name: a.loginCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: a.cookie.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	next, res := a.finishLogin(w, r, oc)
	a.logger.Info("console_login",
		"result", map[bool]string{true: "ok", false: "failed"}[res.reason == ""],
		"reason", res.reason, "sub", res.sub, "duration_ms", time.Since(start).Milliseconds())
	if res.reason != "" {
		http.Redirect(w, r, dashboardHome+"?login_error="+url.QueryEscape(res.reason), http.StatusFound)
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (a *authService) finishLogin(w http.ResponseWriter, r *http.Request, oc oauth2.Config) (string, loginResult) {
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		return "", loginResult{reason: loginStateInvalid}
	}
	p, found, err := a.pending.Take(ctx, sha256Hex(state))
	if err != nil {
		a.logger.Error("console login: pending lookup failed", "error", err)
		return "", loginResult{reason: loginStateInvalid}
	}
	if !found {
		return "", loginResult{reason: loginStateInvalid}
	}
	bc, err := r.Cookie(a.loginCookieName)
	if err != nil || bc.Value == "" ||
		subtle.ConstantTimeCompare([]byte(sha256Hex(bc.Value)), []byte(p.BrowserHash)) != 1 {
		return "", loginResult{reason: loginStateInvalid}
	}
	if q.Get("error") != "" {
		return "", loginResult{reason: loginIDPError}
	}
	code := q.Get("code")
	if code == "" {
		return "", loginResult{reason: loginExchangeFailed}
	}
	ectx := oidc.WithHTTPClient(ctx, a.client)
	tok, err := oc.Exchange(ectx, code, oauth2.VerifierOption(p.Verifier))
	if err != nil {
		return "", loginResult{reason: loginExchangeFailed}
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", loginResult{reason: loginTokenInvalid}
	}
	claims, status, reason := a.verifier.Verify(ectx, raw, identity.WithNonce(p.Nonce))
	switch {
	case status == identity.StatusUnverified:
		return "", loginResult{reason: loginIDPUnavailable}
	case status != identity.StatusValid && reason == identity.ReasonWrongNonce:
		return "", loginResult{reason: loginNonceMismatch, sub: claims.Sub}
	case status != identity.StatusValid || claims.Sub == "":
		return "", loginResult{reason: loginTokenInvalid, sub: claims.Sub}
	}
	if _, ok := a.cfg.RoleFor(claims.Groups); !ok {
		return "", loginResult{reason: loginNoRole, sub: claims.Sub}
	}
	rawID, _, err := a.sessions.Create(ctx, SessionInput{
		Iss: claims.Issuer, Sub: claims.Sub, Email: claims.Email,
		Groups: claims.Groups, AuthMethod: "oidc",
	})
	if err != nil {
		a.logger.Error("console login: session create failed", "error", err)
		return "", loginResult{reason: loginExchangeFailed, sub: claims.Sub}
	}
	// A session cookie the request carried is never reused: its row is dropped
	// and the new id is minted server-side.
	if old, ok := a.cookie.From(r); ok {
		if err := a.sessions.Delete(ctx, old); err != nil {
			a.logger.Warn("console login: old session delete failed", "error", err)
		}
	}
	http.SetCookie(w, a.cookie.New(rawID, a.sessions.absolute))
	return p.Next, loginResult{sub: claims.Sub}
}

// sanitizeNext keeps a post-login path only when it is a plain absolute path
// under /dashboard/: no scheme or host, no "//", no backslash, no dot segment,
// no control character. Anything else becomes /dashboard/.
func sanitizeNext(raw string) string {
	if raw == "" || len(raw) > maxNextBytes || !strings.HasPrefix(raw, dashboardHome) ||
		strings.ContainsAny(raw, "\\\r\n\t") || strings.Contains(raw, "//") {
		return dashboardHome
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, dashboardHome) {
		return dashboardHome
	}
	// The decoded path must pass the same separator rules as the raw string.
	if strings.Contains(u.Path, "//") || strings.ContainsAny(u.Path, "\\\r\n\t") {
		return dashboardHome
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == ".." || seg == "." {
			return dashboardHome
		}
	}
	return raw
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("control plane: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func writeAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}` + "\n"))
}
