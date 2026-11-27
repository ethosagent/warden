package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/webauth"
)

// Console login error codes. They are the whole vocabulary the browser ever
// sees (?login_error=<code>); IdP error text is never echoed.
const (
	loginStateInvalid   = webauth.CodeStateInvalid
	loginNonceMismatch  = webauth.CodeNonceMismatch
	loginTokenInvalid   = webauth.CodeTokenInvalid
	loginExchangeFailed = webauth.CodeExchangeFailed
	loginIDPError       = webauth.CodeIDPError
	loginNoRole         = "no_role"
	loginIDPUnavailable = webauth.CodeIDPUnavailable
	// loginBusy and loginInternal answer /auth/login itself (JSON, not a
	// redirect): the pending table is full, or storing the attempt failed.
	loginBusy     = "login_busy"
	loginInternal = "login_error"
)

const (
	// loginCookieBase is the console's login-binding cookie:
	// __Host-warden_login on https, warden_login on a loopback http
	// redirectURL.
	loginCookieBase = "warden_login"
	// dashboardHome is where a login lands without a usable next.
	dashboardHome = "/dashboard/"
)

// authService is the console's OIDC login: /auth/login starts an
// authorization-code flow with S256 PKCE, /auth/callback finishes it and turns
// a verified ID token into a session. It stores no access, refresh or ID token.
// The flow itself is webauth.Flow with purpose "console"; this type adds the
// console's admission (block list, role) and its session.
type authService struct {
	cfg      config.ConsoleConfig
	provider *webauth.Provider
	flow     *webauth.Flow
	pending  *webauth.PendingStore
	sessions *SessionStore
	// blocks is the user block list; nil means none is kept.
	blocks *BlockStore
	cookie SessionCookie
	logger *slog.Logger

	loginCookieName string

	// audit records a callback's outcome in the admin audit log
	// (Server.recordLogin); nil when admin audit is disabled.
	audit func(*http.Request, loginResult)
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
	provider := webauth.NewProvider(webauth.ProviderConfig{
		Name: "console", Issuer: cc.OIDC.Issuer,
		OAuth: oauth2.Config{
			ClientID: cc.OIDC.ClientID, ClientSecret: s.cfg.ClientSecret,
			RedirectURL: cc.OIDC.RedirectURL, Scopes: cc.OIDC.Scopes,
		},
		Discover: func(ctx context.Context) (webauth.Endpoints, error) {
			ep, err := oidc.Discover(ctx, client, cc.OIDC.Issuer)
			return webauth.Endpoints{AuthURL: ep.AuthURL, TokenURL: ep.TokenURL}, err
		},
		HTTPContext: func(ctx context.Context) context.Context { return oidc.WithHTTPClient(ctx, client) },
		Logger:      s.cfg.Logger,
	})
	pending := webauth.NewPendingStore(s.cfg.State.SQL(), s.cfg.Now)
	loginCookie := s.sessionCookie.Named(loginCookieBase)
	s.auth = &authService{
		cfg:      cc,
		provider: provider,
		flow: &webauth.Flow{
			Name: "console", Provider: provider, Verifier: verifier, Pending: pending,
			Purpose: webauth.PurposeConsole, LoginCookie: loginCookie,
			AllowNext:   func(next string) bool { return webauth.SafeNext(next, dashboardHome) },
			DefaultNext: dashboardHome, Logger: s.cfg.Logger,
		},
		pending:         pending,
		sessions:        s.sessions,
		blocks:          s.blocks,
		cookie:          s.sessionCookie,
		logger:          s.cfg.Logger,
		loginCookieName: loginCookie.Name,
	}
}

// discover fetches the provider's endpoints, retrying with backoff until it
// succeeds or ctx is done. Until then both routes answer 503.
func (a *authService) discover(ctx context.Context) { a.provider.Run(ctx) }

// sweep deletes expired pending logins every minute until ctx is done.
func (a *authService) sweep(ctx context.Context) { a.pending.RunSweeper(ctx, a.logger) }

// ready reports whether discovery has succeeded.
func (a *authService) ready() bool { return a.flow.Ready() }

// handleLogin starts a login: it stores a pending row keyed by the state's
// hash, binds it to this browser with a cookie and redirects to the IdP.
func (a *authService) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	if !a.ready() {
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	if a.blocks != nil && !a.blocks.Ready() {
		writeAuthError(w, http.StatusServiceUnavailable, loginBlockUnavailable)
		return
	}
	err := a.flow.Begin(w, r, r.URL.Query().Get("next"))
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
	a.logger.Warn("console_login", "result", "failed", "reason", code, "duration_ms", time.Since(start).Milliseconds())
	writeAuthError(w, status, code)
}

// loginResult carries what the callback logs and records.
type loginResult struct {
	reason string
	// sub is the token's subject for the log line, verified or not.
	sub string
	// consumed is true once a pending state was taken: only then is a failure
	// recorded in the admin audit log.
	consumed bool
	// actor and role come only from a verified ID token; sessionHash is the
	// new session's id hash (never the raw id).
	actor       adminaudit.Actor
	role        string
	sessionHash string
}

// handleCallback finishes a login. Every outcome redirects to the dashboard;
// a failure carries only a code from the fixed set above.
func (a *authService) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	if !a.ready() {
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	login, err := a.flow.Complete(w, r)
	if errors.Is(err, webauth.ErrUnavailable) {
		writeAuthError(w, http.StatusServiceUnavailable, loginIDPUnavailable)
		return
	}
	next, res := a.finishLogin(w, r, login, err)
	a.logger.Info("console_login",
		"result", map[bool]string{true: "ok", false: "failed"}[res.reason == ""],
		"reason", res.reason, "sub", res.sub, "duration_ms", time.Since(start).Milliseconds())
	if a.audit != nil && (res.reason == "" || res.consumed) {
		a.audit(r, res)
	}
	switch res.reason {
	case loginUserBlocked:
		writeAuthError(w, http.StatusForbidden, loginUserBlocked)
		return
	case loginBlockUnavailable:
		writeAuthError(w, http.StatusServiceUnavailable, loginBlockUnavailable)
		return
	}
	if res.reason != "" {
		http.Redirect(w, r, dashboardHome+"?login_error="+url.QueryEscape(res.reason), http.StatusFound)
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// finishLogin turns the flow's outcome into the console's: a failed flow keeps
// its code; a verified login is admitted (block list, role) and gets a session.
func (a *authService) finishLogin(w http.ResponseWriter, r *http.Request, login webauth.Login, err error) (string, loginResult) {
	if err != nil {
		var fe *webauth.Error
		if errors.As(err, &fe) {
			return "", loginResult{reason: fe.Code, consumed: fe.Consumed, sub: fe.Sub}
		}
		return "", loginResult{reason: loginStateInvalid}
	}
	ctx := r.Context()
	claims := login.Claims
	// From here the token is verified, so the attempt has a known actor.
	actor := adminaudit.Actor{Sub: claims.Sub, Email: claims.Email}
	// A blocked principal gets no session, whatever their role. Without a
	// loaded block list the console cannot tell, so it refuses too.
	if a.blocks != nil {
		if !a.blocks.Ready() {
			return "", loginResult{consumed: true, reason: loginBlockUnavailable, sub: claims.Sub, actor: actor}
		}
		if a.blocks.IsBlocked(claims.Sub, claims.Email) {
			return "", loginResult{consumed: true, reason: loginUserBlocked, sub: claims.Sub, actor: actor}
		}
	}
	role, ok := a.cfg.RoleFor(claims.Groups)
	if !ok {
		return "", loginResult{consumed: true, reason: loginNoRole, sub: claims.Sub, actor: actor}
	}
	rawID, _, err := a.sessions.Create(ctx, SessionInput{
		Iss: claims.Issuer, Sub: claims.Sub, Email: claims.Email,
		Groups: claims.Groups, AuthMethod: "oidc",
	})
	if err != nil {
		a.logger.Error("console login: session create failed", "error", err)
		return "", loginResult{consumed: true, reason: loginExchangeFailed, sub: claims.Sub, actor: actor, role: role.String()}
	}
	// A session cookie the request carried is never reused: its row is dropped
	// and the new id is minted server-side.
	if old, ok := a.cookie.From(r); ok {
		if err := a.sessions.Delete(ctx, old); err != nil {
			a.logger.Warn("console login: old session delete failed", "error", err)
		}
	}
	http.SetCookie(w, a.cookie.New(rawID, a.sessions.Absolute()))
	return login.Next, loginResult{consumed: true, sub: claims.Sub, actor: actor, role: role.String(), sessionHash: hashID(rawID)}
}

func writeAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}` + "\n"))
}
