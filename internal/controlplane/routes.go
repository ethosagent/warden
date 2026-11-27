package controlplane

import (
	"net/http"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// mountDashboard mounts the dashboard on the control-plane mux.
//
// In console.auth none the dashboard keeps its existing gate: reads are open and
// every write needs the CP bearer (dashboardWriteGuard, fail-closed).
//
// In oidc mode sessions replace the bearer: withSession authenticates, then
// requireRole applies the authz table, and the write guard accepts only a
// session Principal. Inside requireRole, query/generate is rate-limited per
// session (limitQueryGenerate) and the settings writer authorizes each changed
// field (writeSettingsAs). If oidc is configured but sessions could not start (no
// state db, bad redirect URL) there is no Principal source, so every dashboard
// request is refused rather than falling back to the bearer.
//
// The control plane also serves cpDashboardRoutes itself, on exact paths that
// win over the "/dashboard/" prefix. They sit outside dash.Handler, so its write
// guard never runs for them: each is wrapped in withSession (session, CSRF on
// DELETE) and requireRole (admin) here. In none mode they are mounted as 404,
// because the dashboard would otherwise serve its index page for the path.
func (s *Server) mountDashboard(mux *http.ServeMux, dash *dashboard.Server) {
	table := authzTable()
	// With admin audit on, every mount below runs behind the request-id and
	// audit middleware (sessionAuditWrap), outside the write guard and authz,
	// so their refusals are recorded; with it off the wrapping is the identity.
	classify := dashboardRoute(table)
	if s.cfg.Console.Auth != config.ConsoleAuthOIDC {
		dash.SetWriteGuard(s.dashboardWriteGuard())
		mux.Handle("/dashboard/", s.sessionAuditWrap(classify, dash.Handler()))
		mux.Handle(sessionsAdminPath, http.NotFoundHandler())
		s.mountTokenSessions(mux, classify, false)
		mux.Handle(apiKeysPath, http.NotFoundHandler())
		mux.Handle(apiKeysSubtree, http.NotFoundHandler())
		return
	}
	dash.SetWriteGuard(s.sessionWriteGuard())
	guarded := requireRoleKeys(s.limitQueryGenerate(dash.Handler()), table, s.cfg.Console, s.cfg.Logger, s.apiKeyCounts, s.keyOwnerBlocked)
	// With API keys on, apiKeyWrap is outermost: a key request is decided before
	// the session, audit and authz layers see it (apikey_auth.go).
	mux.Handle("/dashboard/", s.apiKeyWrap(s.sessionAuditWrap(classify, guarded)))
	// GET lists, DELETE revokes (?handle= or ?sub=); admin only. A revoke is an
	// audited admin change.
	// TODO(#39): a per-session rate limit arrives with the shared console limiter.
	mux.Handle(sessionsAdminPath, s.apiKeyWrap(s.sessionAuditWrap(classify, requireRoleKeys(http.HandlerFunc(s.handleSessions), table, s.cfg.Console, s.cfg.Logger, s.apiKeyCounts, s.keyOwnerBlocked))))
	s.mountTokenSessions(mux, classify, true)
	s.mountAPIKeys(mux, classify, table)
}

// sessionsAdminPath is the admin session list and revoke route (W-P1-SSO-08).
const sessionsAdminPath = "/dashboard/api/sessions"

// cpDashboardRoutes lists the /dashboard/ routes the control plane serves
// itself rather than through dash.Handler, in dashboard.Routes' form, so the
// authz coverage test walks them too.
func cpDashboardRoutes() []dashboard.Route {
	return []dashboard.Route{
		{Method: http.MethodGet, Path: sessionsAdminPath, Action: "sessions.read"},
		{Method: http.MethodDelete, Path: sessionsAdminPath, Action: "sessions.revoke"},
		{Method: http.MethodGet, Path: tokenSessionsListPath, Action: "token_sessions.read"},
		{Method: http.MethodPost, Path: tokenSessionsRevokeAllPath, Action: "token_sessions.revoke_all"},
		{Method: http.MethodPost, Path: tokenSessionRevokePath, Action: "token_sessions.revoke"},
		{Method: http.MethodGet, Path: apiKeysPath, Action: "api_key.list"},
		{Method: http.MethodPost, Path: apiKeysPath, Action: "api_key.create"},
		{Method: http.MethodDelete, Path: apiKeysPath, Action: "api_key.revoke_owner"},
		{Method: http.MethodDelete, Path: apiKeysPath + "/{id}", Action: "api_key.revoke"},
		{Method: http.MethodGet, Path: apiKeysPath + "/self", Action: "api_key.self"},
	}
}

// registerAuthRoutes mounts the console auth routes (rule X9: registrations
// live here). They exist only in console.auth oidc; in none mode they are
// absent (404), which is how the dashboard knows to use the bearer prompt.
//
//	GET  /auth/me       any live session (role: viewer and up, or none)
//	POST /auth/logout   any live session, CSRF-checked by withSession
//	GET  /auth/login    no session (it is how one is obtained)
//	GET  /auth/callback no session; guards itself (state, browser cookie, PKCE, nonce)
//	POST /auth/breakglass no session, no CSRF; only with console.breakGlass.enabled
//	                     (W-P1-OPS1-08); guards itself with a rate limit and argon2id
//
// The login routes also need a state DB (s.auth is nil otherwise), so without
// one they stay 404 as well.
//
// With admin audit on, the callback and logout get a request id and record
// their own rows (W-P1-AAUD-07); off, they are mounted exactly as before.
//
// TODO(#39): a per-session rate limit arrives with the shared console limiter.
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	if s.cfg.Console.Auth != config.ConsoleAuthOIDC {
		return
	}
	mux.Handle("/auth/me", s.apiKeyWrap(s.sessionWrap(http.HandlerFunc(s.handleAuthMe))))
	mux.Handle("/auth/logout", s.requestIDWrap(s.sessionWrap(http.HandlerFunc(s.handleLogout))))
	if s.breakGlass != nil {
		mux.Handle(breakGlassPath, s.requestIDWrap(http.HandlerFunc(s.handleBreakGlass)))
	}
	if s.auth == nil {
		return
	}
	mux.HandleFunc("/auth/login", s.auth.handleLogin)
	mux.Handle("/auth/callback", s.requestIDWrap(http.HandlerFunc(s.auth.handleCallback)))
}

// registerPortalRoutes mounts the consent portal's sign-in (W-P3-CSIG-02,
// rule X9). They exist only when the consent block is enabled and a state DB
// is open (s.portal is nil otherwise), so every /portal path is 404 without
// one. None of them reads a console cookie, the sessions table, a bearer or an
// API key.
//
//	GET /portal/login    no session (it is how one is obtained)
//	GET /portal/callback no session; guards itself (state, purpose, browser cookie, PKCE, nonce)
//	GET /portal          the minimal portal page; reads only the portal cookie
//	GET /portal/api/me   requireSession (W-P3-CSIG-04)
//	POST /portal/logout  requireSession, CSRF-checked
//	/portal/             every other path: requireSession, then 404, so a
//	                     signed-out browser is sent to sign in first and a
//	                     later route (W-P3-PORT-*) slots in behind the same gate
//
// With admin audit on, the callback and logout get a request id and record
// their own portal.login / portal.login_failed / portal.logout row.
func (s *Server) registerPortalRoutes(mux *http.ServeMux) {
	if s.portal == nil {
		return
	}
	mux.HandleFunc(portalLoginPath, s.portal.handleLogin)
	mux.Handle(portalCallbackPath, s.requestIDWrap(http.HandlerFunc(s.portal.handleCallback)))
	mux.HandleFunc(portalHomePath, s.portal.handleHome)
	mux.Handle(portalMePath, s.portalWrap(http.HandlerFunc(s.portal.handleMe)))
	mux.Handle(portalLogoutPath, s.requestIDWrap(s.portalWrap(http.HandlerFunc(s.portal.handleLogout))))
	mux.Handle(portalSubtree, s.portalWrap(http.NotFoundHandler()))
}

// registerConnectRoutes mounts the OAuth broker's connect routes (W-P3-BRKR-03)
// only when the broker is enabled (initBroker); otherwise /connect/* is 404.
//
//	GET  /connect/start  portal session; changes nothing, 303 to the landing page
//	POST /connect/start  portal session + CSRF/Origin; starts a PKCE flow, 303
//
// Both go through connectWrap: no portal session is 303 to /portal/login, and
// no console credential (cookie, bearer, worker token, wak_ key) reaches it.
func (s *Server) registerConnectRoutes(mux *http.ServeMux) {
	if s.broker == nil || s.brokerHTTP == nil {
		return
	}
	mux.Handle(connectStartPath, s.connectWrap(s.brokerHTTP.Start()))
}

// connectStartPath is the connect route's mux pattern, a literal so the
// route-coverage walk can read it; TestConnectRoutePaths pins it to the
// transport package's constant.
const connectStartPath = "/connect/start"

// The portal's mux patterns, as literals so the route-coverage walk can read
// them; TestPortalRoutePaths pins them to the portal package's constants.
const (
	portalLoginPath    = "/portal/login"
	portalCallbackPath = "/portal/callback"
	portalHomePath     = "/portal"
	portalMePath       = "/portal/api/me"
	portalLogoutPath   = "/portal/logout"
	portalSubtree      = "/portal/"
)

// authMode is the console sign-in mode the dashboard reports as authMode:
// "oidc" when console.auth is oidc, otherwise "none" (an absent console block
// is none).
func (s *Server) authMode() string {
	if s.cfg.Console.Auth == config.ConsoleAuthOIDC {
		return config.ConsoleAuthOIDC
	}
	return config.ConsoleAuthNone
}
