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
func (s *Server) mountDashboard(mux *http.ServeMux, dash *dashboard.Server) {
	if s.cfg.Console.Auth != config.ConsoleAuthOIDC {
		dash.SetWriteGuard(s.dashboardWriteGuard())
		mux.Handle("/dashboard/", s.sessionWrap(dash.Handler()))
		return
	}
	dash.SetWriteGuard(s.sessionWriteGuard())
	guarded := requireRole(s.limitQueryGenerate(dash.Handler()), authzTable(), s.cfg.Console, s.cfg.Logger)
	mux.Handle("/dashboard/", s.sessionWrap(guarded))
}

// registerAuthRoutes mounts the browser session routes (rule X9: registrations
// live here). They exist only in console.auth oidc; in none mode they are
// absent (404), which is how the dashboard knows to use the bearer prompt.
//
//	GET  /auth/me      any live session (role: viewer and up, or none)
//	POST /auth/logout  any live session, CSRF-checked by withSession
//
// TODO(#39, #38): audit record for logout once the admin audit chain lands;
// a per-session rate limit arrives with the shared console limiter.
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	if s.cfg.Console.Auth != config.ConsoleAuthOIDC {
		return
	}
	mux.Handle("/auth/me", s.sessionWrap(http.HandlerFunc(s.handleAuthMe)))
	mux.Handle("/auth/logout", s.sessionWrap(http.HandlerFunc(s.handleLogout)))
}
