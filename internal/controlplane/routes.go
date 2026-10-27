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
// session Principal. If oidc is configured but sessions could not start (no
// state db, bad redirect URL) there is no Principal source, so every dashboard
// request is refused rather than falling back to the bearer.
func (s *Server) mountDashboard(mux *http.ServeMux, dash *dashboard.Server) {
	if s.cfg.Console.Auth != config.ConsoleAuthOIDC {
		dash.SetWriteGuard(s.dashboardWriteGuard())
		mux.Handle("/dashboard/", s.sessionWrap(dash.Handler()))
		return
	}
	dash.SetWriteGuard(s.sessionWriteGuard())
	guarded := requireRole(dash.Handler(), authzTable(), s.cfg.Console, s.cfg.Logger)
	mux.Handle("/dashboard/", s.sessionWrap(guarded))
}

// registerAuthRoutes mounts the console login routes. They exist only in oidc
// mode with a state DB (s.auth is nil otherwise), so in none mode both paths
// are 404 exactly as before. Neither route takes a session: they are how one is
// obtained, and each guards itself (state, browser cookie, PKCE, nonce).
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	if s.auth == nil {
		return
	}
	mux.HandleFunc("/auth/login", s.auth.handleLogin)
	mux.HandleFunc("/auth/callback", s.auth.handleCallback)
}
