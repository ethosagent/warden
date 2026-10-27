package controlplane

import (
	"net/http"

	"github.com/ethosagent/warden/internal/config"
)

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
