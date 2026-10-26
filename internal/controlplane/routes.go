package controlplane

import "net/http"

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
