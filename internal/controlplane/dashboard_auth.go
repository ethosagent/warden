package controlplane

import "net/http"

// dashboardWriteGuard gates every state-changing dashboard API call on the CP
// bearer token. Unlike the worker-facing routes (bearerOK passes when no token is
// configured, for development), it fails closed: with no token configured a write
// is refused outright. The comparison is bearerOK's constant-time one. A refusal
// is logged with the route and remote address only, never the presented header.
func (s *Server) dashboardWriteGuard(r *http.Request) (int, string) {
	if s.cfg.Token == "" {
		s.logRefusedWrite(r, "no control-plane token configured")
		return http.StatusForbidden, "dashboard writes are disabled: the control plane has no bearer token configured. " +
			"Start it with --token-env <ENV> (e.g. WARDEN_CP_TOKEN) and send 'Authorization: Bearer <token>'"
	}
	if !s.bearerOK(r) {
		s.logRefusedWrite(r, "missing or invalid bearer token")
		return http.StatusUnauthorized, "unauthorized: dashboard writes need 'Authorization: Bearer <control-plane token>'"
	}
	return 0, ""
}

func (s *Server) logRefusedWrite(r *http.Request, reason string) {
	s.cfg.Logger.Warn("control plane dashboard write refused",
		"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "reason", reason)
}
