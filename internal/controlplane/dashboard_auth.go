package controlplane

import (
	"net/http"

	"github.com/ethosagent/warden/internal/dashboard"
)

// dashboardWriteGuard gates every state-changing dashboard API call on the CP
// bearer token. Unlike the worker-facing routes (bearerOK passes when no token is
// configured, for development), it fails closed: with no token configured a write
// is refused outright. It is the dashboard package's shared bearer guard (also
// used by the worker admin listener), so the constant-time compare and the
// no-token-in-logs rule are defined once.
//
// A wwt_ worker token never passes, even when it equals the configured token.
func (s *Server) dashboardWriteGuard() dashboard.WriteGuard {
	inner := dashboard.NewBearerWriteGuard(dashboard.BearerGuardConfig{
		Token: s.cfg.Token, Logger: s.cfg.Logger,
		Component: "control plane", TokenName: "control-plane token",
		ConfigHint: "Start it with --token-env <ENV> (e.g. WARDEN_CP_TOKEN)",
	})
	return func(r *http.Request) (int, string) {
		if hasWorkerTokenBearer(r) {
			s.cfg.Logger.Warn("control plane dashboard write refused",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "reason", "worker token on a human route")
			return http.StatusUnauthorized, "unauthorized: worker tokens cannot change dashboard state"
		}
		return inner(r)
	}
}
