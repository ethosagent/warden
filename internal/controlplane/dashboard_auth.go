package controlplane

import "github.com/ethosagent/warden/internal/dashboard"

// dashboardWriteGuard gates every state-changing dashboard API call on the CP
// bearer token. Unlike the worker-facing routes (bearerOK passes when no token is
// configured, for development), it fails closed: with no token configured a write
// is refused outright. It is the dashboard package's shared bearer guard (also
// used by the worker admin listener), so the constant-time compare and the
// no-token-in-logs rule are defined once.
func (s *Server) dashboardWriteGuard() dashboard.WriteGuard {
	return dashboard.NewBearerWriteGuard(dashboard.BearerGuardConfig{
		Token: s.cfg.Token, Logger: s.cfg.Logger,
		Component: "control plane", TokenName: "control-plane token",
		ConfigHint: "Start it with --token-env <ENV> (e.g. WARDEN_CP_TOKEN)",
	})
}
