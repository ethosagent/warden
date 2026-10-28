package controlplane

import (
	"crypto/subtle"
	"net/http"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// dashboardWriteToken is the one source of truth for the CP admin bearer in
// console.auth none: the dashboard write guard and the /central/secrets gate
// both read it. It is AdminToken (--admin-token-env) when set. Otherwise it is
// the shared worker token, as a back-compat fallback (warnAdminToken logs it
// once at startup), unless --admin-token-env was given: then an empty
// AdminToken stays empty and writes are refused rather than reopened to the
// worker token.
func (s *Server) dashboardWriteToken() string {
	if s.cfg.AdminToken != "" || s.cfg.RequireAdminToken {
		return s.cfg.AdminToken
	}
	return s.cfg.Token
}

// dashboardWriteGuard gates every state-changing dashboard API call on the CP
// admin bearer (dashboardWriteToken). Unlike the worker-facing routes (open
// mode passes when no token is configured, for development), it fails closed: with
// no token configured a write is refused outright. It is the dashboard
// package's shared bearer guard (also used by the worker admin listener), so
// the constant-time compare and the no-token-in-logs rule are defined once.
//
// A wwt_ worker token never passes, even when it equals the configured token.
func (s *Server) dashboardWriteGuard() dashboard.WriteGuard {
	inner := dashboard.NewBearerWriteGuard(dashboard.BearerGuardConfig{
		Token: s.dashboardWriteToken(), Logger: s.cfg.Logger,
		Component: "control plane", TokenName: "control-plane admin token",
		ConfigHint: "Start it with --admin-token-env <ENV> (e.g. WARDEN_CP_ADMIN_TOKEN)",
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

// adminBearerOK reports whether the request presents the CP admin bearer
// (dashboardWriteToken), compared in constant time. It gates the human
// /central/secrets routes in console.auth none; WorkerAuthenticator gates the
// worker routes. With no token of either kind it passes (development only,
// matching open mode), but an explicit --admin-token-env naming an empty
// variable fails closed.
func (s *Server) adminBearerOK(r *http.Request) bool {
	// A worker token never opens a human route, whatever the configured token.
	if hasWorkerTokenBearer(r) {
		return false
	}
	token := s.dashboardWriteToken()
	if token == "" {
		return !s.cfg.RequireAdminToken
	}
	want := "Bearer " + token
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) == 1
}

// warnAdminToken logs the startup warnings about the admin bearer, once, from
// New. Only console.auth none uses it: in oidc mode sessions replace it. No
// token value is ever logged.
func (s *Server) warnAdminToken() {
	if s.cfg.Console.Auth == config.ConsoleAuthOIDC {
		return
	}
	switch {
	case s.cfg.AdminToken == "" && !s.cfg.RequireAdminToken && s.cfg.Token != "":
		s.cfg.Logger.Warn("control-plane: dashboard writes use the shared worker token; set --admin-token-env",
			"hint", "give the control plane its own admin bearer (e.g. WARDEN_CP_ADMIN_TOKEN) so retiring the shared worker token never disables dashboard writes")
	case s.cfg.AdminToken != "" &&
		subtle.ConstantTimeCompare([]byte(s.cfg.AdminToken), []byte(s.cfg.Token)) == 1:
		s.cfg.Logger.Warn("control-plane: the admin token equals the shared worker token; they should differ",
			"hint", "the admin token separates dashboard writes from worker credentials; set --admin-token-env to a different value")
	}
}

// failClosedWithoutAdminToken handles strict mode with no CP admin token in
// console.auth none (oidc sessions need none): there is nothing left to
// authenticate a human write, so the dashboard write guard already refuses
// every write (dashboardWriteToken is empty and the guard fails closed), and
// here the secret-write API is unmounted too, so it never falls back to open.
// It logs one ERROR naming the flag.
func (s *Server) failClosedWithoutAdminToken() {
	if !s.cfg.RequireWorkerTokens || s.cfg.Console.Auth == config.ConsoleAuthOIDC || s.dashboardWriteToken() != "" {
		return
	}
	s.cfg.Logger.Error("control-plane: dashboard writes are disabled: set --admin-token-env",
		"hint", "strict worker auth (--require-worker-tokens) retires the shared token; give the control plane its own admin bearer (e.g. WARDEN_CP_ADMIN_TOKEN). /central/secrets is not mounted until then")
	s.secretStore = nil
	s.cfg.SecretStoreBackend = ""
}
