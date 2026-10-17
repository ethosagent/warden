package dashboard

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
)

// BearerGuardConfig describes the bearer-token write guard a host (the control
// plane, a worker's admin listener) installs with SetWriteGuard. The wording
// fields keep each host's refusal text and log line specific to it.
type BearerGuardConfig struct {
	Token  string // the expected bearer token; blank (after trimming) = not configured
	Logger *slog.Logger
	// Component names the host in the log line ("control plane", "worker").
	Component string
	// TokenName names the token in messages ("control-plane token").
	TokenName string
	// ConfigHint tells an operator how to configure the token; it appears in the
	// 403 body, e.g. "Start it with --token-env <ENV>".
	ConfigHint string
}

// NewBearerWriteGuard returns the WriteGuard shared by the control plane and the
// worker admin listener. It fails closed: with no token configured every write is
// refused (403) and the body says how to configure one; with a token, a missing or
// wrong 'Authorization: Bearer' header is refused (401). The comparison is
// constant-time. A refusal is logged with the method, path and remote address
// only, never the presented header.
func NewBearerWriteGuard(c BearerGuardConfig) WriteGuard {
	token := strings.TrimSpace(c.Token)
	lg := c.Logger
	if lg == nil {
		lg = slog.Default()
	}
	refuse := func(r *http.Request, reason string) {
		lg.Warn(c.Component+" dashboard write refused",
			"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "reason", reason)
	}
	return func(r *http.Request) (int, string) {
		if token == "" {
			refuse(r, "no "+c.TokenName+" configured")
			return http.StatusForbidden, "dashboard writes are disabled: the " + c.Component + " has no bearer token configured. " +
				c.ConfigHint + " and send 'Authorization: Bearer <token>'"
		}
		want := "Bearer " + token
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			refuse(r, "missing or invalid bearer token")
			return http.StatusUnauthorized, "unauthorized: dashboard writes need 'Authorization: Bearer <" + c.TokenName + ">'"
		}
		return 0, ""
	}
}
