package controlplane

import (
	"context"

	"github.com/ethosagent/warden/internal/config"
)

// Principal kinds. Kind says how the caller authenticated, so later auth
// methods (break-glass, API keys) reuse the same type and context key.
const (
	PrincipalSession    = "session"
	PrincipalBreakglass = "breakglass"
	PrincipalAPIKey     = "apikey"
)

// Principal is the authenticated caller of a console request. withSession puts
// one in the request context when the request carries a live session; nothing
// in this package denies a request for lacking one yet (role enforcement is
// W-P1-SSO-05).
type Principal struct {
	Kind       string
	Iss, Sub   string
	Email      string
	Groups     []string
	AuthMethod string
	// SessionHash is sha256 of the session id for a session Principal (never the
	// raw id). It keys per-session state such as the query/generate rate limit.
	SessionHash string
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the Principal in ctx and whether there is one.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// principalRole is the console role of p. A break-glass Principal is always
// admin: it carries no IdP groups, so console.roles cannot name it, and the
// session exists only after the configured credential verified. Every other
// Principal gets the role its groups map to (zero when none does).
func principalRole(c config.ConsoleConfig, p Principal) config.Role {
	if p.Kind == PrincipalBreakglass {
		return config.RoleAdmin
	}
	role, _ := c.RoleFor(p.Groups)
	return role
}

// sessionRole is principalRole for a stored session.
func sessionRole(c config.ConsoleConfig, s Session) config.Role {
	if s.AuthMethod == AuthMethodBreakglass {
		return config.RoleAdmin
	}
	role, _ := c.RoleFor(s.Groups)
	return role
}
