package controlplane

import "context"

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
