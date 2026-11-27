// Package portal is the domain of the consent portal (P3 consent sign-in):
// the signed-in employee (Principal) and its own context key, the ports the
// portal's sign-in depends on (Blocklist, LinkWriter), the admission rule a
// verified login must pass before it gets a portal session, and the
// post-login path rule.
//
// It does no I/O. The HTTP handlers, the session store (portal_sessions on
// cpstate) and the OIDC flow live in internal/controlplane (portal_*.go),
// which builds them on internal/webauth and injects the ports. A portal
// Principal is a separate type in a separate context key from the console's,
// so no console authorization check can ever see one.
package portal

import (
	"context"
	"log/slog"
	"slices"
)

// Browser paths of the portal.
const (
	// Home is the portal page and where a login without a usable next lands.
	Home = "/portal"
	// LoginPath starts a portal sign-in.
	LoginPath = "/portal/login"
	// CallbackPath is the IdP's redirect target (consent.oidc.redirectURL's
	// path, config.ConsentCallbackPath).
	CallbackPath = "/portal/callback"
)

// Cookie base names. On an https redirectURL each gets the "__Host-" prefix
// (Secure, Path=/, no Domain); the bare names are used only for an http
// redirectURL on a loopback host.
const (
	// SessionCookieBase is the portal session cookie: __Host-warden_portal.
	SessionCookieBase = "warden_portal"
	// LoginCookieBase binds a started login to its browser:
	// __Host-warden_portal_login, distinct from the console's
	// __Host-warden_login so a console state never completes here.
	LoginCookieBase = "warden_portal_login"
)

// CSRFLabel is the HMAC label of a portal session's CSRF token. It differs
// from the console's ("warden-csrf"), so a console token never validates on
// the portal and the reverse.
const CSRFLabel = "warden-portal-csrf"

// MaxGroups caps the groups a portal session keeps.
const MaxGroups = 256

// Portal login error codes, beyond the shared flow codes (state_invalid,
// nonce_mismatch, token_invalid, exchange_failed, idp_error,
// idp_unavailable). They are the whole vocabulary the browser sees as
// /portal?login_error=<code>; IdP error text is never echoed.
const (
	// CodeBlocked: the principal's sub or email is on the block list.
	CodeBlocked = "blocked"
	// CodeNotAllowed: consent.allowedGroups is set and no group matches.
	CodeNotAllowed = "not_allowed"
	// CodeOfflineAccessNotGranted: the IdP link is enabled and the token
	// response carried no refresh token. Answered 502, not redirected.
	CodeOfflineAccessNotGranted = "offline_access_not_granted"
)

// nextPrefixes are the path trees a login may return to.
var nextPrefixes = []string{"/portal/", "/connect/"}

// NextPrefixes returns the path prefixes a post-login next may start with
// (/portal/ and /connect/). The caller applies them with its same-origin path
// check (webauth.SafeNext); anything else lands on Home.
func NextPrefixes() []string { return slices.Clone(nextPrefixes) }

// Scopes are the portal login's fixed scopes: openid email profile groups,
// plus offline_access when the IdP link is enabled.
func Scopes(idpLink bool) []string {
	s := []string{"openid", "email", "profile", "groups"}
	if idpLink {
		s = append(s, "offline_access")
	}
	return s
}

// Principal is a signed-in portal user. The identity key is (Iss, Sub);
// Email is for display only. SessionHash is the session id's hash, never the
// raw id.
type Principal struct {
	Iss, Sub    string
	Email       string
	Groups      []string
	SessionHash string
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p under the portal's own key.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the portal Principal in ctx, if any. A console
// Principal is never returned: it lives under another key.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// Blocklist is the user block list as the portal reads it: the in-memory
// snapshot, no query per request.
type Blocklist interface {
	IsBlocked(sub, email string) bool
}

// Link is what a completed login hands the LinkWriter: the verified identity
// and the IdP refresh token. The token is never logged: String, GoString and
// LogValue leave it out.
type Link struct {
	Iss, Sub, Email string
	// EmailVerified is the ID token's email_verified claim.
	EmailVerified bool
	RefreshToken  string
}

// String renders the link without its token.
func (l Link) String() string { return "portal.Link{iss=" + l.Iss + " sub=" + l.Sub + "}" }

// GoString keeps the token out of %#v.
func (l Link) GoString() string { return l.String() }

// LogValue keeps the token out of structured logs.
func (l Link) LogValue() slog.Value {
	return slog.GroupValue(slog.String("iss", l.Iss), slog.String("sub", l.Sub))
}

// LinkWriter stores a login's IdP link (W-P3-CSIG-03: the refresh token in the
// CP-only consent.store, its Reference in idp_links). The callback calls it
// after admission and before it creates the session; an error means no
// session (fail closed). An error must never carry the token (or any part of
// it): the caller logs only the error's type, but implementations must not
// rely on that.
type LinkWriter interface {
	StoreLink(ctx context.Context, l Link) error
}

// Candidate is a verified login waiting for admission.
type Candidate struct {
	Sub, Email string
	Groups     []string
	// HasRefreshToken is true when the token response carried a refresh token.
	HasRefreshToken bool
}

// Admission is the portal's sign-in rule.
type Admission struct {
	// Blocks is the block list; nil admits everyone it would have checked.
	Blocks Blocklist
	// AllowedGroups, when non-empty, admits only a member of one of them.
	AllowedGroups []string
	// RequireRefreshToken is set when the IdP link is enabled.
	RequireRefreshToken bool
}

// Admit returns "" when c may get a portal session, otherwise the refusal
// code: CodeBlocked, CodeNotAllowed or CodeOfflineAccessNotGranted, checked in
// that order. Only the first MaxGroups groups count.
func (a Admission) Admit(c Candidate) string {
	if a.Blocks != nil && a.Blocks.IsBlocked(c.Sub, c.Email) {
		return CodeBlocked
	}
	if len(a.AllowedGroups) > 0 && !memberOfAny(CapGroups(c.Groups), a.AllowedGroups) {
		return CodeNotAllowed
	}
	if a.RequireRefreshToken && !c.HasRefreshToken {
		return CodeOfflineAccessNotGranted
	}
	return ""
}

// CapGroups returns at most MaxGroups of groups.
func CapGroups(groups []string) []string {
	if len(groups) > MaxGroups {
		return groups[:MaxGroups]
	}
	return groups
}

func memberOfAny(groups, allowed []string) bool {
	for _, g := range groups {
		if g != "" && slices.Contains(allowed, g) {
			return true
		}
	}
	return false
}
