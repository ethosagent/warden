package portal

import (
	"context"
	"net/url"
	"strings"
	"time"
)

// The portal session's request rules (W-P3-CSIG-04): which paths exist
// behind the session middleware, where a signed-out browser is sent, the
// error vocabulary of a refusal, and the IdP link status GET /portal/api/me
// reports. The middleware itself (cookie, session store, CSRF and Origin
// check) is HTTP and lives in internal/controlplane.

// Paths behind the portal session middleware.
const (
	// APIPrefix is the portal's JSON API tree. A signed-out request under it
	// gets 401, never a redirect.
	APIPrefix = "/portal/api/"
	// MePath serves the signed-in user, the session's CSRF token and the IdP
	// link status. W-P3-PORT-01 extends this route rather than adding its own.
	MePath = "/portal/api/me"
	// LogoutPath ends the portal session (POST, CSRF-checked). It leaves the
	// IdP link and its stored token in place.
	LogoutPath = "/portal/logout"
)

// CSRFFormField is the form field that may carry the CSRF token on an
// application/x-www-form-urlencoded post when the X-Warden-CSRF header is
// absent.
const CSRFFormField = "csrf"

// Refusal codes of the session middleware, answered as {"error":"<code>"}.
const (
	// CodeUnauthenticated: no live portal session (401).
	CodeUnauthenticated = "unauthenticated"
	// CodeCSRF: a state-changing request without the session's CSRF token, or
	// with a foreign Origin (403).
	CodeCSRF = "csrf"
	// CodeUserBlocked: the session's sub or email is on the block list (403);
	// the principal's portal sessions are deleted.
	CodeUserBlocked = "user_blocked"
)

// LoginURL is where a signed-out browser is sent to sign in and come back to
// next. An empty next, or one that is not a path under NextPrefixes (no
// scheme, no "//", no backslash), gives the bare LoginPath; the login flow
// checks next again before it redirects anywhere.
func LoginURL(next string) string {
	if !nextAllowed(next) {
		return LoginPath
	}
	return LoginPath + "?next=" + url.QueryEscape(next)
}

// nextAllowed is a conservative pre-check of a post-login path: it must be
// under one of nextPrefixes and hold no scheme, protocol-relative or
// backslash trick.
func nextAllowed(next string) bool {
	if next == "" || strings.Contains(next, "\\") || strings.HasPrefix(next, "//") || strings.Contains(next, "://") {
		return false
	}
	for _, p := range nextPrefixes {
		if strings.HasPrefix(next, p) {
			return true
		}
	}
	return false
}

// SignedOutRedirects reports whether a request without a live session is sent
// to LoginURL (a browser page load: GET or HEAD outside APIPrefix) rather
// than answered 401 (an API call or a state-changing request).
func SignedOutRedirects(method, path string) bool {
	return (method == "GET" || method == "HEAD") && !strings.HasPrefix(path, APIPrefix)
}

// IdP link statuses reported by GET /portal/api/me.
const (
	// LinkDisabled: consent.idpLink is off; no refresh token is kept.
	LinkDisabled = "disabled"
	// LinkLinked: a refresh token is stored for the user.
	LinkLinked = "linked"
	// LinkMissing: the IdP link is on and no link is recorded for the user.
	LinkMissing = "missing"
	// LinkUnknown: the link could not be read (no reader wired, or a read
	// error). It is never reported as linked.
	LinkUnknown = "unknown"
)

// LinkStatus is the value-free state of a user's IdP link. RelinkDueAt is the
// time the user must sign in again (refresh issued + refreshLifetime); zero
// when unknown.
type LinkStatus struct {
	Status      string
	RelinkDueAt time.Time
}

// LinkReader reads a user's IdP link status (W-P3-CSIG-03 implements it over
// idp_links). It never returns the token or its Reference.
type LinkReader interface {
	LinkStatus(ctx context.Context, iss, sub string) (LinkStatus, error)
}
