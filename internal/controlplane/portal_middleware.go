package controlplane

import (
	"context"
	"net/http"
	"strings"
	"time"

	oauthbrokerhttp "github.com/ethosagent/warden/internal/oauthbroker/http"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/internal/webauth"
)

// The portal session middleware (W-P3-CSIG-04). requireSession guards every
// /portal route but the sign-in itself and the stub page, and is what
// /connect/* (W-P3-BRKR-03) and the portal pages (W-P3-PORT-*) mount behind:
//
//   - it reads only the portal cookie (__Host-warden_portal) and the
//     portal_sessions table. A console cookie, the WARDEN_CP_TOKEN bearer, a
//     worker credential and a wak_ API key are never read, so none of them
//     authenticates here, and no console middleware reads the portal cookie;
//   - the session is looked up on every request (idle and absolute expiry on
//     the CP clock, last_seen_at written at most once a minute);
//   - the block list is rechecked on every request from the BlockStore's
//     in-memory snapshot: a blocked principal gets 403 user_blocked and every
//     portal session of theirs is deleted. While no block list has loaded no
//     session authenticates (503 block_list_unavailable);
//   - a state-changing request must carry the session's CSRF token
//     (HMAC-SHA256(raw id, "warden-portal-csrf")) in X-Warden-CSRF, or in a
//     `csrf` field of a urlencoded form, and an Origin header, when sent, must
//     be the portal's own origin; otherwise 403 csrf;
//   - a signed-out browser GET outside /portal/api/ is sent to
//     /portal/login?next=<path>; anything else signed out is 401.
//
// The handler behind it reads the signed-in user with portal.PrincipalFrom,
// a context key no console check reads.

// portalSessionBackend is the part of PortalSessionStore the middleware, me
// and logout use. It is a seam so a test can count calls (the worker routes
// must make none).
type portalSessionBackend interface {
	Lookup(ctx context.Context, rawID string) (webauth.Session, bool, error)
	Touch(ctx context.Context, rawID string) (bool, error)
	Delete(ctx context.Context, rawID string) error
	DeleteBySub(ctx context.Context, sub string) (int, error)
	DeleteByEmail(ctx context.Context, email string) (int, error)
	Now() time.Time
}

// portalMaxBody caps a state-changing portal request body. Every portal and
// connect form and JSON body is small; the cap keeps the CSRF form parse
// bounded.
const portalMaxBody = 64 << 10

// portalSessionUnavailable answers a portal request whose session lookup
// failed (fail closed: no session, 503).
const portalSessionUnavailable = "session_store_unavailable"

// portalRevokedByBlocklist is the by_sub of a portal_session_revoked line
// written when the middleware finds a blocked principal.
const portalRevokedByBlocklist = "system:blocklist"

// portalAuthOutcome is what authenticate found.
type portalAuthOutcome int

const (
	portalSignedOut portalAuthOutcome = iota
	portalSignedIn
	portalBlocked
	portalUnavailable
)

// portalSessionCtx is the live session behind a request, with its raw id
// (for the CSRF token and logout). It is held under a controlplane-private
// key and never leaves the process.
type portalSessionCtx struct {
	sess  webauth.Session
	rawID string
}

type portalSessionKey struct{}

// portalSessionFrom returns the session requireSession put in ctx.
func portalSessionFrom(ctx context.Context) (portalSessionCtx, bool) {
	s, ok := ctx.Value(portalSessionKey{}).(portalSessionCtx)
	return s, ok
}

// csrf is the portal's CSRF rule: its own HMAC label, its own origin and the
// csrf form field.
func (p *portalService) csrf() webauth.CSRF {
	return webauth.CSRF{Label: portal.CSRFLabel, Origin: p.cookie.Origin(), FormField: portal.CSRFFormField}
}

// authenticate resolves the request's portal session. Only the portal cookie
// and the portal session store are read. A blocked principal's portal
// sessions are deleted here, so the stub page and the middleware revoke
// alike. code is the 503 error code for portalUnavailable.
func (p *portalService) authenticate(r *http.Request) (sc portalSessionCtx, out portalAuthOutcome, code string) {
	store := p.store
	if store == nil {
		return sc, portalUnavailable, portalSessionUnavailable
	}
	// Without a loaded block list nobody can be told apart from a blocked
	// user, so no session authenticates (fail closed).
	if p.blocks != nil && !p.blocks.Ready() {
		return sc, portalUnavailable, loginBlockUnavailable
	}
	rawID, ok := p.cookie.From(r)
	if !ok {
		return sc, portalSignedOut, ""
	}
	sess, live, err := store.Lookup(r.Context(), rawID)
	if err != nil {
		p.logger.Error("portal session lookup failed", "error", err)
		return sc, portalUnavailable, portalSessionUnavailable
	}
	if !live {
		return sc, portalSignedOut, ""
	}
	if p.blocks != nil && p.blocks.IsBlocked(sess.Sub, sess.Email) {
		p.revokeBlocked(r.Context(), sess)
		return sc, portalBlocked, ""
	}
	if webauth.TouchDue(sess, store.Now()) {
		if _, err := store.Touch(r.Context(), rawID); err != nil {
			p.logger.Warn("portal session touch failed", "session", shortHash(sess.IDHash), "error", err)
		}
	}
	return portalSessionCtx{sess: sess, rawID: rawID}, portalSignedIn, ""
}

// revokeBlocked deletes every portal session of a principal the block list
// now names (the BlockStore.Add path normally did so already; this catches a
// block that landed between).
func (p *portalService) revokeBlocked(ctx context.Context, sess webauth.Session) {
	ctx = context.WithoutCancel(ctx)
	n := 0
	if sess.Sub != "" {
		c, err := p.store.DeleteBySub(ctx, sess.Sub)
		if err != nil {
			p.logger.Error("portal session revoke failed", "error", err)
		}
		n += c
	}
	if sess.Email != "" {
		c, err := p.store.DeleteByEmail(ctx, sess.Email)
		if err != nil {
			p.logger.Error("portal session revoke failed", "error", err)
		}
		n += c
	}
	p.logger.Info("portal_session_revoked", "by_sub", portalRevokedByBlocklist, "target_sub", sess.Sub, "count", n)
}

// requireSession is the portal session middleware (see the file comment).
// next runs only for a live, unblocked session that passed the CSRF and
// Origin check, with portal.PrincipalFrom set.
func (p *portalService) requireSession(next http.Handler) http.Handler {
	return p.requireSessionWith(next, signedOutPolicy{
		redirects: func(r *http.Request) bool { return portal.SignedOutRedirects(r.Method, r.URL.Path) },
		status:    http.StatusFound,
	})
}

// signedOutPolicy says which signed-out requests a session guard sends to the
// portal sign-in (and with which status) rather than answering 401.
type signedOutPolicy struct {
	redirects func(r *http.Request) bool
	status    int
	// unauthenticated, when set, renders the 401 of a signed-out request that
	// does not redirect (the connect callback answers an HTML page); nil is the
	// JSON error.
	unauthenticated func(w http.ResponseWriter)
}

// requireSessionWith is requireSession with its signed-out rule chosen by the
// route: the portal pages redirect a browser GET with 302, the connect routes
// redirect every method with 303 (a POST cannot be replayed after sign-in, so
// its next is the portal home).
func (p *portalService) requireSessionWith(next http.Handler, so signedOutPolicy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webauth.NoStore(w)
		sc, out, code := p.authenticate(r)
		switch out {
		case portalUnavailable:
			writeAuthError(w, http.StatusServiceUnavailable, code)
			return
		case portalBlocked:
			writeAuthError(w, http.StatusForbidden, portal.CodeUserBlocked)
			return
		case portalSignedOut:
			if so.redirects(r) {
				next := ""
				if safeMethod(r.Method) {
					next = p.loginNext(r)
				}
				http.Redirect(w, r, portal.LoginURL(next), so.status)
				return
			}
			if so.unauthenticated != nil {
				so.unauthenticated(w)
				return
			}
			writeAuthError(w, http.StatusUnauthorized, portal.CodeUnauthenticated)
			return
		}
		if !safeMethod(r.Method) {
			r.Body = http.MaxBytesReader(w, r.Body, portalMaxBody)
		}
		if !p.csrf().Valid(r, sc.rawID) {
			p.logger.Warn("portal_csrf_denied", "session", shortHash(sc.sess.IDHash), "sub", sc.sess.Sub, "method", r.Method, "path", r.URL.Path)
			writeAuthError(w, http.StatusForbidden, portal.CodeCSRF)
			return
		}
		ctx := portal.WithPrincipal(r.Context(), portal.Principal{
			Iss: sc.sess.Iss, Sub: sc.sess.Sub, Email: sc.sess.Email, EmailVerified: sc.sess.EmailVerified,
			Groups: sc.sess.Groups, SessionHash: sc.sess.IDHash,
		})
		ctx = context.WithValue(ctx, portalSessionKey{}, sc)
		next.ServeHTTP(w, p.stripConsoleCredentials(r.WithContext(ctx)))
	})
}

// loginNext is the path a signed-out browser returns to after sign-in: the
// request's path and query when the login flow would accept them, else ""
// (the portal home).
func (p *portalService) loginNext(r *http.Request) string {
	next := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	if !webauth.SafeNext(next, portal.NextPrefixes()...) {
		return ""
	}
	return next
}

// stripConsoleCredentials returns r without the credentials a portal handler
// must never act on: the Authorization header (WARDEN_CP_TOKEN, worker
// tokens, wak_ keys) and the console session cookie. The header map is
// cloned, so the caller's request is unchanged.
func (p *portalService) stripConsoleCredentials(r *http.Request) *http.Request {
	r2 := *r
	r2.Header = r.Header.Clone()
	r2.Header.Del("Authorization")
	if p.consoleCookie != "" {
		cookies := r.Cookies()
		r2.Header.Del("Cookie")
		parts := make([]string, 0, len(cookies))
		for _, c := range cookies {
			if c.Name == p.consoleCookie {
				continue
			}
			parts = append(parts, (&http.Cookie{Name: c.Name, Value: c.Value}).String())
		}
		if len(parts) > 0 {
			r2.Header.Set("Cookie", strings.Join(parts, "; "))
		}
	}
	return &r2
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// connectWrap puts a /connect/* route behind the portal session middleware.
// A signed-out request of any method is sent to /portal/login with 303 (a
// relative next only for GET). A request of any method that carries a console credential (an
// Authorization header: the admin bearer, a worker token or a wak_ key; or the
// console session cookie) is answered 401 instead: none of them authenticates
// here, and redirecting a machine client to a sign-in page would hide that.
// Without a portal the route is 404.
func (s *Server) connectWrap(h http.Handler) http.Handler {
	if s.portal == nil {
		return http.NotFoundHandler()
	}
	p := s.portal
	return p.requireSessionWith(h, signedOutPolicy{
		redirects: func(r *http.Request) bool {
			if r.Header.Get("Authorization") != "" {
				return false
			}
			if p.consoleCookie != "" {
				if _, err := r.Cookie(p.consoleCookie); err == nil {
					return false
				}
			}
			return true
		},
		status: http.StatusSeeOther,
	})
}

// connectCallbackWrap puts GET /connect/callback behind the portal session
// middleware. A signed-out request is a 401 page, never a redirect: the query
// holds the provider's code and state, which must not be carried into a login
// round trip (the login's own next check would drop them anyway). Console
// credentials are stripped like everywhere on /connect. Without a portal the
// route is 404.
func (s *Server) connectCallbackWrap(h http.Handler) http.Handler {
	if s.portal == nil {
		return http.NotFoundHandler()
	}
	return s.portal.requireSessionWith(h, signedOutPolicy{
		redirects: func(*http.Request) bool { return false },
		status:    http.StatusSeeOther,
		unauthenticated: func(w http.ResponseWriter) {
			oauthbrokerhttp.WriteErrorPage(w, http.StatusUnauthorized, portal.CodeUnauthenticated)
		},
	})
}

// portalWrap puts h behind the portal session middleware; without a portal
// (consent off or no state DB) the route answers 404.
func (s *Server) portalWrap(h http.Handler) http.Handler {
	if s.portal == nil {
		return http.NotFoundHandler()
	}
	return s.portal.requireSession(h)
}
