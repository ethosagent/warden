package controlplane

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/webauth"
)

// CSRFHeader carries the per-session CSRF token on state-changing requests.
const CSRFHeader = webauth.CSRFHeader

// consoleCookieBase is the console session cookie's name: __Host-warden_console
// on https, warden_console on a loopback http redirectURL.
const consoleCookieBase = "warden_console"

// SessionCookie names and flags the console session cookie. Secure is decided
// from the configured redirect URL, never from r.TLS: a TLS-terminating proxy
// in front of the control plane must not downgrade the cookie.
type SessionCookie = webauth.Cookie

// NewSessionCookie derives the cookie spec from console.oidc.redirectURL. An
// https URL gives the __Host- cookie (Secure, Path=/, no Domain). Plain http is
// accepted only for a loopback host and gives an unprefixed, non-Secure cookie.
func NewSessionCookie(redirectURL string) (SessionCookie, error) {
	return webauth.NewCookie(redirectURL, consoleCookieBase)
}

// sessionReader is the part of SessionStore the middleware uses. It is a seam so
// a test can count calls (the worker routes must make none).
type sessionReader interface {
	Lookup(ctx context.Context, rawID string) (Session, bool, error)
	Touch(ctx context.Context, rawID string) (bool, error)
	Now() time.Time
}

// withSession authenticates but never denies for a missing session: a request
// with a live session cookie gets a Principal in its context, anything else
// passes through unchanged (role enforcement is W-P1-SSO-05). The one refusal
// is CSRF: a state-changing request that carries a live session must present a
// matching X-Warden-CSRF and, if it sends Origin, the console's own origin.
func withSession(next http.Handler, store sessionReader, cookie SessionCookie, logger *slog.Logger) http.Handler {
	return withSessionRefuse(next, csrfRefusal, store, cookie, logger, nil)
}

// sessionGuard may refuse a request that carries a live, non-break-glass
// session. It returns true when it has already written the response, so the
// request goes no further.
type sessionGuard func(w http.ResponseWriter, r *http.Request, p Principal) bool

// withSessionRefuse is withSession with the CSRF refusal handler given. The
// refusal runs with the session's Principal in its context (and csrfRefused
// set), so the admin audit middleware wrapped around it records the refused
// write as denied. next never runs for a refused request.
func withSessionRefuse(next, refuse http.Handler, store sessionReader, cookie SessionCookie, logger *slog.Logger, guard sessionGuard) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawID, ok := cookie.From(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		sess, live, err := store.Lookup(r.Context(), rawID)
		if err != nil {
			logger.Error("console session lookup failed", "error", err)
			next.ServeHTTP(w, r)
			return
		}
		if !live {
			next.ServeHTTP(w, r)
			return
		}
		kind := PrincipalSession
		if sess.AuthMethod == AuthMethodBreakglass {
			kind = PrincipalBreakglass
		}
		p := Principal{
			Kind: kind, Iss: sess.Iss, Sub: sess.Sub, Email: sess.Email,
			Groups: sess.Groups, AuthMethod: sess.AuthMethod, SessionHash: sess.IDHash,
		}
		// A break-glass session is exempt: it is how a locked-out console is
		// recovered.
		if guard != nil && kind != PrincipalBreakglass && guard(w, r, p) {
			return
		}
		if !consoleCSRF(cookie).Valid(r, rawID) {
			logger.Warn("console csrf check failed", "session", shortHash(sess.IDHash), "method", r.Method, "path", r.URL.Path)
			ctx := WithPrincipal(context.WithValue(r.Context(), csrfRefusedKey{}, true), p)
			refuse.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if webauth.TouchDue(sess, store.Now()) {
			if _, err := store.Touch(r.Context(), rawID); err != nil {
				logger.Warn("console session touch failed", "session", shortHash(sess.IDHash), "error", err)
			}
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// consoleCSRF is the console's CSRF rule: the X-Warden-CSRF header under the
// console label and, when Origin is sent, the console's own origin.
func consoleCSRF(cookie SessionCookie) webauth.CSRF {
	return webauth.CSRF{Label: csrfLabel, Origin: cookie.Origin()}
}

// initSessions builds the session store when the console is in oidc mode and a
// state DB is open. Any other mode leaves s.sessions nil and the dashboard
// exactly as it was.
func (s *Server) initSessions() {
	cc := s.cfg.Console
	if cc.Auth != config.ConsoleAuthOIDC {
		return
	}
	if s.cfg.State == nil {
		s.cfg.Logger.Error("control plane: console sessions disabled (no state db)")
		return
	}
	cookie, err := NewSessionCookie(cc.OIDC.RedirectURL)
	if err != nil {
		s.cfg.Logger.Error("control plane: console sessions disabled", "error", err)
		return
	}
	if !cookie.Secure {
		s.cfg.Logger.Warn("control plane: console session cookie is not Secure (http loopback redirectURL); use https outside development")
	}
	s.sessionCookie = cookie
	s.sessions = NewSessionStore(s.cfg.State.SQL(), cc.Session.Idle, cc.Session.Absolute, s.cfg.Now)
	s.sessionReader = s.sessions
	if s.blocks != nil {
		s.blocks.SetSessionRevoker(s.sessions)
	}
}

// sessionWrap applies withSession when sessions are enabled and is the identity
// otherwise.
func (s *Server) sessionWrap(h http.Handler) http.Handler {
	if s.sessionReader == nil {
		return h
	}
	return withSessionRefuse(h, csrfRefusal, s.sessionReader, s.sessionCookie, s.cfg.Logger, s.blockedSessionGuard())
}

// sessionAuditWrap is sessionWrap for an admin route: h runs behind the
// request-id and admin audit middleware (auditWrap, a no-op with audit off),
// and so does the CSRF refusal, so a refused session write is recorded too.
func (s *Server) sessionAuditWrap(classify func(*http.Request) (authzRow, bool), h http.Handler) http.Handler {
	inner := s.auditWrap(classify, h)
	if s.sessionReader == nil {
		return inner
	}
	return withSessionRefuse(inner, s.auditWrap(classify, csrfRefusal), s.sessionReader, s.sessionCookie, s.cfg.Logger, s.blockedSessionGuard())
}

// sweepSessions deletes expired sessions every minute until ctx is done.
func (s *Server) sweepSessions(ctx context.Context) {
	t := time.NewTicker(sessionSweepInterval)
	defer t.Stop()
	for {
		if n, err := s.sessions.SweepExpired(ctx); err != nil {
			s.cfg.Logger.Warn("control plane: session sweep failed", "error", err)
		} else if n > 0 {
			s.cfg.Logger.Info("control plane: expired console sessions removed", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
