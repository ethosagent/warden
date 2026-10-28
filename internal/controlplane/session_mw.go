package controlplane

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// CSRFHeader carries the per-session CSRF token on state-changing requests.
const CSRFHeader = "X-Warden-CSRF"

// defaultPort lists the ports a browser leaves out of Origin.
var defaultPort = map[string]string{"https": "443", "http": "80"}

const (
	cookieNameSecure = "__Host-warden_console"
	cookieNamePlain  = "warden_console"
)

// SessionCookie names and flags the console session cookie. Secure is decided
// from the configured redirect URL, never from r.TLS: a TLS-terminating proxy
// in front of the control plane must not downgrade the cookie.
type SessionCookie struct {
	Name   string
	Secure bool
	// origin is scheme://host of the redirect URL, the only Origin accepted on
	// state-changing requests.
	origin string
}

// NewSessionCookie derives the cookie spec from console.oidc.redirectURL. An
// https URL gives the __Host- cookie (Secure, Path=/, no Domain). Plain http is
// accepted only for a loopback host and gives an unprefixed, non-Secure cookie.
func NewSessionCookie(redirectURL string) (SessionCookie, error) {
	u, err := url.Parse(redirectURL)
	if err != nil || u.Host == "" {
		return SessionCookie{}, fmt.Errorf("session cookie: redirect URL %q is not absolute", redirectURL)
	}
	// Browsers send Origin lowercased and without the scheme's default port.
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && p != defaultPort[u.Scheme] {
		host += ":" + p
	}
	origin := strings.ToLower(u.Scheme) + "://" + host
	switch u.Scheme {
	case "https":
		return SessionCookie{Name: cookieNameSecure, Secure: true, origin: origin}, nil
	case "http":
		if !isLoopback(u.Hostname()) {
			return SessionCookie{}, errors.New("session cookie: an http redirect URL is allowed only on a loopback host")
		}
		return SessionCookie{Name: cookieNamePlain, origin: origin}, nil
	}
	return SessionCookie{}, fmt.Errorf("session cookie: redirect URL scheme %q is not http(s)", u.Scheme)
}

func isLoopback(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// New returns the Set-Cookie value for a fresh session. maxAge is the absolute
// session lifetime.
func (c SessionCookie) New(rawID string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name: c.Name, Value: rawID, Path: "/", MaxAge: int(maxAge.Seconds()),
		Secure: c.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

// Clear returns the Set-Cookie value that deletes the cookie.
func (c SessionCookie) Clear() *http.Cookie {
	return &http.Cookie{
		Name: c.Name, Value: "", Path: "/", MaxAge: -1,
		Secure: c.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

// From returns the raw session id the request carries, if any.
func (c SessionCookie) From(r *http.Request) (string, bool) {
	ck, err := r.Cookie(c.Name)
	if err != nil || ck.Value == "" {
		return "", false
	}
	return ck.Value, true
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
	return withSessionRefuse(next, csrfRefusal, store, cookie, logger)
}

// withSessionRefuse is withSession with the CSRF refusal handler given. The
// refusal runs with the session's Principal in its context (and csrfRefused
// set), so the admin audit middleware wrapped around it records the refused
// write as denied. next never runs for a refused request.
func withSessionRefuse(next, refuse http.Handler, store sessionReader, cookie SessionCookie, logger *slog.Logger) http.Handler {
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
		if !csrfOK(r, rawID, cookie.origin) {
			logger.Warn("console csrf check failed", "session", shortHash(sess.IDHash), "method", r.Method, "path", r.URL.Path)
			ctx := WithPrincipal(context.WithValue(r.Context(), csrfRefusedKey{}, true), p)
			refuse.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if !sess.LastSeenAt.After(store.Now().Add(-touchInterval)) {
			if _, err := store.Touch(r.Context(), rawID); err != nil {
				logger.Warn("console session touch failed", "session", shortHash(sess.IDHash), "error", err)
			}
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// csrfOK applies the CSRF rules to a request that carries a live session. Safe
// methods pass. Otherwise the header must equal the session's token (constant
// time) and an Origin header, when present, must equal the console origin.
func csrfOK(r *http.Request, rawID, origin string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if o := r.Header.Get("Origin"); o != "" && o != origin {
		return false
	}
	got := r.Header.Get(CSRFHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(CSRFToken(rawID))) == 1
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
}

// sessionWrap applies withSession when sessions are enabled and is the identity
// otherwise.
func (s *Server) sessionWrap(h http.Handler) http.Handler {
	if s.sessionReader == nil {
		return h
	}
	return withSession(h, s.sessionReader, s.sessionCookie, s.cfg.Logger)
}

// sessionAuditWrap is sessionWrap for an admin route: h runs behind the
// request-id and admin audit middleware (auditWrap, a no-op with audit off),
// and so does the CSRF refusal, so a refused session write is recorded too.
func (s *Server) sessionAuditWrap(classify func(*http.Request) (authzRow, bool), h http.Handler) http.Handler {
	inner := s.auditWrap(classify, h)
	if s.sessionReader == nil {
		return inner
	}
	return withSessionRefuse(inner, s.auditWrap(classify, csrfRefusal), s.sessionReader, s.sessionCookie, s.cfg.Logger)
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
