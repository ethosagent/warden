package controlplane

import (
	"encoding/json"
	"net/http"
	"time"
)

// meResponse is the GET /auth/me body: who the browser is, its role, and the
// CSRF token it must echo in X-Warden-CSRF on writes. ExpiresAt is the
// session's absolute expiry (RFC 3339, UTC).
type meResponse struct {
	Sub        string `json:"sub"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	AuthMethod string `json:"authMethod"`
	CSRF       string `json:"csrf"`
	ExpiresAt  string `json:"expiresAt"`
}

func writeAuthJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// authError answers with a fixed JSON error. Every /auth response is no-store.
func authError(w http.ResponseWriter, code int, msg string) {
	writeAuthJSON(w, code, map[string]string{"error": msg})
}

// liveSession returns the raw id and session of the request's live session.
// withSession has already resolved it; the Principal in the context is the
// proof, and the second lookup only adds the expiry the Principal lacks.
func (s *Server) liveSession(r *http.Request) (string, Session, bool, error) {
	if !s.hasSessionPrincipal(r) {
		return "", Session{}, false, nil
	}
	rawID, ok := s.sessionCookie.From(r)
	if !ok {
		return "", Session{}, false, nil
	}
	sess, live, err := s.sessions.Lookup(r.Context(), rawID)
	return rawID, sess, live, err
}

// hasSessionPrincipal reports whether withSession put a session Principal in
// the request context, i.e. the request carries a live session cookie.
func (s *Server) hasSessionPrincipal(r *http.Request) bool {
	p, ok := PrincipalFrom(r.Context())
	return ok && p.Kind == PrincipalSession
}

// handleAuthMe serves GET /auth/me: 200 with the caller's identity for a live
// session, 401 without one.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.sessions == nil {
		authError(w, http.StatusServiceUnavailable, "console sessions unavailable")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		authError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rawID, sess, live, err := s.liveSession(r)
	if err != nil {
		s.cfg.Logger.Error("console session lookup failed", "error", err)
		authError(w, http.StatusInternalServerError, "session store error")
		return
	}
	if !live {
		authError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	role, _ := s.cfg.Console.RoleFor(sess.Groups)
	writeAuthJSON(w, http.StatusOK, meResponse{
		Sub: sess.Sub, Email: sess.Email, Role: role.String(), AuthMethod: sess.AuthMethod,
		CSRF: CSRFToken(rawID), ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handleLogout serves POST /auth/logout. withSession has already refused a
// live session without a valid CSRF token (403, session kept). The logout is
// local: the session row is deleted and the cookie cleared; the IdP is never
// called and there is no redirect, so the IdP's own session is untouched. A
// request without a live session still gets 204 and a clearing cookie. With
// admin audit on, ending a live session records auth.logout; a request
// without one records nothing.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.sessions == nil {
		authError(w, http.StatusServiceUnavailable, "console sessions unavailable")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		authError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.hasSessionPrincipal(r) {
		rawID, _ := s.sessionCookie.From(r)
		// The audit actor is the session's Principal, taken before the row goes.
		who, _ := s.resolveActor(r)
		if err := s.sessions.Delete(r.Context(), rawID); err != nil {
			s.cfg.Logger.Error("console logout failed", "session", shortHash(hashID(rawID)), "error", err)
			authError(w, http.StatusInternalServerError, "session store error")
			return
		}
		s.cfg.Logger.Info("console logout", "session", shortHash(hashID(rawID)))
		if s.audit != nil {
			s.recordLogout(r, who, hashID(rawID))
		}
	}
	http.SetCookie(w, s.sessionCookie.Clear())
	w.WriteHeader(http.StatusNoContent)
}
