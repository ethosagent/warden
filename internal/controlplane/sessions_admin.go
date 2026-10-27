package controlplane

import (
	"net/http"
	"regexp"
	"time"
)

// maxRevokeSubLen bounds the ?sub= of a revoke. An IdP subject is at most 255
// ASCII characters (OIDC Core 2), so anything longer is malformed.
const maxRevokeSubLen = 255

// handlePattern is the stored form of a session handle: the lowercase hex
// sha256 of the raw id.
var handlePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// sessionView is one GET /dashboard/api/sessions row. Handle is the session's
// id hash: it identifies the row for a revoke but cannot be used as a cookie.
// The raw id, the CSRF token and the groups are never returned. Current marks
// the caller's own session.
type sessionView struct {
	Handle     string `json:"handle"`
	Iss        string `json:"iss"`
	Sub        string `json:"sub"`
	Email      string `json:"email"`
	AuthMethod string `json:"authMethod"`
	CreatedAt  string `json:"createdAt"`
	LastSeenAt string `json:"lastSeenAt"`
	ExpiresAt  string `json:"expiresAt"`
	Current    bool   `json:"current"`
}

// handleSessions serves /dashboard/api/sessions. It runs inside withSession and
// requireRole (admin for GET and DELETE, routes.go), so a Principal is always
// present and DELETE has passed the CSRF check.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, ok := PrincipalFrom(r.Context())
	if s.sessions == nil || !ok {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleSessionsList(w, r, p)
	case http.MethodDelete:
		s.handleSessionsRevoke(w, r, p)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeAuthJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleSessionsList returns the live console sessions, newest first.
func (s *Server) handleSessionsList(w http.ResponseWriter, r *http.Request, p Principal) {
	list, err := s.sessions.List(r.Context())
	if err != nil {
		s.cfg.Logger.Error("console session list failed", "error", err)
		writeAuthJSON(w, http.StatusInternalServerError, map[string]string{"error": "session store error"})
		return
	}
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	out := make([]sessionView, 0, len(list))
	for _, sess := range list {
		out = append(out, sessionView{
			Handle: sess.IDHash, Iss: sess.Iss, Sub: sess.Sub, Email: sess.Email, AuthMethod: sess.AuthMethod,
			CreatedAt: ts(sess.CreatedAt), LastSeenAt: ts(sess.LastSeenAt), ExpiresAt: ts(sess.ExpiresAt),
			Current: sess.IDHash == p.SessionHash,
		})
	}
	writeAuthJSON(w, http.StatusOK, out)
}

// handleSessionsRevoke deletes one session (?handle=<hex id hash>) or every
// session of a subject (?sub=<sub>); exactly one is required. The next request
// carrying a revoked cookie gets 401: withSession looks every session up in the
// store, there is no cache to clear. An unknown handle is 404; a subject with no
// sessions revokes 0.
func (s *Server) handleSessionsRevoke(w http.ResponseWriter, r *http.Request, p Principal) {
	q := r.URL.Query()
	handle, sub := q.Get("handle"), q.Get("sub")
	switch {
	case (handle == "") == (sub == ""):
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "exactly one of handle or sub is required"})
		return
	case handle != "" && !handlePattern.MatchString(handle):
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "handle must be 64 lowercase hex characters"})
		return
	case len(sub) > maxRevokeSubLen:
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "sub is too long"})
		return
	}

	var (
		count  int
		target = sub
	)
	if handle != "" {
		// Resolve the subject for the log line before the row is gone.
		list, err := s.sessions.List(r.Context())
		if err != nil {
			s.revokeFailed(w, err)
			return
		}
		for _, sess := range list {
			if sess.IDHash == handle {
				target = sess.Sub
			}
		}
		found, err := s.sessions.DeleteByHash(r.Context(), handle)
		if err != nil {
			s.revokeFailed(w, err)
			return
		}
		if !found {
			writeAuthJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
			return
		}
		count = 1
	} else {
		n, err := s.sessions.DeleteBySub(r.Context(), sub)
		if err != nil {
			s.revokeFailed(w, err)
			return
		}
		count = n
	}
	attrs := []any{"by_sub", p.Sub, "target_sub", target, "count", count}
	if handle != "" {
		attrs = append(attrs, "session", shortHash(handle))
	}
	s.cfg.Logger.Info("console_session_revoked", attrs...)
	writeAuthJSON(w, http.StatusOK, map[string]int{"revoked": count})
}

func (s *Server) revokeFailed(w http.ResponseWriter, err error) {
	s.cfg.Logger.Error("console session revoke failed", "error", err)
	writeAuthJSON(w, http.StatusInternalServerError, map[string]string{"error": "session store error"})
}
