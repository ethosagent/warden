package controlplane

import (
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
)

// Console denial for blocked principals (W-P1-BLOCK-07). A principal on the
// block list cannot sign in (the OIDC callback answers 403 user_blocked and
// sets no session) and cannot keep using a session (withSession answers 403
// from the in-memory snapshot, with no query). Break-glass is exempt in both
// places, so the console stays recoverable. Both denials happen before the
// admin audit middleware runs, so they record their own rows:
//
//	auth.blocked_login    the callback refused a blocked principal
//	auth.blocked_session  the session middleware refused a blocked principal,
//	                      at most one row a minute per principal

const (
	actionBlockedLogin   = "auth.blocked_login"
	actionBlockedSession = "auth.blocked_session"

	// loginUserBlocked is the JSON error code of both denials.
	loginUserBlocked = "user_blocked"
	// loginBlockUnavailable answers a login while no block list has loaded:
	// without it the console cannot tell who is blocked, so it refuses (503).
	loginBlockUnavailable = "block_list_unavailable"

	failUserBlocked      = "user_blocked"
	failBlockUnavailable = "block_list_unavailable"

	blockedSessionWindow  = time.Minute
	blockedSessionMaxKeys = 4096
)

// blockedSessionGuard returns the session middleware's block check, or nil when
// there is no block store.
func (s *Server) blockedSessionGuard() sessionGuard {
	if s.blocks == nil {
		return nil
	}
	return func(w http.ResponseWriter, r *http.Request, p Principal) bool {
		if !s.blocks.IsBlocked(p.Sub, p.Email) {
			return false
		}
		s.recordBlockedSession(r, p)
		writeAuthError(w, http.StatusForbidden, loginUserBlocked)
		return true
	}
}

// recordBlockedSession records one auth.blocked_session row for p, rate-limited
// to one a minute per principal. With admin audit off it does nothing.
func (s *Server) recordBlockedSession(r *http.Request, p Principal) {
	a := s.audit
	if a == nil {
		return
	}
	key := p.Sub + "\x00" + p.Email
	if !a.blockedSession.allow(key) {
		return
	}
	reqID := RequestIDFrom(r.Context())
	if reqID == "" {
		reqID = newRequestID()
	}
	s.recordAuth(r.Context(), adminaudit.Input{
		Actor: adminaudit.Actor{Sub: p.Sub, Email: p.Email}, AuthMethod: adminaudit.AuthMethodOIDC,
		Action: actionBlockedSession, Target: targetSession, TargetRef: shortHash(p.SessionHash),
		Details: map[string]string{detailReason: failUserBlocked},
		Outcome: adminaudit.OutcomeDenied, HTTPStatus: http.StatusForbidden,
		ClientIP: clientIP(r, a.trusted), RequestID: reqID,
	})
}
