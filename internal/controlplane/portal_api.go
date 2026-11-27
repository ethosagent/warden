package controlplane

import (
	"fmt"
	"mime"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/internal/webauth"
)

// The portal's session API (W-P3-CSIG-04), both behind requireSession:
//
//	GET  /portal/api/me  the signed-in user, the session's CSRF token and the
//	                     IdP link status; W-P3-PORT-01 extends it
//	POST /portal/logout  deletes the portal session and clears its cookie; the
//	                     IdP link (idp_links and the stored refresh token) stays
//
// Neither returns or logs the raw session id, and the CSRF token is only ever
// in the /portal/api/me body.

// portalMe is the GET /portal/api/me body.
type portalMe struct {
	Sub       string     `json:"sub"`
	Email     string     `json:"email"`
	ExpiresAt string     `json:"expiresAt"`
	CSRF      string     `json:"csrf"`
	Link      portalLink `json:"link"`
}

// portalLink is the value-free IdP link status: no token, no Reference.
type portalLink struct {
	Status      string `json:"status"`
	RelinkDueAt string `json:"relinkDueAt,omitempty"`
}

// handleMe serves GET /portal/api/me.
func (p *portalService) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	sc, ok := portalSessionFrom(r.Context())
	if !ok {
		writeAuthError(w, http.StatusUnauthorized, portal.CodeUnauthenticated)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeAuthJSON(w, http.StatusOK, portalMe{
		Sub: sc.sess.Sub, Email: sc.sess.Email,
		ExpiresAt: sc.sess.ExpiresAt.UTC().Format(time.RFC3339),
		CSRF:      webauth.CSRFToken([]byte(sc.rawID), portal.CSRFLabel),
		Link:      p.link(r, sc.sess),
	})
}

// link reads the session user's IdP link status. It is "disabled" with the
// IdP link off and "unknown" when no reader is wired or the read fails; it is
// never reported as linked without a successful read.
func (p *portalService) link(r *http.Request, sess webauth.Session) portalLink {
	if !p.cfg.IdPLink.Enabled {
		return portalLink{Status: portal.LinkDisabled}
	}
	if p.linkStatus == nil {
		return portalLink{Status: portal.LinkUnknown}
	}
	st, err := p.linkStatus.LinkStatus(r.Context(), sess.Iss, sess.Sub)
	if err != nil {
		// Only the error's type: a store error must not reach the log verbatim.
		p.logger.Warn("portal idp link status read failed", "sub", sess.Sub, "error_type", fmt.Sprintf("%T", err))
		return portalLink{Status: portal.LinkUnknown}
	}
	out := portalLink{Status: st.Status}
	if out.Status == "" {
		out.Status = portal.LinkUnknown
	}
	if !st.RelinkDueAt.IsZero() {
		out.RelinkDueAt = st.RelinkDueAt.UTC().Format(time.RFC3339)
	}
	return out
}

// handleLogout serves POST /portal/logout. requireSession has checked the
// session and the CSRF token. A form post (the stub's sign-out button) is
// redirected to the portal home; any other caller gets 204.
func (p *portalService) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	sc, ok := portalSessionFrom(r.Context())
	if !ok {
		writeAuthError(w, http.StatusUnauthorized, portal.CodeUnauthenticated)
		return
	}
	if err := p.store.Delete(r.Context(), sc.rawID); err != nil {
		p.logger.Error("portal logout failed", "session", shortHash(sc.sess.IDHash), "error", err)
		writeAuthError(w, http.StatusServiceUnavailable, portalSessionUnavailable)
		return
	}
	// The IdP link is the user's, not the session's: it is left in place.
	p.logger.Info("portal_logout", "session", shortHash(sc.sess.IDHash), "sub", sc.sess.Sub)
	status := http.StatusNoContent
	if isFormPost(r) && r.Header.Get(webauth.CSRFHeader) == "" {
		status = http.StatusSeeOther
	}
	if p.auditLogout != nil {
		if pr, ok := portal.PrincipalFrom(r.Context()); ok {
			p.auditLogout(r, pr, status)
		}
	}
	http.SetCookie(w, p.cookie.Clear())
	if status == http.StatusSeeOther {
		http.Redirect(w, r, portal.Home, status)
		return
	}
	w.WriteHeader(status)
}

func isFormPost(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/x-www-form-urlencoded"
}

// recordPortalLogout records portal.logout for the session's user. With
// admin audit off it is never wired.
func (s *Server) recordPortalLogout(r *http.Request, pr portal.Principal, status int) {
	a := s.audit
	s.recordAuth(r.Context(), adminaudit.Input{
		Actor: adminaudit.Actor{Sub: pr.Sub, Email: pr.Email}, AuthMethod: adminaudit.AuthMethodOIDC,
		Action: actionPortalLogout, Target: targetPortalSession, TargetRef: shortHash(pr.SessionHash),
		Outcome: adminaudit.OutcomeOK, HTTPStatus: status,
		ClientIP: clientIP(r, a.trusted), RequestID: RequestIDFrom(r.Context()),
	})
}

const actionPortalLogout = "portal.logout"
