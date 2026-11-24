package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/tokensvc"
)

// The token session admin API (W-P2-TOKX-07). A token session is one user at
// one IdP using one agent (tokensvc.SessionStore); revoking it makes the token
// service refuse every exchange whose subject token was issued at or before the
// revoke (invalid_grant/session_revoked), so the user must sign in again. The
// check reads the session table on each exchange, so a revoke applies to the
// very next exchange of this control plane, with no cache to clear.
//
// A revoke does not reach Warden tokens already minted: they are short-lived
// JWTs that workers verify offline against the served JWKS and have no
// revocation list, so each stays valid until its exp (at most tokenService.ttl,
// default 15m). To stop traffic sooner, block the user (block list), disable
// the agent, or rotate the token key.
//
//	GET  /dashboard/api/token-sessions?agent_id=&sub=&limit=&cursor=  list
//	POST /dashboard/api/token-sessions/{sid}/revoke                   204 or 404
//	POST /dashboard/api/token-sessions/revoke {sub?,idp_iss?,agent_id?} 200 {revoked:n}
//
// All three are admin-only; the revokes are audited (target token_sessions).
// Without the token service they are 404. No token value is ever read, shown or
// logged: the sid is an identifier, not a credential.

const (
	// tokenSessionsListPath is the list route; the revoke routes extend it.
	tokenSessionsListPath = "/dashboard/api/token-sessions"
	// tokenSessionsRevokeAllPath revokes by filter.
	tokenSessionsRevokeAllPath = "/dashboard/api/token-sessions/revoke"
	// tokenSessionRevokePath is the mux pattern of the single revoke; its table
	// key is the same string (dashboard.RoutePath maps requests to it).
	tokenSessionRevokePath = "/dashboard/api/token-sessions/{sid}/revoke"

	// auditTargetTokenSessions is the admin audit target of a revoke.
	auditTargetTokenSessions = "token_sessions"

	// maxRevokeFilterBody bounds the revoke-by-filter body.
	maxRevokeFilterBody = 4 << 10
	// maxSessionFilterLen bounds each filter value: an IdP subject is at most
	// 255 characters, and an issuer URL or agent id is shorter in practice.
	maxSessionFilterLen = 512
	// maxSessionSIDLen bounds a sid path segment (wts_ + 22 base64url chars).
	maxSessionSIDLen = 64
)

// tokenSessionView is one list row. The sub and issuer are shown so an admin
// can tell whose session a sid is; nothing here is a credential.
type tokenSessionView struct {
	SID        string `json:"sid"`
	AgentID    string `json:"agent_id"`
	IdPIss     string `json:"idp_iss"`
	Sub        string `json:"sub"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"`
	RevokedAt  string `json:"revoked_at,omitempty"`
}

// handleTokenSessionsList serves GET /dashboard/api/token-sessions.
func (s *Server) handleTokenSessionsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	limit := tokensvc.MaxSessionPage
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > tokensvc.MaxSessionPage {
			writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1 to " + strconv.Itoa(tokensvc.MaxSessionPage)})
			return
		}
		limit = n
	}
	query := tokensvc.SessionQuery{AgentID: q.Get("agent_id"), Sub: q.Get("sub"), Limit: limit}
	if len(query.AgentID) > maxSessionFilterLen || len(query.Sub) > maxSessionFilterLen {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "filter is too long"})
		return
	}
	if c := q.Get("cursor"); c != "" {
		created, sid, ok := parseSessionCursor(c)
		if !ok {
			writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cursor"})
			return
		}
		query.AfterCreated, query.AfterSID = created, sid
	}
	// One extra row says whether another page follows.
	query.Limit = limit + 1
	list, err := s.cfg.TokenEdge.Sessions.List(r.Context(), query)
	if err != nil {
		s.cfg.Logger.Error("token session list failed", "error_type", errorKind(err))
		writeAuthJSON(w, http.StatusInternalServerError, map[string]string{"error": "session store error"})
		return
	}
	next := ""
	if len(list) > limit {
		list = list[:limit]
		last := list[len(list)-1]
		next = strconv.FormatInt(last.CreatedAt.Unix(), 10) + "." + last.SID
	}
	out := make([]tokenSessionView, 0, len(list))
	for _, in := range list {
		v := tokenSessionView{
			SID: in.SID, AgentID: in.AgentID, IdPIss: in.IdPIss, Sub: in.Sub,
			CreatedAt: rfc3339(in.CreatedAt), LastUsedAt: rfc3339(in.LastUsedAt),
		}
		if !in.RevokedAt.IsZero() {
			v.RevokedAt = rfc3339(in.RevokedAt)
		}
		out = append(out, v)
	}
	writeAuthJSON(w, http.StatusOK, map[string]any{"sessions": out, "next": next})
}

// parseSessionCursor splits "<created unix>.<sid>".
func parseSessionCursor(c string) (time.Time, string, bool) {
	secs, sid, ok := strings.Cut(c, ".")
	if !ok || !validSessionSID(sid) {
		return time.Time{}, "", false
	}
	n, err := strconv.ParseInt(secs, 10, 64)
	if err != nil || n < 0 {
		return time.Time{}, "", false
	}
	return time.Unix(n, 0).UTC(), sid, true
}

// validSessionSID reports whether sid has the shape of a token session id.
func validSessionSID(sid string) bool {
	if !strings.HasPrefix(sid, tokensvc.SessionPrefix) || len(sid) > maxSessionSIDLen {
		return false
	}
	return plainChars(sid, "-_")
}

// plainChars reports whether s is only ASCII letters, digits and the extra
// characters.
func plainChars(s, extra string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune(extra, r):
		default:
			return false
		}
	}
	return true
}

// handleTokenSessionRevoke serves POST /dashboard/api/token-sessions/{sid}/revoke:
// 204 when the session exists (also when it was already revoked: the first
// revoked_at stays), 404 otherwise.
func (s *Server) handleTokenSessionRevoke(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if !validSessionSID(sid) {
		writeAuthJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	adminaudit.Annotate(r.Context(), "sid:"+sid, map[string]string{adminaudit.DetailOp: "revoke"})
	found, err := s.cfg.TokenEdge.Sessions.Revoke(r.Context(), sid, s.cfg.Clock.Now())
	if err != nil {
		s.cfg.Logger.Error("token session revoke failed", "error_type", errorKind(err))
		writeAuthJSON(w, http.StatusInternalServerError, map[string]string{"error": "session store error"})
		return
	}
	if !found {
		writeAuthJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	s.cfg.Logger.Info("token_session_revoked", "by", tokenSessionActor(r.Context()), "sid", sid)
	w.WriteHeader(http.StatusNoContent)
}

// revokeFilterBody is the body of the revoke-by-filter route.
type revokeFilterBody struct {
	Sub     string `json:"sub"`
	IdPIss  string `json:"idp_iss"`
	AgentID string `json:"agent_id"`
}

// handleTokenSessionsRevokeAll serves POST /dashboard/api/token-sessions/revoke:
// it revokes every live session matching the filter (at least one field) and
// answers {revoked: n}. A repeat revokes 0.
func (s *Server) handleTokenSessionsRevokeAll(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRevokeFilterBody+1))
	dec.DisallowUnknownFields()
	var body revokeFilterBody
	if err := dec.Decode(&body); err != nil || dec.More() {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be a JSON object with sub, idp_iss and agent_id"})
		return
	}
	filter := tokensvc.SessionFilter{IdPIss: body.IdPIss, Sub: body.Sub, AgentID: body.AgentID}
	switch {
	case filter.Empty():
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one of sub, idp_iss or agent_id is required"})
		return
	case len(filter.IdPIss) > maxSessionFilterLen || len(filter.Sub) > maxSessionFilterLen || len(filter.AgentID) > maxSessionFilterLen:
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "filter is too long"})
		return
	}
	adminaudit.Annotate(r.Context(), filterTargetRef(filter), map[string]string{adminaudit.DetailOp: "revoke_all"})
	n, err := s.cfg.TokenEdge.Sessions.RevokeAll(r.Context(), filter, s.cfg.Clock.Now())
	if err != nil {
		s.cfg.Logger.Error("token session revoke failed", "error_type", errorKind(err))
		writeAuthJSON(w, http.StatusInternalServerError, map[string]string{"error": "session store error"})
		return
	}
	s.cfg.Logger.Info("token_sessions_revoked", "by", tokenSessionActor(r.Context()), "count", n,
		"by_agent", filter.AgentID != "", "by_sub", filter.Sub != "", "by_idp_iss", filter.IdPIss != "")
	writeAuthJSON(w, http.StatusOK, map[string]int64{"revoked": n})
}

// filterTargetRef is the audit target_ref of a revoke-by-filter: the fields
// that were set. The agent id is a registry identifier and is written as is
// when it is a plain one; a subject and an issuer are written as short SHA-256
// prefixes, so the row names whom without carrying a person's identifier.
func filterTargetRef(f tokensvc.SessionFilter) string {
	var parts []string
	if f.AgentID != "" {
		parts = append(parts, "agent="+refValue(f.AgentID))
	}
	if f.Sub != "" {
		parts = append(parts, "sub_sha256="+shortSHA(f.Sub))
	}
	if f.IdPIss != "" {
		parts = append(parts, "iss_sha256="+shortSHA(f.IdPIss))
	}
	return "filter:" + strings.Join(parts, ",")
}

// refValue returns v when it is a short plain identifier, else its hash.
func refValue(v string) string {
	if len(v) > 64 || !plainChars(v, "-_.:") {
		return "sha256:" + shortSHA(v)
	}
	return v
}

func shortSHA(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}

// tokenSessionActor names the admin for the log line: the console subject, or
// the admin bearer's fixed actor.
func tokenSessionActor(ctx context.Context) string {
	if p, ok := PrincipalFrom(ctx); ok && p.Sub != "" {
		return p.Sub
	}
	return actorCPAdminToken
}

// tokenSessionsHash is the keyed hash of the revoked-row summary: it changes
// when a revoke changes anything and stays equal when it changed nothing.
func (s *Server) tokenSessionsHash(ctx context.Context) (string, error) {
	n, latest, err := s.cfg.TokenEdge.Sessions.RevokedState(ctx)
	if err != nil {
		return "", err
	}
	return s.stateHashJSON(auditTargetTokenSessions, map[string]int64{"revoked": n, "latest": latest.Unix()})
}

// bearerGate admits a request only with the CP admin bearer, for console.auth
// none, where there are no roles: the token session routes (reads included,
// since they list whose sessions exist) need the same credential as the
// dashboard's writes.
func (s *Server) bearerGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.adminBearerOK(r) {
			writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mountTokenSessions mounts the token session routes. Without the token
// service (or in a unit-test server with no session store) all three are 404.
// oidc mode runs them behind withSession and requireRole like every admin
// route; none mode needs the admin bearer.
func (s *Server) mountTokenSessions(mux *http.ServeMux, classify func(*http.Request) (authzRow, bool), oidc bool) {
	if s.cfg.Tokens == nil || s.cfg.TokenEdge.Sessions == nil {
		mux.Handle(tokenSessionsListPath, http.NotFoundHandler())
		mux.Handle(tokenSessionsRevokeAllPath, http.NotFoundHandler())
		mux.Handle(tokenSessionRevokePath, http.NotFoundHandler())
		return
	}
	s.RegisterStateHasher(auditTargetTokenSessions, s.tokenSessionsHash)
	table := authzTable()
	guard := func(h http.HandlerFunc) http.Handler {
		if oidc {
			return s.sessionAuditWrap(classify, requireRole(h, table, s.cfg.Console, s.cfg.Logger))
		}
		return s.sessionAuditWrap(classify, s.bearerGate(h))
	}
	mux.Handle(tokenSessionsListPath, methodOnly(http.MethodGet, guard(s.handleTokenSessionsList)))
	mux.Handle(tokenSessionsRevokeAllPath, methodOnly(http.MethodPost, guard(s.handleTokenSessionsRevokeAll)))
	mux.Handle(tokenSessionRevokePath, methodOnly(http.MethodPost, guard(s.handleTokenSessionRevoke)))
}

// methodOnly answers 405 with Allow for any other method, before any
// authentication: the route exists, the verb does not.
func methodOnly(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeAuthJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
