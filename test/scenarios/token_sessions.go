package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/test/harness"
)

// Admin revocation of token sessions (W-P2-TOKX-07): an admin revokes one
// session, or every session of a user or an agent, and the very next exchange
// of a revoked session is refused with invalid_grant/session_revoked. The
// harness drives the control plane in console.auth none, so the admin bearer is
// the credential; role checks (editor and viewer get 403) are covered by the
// control plane's unit tests, which run in oidc mode. A token already minted is
// not recalled: it stays valid until its exp.

// revokedSubjectBound is the identity max token ttl plus clock skew (the
// harness leaves both at their defaults).
const revokedSubjectBound = identity.DefaultMaxTokenTTL + identity.DefaultClockSkew

const (
	tokenSessionsPath    = "/dashboard/api/token-sessions"
	tokenSessionsRevoke  = "/dashboard/api/token-sessions/revoke"
	revokedRetentionTick = 10 * time.Minute
)

type sessionRow struct {
	SID       string `json:"sid"`
	AgentID   string `json:"agent_id"`
	Sub       string `json:"sub"`
	RevokedAt string `json:"revoked_at"`
}

// adminCall sends a token session admin request with the control plane's
// admin bearer.
func adminCall(t *testing.T, h *harness.H, method, path, body string) (int, string) {
	t.Helper()
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	status, resp, err := h.CP().Do(method, path, h.ControlPlaneAdminToken(), b)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return status, resp
}

// listSessions returns the token sessions of the admin list, by sid.
func listSessions(t *testing.T, h *harness.H, query string) map[string]sessionRow {
	t.Helper()
	status, body := adminCall(t, h, http.MethodGet, tokenSessionsPath+query, "")
	var out struct{ Sessions []sessionRow }
	if status != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil {
		t.Fatalf("list token sessions = %d %s", status, body)
	}
	m := map[string]sessionRow{}
	for _, s := range out.Sessions {
		m[s.SID] = s
	}
	return m
}

// exchangeSID exchanges subject at agent and returns the issued token's sid.
func exchangeSID(t *testing.T, h *harness.H, agent *harness.TokenAgent, subject string) string {
	t.Helper()
	tr := decodeToken(t, exchangeForm(h, agent.Form(subject, nil)))
	_, c := verifyWardenToken(t, h, tr.AccessToken)
	return c.SID
}

func requireRevoked(t *testing.T, h *harness.H, name string, agent *harness.TokenAgent, subject string) {
	t.Helper()
	requireRefusal(t, name, exchangeForm(h, agent.Form(subject, nil)), 400, "invalid_grant", "session_revoked")
}

func tokenAuditRows(h *harness.H) []harness.AdminAuditRow {
	var out []harness.AdminAuditRow
	for _, r := range h.AdminAuditRows() {
		if r.Target == "token_sessions" {
			out = append(out, r)
		}
	}
	return out
}

// tokenSessionRevokeOne: revoking one session by sid is 204 and audited; the
// next exchange of that user through that agent is refused, another user is
// not, a subject token issued after the revoke starts a new session, an
// unknown sid is 404, and a Warden token minted before the revoke still
// verifies until its exp.
func tokenSessionRevokeOne(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	user1, user2 := tokenUser(h, "user-1", "eng"), tokenUser(h, "user-2", "eng")
	minted := decodeToken(t, exchangeForm(h, agent.Form(user1, nil)))
	_, claims := verifyWardenToken(t, h, minted.AccessToken)
	sid := claims.SID
	other := exchangeSID(t, h, agent, user2)

	if rows := listSessions(t, h, "?agent_id=harness-agent"); len(rows) != 2 || rows[sid].Sub != "user-1" || rows[sid].RevokedAt != "" {
		t.Fatalf("list before the revoke = %+v", rows)
	}
	auditBefore := len(tokenAuditRows(h))
	path := tokenSessionsPath + "/" + sid + "/revoke"
	if status, _, _ := h.CP().Do(http.MethodPost, path, "", nil); status != http.StatusUnauthorized {
		t.Errorf("revoke without the admin bearer = %d, want 401", status)
	}
	if status, _, _ := h.CP().Do(http.MethodGet, tokenSessionsPath, "", nil); status != http.StatusUnauthorized {
		t.Errorf("list without the admin bearer = %d, want 401", status)
	}
	if got := exchangeSID(t, h, agent, user1); got != sid {
		t.Fatalf("an unauthenticated revoke changed the session: sid %s, want %s", got, sid)
	}

	h.Clock().Advance(time.Second)
	if status, body := adminCall(t, h, http.MethodPost, path, ""); status != http.StatusNoContent || body != "" {
		t.Fatalf("revoke = %d %q, want an empty 204", status, body)
	}
	rows := tokenAuditRows(h)
	if len(rows) != auditBefore+1 {
		t.Fatalf("%d token_sessions audit rows, want %d", len(rows), auditBefore+1)
	}
	if r := rows[len(rows)-1]; r.Action != "token_sessions.revoke" || r.TargetRef != "sid:"+sid || r.Outcome != "ok" || r.HTTPStatus != 204 ||
		r.BeforeHash == "" || r.BeforeHash == r.AfterHash {
		t.Errorf("audit row = %+v", r)
	}

	// The very next exchange, with the same subject token, is refused.
	requireRevoked(t, h, "revoked session", agent, user1)
	if events := h.TokenEvents(); events[len(events)-1].Outcome != "denied" || events[len(events)-1].Reason != "session_revoked" {
		t.Errorf("last token event = %+v, want denied/session_revoked", events[len(events)-1])
	}
	if got := exchangeSID(t, h, agent, user2); got != other {
		t.Errorf("another user's session changed: %s, want %s", got, other)
	}
	// A token minted before the revoke is not recalled: it lives until its exp.
	if _, c := verifyWardenToken(t, h, minted.AccessToken); c.SID != sid {
		t.Errorf("minted token sid = %s", c.SID)
	}

	// The user signs in again: a subject token issued after the revoke starts
	// a new session; the old row stays, marked revoked.
	h.Clock().Advance(2 * time.Second)
	if fresh := exchangeSID(t, h, agent, tokenUser(h, "user-1", "eng")); fresh == sid || !strings.HasPrefix(fresh, "wts_") {
		t.Errorf("sid after sign-in = %s, want a new session", fresh)
	}
	if rows := listSessions(t, h, "?sub=user-1"); len(rows) != 2 || rows[sid].RevokedAt == "" {
		t.Errorf("list after the revoke = %+v, want the revoked row kept and a new one", rows)
	}

	// Idempotent; unknown is 404.
	if status, _ := adminCall(t, h, http.MethodPost, path, ""); status != http.StatusNoContent {
		t.Errorf("repeat revoke = %d, want 204", status)
	}
	if status, _ := adminCall(t, h, http.MethodPost, tokenSessionsPath+"/wts_doesnotexistdoesnot/revoke", ""); status != http.StatusNotFound {
		t.Errorf("unknown sid = %d, want 404", status)
	}
	requireNoCredentialsInLogs(t, h, user1, user2, minted.AccessToken)
}

// tokenSessionRevokeAll: revoke by agent_id revokes only that agent's sessions
// and the count matches; revoke by sub revokes that user's sessions at every
// agent; a repeat revokes none; a filterless body is 400.
func tokenSessionRevokeAll(t *testing.T, h *harness.H) {
	a := h.RegisterTokenAgent("agent-a", []string{"eng"}, []string{"read"})
	b := h.RegisterTokenAgent("agent-b", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	user1, user2 := tokenUser(h, "user-1", "eng"), tokenUser(h, "user-2", "eng")
	exchangeSID(t, h, a, user1)
	exchangeSID(t, h, a, user2)
	exchangeSID(t, h, b, user1)

	for _, body := range []string{``, `{}`, `{"sub":""}`, `{"unknown":"x"}`} {
		if status, _ := adminCall(t, h, http.MethodPost, tokenSessionsRevoke, body); status != http.StatusBadRequest {
			t.Errorf("revoke with body %q = %d, want 400", body, status)
		}
	}
	if exchangeSID(t, h, b, user1) == "" {
		t.Fatal("a refused revoke changed a session")
	}
	auditBefore := len(tokenAuditRows(h)) // the refusals above are audited too

	h.Clock().Advance(time.Second)
	revoked := func(body string) int {
		t.Helper()
		status, resp := adminCall(t, h, http.MethodPost, tokenSessionsRevoke, body)
		var out struct{ Revoked int }
		if status != http.StatusOK || json.Unmarshal([]byte(resp), &out) != nil {
			t.Fatalf("revoke %s = %d %s", body, status, resp)
		}
		return out.Revoked
	}
	if n := revoked(`{"agent_id":"agent-a"}`); n != 2 {
		t.Errorf("revoked by agent = %d, want 2 (agent-a's two sessions)", n)
	}
	requireRevoked(t, h, "agent-a user-1", a, user1)
	requireRevoked(t, h, "agent-a user-2", a, user2)
	if exchangeSID(t, h, b, user1) == "" {
		t.Error("agent-b's session was revoked by an agent-a revoke")
	}
	if n := revoked(`{"agent_id":"agent-a"}`); n != 0 {
		t.Errorf("repeat revoked %d, want 0", n)
	}
	if n := revoked(`{"sub":"user-1"}`); n != 1 {
		t.Errorf("revoked by sub = %d, want 1 (agent-b's; agent-a's was already revoked)", n)
	}
	requireRevoked(t, h, "agent-b user-1", b, user1)

	rows := tokenAuditRows(h)
	if len(rows) != auditBefore+3 {
		t.Fatalf("%d token_sessions audit rows, want %d", len(rows), auditBefore+3)
	}
	if r := rows[auditBefore]; r.Action != "token_sessions.revoke_all" || r.TargetRef != "filter:agent=agent-a" {
		t.Errorf("by-agent audit row = %+v", r)
	}
	if r := rows[auditBefore+2]; !strings.HasPrefix(r.TargetRef, "filter:sub_sha256=") || strings.Contains(r.TargetRef, "user-1") {
		t.Errorf("by-sub audit row target_ref = %q, want a hash and not the subject", r.TargetRef)
	}
	requireNoCredentialsInLogs(t, h, user1, user2)
}

// tokenSessionRevokeRetained: a revoked row outlives every subject token that
// was issued before the revoke, so the retention pass never turns a revoke back
// into a fresh session for such a token; once those tokens are expired the row
// is purged.
func tokenSessionRevokeRetained(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	user := tokenUser(h, "user-1", "eng")
	sid := exchangeSID(t, h, agent, user)
	h.Clock().Advance(time.Second)
	revokedAt := h.Clock().Now()
	if status, _ := adminCall(t, h, http.MethodPost, tokenSessionsPath+"/"+sid+"/revoke", ""); status != http.StatusNoContent {
		t.Fatalf("revoke = %d", status)
	}
	// The spent assertion's record is purged by the first retention pass, which
	// shows a pass has run. Whenever one has, the revoked row must still be
	// there unless a whole subject lifetime has passed since the revoke.
	h.Eventually("a retention pass runs", func() bool {
		h.Clock().Advance(revokedRetentionTick)
		if h.TokenReplayRows() != 0 {
			return false
		}
		if elapsed := h.Clock().Now().Sub(revokedAt); elapsed < revokedSubjectBound {
			if _, ok := listSessions(t, h, "?agent_id=harness-agent")[sid]; !ok {
				t.Errorf("the revoked session was purged %s after the revoke, before a subject token could expire (%s)", elapsed, revokedSubjectBound)
			}
		}
		return true
	})
	h.Eventually("the revoked row is purged once subject tokens have expired", func() bool {
		h.Clock().Advance(time.Hour)
		_, ok := listSessions(t, h, "?agent_id=harness-agent")[sid]
		return !ok
	})
	if got := h.Clock().Now().Sub(revokedAt); got < revokedSubjectBound {
		t.Errorf("purged after %s, want at least %s", got, revokedSubjectBound)
	}
	// By then the old subject token is expired too: still refused.
	requireRefusal(t, "old subject after the purge", exchangeForm(h, agent.Form(user, nil)), 400, "invalid_grant", "subject_expired")
}

// tokenSessionRoutesDisabled: with tokenService disabled every token session
// route is 404, even for the admin.
func tokenSessionRoutesDisabled(t *testing.T, h *harness.H) {
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, tokenSessionsPath, ""},
		{http.MethodPost, tokenSessionsRevoke, `{"agent_id":"a"}`},
		{http.MethodPost, tokenSessionsPath + "/wts_x/revoke", ""},
	} {
		if status, _ := adminCall(t, h, c.method, c.path, c.body); status != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404 with the token service disabled", c.method, c.path, status)
		}
	}
}
