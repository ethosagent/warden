package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/tokensvc"
)

const testIdP = "https://idp.example.com"

var testSessionPolicy = tokensvc.SessionPolicy{Idle: 12 * time.Hour, Absolute: 168 * time.Hour}

// touchTokenSession starts (or continues) the token session of sub at agent
// and returns its sid.
func touchTokenSession(t *testing.T, e *auditEnv, sub, agent, sid string) string {
	t.Helper()
	now := e.srv.cfg.Clock.Now()
	got, err := e.srv.cfg.TokenEdge.Sessions.Touch(context.Background(),
		tokensvc.SessionKey{IdPIss: testIdP, Sub: sub, AgentID: agent}, now, now, testSessionPolicy, sid)
	if err != nil {
		t.Fatalf("touch %s/%s: %v", sub, agent, err)
	}
	return got
}

// exchangeAfterRevoke asks the session store what the next exchange of sub at
// agent would get, with a subject token issued at issuedAt.
func exchangeAfterRevoke(e *auditEnv, sub, agent string, issuedAt time.Time) error {
	_, err := e.srv.cfg.TokenEdge.Sessions.Touch(context.Background(),
		tokensvc.SessionKey{IdPIss: testIdP, Sub: sub, AgentID: agent}, issuedAt, e.srv.cfg.Clock.Now(), testSessionPolicy, "wts_fresh")
	return err
}

// TestTokenSessionRevoke: an admin revoke is 204 and one audit row (target
// token_sessions, target_ref sid:<sid>) whose state hash moves; a repeat is 204
// and changes nothing; an unknown or malformed sid is 404 and writes the row
// with the 404 outcome; editors and viewers get 403 and revoke nothing. The
// next exchange of that session is refused, and a subject token issued after
// the revoke starts a new session.
func TestTokenSessionRevoke(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin, editor, viewer := e.session(t, groupAdmin), e.session(t, groupEditor), e.session(t, groupViewer)
	issuedBefore := e.srv.cfg.Clock.Now()
	sidA := touchTokenSession(t, e, "u1", "agent-a", "wts_aaaaaaaaaaaaaaaaaaaaaa")
	touchTokenSession(t, e, "u2", "agent-a", "wts_bbbbbbbbbbbbbbbbbbbbbb")
	path := "/dashboard/api/token-sessions/" + sidA + "/revoke"
	rows := func() []adminaudit.Input { return e.rec.inputs() }

	for name, raw := range map[string]string{"editor": editor, "viewer": viewer} {
		if rec := e.send(raw, "", http.MethodPost, path, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s revoke = %d, want 403", name, rec.Code)
		}
	}
	if rec := e.send("", "", http.MethodPost, path, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous revoke = %d, want 401", rec.Code)
	}
	if err := exchangeAfterRevoke(e, "u1", "agent-a", issuedBefore); err != nil {
		t.Fatalf("a refused revoke still revoked the session: %v", err)
	}
	for _, r := range rows() {
		if r.Target == auditTargetTokenSessions && r.Outcome == adminaudit.OutcomeOK {
			t.Fatalf("a refused revoke wrote an ok row: %+v", r)
		}
	}

	e.srv.cfg.Clock.(*clocktest.Fake).Advance(time.Minute)
	before := len(rows())
	rec := e.send(admin, "", http.MethodPost, path, "")
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("admin revoke = %d %q, want an empty 204", rec.Code, rec.Body.String())
	}
	got := rows()
	if len(got) != before+1 {
		t.Fatalf("%d audit rows after the revoke, want %d", len(got), before+1)
	}
	first := got[len(got)-1]
	if first.Action != "token_sessions.revoke" || first.Target != "token_sessions" || first.TargetRef != "sid:"+sidA ||
		first.Details[adminaudit.DetailOp] != "revoke" || first.Outcome != adminaudit.OutcomeOK || first.HTTPStatus != 204 ||
		first.ActorRole != "admin" || first.BeforeHash == "" || first.BeforeHash == first.AfterHash {
		t.Errorf("audit row = %+v", first)
	}

	// The very next exchange of that session is refused; a subject issued
	// after the revoke starts a new session; another user is untouched.
	if err := exchangeAfterRevoke(e, "u1", "agent-a", issuedBefore); !errors.Is(err, tokensvc.ErrSessionRevoked) {
		t.Errorf("exchange after revoke = %v, want ErrSessionRevoked", err)
	}
	if err := exchangeAfterRevoke(e, "u2", "agent-a", issuedBefore); err != nil {
		t.Errorf("another user's session was revoked: %v", err)
	}
	e.srv.cfg.Clock.(*clocktest.Fake).Advance(time.Minute)
	if err := exchangeAfterRevoke(e, "u1", "agent-a", e.srv.cfg.Clock.Now()); err != nil {
		t.Errorf("a subject issued after the revoke was refused: %v", err)
	}

	// Idempotent: 204 again, a row, no state change.
	if rec := e.send(admin, "", http.MethodPost, path, ""); rec.Code != http.StatusNoContent {
		t.Errorf("repeat revoke = %d, want 204", rec.Code)
	}
	again := rows()[len(rows())-1]
	if again.BeforeHash != again.AfterHash {
		t.Errorf("a repeat revoke moved the state hash: %+v", again)
	}

	for _, p := range []string{"wts_doesnotexistdoesnot", "nope", "wts_" + strings.Repeat("a", 80), "wts_bad%20sid"} {
		if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/token-sessions/"+p+"/revoke", ""); rec.Code != http.StatusNotFound {
			t.Errorf("revoke of %q = %d, want 404", p, rec.Code)
		}
	}
	if rec := e.send(admin, "", http.MethodGet, path, ""); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Errorf("GET on the revoke route = %d allow %q, want 405 POST", rec.Code, rec.Header().Get("Allow"))
	}
	assertNoTokenMaterial(t, e)
}

// assertNoTokenMaterial checks no log line or audit row carries a raw subject.
func assertNoTokenMaterial(t *testing.T, e *auditEnv) {
	t.Helper()
	logs := e.log.String()
	for _, r := range e.rec.inputs() {
		b, _ := json.Marshal(r)
		logs += string(b)
	}
	for _, secret := range []string{"Bearer ", "subject_token", "client_assertion"} {
		if strings.Contains(logs, secret) {
			t.Errorf("log or audit contains %q", secret)
		}
	}
}

// TestTokenSessionRevokeAll: the filter revokes only matching live sessions and
// the count is exact; a repeat revokes 0; the audit row names the filter
// without the raw subject; a bad body is 400 and revokes nothing.
func TestTokenSessionRevokeAll(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin, editor := e.session(t, groupAdmin), e.session(t, groupEditor)
	t0 := e.srv.cfg.Clock.Now()
	touchTokenSession(t, e, "u1", "agent-a", "wts_aaaaaaaaaaaaaaaaaaaaaa")
	touchTokenSession(t, e, "u2", "agent-a", "wts_bbbbbbbbbbbbbbbbbbbbbb")
	touchTokenSession(t, e, "u1", "agent-b", "wts_cccccccccccccccccccccc")
	const route = "/dashboard/api/token-sessions/revoke"

	if rec := e.send(editor, "", http.MethodPost, route, `{"agent_id":"agent-a"}`); rec.Code != http.StatusForbidden {
		t.Errorf("editor revoke-all = %d, want 403", rec.Code)
	}
	for _, body := range []string{``, `{}`, `{"sub":""}`, `[]`, `{"sub":"u1"} {"x":1}`, `{"sub":"u1","extra":1}`, `{"agent_id":"` + strings.Repeat("a", 600) + `"}`, `not json`} {
		if rec := e.send(admin, "", http.MethodPost, route, body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %.30q = %d, want 400", body, rec.Code)
		}
	}
	for _, c := range []struct{ sub, agent string }{{"u1", "agent-a"}, {"u2", "agent-a"}, {"u1", "agent-b"}} {
		if err := exchangeAfterRevoke(e, c.sub, c.agent, t0); err != nil {
			t.Fatalf("a refused request revoked %s/%s: %v", c.sub, c.agent, err)
		}
	}

	e.srv.cfg.Clock.(*clocktest.Fake).Advance(time.Minute)
	rec := e.send(admin, "", http.MethodPost, route, `{"agent_id":"agent-a"}`)
	var out struct{ Revoked int }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Revoked != 2 {
		t.Fatalf("revoke by agent = %d %s, want 200 {revoked:2}", rec.Code, rec.Body.String())
	}
	row := e.rec.inputs()[len(e.rec.inputs())-1]
	if row.Action != "token_sessions.revoke_all" || row.Target != "token_sessions" || row.TargetRef != "filter:agent=agent-a" ||
		row.Details[adminaudit.DetailOp] != "revoke_all" || row.BeforeHash == row.AfterHash {
		t.Errorf("audit row = %+v", row)
	}
	for _, c := range []struct {
		sub, agent string
		revoked    bool
	}{{"u1", "agent-a", true}, {"u2", "agent-a", true}, {"u1", "agent-b", false}} {
		err := exchangeAfterRevoke(e, c.sub, c.agent, t0)
		if c.revoked != errors.Is(err, tokensvc.ErrSessionRevoked) {
			t.Errorf("%s/%s after revoke by agent: err %v, want revoked=%v", c.sub, c.agent, err, c.revoked)
		}
	}
	if rec := e.send(admin, "", http.MethodPost, route, `{"agent_id":"agent-a"}`); !strings.Contains(rec.Body.String(), `"revoked":0`) {
		t.Errorf("repeat = %s, want revoked 0", rec.Body.String())
	}

	// By sub: the row says a sub and an issuer were named, never which.
	rec = e.send(admin, "", http.MethodPost, route, `{"sub":"u1@corp.example","idp_iss":"`+testIdP+`"}`)
	row = e.rec.inputs()[len(e.rec.inputs())-1]
	if b, _ := json.Marshal(row); rec.Code != http.StatusOK || row.TargetRef != "filter" ||
		row.Details[adminaudit.DetailHasSub] != "true" || row.Details[adminaudit.DetailHasIss] != "true" ||
		strings.Contains(string(b), "corp.example") {
		t.Errorf("revoke by sub = %d, ref %q", rec.Code, row.TargetRef)
	}
	rec = e.send(admin, "", http.MethodPost, route, `{"sub":"u1"}`)
	if !strings.Contains(rec.Body.String(), `"revoked":1`) {
		t.Errorf("revoke by sub u1 = %s, want agent-b's session only (agent-a's already revoked)", rec.Body.String())
	}
	assertNoTokenMaterial(t, e)
}

// TestTokenSessionsList: filters, newest first, pages of at most 200 with a
// cursor, revoked_at only on revoked rows, admin only.
func TestTokenSessionsList(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin, viewer := e.session(t, groupAdmin), e.session(t, groupViewer)
	clk := e.srv.cfg.Clock.(*clocktest.Fake)
	sids := []string{"wts_1111111111111111111111", "wts_2222222222222222222222", "wts_3333333333333333333333"}
	for i, sub := range []string{"u1", "u2", "u3"} {
		agent := "agent-a"
		if i == 2 {
			agent = "agent-b"
		}
		touchTokenSession(t, e, sub, agent, sids[i])
		clk.Advance(time.Minute)
	}
	if found, err := e.srv.cfg.TokenEdge.Sessions.Revoke(context.Background(), sids[0], e.srv.cfg.Clock.Now()); err != nil || !found {
		t.Fatal(found, err)
	}

	type page struct {
		Sessions []tokenSessionView
		Next     string
	}
	get := func(raw, q string) (int, page) {
		rec := e.send(raw, "", http.MethodGet, "/dashboard/api/token-sessions"+q, "")
		var p page
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("list body: %v", err)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("list is cacheable: %v", rec.Header())
			}
		}
		return rec.Code, p
	}
	if code, _ := get(viewer, ""); code != http.StatusForbidden {
		t.Errorf("viewer list = %d, want 403", code)
	}
	code, all := get(admin, "")
	if code != 200 || len(all.Sessions) != 3 || all.Next != "" || all.Sessions[0].SID != sids[2] || all.Sessions[2].SID != sids[0] {
		t.Fatalf("list = %d %+v, want 3 newest first", code, all)
	}
	if all.Sessions[2].RevokedAt == "" || all.Sessions[0].RevokedAt != "" || all.Sessions[0].AgentID != "agent-b" || all.Sessions[0].LastUsedAt == "" {
		t.Errorf("rows = %+v", all.Sessions)
	}
	if _, a := get(admin, "?agent_id=agent-a"); len(a.Sessions) != 2 {
		t.Errorf("agent filter = %+v", a.Sessions)
	}
	if _, s := get(admin, "?sub=u2&agent_id=agent-a"); len(s.Sessions) != 1 || s.Sessions[0].SID != sids[1] {
		t.Errorf("sub+agent filter = %+v", s.Sessions)
	}
	// Paging: two at a time.
	_, p1 := get(admin, "?limit=2")
	if len(p1.Sessions) != 2 || p1.Next == "" {
		t.Fatalf("page 1 = %+v", p1)
	}
	_, p2 := get(admin, "?limit=2&cursor="+p1.Next)
	if len(p2.Sessions) != 1 || p2.Sessions[0].SID != sids[0] || p2.Next != "" {
		t.Errorf("page 2 = %+v", p2)
	}
	for _, q := range []string{"?limit=0", "?limit=201", "?limit=x", "?cursor=junk", "?cursor=1.notasid", "?cursor=-5.wts_x"} {
		if code, _ := get(admin, q); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, code)
		}
	}
}

// TestTokenSessionRoutesDisabled: without the token service every token
// session route is 404 for every caller, in oidc and in none mode.
func TestTokenSessionRoutesDisabled(t *testing.T) {
	check := func(name string, e *auditEnv, who ...[2]string) {
		t.Helper()
		e.srv.cfg.Tokens = nil
		e.srv.cfg.TokenEdge = TokenEdge{}
		h := e.srv.Handler()
		for _, w := range who {
			for _, rt := range []struct{ method, path string }{
				{http.MethodGet, "/dashboard/api/token-sessions"},
				{http.MethodPost, "/dashboard/api/token-sessions/revoke"},
				{http.MethodPost, "/dashboard/api/token-sessions/wts_x/revoke"},
			} {
				req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(`{"agent_id":"a"}`))
				if w[0] != "" {
					req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: w[0]})
					if rt.method != http.MethodGet {
						req.Header.Set(CSRFHeader, CSRFToken(w[0]))
					}
				}
				if w[1] != "" {
					req.Header.Set("Authorization", "Bearer "+w[1])
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s: %s %s as %q = %d, want 404", name, rt.method, rt.path, w, rec.Code)
				}
			}
		}
		if n := len(e.rec.inputs()); n != 0 {
			t.Errorf("%s: %d audit rows from 404 routes", name, n)
		}
	}
	oidc := newOIDCAuditEnv(t)
	check("oidc", oidc, [2]string{oidc.session(t, groupAdmin), ""}, [2]string{oidc.session(t, groupEditor), ""}, [2]string{"", ""})
	none := newAuditEnv(t, auditEnvOpts{token: dashTestToken, adminToken: "admin-bearer"})
	check("none", none, [2]string{"", "admin-bearer"}, [2]string{"", ""})
}

// TestTokenSessionRoutesNoneMode: console.auth none has no roles, so the admin
// bearer is the credential for reads and writes alike.
func TestTokenSessionRoutesNoneMode(t *testing.T) {
	const adminTok = "admin-bearer"
	e := newAuditEnv(t, auditEnvOpts{token: dashTestToken, adminToken: adminTok})
	sid := touchTokenSession(t, e, "u1", "agent-a", "wts_aaaaaaaaaaaaaaaaaaaaaa")
	path := "/dashboard/api/token-sessions/" + sid + "/revoke"
	for _, tok := range []string{"", dashTestToken, "wrong"} {
		for _, rt := range []struct{ method, path string }{
			{http.MethodGet, "/dashboard/api/token-sessions"}, {http.MethodPost, path}, {http.MethodPost, "/dashboard/api/token-sessions/revoke"},
		} {
			if rec := e.send("", tok, rt.method, rt.path, `{"sub":"u1"}`); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with bearer %q = %d, want 401", rt.method, rt.path, tok, rec.Code)
			}
		}
	}
	if err := exchangeAfterRevoke(e, "u1", "agent-a", e.srv.cfg.Clock.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("an unauthenticated request revoked the session: %v", err)
	}
	if rec := e.send("", adminTok, http.MethodGet, "/dashboard/api/token-sessions", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), sid) {
		t.Errorf("list with the admin bearer = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.send("", adminTok, http.MethodPost, path, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke with the admin bearer = %d", rec.Code)
	}
	row := e.rec.inputs()[len(e.rec.inputs())-1]
	if row.Action != "token_sessions.revoke" || row.AuthMethod != adminaudit.AuthMethodBearer || row.Actor.Sub != actorCPAdminToken {
		t.Errorf("audit row = %+v", row)
	}
	if err := exchangeAfterRevoke(e, "u1", "agent-a", e.srv.cfg.Clock.Now().Add(-time.Hour)); !errors.Is(err, tokensvc.ErrSessionRevoked) {
		t.Errorf("exchange after revoke = %v", err)
	}
}

// TestFilterTargetRef: the audit reference of a filter revoke stays plain ASCII
// within the row's limits whatever the caller sent.
func TestFilterTargetRef(t *testing.T) {
	long := strings.Repeat("x", 500)
	for _, c := range []struct {
		f    tokensvc.SessionFilter
		want string
	}{
		{tokensvc.SessionFilter{AgentID: "agent-a"}, "filter:agent=agent-a"},
		{tokensvc.SessionFilter{AgentID: "a b\n"}, "filter:agent=other"},
		{tokensvc.SessionFilter{AgentID: long, Sub: long, IdPIss: long}, "filter:agent=other"},
		{tokensvc.SessionFilter{Sub: "u@corp.example"}, "filter"},
	} {
		got := filterTargetRef(c.f)
		if got != c.want {
			t.Errorf("filterTargetRef(%+v) = %q, want %q", c.f, got, c.want)
		}
	}
}

// TestTokenSessionsListPagesPast200: with 201 sessions the default page holds
// 200 rows and a cursor, and the second page holds the last row and no cursor.
func TestTokenSessionsListPagesPast200(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	for i := range tokensvc.MaxSessionPage + 1 {
		touchTokenSession(t, e, fmt.Sprintf("u%03d", i), "agent-a", fmt.Sprintf("wts_%022d", i))
	}
	type page struct {
		Sessions []tokenSessionView
		Next     string
	}
	get := func(q string) page {
		rec := e.send(admin, "", http.MethodGet, "/dashboard/api/token-sessions"+q, "")
		var p page
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &p) != nil {
			t.Fatalf("list %s = %d", q, rec.Code)
		}
		return p
	}
	p1 := get("")
	if len(p1.Sessions) != tokensvc.MaxSessionPage || p1.Next == "" {
		t.Fatalf("default page = %d rows, next %q; want 200 and a cursor", len(p1.Sessions), p1.Next)
	}
	p2 := get("?cursor=" + p1.Next)
	if len(p2.Sessions) != 1 || p2.Next != "" {
		t.Fatalf("page 2 = %d rows, next %q; want 1 and no cursor", len(p2.Sessions), p2.Next)
	}
	seen := map[string]bool{}
	for _, s := range append(p1.Sessions, p2.Sessions...) {
		seen[s.SID] = true
	}
	if len(seen) != tokensvc.MaxSessionPage+1 {
		t.Errorf("pages cover %d distinct sessions, want 201", len(seen))
	}
}
