package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The agent registry admin API (W-P2-AREG-02) on the control plane: the routes
// over a real SQLite store behind the oidc role table and the admin audit
// middleware, and the adapter's own behaviour.

const agentsAPIPath = "/dashboard/api/agents"

func agentJSON(t *testing.T, id, keyName string, groups ...string) string {
	t.Helper()
	g, _ := json.Marshal(groups)
	return `{"id":"` + id + `","displayName":"Agent ` + id + `","keys":[` + string(agentregtest.Ed25519JWK(t, keyName)) + `],"allowedGroups":` + string(g) + `}`
}

// agentUpdateJSON is an edit body (no id: it is the path's).
func agentUpdateJSON(t *testing.T, keyName string, groups ...string) string {
	t.Helper()
	g, _ := json.Marshal(groups)
	return `{"keys":[` + string(agentregtest.Ed25519JWK(t, keyName)) + `],"allowedGroups":` + string(g) + `}`
}

func decodeAgent(t *testing.T, rec *httptest.ResponseRecorder) dashboard.AgentView {
	t.Helper()
	var v dashboard.AgentView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode agent %q: %v", rec.Body.String(), err)
	}
	return v
}

func lastRow(t *testing.T, e *auditEnv, n int) adminaudit.Input {
	t.Helper()
	rows := e.rec.inputs()
	if len(rows) != n {
		t.Fatalf("admin audit rows = %d, want %d: %+v", len(rows), n, rows)
	}
	return rows[n-1]
}

// TestAgents_RolesAndAudit: viewers and editors read but cannot write; an admin
// creates, edits, disables and enables, each write leaves exactly one audit row
// naming agent:<id> with no key coordinates, and the views never carry any
// private or raw material.
func TestAgents_RolesAndAudit(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin, editor, viewer := e.session(t, groupAdmin), e.session(t, groupEditor), e.session(t, groupViewer)
	jwk := agentregtest.Ed25519JWK(t, "k1")
	var members map[string]string
	if err := json.Unmarshal(jwk, &members); err != nil {
		t.Fatal(err)
	}
	x := members["x"]

	body := agentJSON(t, "claude-code", "k1", "warden-agents")
	rows := 0
	for _, who := range []struct{ name, session string }{{"viewer", viewer}, {"editor", editor}} {
		for _, c := range []struct{ method, path, action string }{
			{http.MethodPost, agentsAPIPath, "agent.create"},
			{http.MethodPut, agentsAPIPath + "/claude-code", "agent.update"},
			{http.MethodPost, agentsAPIPath + "/claude-code/disable", "agent.disable"},
			{http.MethodPost, agentsAPIPath + "/claude-code/enable", "agent.enable"},
		} {
			rec := e.send(who.session, "", c.method, c.path, body, "If-Match", `"r1"`)
			rows++
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"role_required"`) {
				t.Fatalf("%s %s %s = %d %s, want 403 role_required", who.name, c.method, c.path, rec.Code, rec.Body)
			}
			if r := lastRow(t, e, rows); r.Outcome != adminaudit.OutcomeDenied || r.Action != c.action {
				t.Fatalf("%s %s row = %+v, want denied %s", who.name, c.path, r, c.action)
			}
		}
	}
	if got := e.srv.AgentRegistryWrites(); len(got) != 0 {
		t.Fatalf("a refused write was counted: %v", got)
	}

	rec := e.send(admin, "", http.MethodPost, agentsAPIPath, body)
	rows++
	if rec.Code != http.StatusCreated || rec.Header().Get("ETag") != `"r1"` || rec.Header().Get("Location") != agentsAPIPath+"/claude-code" {
		t.Fatalf("create = %d %s ETag %q Location %q", rec.Code, rec.Body, rec.Header().Get("ETag"), rec.Header().Get("Location"))
	}
	created := decodeAgent(t, rec)
	if created.ID != "claude-code" || created.Revision != 1 || created.Status != "active" || len(created.Keys) != 1 ||
		created.Keys[0].KID != created.Keys[0].JKT || created.Keys[0].Alg != "EdDSA" || created.Keys[0].JWK.X != x ||
		created.OwnerSub != "u1" || created.OwnerIss != "https://idp.example" || created.OwnerEmail != "u1@example.com" || created.CreatedBy != "oidc:u1" {
		t.Fatalf("created view = %+v", created)
	}
	if strings.Contains(rec.Body.String(), `"d"`) {
		t.Errorf("view carries a private member: %s", rec.Body)
	}
	r := lastRow(t, e, rows)
	if r.Action != "agent.create" || r.Target != "agents" || r.TargetRef != "agent:claude-code" || r.Outcome != adminaudit.OutcomeOK ||
		r.Details[adminaudit.DetailKidsAdded] != created.Keys[0].KID || r.Details[adminaudit.DetailJktsAdded] != created.Keys[0].JKT ||
		r.Details[adminaudit.DetailGroupsAdded] != "warden-agents" || r.Details[adminaudit.DetailGroupsRemoved+adminaudit.DetailCountSuffix] != "0" ||
		r.Details[adminaudit.DetailStatusTo] != "active" || r.BeforeHash == r.AfterHash {
		t.Fatalf("create row = %+v", r)
	}

	// Viewers and editors read.
	for _, s := range []string{viewer, editor} {
		if rec := e.send(s, "", http.MethodGet, agentsAPIPath+"/claude-code", ""); rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"r1"` {
			t.Errorf("read = %d ETag %q, want 200 \"r1\"", rec.Code, rec.Header().Get("ETag"))
		}
		rec := e.send(s, "", http.MethodGet, agentsAPIPath, "")
		var list struct{ Agents []dashboard.AgentView }
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Agents) != 1 {
			t.Errorf("list = %d %s, want one agent", rec.Code, rec.Body)
		}
	}
	if n := len(e.rec.inputs()); n != rows {
		t.Errorf("reads wrote audit rows: %d, want %d", n, rows)
	}

	// Update: rotate to a second key and add a group. The owner stays.
	upd := `{"displayName":"Renamed","keys":[` + string(jwk) + `,` + string(agentregtest.Ed25519JWK(t, "k2")) + `],"allowedGroups":["warden-agents","extra"]}`
	rec = e.send(admin, "", http.MethodPut, agentsAPIPath+"/claude-code", upd, "If-Match", `"r1"`)
	rows++
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"r2"` {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	updated := decodeAgent(t, rec)
	if updated.Revision != 2 || len(updated.Keys) != 2 || updated.OwnerSub != "u1" || updated.UpdatedBy != "oidc:u1" || updated.DisplayName != "Renamed" {
		t.Fatalf("updated view = %+v", updated)
	}
	r = lastRow(t, e, rows)
	if r.Action != "agent.update" || r.TargetRef != "agent:claude-code" || r.Details[adminaudit.DetailChanged] != "displayName,keys,allowedGroups" ||
		r.Details[adminaudit.DetailGroupsAdded] != "extra" || r.Details[adminaudit.DetailKidsAdded] == "" || r.Details[adminaudit.DetailKidsRemoved] != "" ||
		r.Details[adminaudit.DetailJktsAdded] == "" {
		t.Fatalf("update row = %+v", r)
	}

	for _, c := range []struct {
		action, path, rev, from, to string
	}{
		{"agent.disable", "/disable", `"r2"`, "active", "disabled"},
		{"agent.enable", "/enable", `"r3"`, "disabled", "active"},
	} {
		rec = e.send(admin, "", http.MethodPost, agentsAPIPath+"/claude-code"+c.path, "", "If-Match", c.rev)
		rows++
		if rec.Code != http.StatusOK || decodeAgent(t, rec).Status != c.to {
			t.Fatalf("%s = %d %s", c.action, rec.Code, rec.Body)
		}
		r = lastRow(t, e, rows)
		if r.Action != c.action || r.TargetRef != "agent:claude-code" || r.Details[adminaudit.DetailStatusFrom] != c.from || r.Details[adminaudit.DetailStatusTo] != c.to {
			t.Fatalf("%s row = %+v", c.action, r)
		}
	}

	// No row, log line or hash input carries a key coordinate.
	for _, in := range e.rec.inputs() {
		b, _ := json.Marshal(in)
		if strings.Contains(string(b), x) || strings.Contains(string(b), `"x":`) || strings.Contains(string(b), `"y":`) {
			t.Errorf("audit row carries key material: %s", b)
		}
	}
	if strings.Contains(e.log.String(), x) {
		t.Error("a log line carries a key coordinate")
	}

	want := map[AgentWriteKey]uint64{
		{agentActionCreate, agentOutcomeOK}: 1, {agentActionUpdate, agentOutcomeOK}: 1,
		{agentActionDisable, agentOutcomeOK}: 1, {agentActionEnable, agentOutcomeOK}: 1,
	}
	got := e.srv.AgentRegistryWrites()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("writes %v = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
	if c := e.srv.AgentRegistryCounts(context.Background()); c["active"] != 1 || c["disabled"] != 0 {
		t.Errorf("agents gauge = %v, want 1 active", c)
	}
}

// TestAgents_Errors: the status codes the issue names, through the whole chain.
func TestAgents_Errors(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	if rec := e.send(admin, "", http.MethodPost, agentsAPIPath, agentJSON(t, "a1", "k1", "g")); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}

	// A P-384 key names its own field.
	p384 := `{"id":"a2","keys":[{"kty":"EC","crv":"P-384","x":"AAAA","y":"AAAA"}],"allowedGroups":["g"]}`
	rec := e.send(admin, "", http.MethodPost, agentsAPIPath, p384)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"invalid_agent"`) || !strings.Contains(rec.Body.String(), `"field":"keys[0].crv"`) {
		t.Errorf("P-384 create = %d %s, want 400 invalid_agent keys[0].crv", rec.Code, rec.Body)
	}
	// A private member is refused by name and never echoed.
	priv := `{"id":"a2","keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA","d":"SECRET-PRIVATE-VALUE"}],"allowedGroups":["g"]}`
	rec = e.send(admin, "", http.MethodPost, agentsAPIPath, priv)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"keys[0].d"`) || strings.Contains(rec.Body.String(), "SECRET-PRIVATE-VALUE") {
		t.Errorf("private-key create = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(e.log.String(), "SECRET-PRIVATE-VALUE") {
		t.Error("a private value reached the logs")
	}
	rec = e.send(admin, "", http.MethodPost, agentsAPIPath, `{"id":"a2","keys":[],"allowedGroups":[" "]}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"allowedGroups[0]"`) {
		t.Errorf("empty group = %d %s, want the API's member name", rec.Code, rec.Body)
	}

	// Duplicate id, and a key bound to another agent.
	if rec := e.send(admin, "", http.MethodPost, agentsAPIPath, agentJSON(t, "a1", "k9", "g")); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "agent_exists") {
		t.Errorf("duplicate id = %d %s, want 409 agent_exists", rec.Code, rec.Body)
	}
	if rec := e.send(admin, "", http.MethodPost, agentsAPIPath, agentJSON(t, "a3", "k1", "g")); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "key_in_use") {
		t.Errorf("shared key = %d %s, want 409 key_in_use", rec.Code, rec.Body)
	}

	// If-Match: missing 428, stale 409, current 200; the audit rows classify.
	upd := agentUpdateJSON(t, "k1", "g", "h")
	if rec := e.send(admin, "", http.MethodPut, agentsAPIPath+"/a1", upd); rec.Code != http.StatusPreconditionRequired {
		t.Errorf("PUT without If-Match = %d %s, want 428", rec.Code, rec.Body)
	}
	rec = e.send(admin, "", http.MethodPut, agentsAPIPath+"/a1", upd, "If-Match", `"r5"`)
	if rec.Code != http.StatusConflict || strings.TrimSpace(rec.Body.String()) != `{"error":"agent_conflict"}` {
		t.Errorf("stale PUT = %d %s, want 409 agent_conflict", rec.Code, rec.Body)
	}
	if rec := e.send(admin, "", http.MethodPost, agentsAPIPath+"/a1/disable", "", "If-Match", `"r5"`); rec.Code != http.StatusConflict {
		t.Errorf("stale disable = %d, want 409", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodPut, agentsAPIPath+"/ghost", upd, "If-Match", `"r1"`); rec.Code != http.StatusNotFound {
		t.Errorf("PUT of an unknown agent = %d, want 404", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodGet, agentsAPIPath+"/ghost", ""); rec.Code != http.StatusNotFound {
		t.Errorf("GET of an unknown agent = %d, want 404", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodPost, agentsAPIPath, `{"displayName":"`+strings.Repeat("x", 65<<10)+`"}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("65 KiB body = %d, want 413", rec.Code)
	}
	// A DELETE has no route row: refused for every role, and nothing is deleted.
	if rec := e.send(admin, "", http.MethodDelete, agentsAPIPath+"/a1", ""); rec.Code != http.StatusForbidden {
		t.Errorf("DELETE = %d, want 403 (no authz row)", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodGet, agentsAPIPath+"/a1", ""); rec.Code != http.StatusOK {
		t.Errorf("agent after DELETE = %d, want 200", rec.Code)
	}

	got := e.srv.AgentRegistryWrites()
	for k, want := range map[AgentWriteKey]uint64{
		{agentActionCreate, agentOutcomeInvalid}:   3,
		{agentActionCreate, agentOutcomeExists}:    1,
		{agentActionCreate, agentOutcomeKeyInUse}:  1,
		{agentActionUpdate, agentOutcomeConflict}:  1,
		{agentActionUpdate, agentOutcomeNotFound}:  1,
		{agentActionDisable, agentOutcomeConflict}: 1,
	} {
		if got[k] != want {
			t.Errorf("writes %v = %d, want %d (all: %v)", k, got[k], want, got)
		}
	}
}

// TestAgents_CSRFDenied: an admin session's write without the CSRF header is
// refused and recorded as denied; nothing is registered.
func TestAgents_CSRFDenied(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	req := httptest.NewRequest(http.MethodPost, agentsAPIPath, strings.NewReader(agentJSON(t, "a1", "k1", "g")))
	req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: admin})
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF = %d %s, want 403", w.Code, w.Body)
	}
	r := lastRow(t, e, 1)
	if r.Outcome != adminaudit.OutcomeDenied || r.Action != "agent.create" || r.Details[detailReason] != "csrf" {
		t.Errorf("row = %+v, want denied agent.create (csrf)", r)
	}
	if rec := e.send(admin, "", http.MethodGet, agentsAPIPath+"/a1", ""); rec.Code != http.StatusNotFound {
		t.Errorf("agent after refused POST = %d, want 404", rec.Code)
	}
}

// TestAgents_NoneModeAndNoState: console.auth none reads but never writes
// (use_cli); a control plane without a state dir answers 503 everywhere; a
// control plane without admin audit still serves the routes.
func TestAgents_NoneModeAndNoState(t *testing.T) {
	_, ts := noneAPI(t, nil)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, agentsAPIPath},
		{http.MethodPut, agentsAPIPath + "/a1"},
		{http.MethodPost, agentsAPIPath + "/a1/disable"},
		{http.MethodPost, agentsAPIPath + "/a1/enable"},
	} {
		code, body := doJSON(t, c.method, ts.URL+c.path, dashTestToken, agentJSON(t, "a1", "k1", "g"))
		if code != http.StatusForbidden || !strings.Contains(body, `"use_cli"`) {
			t.Errorf("%s %s = %d %s, want 403 use_cli", c.method, c.path, code, body)
		}
	}
	if code, body := doJSON(t, http.MethodGet, ts.URL+agentsAPIPath, "", ""); code != http.StatusOK || !strings.HasPrefix(body, `{"agents":[]`) {
		t.Errorf("none-mode GET = %d %s, want 200 with an empty list", code, body)
	}

	s := blockServer(t, nil, func(c *Config) { c.AdminToken = dashTestToken; c.State = nil })
	nostate := httptest.NewServer(s.Handler())
	t.Cleanup(nostate.Close)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, agentsAPIPath},
		{http.MethodGet, agentsAPIPath + "/a1"},
		{http.MethodPost, agentsAPIPath},
		{http.MethodPut, agentsAPIPath + "/a1"},
		{http.MethodPost, agentsAPIPath + "/a1/disable"},
	} {
		code, body := doJSON(t, c.method, nostate.URL+c.path, dashTestToken, `{}`)
		if code != http.StatusServiceUnavailable || !strings.Contains(body, "state_dir_required") {
			t.Errorf("no state dir: %s %s = %d %s, want 503 state_dir_required", c.method, c.path, code, body)
		}
	}
}

// fakeAgentStore records the revision the adapter passes to Update.
type fakeAgentStore struct {
	agentreg.Store
	updateRev int64
}

func (f *fakeAgentStore) Update(ctx context.Context, a agentreg.Agent, actor string) (agentreg.Agent, error) {
	f.updateRev = a.Revision
	return f.Store.Update(ctx, a, actor)
}

// TestAgents_UpdateUsesClientRevision: a row newer than the client's If-Match
// is a conflict before any write; the compare-and-swap token is the client's
// revision, never one the handler read; and a
// successful write refreshes the policy server.
func TestAgents_UpdateUsesClientRevision(t *testing.T) {
	db := openAuditDB(t)
	inner := agentregsqlite.New(db)
	fake := &fakeAgentStore{Store: inner}
	if _, err := inner.Create(context.Background(), agentreg.Agent{
		ID: "a1", Keys: []agentreg.Key{{JWK: agentregtest.Ed25519JWK(t, "k1")}}, AllowedGroups: []string{"g"},
	}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := inner.SetStatus(context.Background(), "a1", agentreg.StatusActive, 1, "t"); err != nil { // revision 2
		t.Fatal(err)
	}
	refreshes := 0
	lg, _ := testLogger()
	api := agentRegistryAPI{store: fake, logger: lg, refresh: func() { refreshes++ }, metrics: &agentMetrics{}}
	in := dashboard.AgentInput{Keys: []json.RawMessage{agentregtest.Ed25519JWK(t, "k1")}, AllowedGroups: []string{"g"}}

	// The client saw revision 1; the stored one is 2.
	if _, err := api.Update(context.Background(), "a1", 1, in); err != dashboard.ErrAgentConflict {
		t.Fatalf("stale update err = %v, want ErrAgentConflict", err)
	}
	if fake.updateRev != 0 {
		t.Errorf("Store.Update was called (revision %d) for a row newer than the client saw", fake.updateRev)
	}
	if refreshes != 0 {
		t.Errorf("a failed write refreshed %d times", refreshes)
	}
	if _, err := api.Update(context.Background(), "a1", 2, in); err != nil {
		t.Fatalf("current update: %v", err)
	}
	if fake.updateRev != 2 {
		t.Errorf("Store.Update got revision %d, want the client's 2", fake.updateRev)
	}
	if refreshes != 1 {
		t.Errorf("a successful write refreshed %d times, want 1", refreshes)
	}
	if _, err := api.SetEnabled(context.Background(), "a1", false, 3); err != nil || refreshes != 2 {
		t.Errorf("SetEnabled err %v, refreshes %d, want nil and 2", err, refreshes)
	}
}
