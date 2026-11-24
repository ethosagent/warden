package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// fakeAgents is an AgentRegistry that records what the handlers passed it and
// returns canned errors.
type fakeAgents struct {
	ready    error
	err      error
	view     AgentView
	created  []AgentInput
	updated  []AgentInput
	revs     []int64
	enabled  []bool
	updateID string
}

func (f *fakeAgents) Ready() error { return f.ready }

func (f *fakeAgents) List(context.Context) ([]AgentView, error) { return nil, f.err }

func (f *fakeAgents) Get(context.Context, string) (AgentView, error) { return f.view, f.err }

func (f *fakeAgents) Create(_ context.Context, in AgentInput) (AgentView, error) {
	if f.err != nil {
		return AgentView{}, f.err
	}
	f.created = append(f.created, in)
	v := f.view
	v.ID = in.ID
	return v, nil
}

func (f *fakeAgents) Update(_ context.Context, id string, rev int64, in AgentInput) (AgentView, error) {
	if f.err != nil {
		return AgentView{}, f.err
	}
	f.updateID = id
	f.updated = append(f.updated, in)
	f.revs = append(f.revs, rev)
	v := f.view
	v.Revision = rev + 1
	return v, nil
}

func (f *fakeAgents) SetEnabled(_ context.Context, _ string, enabled bool, rev int64) (AgentView, error) {
	if f.err != nil {
		return AgentView{}, f.err
	}
	f.enabled = append(f.enabled, enabled)
	f.revs = append(f.revs, rev)
	v := f.view
	v.Revision = rev + 1
	return v, nil
}

func agentsHandler(reg AgentRegistry, authMode string) http.Handler {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetAuthMode(authMode)
	if reg != nil {
		srv.SetAgentRegistry(reg)
	}
	return srv.Handler()
}

func agentsDo(h http.Handler, method, target, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const agentBodyNoID = `{"displayName":"Claude Code","keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}],"allowedGroups":["g"]}`

const agentBody = `{"id":"claude-code","displayName":"Claude Code","keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}],"allowedGroups":["g"]}`

// TestAgents_NotWired: on a worker dashboard (no seam) every agent route is
// 404, whatever the method.
func TestAgents_NotWired(t *testing.T) {
	h := agentsHandler(nil, "oidc")
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/agents"},
		{http.MethodPost, "/dashboard/api/agents"},
		{http.MethodGet, "/dashboard/api/agents/a"},
		{http.MethodPut, "/dashboard/api/agents/a"},
		{http.MethodPost, "/dashboard/api/agents/a/disable"},
		{http.MethodPost, "/dashboard/api/agents/a/enable"},
	} {
		if rec := agentsDo(h, c.method, c.path, `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
	// A worker does not claim any method on these paths, DELETE included.
	if rec := agentsDo(h, http.MethodDelete, "/dashboard/api/agents/a", ""); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE with no seam = %d, want 404", rec.Code)
	}
}

// TestAgents_RoutePath: concrete agent paths map to their templates and
// nothing else does.
func TestAgents_RoutePath(t *testing.T) {
	for in, want := range map[string]string{
		"/dashboard/api/agents":                 "/dashboard/api/agents",
		"/dashboard/api/agents/a":               "/dashboard/api/agents/{id}",
		"/dashboard/api/agents/a:b.c-1/disable": "/dashboard/api/agents/{id}/disable",
		"/dashboard/api/agents/a/enable":        "/dashboard/api/agents/{id}/enable",
		"/dashboard/api/agents/a/delete":        "/dashboard/api/agents/a/delete",
		"/dashboard/api/agents/a/enable/x":      "/dashboard/api/agents/a/enable/x",
		"/dashboard/api/agents/":                "/dashboard/api/agents/",
		"/dashboard/api/agentsX/a":              "/dashboard/api/agentsX/a",
	} {
		if got := RoutePath(in); got != want {
			t.Errorf("RoutePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAgents_Methods: there is no DELETE, and a wrong method is 405 with Allow.
func TestAgents_Methods(t *testing.T) {
	h := agentsHandler(&fakeAgents{}, "oidc")
	for _, c := range []struct{ method, path, allow string }{
		{http.MethodDelete, "/dashboard/api/agents/a", "GET, PUT"},
		{http.MethodPost, "/dashboard/api/agents/a", "GET, PUT"},
		{http.MethodPut, "/dashboard/api/agents", "GET, POST"},
		{http.MethodDelete, "/dashboard/api/agents", "GET, POST"},
		{http.MethodGet, "/dashboard/api/agents/a/disable", "POST"},
		{http.MethodPut, "/dashboard/api/agents/a/enable", "POST"},
	} {
		rec := agentsDo(h, c.method, c.path, "")
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != c.allow {
			t.Errorf("%s %s = %d Allow %q, want 405 %q", c.method, c.path, rec.Code, rec.Header().Get("Allow"), c.allow)
		}
	}
	if rec := agentsDo(h, http.MethodGet, "/dashboard/api/agents/a/other", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown action = %d, want 404", rec.Code)
	}
}

// TestAgents_ErrorMapping: each registry error has one fixed status and body,
// and no error text from the registry reaches the caller.
func TestAgents_ErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int
		body   string
	}{
		{ErrAgentStateRequired, http.StatusServiceUnavailable, `"state_dir_required"`},
		{&AgentInvalidError{Field: "keys[0].crv", Reason: "an EC key must use P-256"}, http.StatusBadRequest, `{"error":"invalid_agent","field":"keys[0].crv","message":"an EC key must use P-256"}`},
		{&AgentInvalidError{Field: "allowed_groups[2]", Reason: "must not be empty"}, http.StatusBadRequest, `"field":"allowedGroups[2]"`},
		{&AgentInvalidError{Field: "display_name", Reason: "r"}, http.StatusBadRequest, `"field":"displayName"`},
		{ErrAgentNotFound, http.StatusNotFound, `"not_found"`},
		{ErrAgentExists, http.StatusConflict, `"agent_exists"`},
		{ErrAgentKeyInUse, http.StatusConflict, `"key_in_use"`},
		{ErrAgentConflict, http.StatusConflict, `{"error":"agent_conflict"}`},
		{ErrAgentFull, http.StatusUnprocessableEntity, `"registry_full"`},
		{fmt.Errorf("sqlite: disk on fire"), http.StatusInternalServerError, `"agent_registry_error"`},
	}
	for _, c := range cases {
		h := agentsHandler(&fakeAgents{err: c.err}, "oidc")
		for _, req := range []struct{ method, path, body string }{
			{http.MethodGet, "/dashboard/api/agents", ""},
			{http.MethodGet, "/dashboard/api/agents/a", ""},
			{http.MethodPost, "/dashboard/api/agents", agentBody},
			{http.MethodPut, "/dashboard/api/agents/a", agentBodyNoID},
			{http.MethodPost, "/dashboard/api/agents/a/disable", ""},
		} {
			rec := agentsDo(h, req.method, req.path, req.body, "If-Match", `"r1"`)
			if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.body) || strings.Contains(rec.Body.String(), "disk on fire") {
				t.Errorf("%v on %s %s = %d %s, want %d %q", c.err, req.method, req.path, rec.Code, rec.Body, c.status, c.body)
			}
		}
	}
}

// TestAgents_StateDirRequired: a registry that is not ready answers 503 on
// every route first, before the method-specific checks.
func TestAgents_StateDirRequired(t *testing.T) {
	for _, mode := range []string{"oidc", "none"} {
		h := agentsHandler(&fakeAgents{ready: ErrAgentStateRequired}, mode)
		for _, c := range []struct{ method, path string }{
			{http.MethodGet, "/dashboard/api/agents"},
			{http.MethodPost, "/dashboard/api/agents"},
			{http.MethodGet, "/dashboard/api/agents/a"},
			{http.MethodPut, "/dashboard/api/agents/a"},
			{http.MethodPost, "/dashboard/api/agents/a/disable"},
			{http.MethodPost, "/dashboard/api/agents/a/enable"},
		} {
			rec := agentsDo(h, c.method, c.path, agentBody)
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "state_dir_required") {
				t.Errorf("%s %s %s = %d %s, want 503 state_dir_required", mode, c.method, c.path, rec.Code, rec.Body)
			}
		}
	}
}

// TestAgents_UseCLIWithoutSignIn: console.auth none reads but never writes.
func TestAgents_UseCLIWithoutSignIn(t *testing.T) {
	f := &fakeAgents{}
	for _, mode := range []string{"none", ""} {
		h := agentsHandler(f, mode)
		for _, c := range []struct{ method, path string }{
			{http.MethodPost, "/dashboard/api/agents"},
			{http.MethodPut, "/dashboard/api/agents/a"},
			{http.MethodPost, "/dashboard/api/agents/a/disable"},
			{http.MethodPost, "/dashboard/api/agents/a/enable"},
		} {
			rec := agentsDo(h, c.method, c.path, agentBody, "If-Match", `"r1"`)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"use_cli"`) {
				t.Errorf("mode %q %s %s = %d %s, want 403 use_cli", mode, c.method, c.path, rec.Code, rec.Body)
			}
		}
		for _, p := range []string{"/dashboard/api/agents", "/dashboard/api/agents/a"} {
			if rec := agentsDo(h, http.MethodGet, p, ""); rec.Code != http.StatusOK {
				t.Errorf("mode %q GET %s = %d, want 200", mode, p, rec.Code)
			}
		}
	}
	if len(f.created)+len(f.updated)+len(f.enabled) != 0 {
		t.Errorf("a refused write reached the registry: %+v", f)
	}
}

func TestAgents_CreateAndRead(t *testing.T) {
	f := &fakeAgents{view: AgentView{Revision: 1, Status: "active", Keys: []AgentKeyView{}}}
	h := agentsHandler(f, "oidc")
	rec := agentsDo(h, http.MethodPost, "/dashboard/api/agents", agentBody)
	if rec.Code != http.StatusCreated || rec.Header().Get("Location") != "/dashboard/api/agents/claude-code" ||
		rec.Header().Get("ETag") != `"r1"` || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("POST = %d %s, Location %q ETag %q", rec.Code, rec.Body, rec.Header().Get("Location"), rec.Header().Get("ETag"))
	}
	if len(f.created) != 1 || f.created[0].ID != "claude-code" || f.created[0].DisplayName != "Claude Code" ||
		len(f.created[0].Keys) != 1 || !strings.Contains(string(f.created[0].Keys[0]), `"x":"AAAA"`) || f.created[0].AllowedGroups[0] != "g" {
		t.Errorf("registry got %+v", f.created)
	}

	rec = agentsDo(h, http.MethodGet, "/dashboard/api/agents/claude-code", "")
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"r1"` {
		t.Errorf("GET = %d, ETag %q", rec.Code, rec.Header().Get("ETag"))
	}
	var list struct {
		Agents []AgentView `json:"agents"`
	}
	rec = agentsDo(h, http.MethodGet, "/dashboard/api/agents", "")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), `{"agents":[]`) || json.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Errorf("empty list = %d %s, want an empty agents envelope", rec.Code, rec.Body)
	}
}

func TestAgents_BodyRules(t *testing.T) {
	f := &fakeAgents{}
	h := agentsHandler(f, "oidc")
	for name, body := range map[string]string{
		"not json":      `nope`,
		"unknown field": `{"id":"a","status":"disabled"}`,
		"owner field":   `{"id":"a","ownerSub":"x"}`,
		"trailing":      agentBody + ` {}`,
		"wrong type":    `{"id":"a","keys":5}`,
		"empty":         ``,
	} {
		rec := agentsDo(h, http.MethodPost, "/dashboard/api/agents", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_json"`) {
			t.Errorf("%s: POST = %d %s, want 400 invalid_json", name, rec.Code, rec.Body)
		}
	}
	big := `{"id":"a","displayName":"` + strings.Repeat("x", maxAgentBody) + `"}`
	if rec := agentsDo(h, http.MethodPost, "/dashboard/api/agents", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized POST = %d, want 413", rec.Code)
	}
	if rec := agentsDo(h, http.MethodPut, "/dashboard/api/agents/a", big, "If-Match", `"r1"`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized PUT = %d, want 413", rec.Code)
	}
	if len(f.created)+len(f.updated) != 0 {
		t.Errorf("a refused body reached the registry: %+v", f)
	}
}

// TestAgents_IfMatch: PUT, disable and enable need If-Match "r<n>" and pass n
// to the registry; the registry's ErrAgentConflict is the 409.
func TestAgents_IfMatch(t *testing.T) {
	f := &fakeAgents{view: AgentView{ID: "a", Status: "active"}}
	h := agentsHandler(f, "oidc")
	for _, c := range []struct{ method, path string }{
		{http.MethodPut, "/dashboard/api/agents/a"},
		{http.MethodPost, "/dashboard/api/agents/a/disable"},
		{http.MethodPost, "/dashboard/api/agents/a/enable"},
	} {
		rec := agentsDo(h, c.method, c.path, agentBody)
		if rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), "if_match_required") {
			t.Errorf("%s %s without If-Match = %d %s, want 428", c.method, c.path, rec.Code, rec.Body)
		}
		for _, bad := range []string{`*`, `r3`, `"3"`, `"r"`, `"r0"`, `"r-1"`, `"r03"`, `W/"r3"`, `"r3" `[:3], `"r99999999999999999999"`} {
			rec := agentsDo(h, c.method, c.path, agentBody, "If-Match", bad)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_if_match") {
				t.Errorf("%s %s If-Match %q = %d %s, want 400", c.method, c.path, bad, rec.Code, rec.Body)
			}
		}
	}
	if len(f.revs) != 0 {
		t.Fatalf("a refused request reached the registry: %v", f.revs)
	}

	rec := agentsDo(h, http.MethodPut, "/dashboard/api/agents/a", agentBody[:len(agentBody)-1]+`,"allowedScopes":["s"]}`, "If-Match", `"r7"`)
	if rec.Code != http.StatusBadRequest {
		// agentBody names id claude-code; the path says a.
		t.Fatalf("PUT with a mismatched id = %d %s, want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"field":"id"`) {
		t.Errorf("mismatched id body = %s", rec.Body)
	}
	body := `{"displayName":"New","keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}],"allowedGroups":["g"]}`
	rec = agentsDo(h, http.MethodPut, "/dashboard/api/agents/a", body, "If-Match", `"r7"`)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"r8"` || f.updateID != "a" || f.revs[0] != 7 || f.updated[0].ID != "a" {
		t.Fatalf("PUT = %d %s ETag %q, update id %q revs %v", rec.Code, rec.Body, rec.Header().Get("ETag"), f.updateID, f.revs)
	}
	rec = agentsDo(h, http.MethodPost, "/dashboard/api/agents/a/disable", "", "If-Match", `"r8"`)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"r9"` || len(f.enabled) != 1 || f.enabled[0] || f.revs[1] != 8 {
		t.Fatalf("disable = %d %s, enabled %v revs %v", rec.Code, rec.Body, f.enabled, f.revs)
	}
	rec = agentsDo(h, http.MethodPost, "/dashboard/api/agents/a/enable", "", "If-Match", `"r9"`)
	if rec.Code != http.StatusOK || !f.enabled[1] || f.revs[2] != 9 {
		t.Fatalf("enable = %d %s, enabled %v revs %v", rec.Code, rec.Body, f.enabled, f.revs)
	}

	f.err = ErrAgentConflict
	if rec := agentsDo(h, http.MethodPut, "/dashboard/api/agents/a", body, "If-Match", `"r1"`); rec.Code != http.StatusConflict {
		t.Errorf("stale PUT = %d, want 409", rec.Code)
	}
}
