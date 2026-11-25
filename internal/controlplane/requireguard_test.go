package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// beat registers a worker heartbeat on srv: agentID "" is a worker that sends none.
func beat(srv *Server, proxyID, agentID string, caps ...string) {
	srv.registry.SeenHeartbeat(proxyID, "etag", caps, agentID, "", WorkerBundle{})
}

type lackBody struct {
	Error   string   `json:"error"`
	Workers []string `json:"workers"`
}

func decodeLack(t *testing.T, body string) lackBody {
	t.Helper()
	var b lackBody
	_ = json.Unmarshal([]byte(body), &b)
	return b
}

func setAgentIdentity(doc map[string]any, mode string) {
	doc["agents"].([]any)[0].(map[string]any)["identity"] = mode
}

// TestRequireRefusedForOldWorkers: a worker bound to agent-a that lacks
// identity/require-v1 makes the save that sets agent-a to require a 409 naming
// it; other agents' workers, workers with no agent id (for a per-agent switch)
// and workers that went offline do not block.
func TestRequireRefusedForOldWorkers(t *testing.T) {
	e := newAuthzEnvOn(t, openSessionDB(t), writePolicyFileForFieldAuthz(t), defaultRoles())
	admin := e.session(t, groupAdmin)
	now := time.Unix(1_800_000_000, 0)
	e.srv.registry.now = func() time.Time { return now }

	beat(e.srv, "old", "agent-a", config.CapBlocklistV1, config.CapAgentRegV1)
	beat(e.srv, "ok", "agent-a", config.CapIdentityRequireV1)
	beat(e.srv, "other-agent", "agent-b", config.CapBlocklistV1)
	beat(e.srv, "anon", "", config.CapBlocklistV1)

	doc := e.liveSettingsDoc(t, admin)
	setAgentIdentity(doc, "require")
	rec := e.do(admin, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc))
	if b := decodeLack(t, rec.Body.String()); rec.Code != http.StatusConflict || b.Error != "workers_lack_capability" || !slices.Equal(b.Workers, []string{"old"}) {
		t.Fatalf("require with an old worker = %d %s, want 409 workers_lack_capability [old]", rec.Code, rec.Body.String())
	}
	if got := readFile(t, e.policy); strings.Contains(got, "identity: require") {
		t.Fatalf("a refused save reached the config file:\n%s", got)
	}

	// The old worker goes offline (no contact for more than staleAfter): it no
	// longer serves the agent, so the save goes through.
	now = now.Add(staleAfter + time.Second)
	beat(e.srv, "ok", "agent-a", config.CapIdentityRequireV1)
	if rec := e.do(admin, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc)); rec.Code/100 != 2 {
		t.Fatalf("require with only an offline old worker = %d %s, want 2xx", rec.Code, rec.Body.String())
	}
	if got := readFile(t, e.policy); !strings.Contains(got, "identity: require") {
		t.Fatalf("the accepted save did not reach the config file:\n%s", got)
	}

	// Saving an unrelated field while require is already set is never refused,
	// even though an old worker has connected since.
	beat(e.srv, "late", "agent-a", config.CapBlocklistV1)
	doc = e.liveSettingsDoc(t, admin)
	doc["dlp"] = map[string]any{"mode": "monitor"}
	if rec := e.do(admin, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc)); rec.Code/100 != 2 {
		t.Fatalf("unrelated save under existing require = %d %s, want 2xx", rec.Code, rec.Body.String())
	}
}

// TestRequireDefaultModeRefusedForAnyWorker: identity.defaultMode=require is
// refused while any connected worker lacks the cap, including one that reports
// no agent id.
func TestRequireDefaultModeRefusedForAnyWorker(t *testing.T) {
	e := newAuthzEnvOn(t, openSessionDB(t), writePolicyFileForFieldAuthz(t), defaultRoles())
	admin := e.session(t, groupAdmin)
	beat(e.srv, "anon", "", config.CapBlocklistV1)
	beat(e.srv, "new", "agent-a", config.CapIdentityRequireV1)

	doc := e.liveSettingsDoc(t, admin)
	doc["identity"].(map[string]any)["defaultMode"] = "require"
	rec := e.do(admin, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc))
	if b := decodeLack(t, rec.Body.String()); rec.Code != http.StatusConflict || !slices.Equal(b.Workers, []string{"anon"}) {
		t.Fatalf("defaultMode require with an agent-less old worker = %d %s, want 409 [anon]", rec.Code, rec.Body.String())
	}
	beat(e.srv, "anon", "", config.CapIdentityRequireV1)
	if rec := e.do(admin, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc)); rec.Code/100 != 2 {
		t.Fatalf("defaultMode require once every worker has the cap = %d %s, want 2xx", rec.Code, rec.Body.String())
	}
}

// TestRequireForceAudited: ?force=true by an admin overrides the refusal and
// the admin audit row records force and the worker ids.
func TestRequireForceAudited(t *testing.T) {
	e := newAuditEnv(t, auditEnvOpts{console: authzConsole(defaultRoles()), token: dashTestToken})
	admin := e.session(t, groupAdmin)
	beat(e.srv, "old-1", "agent-a", config.CapBlocklistV1, config.CapAgentRegV1)
	beat(e.srv, "old-2", "agent-a")

	body := `{"agents":[{"id":"agent-a","identity":"require"}],"identity":{"defaultMode":"off","issuer":"https://idp.example","audience":"warden"}}`

	if rec := e.send(admin, "", http.MethodPost, "/dashboard/api/settings", body); rec.Code != http.StatusConflict {
		t.Fatalf("unforced = %d %s, want 409", rec.Code, rec.Body.String())
	}
	rec := e.send(admin, "", http.MethodPost, "/dashboard/api/settings?force=true", body)
	if rec.Code/100 != 2 {
		t.Fatalf("forced by an admin = %d %s, want 2xx", rec.Code, rec.Body.String())
	}
	var forced *adminaudit.Input
	for _, in := range e.rec.inputs() {
		if in.Action == "settings.write" && in.Details[adminaudit.DetailForce] == "true" {
			in := in
			forced = &in
		}
	}
	if forced == nil {
		t.Fatalf("no settings.write audit row carries force: %+v", e.rec.inputs())
	}
	if forced.Details[adminaudit.DetailWorkersLacking] != "old-1,old-2" || forced.Details[adminaudit.DetailWorkersLacking+adminaudit.DetailCountSuffix] != "2" {
		t.Errorf("audit details = %v, want workersLacking old-1,old-2 (count 2)", forced.Details)
	}
	// A save that needed no force records no force.
	for _, in := range e.rec.inputs() {
		if in.Outcome != adminaudit.OutcomeOK && in.Details[adminaudit.DetailForce] != "" {
			t.Errorf("a refused request recorded force: %+v", in)
		}
	}
}

// TestIdentityModeAdminOnly: an editor cannot change agents[].identity or
// identity.defaultMode (403 role_required), and once the worker advertises
// identity/require-v1 an admin's save succeeds without force.
func TestIdentityModeAdminOnly(t *testing.T) {
	e := newAuthzEnvOn(t, openSessionDB(t), writePolicyFileForFieldAuthz(t), defaultRoles())
	editor, admin := e.session(t, groupEditor), e.session(t, groupAdmin)
	beat(e.srv, "w1", "agent-a", config.CapBlocklistV1)

	for name, edit := range map[string]func(map[string]any){
		"agents[0].identity":   func(d map[string]any) { setAgentIdentity(d, "require") },
		"identity.defaultMode": func(d map[string]any) { d["identity"].(map[string]any)["defaultMode"] = "require" },
	} {
		doc := e.liveSettingsDoc(t, editor)
		edit(doc)
		rec := e.do(editor, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"role_required"`) {
			t.Errorf("editor sets %s = %d %s, want 403 role_required", name, rec.Code, rec.Body.String())
		}
		// An editor cannot use force to get around it either.
		rec = e.do(editor, http.MethodPost, "/dashboard/api/settings?force=true", mustJSON(t, doc))
		if rec.Code != http.StatusForbidden {
			t.Errorf("editor forces %s = %d %s, want 403", name, rec.Code, rec.Body.String())
		}
	}
	doc := e.liveSettingsDoc(t, admin)
	setAgentIdentity(doc, "require")
	if rec := e.do(admin, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc)); rec.Code != http.StatusConflict {
		t.Fatalf("admin before the worker upgrades = %d %s, want 409", rec.Code, rec.Body.String())
	}
	beat(e.srv, "w1", "agent-a", config.CapBlocklistV1, config.CapIdentityRequireV1)
	if rec := e.do(admin, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc)); rec.Code/100 != 2 {
		t.Fatalf("admin after the worker heartbeats the cap = %d %s, want 2xx", rec.Code, rec.Body.String())
	}
}

// TestRequireGuardForceNeedsAdmin: a force request from a principal below admin
// is refused with 403 role_required naming force, never honoured.
func TestRequireGuardForceNeedsAdmin(t *testing.T) {
	e := newAuthzEnvOn(t, openSessionDB(t), writePolicyFileForFieldAuthz(t), defaultRoles())
	beat(e.srv, "old", "agent-a")
	in := config.SettingsWire{Agents: []config.AgentSettings{{ID: "agent-a", Identity: "require"}}}
	ctx := dashboard.WithForce(context.Background())
	err := e.srv.requireGuard(ctx, nil, in)
	var re *dashboard.RoleRequiredError
	if !errors.As(err, &re) || re.Need != "admin" || !slices.Equal(re.Fields, []string{"force"}) {
		t.Fatalf("requireGuard(force, no principal) = %v, want RoleRequiredError admin [force]", err)
	}
}

// TestFleetFlagsWorkersWithoutIdentityRequire: while require is served for a
// worker's agent, an online worker lacking the cap is flagged; one that has it,
// or serves an agent not in require, is not.
func TestFleetFlagsWorkersWithoutIdentityRequire(t *testing.T) {
	served := &config.SettingsWire{
		Agents:   []config.AgentSettings{{ID: "a", Identity: "require"}, {ID: "b", Identity: "attribute"}},
		Identity: &config.IdentitySettings{DefaultMode: "require"},
	}
	views := []dashboard.WorkerView{
		{ProxyID: "old-a", AgentID: "a", Online: true},
		{ProxyID: "new-a", AgentID: "a", Online: true, Caps: []string{config.CapIdentityRequireV1}},
		{ProxyID: "old-b", AgentID: "b", Online: true},
		{ProxyID: "old-default", AgentID: "c", Online: true},
		{ProxyID: "old-anon", Online: true},
		{ProxyID: "stale-a", AgentID: "a"},
	}
	FlagNoIdentityRequire(views, served)
	got := map[string]bool{}
	for _, v := range views {
		got[v.ProxyID] = v.NoIdentityRequire
	}
	want := map[string]bool{"old-a": true, "new-a": false, "old-b": false, "old-default": true, "old-anon": true, "stale-a": false}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s flagged = %v, want %v", id, got[id], w)
		}
	}
	FlagNoIdentityRequire(views, nil)
	for _, v := range views {
		if v.NoIdentityRequire {
			t.Errorf("%s flagged with nothing served", v.ProxyID)
		}
	}
}

// TestDraftApplyRequireGuard: a held draft that newly sets require mode meets
// the capability guard when it is applied, since workers may have changed since
// it was held; the approver's force overrides it.
func TestDraftApplyRequireGuard(t *testing.T) {
	srv := newApprovalsServer(t, approvalsConsole(), nil)
	beat(srv, "old", "agent-a", config.CapBlocklistV1)
	_, hd, err := srv.headDoc(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doc := draftDoc(hd)
	doc.Settings = &config.SettingsWire{
		Agents:   []config.AgentSettings{{ID: "agent-a", Identity: "require"}},
		Identity: &config.IdentitySettings{DefaultMode: "off", Issuer: "https://idp.example", Audience: "warden"},
	}
	d, err := srv.Approvals().CreateDraft(context.Background(), approvals.TargetPolicy, doc, draftAuthor, approvals.Provenance{Message: "require"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if d, err = srv.Approvals().Store().Submit(context.Background(), d.ID, d.Revision, draftAuthor.Sub); err != nil {
		t.Fatal(err)
	}

	approver := sessionCtx("bob", "bob@example.com")
	_, err = srv.Approvals().Apply(approver, d.ID, d.Revision, "bob")
	var wl *dashboard.WorkersLackCapabilityError
	if !errors.As(err, &wl) || !slices.Equal(wl.Workers, []string{"old"}) {
		t.Fatalf("Apply with an old worker = %v, want WorkersLackCapabilityError [old]", err)
	}
	if n := versionCount(t, srv); n != 1 {
		t.Fatalf("%d versions after the refused apply, want 1", n)
	}
	// The same refusal maps to 409 workers_lack_capability on the approve route.
	var ce *dashboard.ChangeError
	if mapped := (changeDraftAPI{s: srv}).changeErr(context.Background(), err); !errors.As(mapped, &ce) || ce.Status != http.StatusConflict || ce.Code != "workers_lack_capability" {
		t.Fatalf("changeErr = %v, want 409 workers_lack_capability", mapped)
	}
	if _, err := srv.Approvals().Apply(dashboard.WithForce(approver), d.ID, d.Revision, "bob"); err != nil {
		t.Fatalf("forced Apply = %v, want success", err)
	}
	if n := versionCount(t, srv); n != 2 {
		t.Errorf("%d versions after the forced apply, want 2", n)
	}
}

// TestHeartbeatLogsWorkerWithoutIdentityRequire: a worker that connects without
// the cap while its agent is served in require mode is logged once per ETag and
// flagged; a worker with the cap is not.
func TestHeartbeatLogsWorkerWithoutIdentityRequire(t *testing.T) {
	logger, buf := testLogger()
	srv := New(Config{PolicyPath: writeScopedPolicy(t, "policy:\n  allowlist:\n    - domain: plain.example.com\nagents:\n  - id: a\n    identity: require\nidentity:\n  issuer: https://idp.example.com\n  audience: warden\n"), Logger: logger})
	for i := 0; i < 3; i++ {
		srv.noteIdentityRequire("old", "a", []string{config.CapBlocklistV1})
	}
	srv.noteIdentityRequire("new", "a", []string{config.CapIdentityRequireV1})
	srv.noteIdentityRequire("other", "b", nil)
	srv.noteIdentityRequire("", "a", nil)
	if n := strings.Count(buf.String(), "worker_lacks_identity_require"); n != 1 || !strings.Contains(buf.String(), "proxy_id=old") {
		t.Errorf("log lines = %d, want exactly one for old:\n%s", n, buf.String())
	}
	if served := srv.servedSettings(); !requireModeFor(served, "a") || requireModeFor(served, "b") {
		t.Errorf("served require: a=%v b=%v, want true false", requireModeFor(served, "a"), requireModeFor(served, "b"))
	}
}
