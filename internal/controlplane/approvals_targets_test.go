package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
)

// W-P2-APPR-08: block-list removals and widening agent edits are held for a
// second admin; adding a block and narrowing agent edits stay direct.

const blockedReason = "incident 42: exfil attempt"

// blockedEntry adds a block as the seed actor and returns its id.
func blockedEntry(t *testing.T, e *draftEnv, sub string) string {
	t.Helper()
	id, err := e.srv.blocks.Add(context.Background(), BlockEntry{Sub: sub, Reason: blockedReason}, "seed")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func servedBlocked(e *draftEnv, sub string) bool {
	for _, u := range servedWire(e.srv).BlockedUsers {
		if u.Sub == sub {
			return true
		}
	}
	return false
}

// approveTarget has who approve the draft. Replay does not apply to these
// targets, so the approval acknowledges there is none.
func (e *draftEnv) approveTarget(t *testing.T, who, id string) *httptest.ResponseRecorder {
	t.Helper()
	d := e.view(t, id)
	return e.do(who, http.MethodPost, draftsPath+"/"+id+"/approve", approveBody(d.ChangeDraftView, "", ""))
}

// heldBy asserts rec is a 202 held response for target and returns the draft.
func (e *draftEnv) heldBy(t *testing.T, rec *httptest.ResponseRecorder, target, wantCode string) dashboard.ChangeDraftDetail {
	t.Helper()
	h, d := e.wantHeld(t, rec, wantCode)
	if d.Target != target || d.ID != h.DraftID || d.RequiredRole != "admin" || d.State != "pending" {
		t.Fatalf("held draft = %+v, want a pending %s draft needing an admin", d.ChangeDraftView, target)
	}
	return d
}

func TestApprovalsBlockListRemoval(t *testing.T) {
	e := newDraftEnv(t, nil)
	id := blockedEntry(t, e, "victim")
	blockedEntry(t, e, "other")
	path := blockAPIPath + "/" + id

	// Adding a block stays immediate: 201, and the user is blocked at once.
	rec := e.do("admin", http.MethodPost, blockAPIPath, `{"sub":"fresh","reason":"kill switch"}`)
	if rec.Code != http.StatusCreated || !e.srv.blocks.IsBlocked("fresh", "") || !servedBlocked(e, "fresh") {
		t.Fatalf("add block = %d %s, want 201 and the user blocked", rec.Code, rec.Body.String())
	}

	// An editor cannot even ask: removal is an admin write.
	if rec := e.do("u1", http.MethodDelete, path, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("editor DELETE = %d, want 403", rec.Code)
	}

	// Removal is held: 202, the entry and the served list are untouched.
	etag := e.srv.policy.currentETag()
	d := e.heldBy(t, e.do("admin", http.MethodDelete, path, ""), "blocked_users", approvals.CodeBlockRemoved)
	if !e.srv.blocks.IsBlocked("victim", "") || !servedBlocked(e, "victim") || e.srv.policy.currentETag() != etag {
		t.Fatal("a held removal changed the block list or the served policy")
	}
	if d.TargetRef != id || d.BaseVersion != 0 || d.Author.Sub != "admin" || d.Source != "console" {
		t.Errorf("draft = %+v", d.ChangeDraftView)
	}
	// A viewer sees that an entry is named, never who. An admin sees the entry
	// without its reason.
	raw, _ := json.Marshal(d.Doc)
	if strings.Contains(string(raw), "victim") || !strings.Contains(string(raw), `"has_sub":true`) {
		t.Errorf("viewer draft doc = %s, want {id, has_sub, has_email}", raw)
	}
	adm := decodeBody[dashboard.ChangeDraftDetail](t, e.do("admin", http.MethodGet, draftsPath+"/"+d.ID, ""))
	raw, _ = json.Marshal(adm.Doc)
	if !strings.Contains(string(raw), `"sub":"victim"`) || strings.Contains(string(raw), "reason") || strings.Contains(string(raw), "exfil") {
		t.Errorf("admin draft doc = %s, want the entry without its reason", raw)
	}
	if strings.Contains(e.logs.String(), "exfil") {
		t.Error("the block reason reached the logs")
	}
	// The request is one audited row naming the draft; the held row hides the user.
	rows := okRows(e.auditRows("blocked_users.remove"))
	if len(rows) != 1 || rows[0].HTTPStatus != http.StatusAccepted || rows[0].TargetRef != "draft:"+d.ID+"@r1" || rows[0].Details["op"] != "held" {
		t.Fatalf("held rows = %+v", rows)
	}
	if fs := e.pub.byRule("policy_approval_requested"); len(fs) != 1 || fs[0].DedupKey != "policy_approval_requested:"+d.ID ||
		!strings.Contains(string(fs[0].Evidence), "blocked_users") {
		t.Errorf("approval Finding = %+v", fs)
	}

	// The diff of a non-policy draft is current vs proposed.
	rec = e.do("admin", http.MethodGet, draftsPath+"/"+d.ID+"/diff", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"current":{"id":"`+id) || !strings.Contains(rec.Body.String(), `"proposed"`) {
		t.Errorf("diff = %d %s", rec.Code, rec.Body.String())
	}
	// It lists under its target, and the other entry is unaffected.
	rec = e.do("viewer", http.MethodGet, draftsPath+"?target=blocked_users", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), d.ID) || !strings.Contains(rec.Body.String(), `"target_ref":"`+id+`"`) {
		t.Errorf("list by target = %d %s", rec.Code, rec.Body.String())
	}

	// Two-person rule: the author cannot approve; an editor lacks the role.
	e.wantErr(t, e.approveTarget(t, "admin", d.ID), http.StatusForbidden, "self_approval_forbidden")
	e.wantErr(t, e.approveTarget(t, "u2", d.ID), http.StatusForbidden, "role_required")
	// Without the acknowledgement the evidence rule refuses.
	bad := approveBody(d.ChangeDraftView, "", "")
	bad = strings.Replace(bad, `"acknowledgeNoReplay":true`, `"acknowledgeNoReplay":false`, 1)
	e.wantErr(t, e.do("admin2", http.MethodPost, draftsPath+"/"+d.ID+"/approve", bad), http.StatusConflict, "replay_required")
	if !e.srv.blocks.IsBlocked("victim", "") {
		t.Fatal("a refused approval removed the entry")
	}

	// A second admin approves: the entry goes, the served list changes, the
	// approver is recorded and the removal has its own audit row.
	rec = e.approveTarget(t, "admin2", d.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	res := decodeBody[dashboard.ChangeResult](t, rec)
	if res.State != "applied" || res.Target != "blocked_users" || res.Version != 0 || res.AppliedVersion != 0 {
		t.Errorf("result = %+v", res.ChangeDraftView)
	}
	if e.srv.blocks.IsBlocked("victim", "") || servedBlocked(e, "victim") || !servedBlocked(e, "other") || e.srv.policy.currentETag() == etag {
		t.Error("the removal did not reach the served policy (or removed the wrong entry)")
	}
	follow := okRows(e.auditRows("blocked_users.remove"))
	last := follow[len(follow)-1]
	if len(follow) != 2 || last.Actor.Sub != "admin2" || last.TargetRef != "block:"+id || last.Details["source"] != SourceApproval ||
		last.BeforeHash == last.AfterHash || last.Outcome != adminaudit.OutcomeOK {
		t.Errorf("removal rows = %+v", follow)
	}
	for _, in := range e.rec.inputs() {
		for _, v := range in.Details {
			if strings.Contains(v, "victim") || strings.Contains(v, "exfil") {
				t.Errorf("audit row %s carries the entry in %v", in.Action, in.Details)
			}
		}
	}
}

// TestApprovalsBlockListRebase: an entry already gone when the second admin
// approves is a rebase, not a silent success.
func TestApprovalsBlockListRebase(t *testing.T) {
	e := newDraftEnv(t, nil)
	id := blockedEntry(t, e, "victim")
	d := e.heldBy(t, e.do("admin", http.MethodDelete, blockAPIPath+"/"+id, ""), "blocked_users", approvals.CodeBlockRemoved)
	if err := e.srv.blocks.Remove(context.Background(), id, "someone"); err != nil {
		t.Fatal(err)
	}
	e.wantErr(t, e.approveTarget(t, "admin2", d.ID), http.StatusConflict, "rebase_required")
	if got := e.view(t, d.ID); got.State != "needs_rebase" {
		t.Errorf("draft = %s, want needs_rebase", got.State)
	}
	// A non-policy draft is edited by withdrawing it, never rebased.
	e.wantErr(t, e.do("admin", http.MethodPost, draftsPath+"/"+d.ID+"/rebase", ""), http.StatusBadRequest, "unsupported_target")
}

// TestApprovalsBlockListSelfUnblock: the Applier refuses to unblock the person
// applying it (a blocked person cannot sign in, so this is defense in depth),
// and leaves the draft pending.
func TestApprovalsBlockListSelfUnblock(t *testing.T) {
	e := newDraftEnv(t, nil)
	id := blockedEntry(t, e, "victim")
	d := e.heldBy(t, e.do("admin", http.MethodDelete, blockAPIPath+"/"+id, ""), "blocked_users", approvals.CodeBlockRemoved)
	ctx := WithPrincipal(context.Background(), Principal{Kind: PrincipalSession, Sub: "victim", Iss: "https://idp.example"})
	_, err := e.srv.Approvals().Approve(ctx, approvals.ApproveInput{
		ID: d.ID, Revision: d.Revision, DocSHA256: d.DocSHA256,
		Approver: approvals.Author{Iss: "https://idp.example", Sub: "victim", Kind: AuthorKindOIDC},
		Role:     config.RoleAdmin, AcknowledgeNoReplay: true,
	})
	var ce *dashboard.ChangeError
	if !errors.As(err, &ce) || ce.Code != "self_unblock_forbidden" {
		t.Fatalf("approve by the blocked person = %v, want self_unblock_forbidden", err)
	}
	if got := e.view(t, d.ID); got.State != "pending" || !e.srv.blocks.IsBlocked("victim", "") {
		t.Errorf("draft = %s, blocked = %v", got.State, e.srv.blocks.IsBlocked("victim", ""))
	}
}

// TestApprovalsBlockListFailsClosed: approvals on with no Service refuses the
// removal; adding a block still works.
func TestApprovalsBlockListFailsClosed(t *testing.T) {
	e := newDraftEnv(t, nil)
	id := blockedEntry(t, e, "victim")
	e.srv.gate = approvals.NewGate(true, nil)
	e.wantErr(t, e.do("admin", http.MethodDelete, blockAPIPath+"/"+id, ""), http.StatusServiceUnavailable, "approvals_unavailable")
	if !e.srv.blocks.IsBlocked("victim", "") {
		t.Fatal("the removal went through a missing approval service")
	}
	if rec := e.do("admin", http.MethodPost, blockAPIPath, `{"sub":"fresh"}`); rec.Code != http.StatusCreated {
		t.Errorf("add with the gate down = %d, want 201 (the kill switch never fails closed)", rec.Code)
	}
}

// TestApprovalsBlockListBreakGlass: a break-glass emergency apply of a held
// removal removes the entry and writes one change.draft.emergency_apply row.
func TestApprovalsBlockListBreakGlass(t *testing.T) {
	e := emergencyEnv(t)
	id := blockedEntry(t, e, "victim")
	d := e.heldBy(t, e.do("admin", http.MethodDelete, blockAPIPath+"/"+id, ""), "blocked_users", approvals.CodeBlockRemoved)
	path := draftsPath + "/" + d.ID + "/emergency-apply"

	e.wantErr(t, e.do("admin2", http.MethodPost, path, emergencyBody(emergencyReason)), http.StatusForbidden, "breakglass_required")
	if !e.srv.blocks.IsBlocked("victim", "") {
		t.Fatal("a refused emergency apply removed the entry")
	}
	rec := e.do("breakglass", http.MethodPost, path, emergencyBody(emergencyReason))
	if rec.Code != http.StatusOK {
		t.Fatalf("emergency-apply = %d %s", rec.Code, rec.Body.String())
	}
	if res := decodeBody[dashboard.ChangeResult](t, rec); res.State != "applied_unreviewed" {
		t.Errorf("state = %s, want applied_unreviewed", res.State)
	}
	if e.srv.blocks.IsBlocked("victim", "") || servedBlocked(e, "victim") {
		t.Error("the emergency apply did not remove the entry")
	}
	if n := len(okRows(e.auditRows("change.draft.emergency_apply"))); n != 1 {
		t.Errorf("change.draft.emergency_apply rows = %d, want 1", n)
	}
	rows := e.auditRows("blocked_users.remove")
	if got := rows[len(rows)-1]; got.Actor.Sub != "breakglass:ops" || got.Details["source"] != SourceApproval || got.TargetRef != "block:"+id {
		t.Errorf("removal row = %+v", got)
	}
	fs := e.pub.byRule("approval_bypassed")
	if len(fs) != 1 || fs[0].Severity != integration.SevCritical || !strings.Contains(string(fs[0].Evidence), "target=blocked_users") {
		t.Errorf("bypass Findings = %+v", fs)
	}
	// The post-hoc review closes it.
	if rec := e.do("admin2", http.MethodPost, draftsPath+"/"+d.ID+"/review", `{"comment":"confirmed with the incident lead"}`); rec.Code != http.StatusOK {
		t.Errorf("review = %d %s", rec.Code, rec.Body.String())
	}
}

// --- agents ---

const agentPathBase = "/dashboard/api/agents"

// seedAgent registers an active agent straight in the store.
func seedAgent(t *testing.T, e *draftEnv, id string, groups ...string) agentreg.Agent {
	t.Helper()
	a, err := e.srv.agents.Create(context.Background(), agentreg.Agent{
		ID: id, DisplayName: "Agent " + id, AllowedGroups: groups,
		Keys: []agentreg.Key{{JWK: agentregtest.Ed25519JWK(t, id+"-k1")}},
	}, "seed")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func agentRev(rev int64) []string {
	return []string{"If-Match", `"r` + strconv.FormatInt(rev, 10) + `"`}
}

func (e *draftEnv) agent(t *testing.T, id string) agentreg.Agent {
	t.Helper()
	a, err := e.srv.agents.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func servedAgent(e *draftEnv, id string) (config.RegisteredAgent, bool) {
	for _, a := range servedWire(e.srv).RegisteredAgents {
		if a.ID == id {
			return a, true
		}
	}
	return config.RegisteredAgent{}, false
}

func TestApprovalsAgents(t *testing.T) {
	e := newDraftEnv(t, nil)
	jwk := agentregtest.Ed25519JWK(t, "new-k1")
	var members map[string]string
	if err := json.Unmarshal(jwk, &members); err != nil {
		t.Fatal(err)
	}

	// Registering an agent is held: nothing is registered, nothing is served.
	body := agentJSON(t, "bot", "new-k1", "devs")
	d := e.heldBy(t, e.do("admin", http.MethodPost, agentPathBase, body), "agents", approvals.CodeAgentCreated)
	if d.TargetRef != "bot" || d.BaseVersion != 0 {
		t.Errorf("draft = %+v", d.ChangeDraftView)
	}
	if _, err := e.srv.agents.Get(context.Background(), "bot"); err == nil {
		t.Fatal("a held registration created the agent")
	}
	// The draft shows the key by id and thumbprint only.
	raw, _ := json.Marshal(d.Doc)
	if strings.Contains(string(raw), members["x"]) || strings.Contains(string(raw), `"jwk"`) || !strings.Contains(string(raw), `"jkt"`) {
		t.Errorf("draft doc = %s, want key ids and thumbprints only", raw)
	}
	if a := e.auditRows("agent.create"); len(a) != 1 || a[0].HTTPStatus != http.StatusAccepted || a[0].Details["op"] != "held" {
		t.Errorf("held row = %+v", a)
	}
	e.wantErr(t, e.approveTarget(t, "admin", d.ID), http.StatusForbidden, "self_approval_forbidden")
	rec := e.approveTarget(t, "admin2", d.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve registration = %d %s", rec.Code, rec.Body.String())
	}
	bot := e.agent(t, "bot")
	if bot.Status != agentreg.StatusActive || bot.CreatedBy != "oidc:admin2" || bot.OwnerSub != "admin" || bot.Revision != 1 || len(bot.Keys) != 1 {
		t.Fatalf("registered agent = %+v", bot)
	}
	if _, ok := servedAgent(e, "bot"); !ok {
		t.Error("the approved agent is not served")
	}
	rows := e.auditRows("agent.create")
	if last := rows[len(rows)-1]; last.Actor.Sub != "admin2" || last.TargetRef != "agent:bot" || last.Details["source"] != SourceApproval || last.Details["op"] != "create" {
		t.Errorf("create rows = %+v", rows)
	}

	// Display name edits apply directly (200, revision bumps).
	rec = e.do("admin", http.MethodPut, agentPathBase+"/bot", `{"displayName":"Renamed","keys":[`+string(jwk)+`],"allowedGroups":["devs"]}`, agentRev(bot.Revision)...)
	if rec.Code != http.StatusOK || e.agent(t, "bot").DisplayName != "Renamed" {
		t.Fatalf("rename = %d %s", rec.Code, rec.Body.String())
	}
	rev := e.agent(t, "bot").Revision

	// Adding a group is held with the If-Match revision as its base; the
	// served wire is unchanged until a second approval.
	wireBefore := wireJSON(t, servedWire(e.srv))
	addGroup := `{"displayName":"Renamed","keys":[` + string(jwk) + `],"allowedGroups":["devs","ops"]}`
	g := e.heldBy(t, e.do("admin", http.MethodPut, agentPathBase+"/bot", addGroup, agentRev(rev)...), "agents", approvals.CodeAgentGroupAdded)
	if g.BaseVersion != rev || e.agent(t, "bot").Revision != rev || wireJSON(t, servedWire(e.srv)) != wireBefore {
		t.Fatalf("held group add: base %d (want %d), revision %d, wire changed %v", g.BaseVersion, rev, e.agent(t, "bot").Revision, wireJSON(t, servedWire(e.srv)) != wireBefore)
	}
	if rec := e.approveTarget(t, "admin2", g.ID); rec.Code != http.StatusOK {
		t.Fatalf("approve group add = %d %s", rec.Code, rec.Body.String())
	}
	if got := e.agent(t, "bot"); len(got.AllowedGroups) != 2 || got.Revision != rev+1 || got.UpdatedBy != "oidc:admin2" || got.OwnerSub != "admin" {
		t.Fatalf("agent after the approved group add = %+v", got)
	}
	rev = e.agent(t, "bot").Revision

	// A stale draft: the agent moved since, so the approval is a rebase.
	scope := `{"displayName":"Renamed","keys":[` + string(jwk) + `],"allowedGroups":["devs","ops"],"allowedScopes":["read:repo"]}`
	s := e.heldBy(t, e.do("admin", http.MethodPut, agentPathBase+"/bot", scope, agentRev(rev)...), "agents", approvals.CodeAgentScopeAdded)
	if rec := e.do("admin2", http.MethodPost, agentPathBase+"/bot/disable", "", agentRev(rev)...); rec.Code != http.StatusOK {
		t.Fatalf("disable = %d %s", rec.Code, rec.Body.String())
	}
	e.wantErr(t, e.approveTarget(t, "admin2", s.ID), http.StatusConflict, "rebase_required")

	// Disabling was direct; enabling is held and never changes the wire first.
	rev = e.agent(t, "bot").Revision
	if got, ok := servedAgent(e, "bot"); !ok || got.Status != "disabled" {
		t.Fatalf("served agent = %+v %v, want disabled", got, ok)
	}
	en := e.heldBy(t, e.do("admin", http.MethodPost, agentPathBase+"/bot/enable", "", agentRev(rev)...), "agents", approvals.CodeAgentEnabled)
	if got, _ := servedAgent(e, "bot"); got.Status != "disabled" {
		t.Fatal("a held enable re-enabled the agent")
	}
	if rec := e.approveTarget(t, "admin2", en.ID); rec.Code != http.StatusOK || e.agent(t, "bot").Status != agentreg.StatusActive {
		t.Fatalf("approve enable = %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := servedAgent(e, "bot"); got.Status != "active" {
		t.Errorf("served status = %q after the approved enable", got.Status)
	}
	rev = e.agent(t, "bot").Revision

	// A replaced key is held; removing a group is direct.
	newKey := agentregtest.Ed25519JWK(t, "new-k2")
	k := e.heldBy(t, e.do("admin", http.MethodPut, agentPathBase+"/bot", `{"displayName":"Renamed","keys":[`+string(newKey)+`],"allowedGroups":["devs","ops"]}`, agentRev(rev)...), "agents", approvals.CodeAgentKeyAdded)
	if k.Reasons[0].Code != approvals.CodeAgentKeyAdded || strings.Contains(k.Reasons[0].Detail, members["x"]) {
		t.Errorf("reasons = %+v", k.Reasons)
	}
	if rec := e.do("admin", http.MethodPut, agentPathBase+"/bot", `{"displayName":"Renamed","keys":[`+string(jwk)+`],"allowedGroups":["devs"]}`, agentRev(rev)...); rec.Code != http.StatusOK {
		t.Fatalf("remove group = %d %s", rec.Code, rec.Body.String())
	}
	// The draft's base is now stale.
	e.wantErr(t, e.approveTarget(t, "admin2", k.ID), http.StatusConflict, "rebase_required")

	// A second registration of the same id is refused before it can be held.
	e.wantErr(t, e.do("admin", http.MethodPost, agentPathBase, body), http.StatusConflict, "agent_exists")
}

// TestApprovalsAgentsFailsClosed: an enabled gate with no Service refuses a
// registration or an enable and holds nothing.
func TestApprovalsAgentsFailsClosed(t *testing.T) {
	e := newDraftEnv(t, nil)
	a := seedAgent(t, e, "bot", "devs")
	if _, err := e.srv.agents.SetStatus(context.Background(), "bot", agentreg.StatusDisabled, a.Revision, "seed"); err != nil {
		t.Fatal(err)
	}
	e.srv.gate = approvals.NewGate(true, nil)
	e.wantErr(t, e.do("admin", http.MethodPost, agentPathBase, agentJSON(t, "other", "other-k1", "devs")), http.StatusServiceUnavailable, "approvals_unavailable")
	e.wantErr(t, e.do("admin", http.MethodPost, agentPathBase+"/bot/enable", "", agentRev(a.Revision+1)...), http.StatusServiceUnavailable, "approvals_unavailable")
	if got := e.agent(t, "bot"); got.Status != agentreg.StatusDisabled {
		t.Fatalf("status = %s, the enable went through a missing service", got.Status)
	}
	if n := openDrafts(t, e); n != 0 {
		t.Errorf("drafts = %d, want none", n)
	}
}

// TestApprovalsTargetRoutesHold: every route listed in gatedTargetRoutes
// answers 202 for a widening request, with the draft of its own target.
func TestApprovalsTargetRoutesHold(t *testing.T) {
	for key, target := range gatedTargetRoutes {
		t.Run(key.Method+" "+key.Path, func(t *testing.T) {
			e := newDraftEnv(t, nil)
			var rec *httptest.ResponseRecorder
			switch {
			case target == "blocked_users":
				id := blockedEntry(t, e, "victim")
				rec = e.do("admin", key.Method, strings.ReplaceAll(key.Path, "{id}", id), "")
			case key.Method == http.MethodPost && strings.HasSuffix(key.Path, "/enable"):
				a := seedAgent(t, e, "bot", "devs")
				if _, err := e.srv.agents.SetStatus(context.Background(), "bot", agentreg.StatusDisabled, a.Revision, "seed"); err != nil {
					t.Fatal(err)
				}
				rec = e.do("admin", key.Method, strings.ReplaceAll(key.Path, "{id}", "bot"), "", agentRev(a.Revision+1)...)
			case key.Method == http.MethodPost:
				rec = e.do("admin", key.Method, key.Path, agentJSON(t, "bot", "bot-k1", "devs"))
			default:
				a := seedAgent(t, e, "bot", "devs")
				rec = e.do("admin", key.Method, strings.ReplaceAll(key.Path, "{id}", "bot"), `{"keys":[`+string(agentregtest.Ed25519JWK(t, "bot-k1"))+`],"allowedGroups":["devs","more"]}`, agentRev(a.Revision)...)
			}
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d %s, want 202 (a widening write must be held)", rec.Code, rec.Body.String())
			}
			if d := decodeBody[heldBody](t, rec); e.view(t, d.DraftID).Target != target {
				t.Errorf("held draft target = %s, want %s", e.view(t, d.DraftID).Target, target)
			}
		})
	}
}

// TestApprovalsAgentsEmergency: a break-glass session applies a held agent
// draft, which records the bypass.
func TestApprovalsAgentsEmergency(t *testing.T) {
	e := emergencyEnv(t)
	d := e.heldBy(t, e.do("admin", http.MethodPost, agentPathBase, agentJSON(t, "bot", "bot-k1", "devs")), "agents", approvals.CodeAgentCreated)
	rec := e.do("breakglass", http.MethodPost, draftsPath+"/"+d.ID+"/emergency-apply", emergencyBody(emergencyReason))
	if rec.Code != http.StatusOK {
		t.Fatalf("emergency-apply = %d %s", rec.Code, rec.Body.String())
	}
	if got := e.agent(t, "bot"); got.CreatedBy != "breakglass:ops" || got.Status != agentreg.StatusActive {
		t.Errorf("agent = %+v", got)
	}
	if fs := e.pub.byRule("approval_bypassed"); len(fs) != 1 {
		t.Errorf("bypass Findings = %d, want 1", len(fs))
	}
}

// TestApprovalsAgentsApprovalsOff: with approvals disabled the registry writes
// are unchanged (201 / 200, never 202).
func TestApprovalsAgentsApprovalsOff(t *testing.T) {
	e := newDraftEnv(t, nil)
	e.srv.gate = approvals.NewGate(false, nil)
	if rec := e.do("admin", http.MethodPost, agentPathBase, agentJSON(t, "bot", "bot-k1", "devs")); rec.Code != http.StatusCreated {
		t.Fatalf("create with approvals off = %d %s", rec.Code, rec.Body.String())
	}
	id := blockedEntry(t, e, "victim")
	if rec := e.do("admin", http.MethodDelete, blockAPIPath+"/"+id, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("unblock with approvals off = %d", rec.Code)
	}
}

// TestApprovalsBlockDraftHidesWho: the block list is admin-only, so a viewer
// session and a policy:read API key see no sub or email in the draft list,
// detail or diff of a blocked_users draft; an admin session and a key whose
// owner is an admin do.
func TestApprovalsBlockDraftHidesWho(t *testing.T) {
	e := newDraftEnvKeys(t)
	id, err := e.srv.blocks.Add(context.Background(), BlockEntry{Sub: "victim", Email: "victim@corp.example", Reason: blockedReason}, "seed")
	if err != nil {
		t.Fatal(err)
	}
	d := e.heldBy(t, e.do("admin", http.MethodDelete, blockAPIPath+"/"+id, ""), "blocked_users", approvals.CodeBlockRemoved)
	viewerKey := e.mintKey(t, "viewer", groupViewer, "policy:read")
	adminKey := e.mintKey(t, "admin", groupAdmin, "policy:read")
	paths := []string{draftsPath, draftsPath + "?target=blocked_users", draftsPath + "/" + d.ID, draftsPath + "/" + d.ID + "/diff"}
	for _, p := range paths {
		for who, rec := range map[string]*httptest.ResponseRecorder{
			"viewer session": e.do("viewer", http.MethodGet, p, ""),
			"viewer key":     e.doKey(viewerKey, http.MethodGet, p, ""),
		} {
			if rec.Code != http.StatusOK {
				t.Fatalf("%s GET %s = %d %s", who, p, rec.Code, rec.Body)
			}
			if b := rec.Body.String(); strings.Contains(b, "victim") || strings.Contains(b, "corp.example") {
				t.Errorf("%s GET %s names the blocked person: %s", who, p, b)
			}
		}
	}
	rec := e.do("viewer", http.MethodGet, draftsPath+"/"+d.ID+"/diff", "")
	if !strings.Contains(rec.Body.String(), `"has_sub":true`) || !strings.Contains(rec.Body.String(), `"has_email":true`) {
		t.Errorf("viewer diff = %s, want has_sub and has_email", rec.Body)
	}
	for who, rec := range map[string]*httptest.ResponseRecorder{
		"admin session": e.do("admin", http.MethodGet, draftsPath+"/"+d.ID, ""),
		"admin key":     e.doKey(adminKey, http.MethodGet, draftsPath+"/"+d.ID+"/diff", ""),
	} {
		if !strings.Contains(rec.Body.String(), `"sub":"victim"`) {
			t.Errorf("%s = %s, want the entry", who, rec.Body)
		}
	}
}

// TestApprovalsDisableIsKillSwitch: disabling an agent never waits on the gate.
func TestApprovalsDisableIsKillSwitch(t *testing.T) {
	e := newDraftEnv(t, nil)
	a := seedAgent(t, e, "bot", "devs")
	e.srv.gate = approvals.NewGate(true, nil)
	rec := e.do("admin", http.MethodPost, agentPathBase+"/bot/disable", "", agentRev(a.Revision)...)
	if rec.Code != http.StatusOK || e.agent(t, "bot").Status != agentreg.StatusDisabled {
		t.Fatalf("disable with the gate down = %d %s, want 200", rec.Code, rec.Body)
	}
}

// crashApply claims d like an approval or emergency apply and runs the target's
// Applier, then stops before the draft is marked: the state a crash leaves.
func crashApply(t *testing.T, e *draftEnv, d dashboard.ChangeDraftView, emergency bool) {
	t.Helper()
	ctx := context.Background()
	store := e.srv.Approvals().Store()
	ad := e.srv.targetAdapters()[approvals.Target(d.Target)]
	actor := approvals.Author{Iss: "https://idp.example", Sub: "admin2", Kind: AuthorKindOIDC}
	in := approvals.DecisionInput{Revision: d.Revision, DocSHA256: d.DocSHA256, Approver: actor, ApproverRole: "admin"}
	var claimed approvals.Draft
	var err error
	if emergency {
		actor = approvals.Author{Iss: "warden-breakglass", Sub: "breakglass:ops", Kind: approvals.AuthorKindBreakglass}
		in.Approver, in.Decision, in.Comment = actor, approvals.DecisionEmergency, emergencyReason
		claimed, err = store.BeginEmergency(ctx, d.ID, in)
	} else {
		in.Decision, in.AcknowledgeNoReplay = approvals.DecisionApprove, true
		if _, _, err = store.RecordDecision(ctx, d.ID, in); err == nil {
			claimed, err = store.BeginApply(ctx, d.ID, d.Revision, actor.Sub)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	pctx := WithPrincipal(ctx, Principal{Kind: PrincipalSession, Sub: actor.Sub, Iss: actor.Iss})
	if emergency {
		pctx = WithPrincipal(ctx, Principal{Kind: PrincipalBreakglass, Sub: actor.Sub})
		_, err = ad.ApplyEmergency(pctx, claimed, approvals.Clearance{}, actor)
	} else {
		_, err = ad.Apply(pctx, claimed)
	}
	if err != nil {
		t.Fatal(err)
	}
	if got := e.view(t, d.ID); got.State != "applying" {
		t.Fatalf("draft = %s, want applying (the crash window)", got.State)
	}
}

// TestApprovalsReconcileTargets: a crash after the Applier wrote and before the
// draft was marked is settled from the target's own state: an ordinary apply
// becomes applied, an emergency one applied_unreviewed (and the bypass is
// reported), never pending again.
func TestApprovalsReconcileTargets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		emergency bool
		want      string
	}{{"ordinary", false, "applied"}, {"emergency", true, "applied_unreviewed"}} {
		for _, target := range []string{"blocked_users", "agents_create", "agents_update"} {
			t.Run(tc.name+"/"+target, func(t *testing.T) {
				e := emergencyEnv(t)
				var rec *httptest.ResponseRecorder
				switch target {
				case "blocked_users":
					rec = e.do("admin", http.MethodDelete, blockAPIPath+"/"+blockedEntry(t, e, "victim"), "")
				case "agents_create":
					rec = e.do("admin", http.MethodPost, agentPathBase, agentJSON(t, "bot", "bot-k1", "devs"))
				default:
					a := seedAgent(t, e, "bot", "devs")
					rec = e.do("admin", http.MethodPut, agentPathBase+"/bot", `{"keys":[`+string(agentregtest.Ed25519JWK(t, "bot-k1"))+`],"allowedGroups":["devs","more"]}`, agentRev(a.Revision)...)
				}
				if rec.Code != http.StatusAccepted {
					t.Fatalf("write = %d %s, want 202", rec.Code, rec.Body)
				}
				d := e.view(t, decodeBody[heldBody](t, rec).DraftID)
				crashApply(t, e, d.ChangeDraftView, tc.emergency)

				n, err := e.srv.Approvals().Reconcile(context.Background(), e.srv.versionFinder(e.srv.Approvals()))
				if err != nil || n != 1 {
					t.Fatalf("Reconcile = %d, %v; want 1", n, err)
				}
				if got := e.view(t, d.ID); got.State != tc.want {
					t.Fatalf("draft after reconcile = %s, want %s", got.State, tc.want)
				}
				if tc.emergency && !strings.Contains(e.logs.String(), "approval_bypassed") {
					t.Error("a repaired emergency apply was not reported")
				}
			})
		}
	}
}

// TestApprovalsReconcileTargetsNotApplied: a crash before the Applier wrote
// returns the draft to pending.
func TestApprovalsReconcileTargetsNotApplied(t *testing.T) {
	e := newDraftEnv(t, nil)
	id := blockedEntry(t, e, "victim")
	rec := e.do("admin", http.MethodDelete, blockAPIPath+"/"+id, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("remove = %d, want 202", rec.Code)
	}
	d := e.view(t, decodeBody[heldBody](t, rec).DraftID)
	if _, _, err := e.srv.Approvals().Store().RecordDecision(context.Background(), d.ID, approvals.DecisionInput{
		Revision: d.Revision, DocSHA256: d.DocSHA256, Decision: approvals.DecisionApprove, AcknowledgeNoReplay: true,
		Approver: approvals.Author{Iss: "https://idp.example", Sub: "admin2", Kind: AuthorKindOIDC}, ApproverRole: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Approvals().Store().BeginApply(context.Background(), d.ID, d.Revision, "admin2"); err != nil {
		t.Fatal(err)
	}
	if n, err := e.srv.Approvals().Reconcile(context.Background(), e.srv.versionFinder(e.srv.Approvals())); err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, %v", n, err)
	}
	if got := e.view(t, d.ID); got.State != "pending" || !e.srv.blocks.IsBlocked("victim", "") {
		t.Errorf("draft = %s, blocked = %v; want pending and still blocked", got.State, e.srv.blocks.IsBlocked("victim", ""))
	}
}

type appendFailRecorder struct{}

func (appendFailRecorder) Record(context.Context, adminaudit.Input) (adminaudit.Entry, error) {
	return adminaudit.Entry{}, errors.New("append failed")
}

// TestBlockCLIHoldAuditFailure: when the audit row cannot be appended the
// offline removal leaves no pending draft behind.
func TestBlockCLIHoldAuditFailure(t *testing.T) {
	e := newDraftEnv(t, nil)
	id := blockedEntry(t, e, "victim")
	entry, ok, err := blockTarget{s: e.srv}.entry(context.Background(), id)
	if err != nil || !ok {
		t.Fatal(err)
	}
	got, err := holdBlockRemoval(context.Background(), e.srv.blocks, sqlstore.Meta{Enabled: true, DraftTTL: time.Hour, MaxOpenDrafts: 5}, entry, appendFailRecorder{})
	if err == nil || got != "" {
		t.Fatalf("holdBlockRemoval = %q, %v; want an audit error and no draft id", got, err)
	}
	pending, _, lerr := e.srv.Approvals().Store().List(context.Background(), approvals.Filter{State: approvals.StatePending}, "", 10)
	if lerr != nil || len(pending) != 0 {
		t.Errorf("pending drafts = %d, %v; want none", len(pending), lerr)
	}
}
