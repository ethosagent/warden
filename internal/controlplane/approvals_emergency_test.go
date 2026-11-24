package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/alertpipeline"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
)

// The break-glass emergency apply and its post-hoc review (W-P2-APPR-07) over a
// real control plane: oidc console, versioned store, approvals on, a break-glass
// session and OIDC admins created through SessionStore.Create.

const emergencyReason = "dex is down and the payments vendor is blocked"

func emergencyEnv(t *testing.T) *draftEnv {
	t.Helper()
	return newDraftEnv(t, func(a *config.ConsoleApprovals) { a.AllowEmergencyApply = true })
}

func emergencyBody(reason string) string { return `{"reason":` + quoteJSON(reason) + `}` }

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// heldDraft makes a submitted widening draft by u1 and returns it.
func (e *draftEnv) heldDraft(t *testing.T, domain string) dashboard.ChangeDraftDetail {
	t.Helper()
	d := e.create(t, "u1", docWith(`{"domain":"`+domain+`"}`))
	if rec := e.submit(t, "u1", d.ID); rec.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", rec.Code, rec.Body.String())
	}
	return d
}

// auditRows are the audit rows recorded so far with the given action.
func (e *draftEnv) auditRows(action string) []adminaudit.Input {
	var out []adminaudit.Input
	for _, in := range e.rec.inputs() {
		if in.Action == action {
			out = append(out, in)
		}
	}
	return out
}

// TestEmergencyApplyDisabled: with allowEmergencyApply off (the default) a
// break-glass session cannot apply, and nothing changes.
func TestEmergencyApplyDisabled(t *testing.T) {
	e := newDraftEnv(t, nil)
	d := e.heldDraft(t, "off.example.com")
	rows := len(e.rec.inputs())
	rec := e.do("breakglass", http.MethodPost, draftsPath+"/"+d.ID+"/emergency-apply", emergencyBody(emergencyReason))
	e.wantErr(t, rec, http.StatusForbidden, "emergency_apply_disabled")
	e.wantHead(t, 1)
	if got := e.view(t, d.ID); got.State != "pending" || len(got.ApprovalRows) != 0 {
		t.Errorf("draft = %s with %d rows, want an untouched pending draft", got.State, len(got.ApprovalRows))
	}
	if n := len(e.pub.byRule("approval_bypassed")); n != 0 {
		t.Errorf("approval_bypassed Findings = %d, want 0", n)
	}
	if got := e.rec.inputs(); len(got) != rows+1 || got[rows].Action != "change.draft.emergency_apply" || got[rows].Outcome != adminaudit.OutcomeDenied {
		t.Errorf("rows after a refused call = %+v, want one denied change.draft.emergency_apply row", got[rows:])
	}
	if strings.Contains(e.logs.String(), "approval_bypassed") {
		t.Error("a refused emergency apply logged approval_bypassed")
	}
}

// TestEmergencyApply is the whole route: who may call it, what it does, and
// everything it records.
func TestEmergencyApply(t *testing.T) {
	e := emergencyEnv(t)
	seedEvent(t, e)
	d := e.heldDraft(t, "vendor.example.com")
	path := draftsPath + "/" + d.ID + "/emergency-apply"
	body := emergencyBody(emergencyReason)

	// An OIDC admin is not a break-glass session; an editor is not even an
	// admin; a viewer and a stranger are refused first.
	e.wantErr(t, e.do("admin", http.MethodPost, path, body), http.StatusForbidden, "breakglass_required")
	for who, want := range map[string]int{"u1": http.StatusForbidden, "viewer": http.StatusForbidden, "": http.StatusUnauthorized} {
		if rec := e.do(who, http.MethodPost, path, body); rec.Code != want {
			t.Errorf("emergency-apply as %q = %d, want %d", who, rec.Code, want)
		}
	}
	e.wantHead(t, 1)
	if got := e.view(t, d.ID); got.State != "pending" || len(got.ApprovalRows) != 0 {
		t.Fatalf("draft after refusals = %s with %d rows", got.State, len(got.ApprovalRows))
	}
	// A break-glass session still cannot approve a normal draft (#104).
	e.wantErr(t, e.do("breakglass", http.MethodPost, draftsPath+"/"+d.ID+"/approve", approveBody(d.ChangeDraftView, "", "")), http.StatusForbidden, "breakglass_cannot_approve")
	e.wantHead(t, 1)

	etagBefore := e.srv.policy.currentETag()
	rec := e.do("breakglass", http.MethodPost, path, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("emergency-apply = %d %s", rec.Code, rec.Body.String())
	}
	res := decodeBody[dashboard.ChangeResult](t, rec)
	if res.State != "applied_unreviewed" || res.AppliedVersion != 2 || res.Version != 2 || rec.Header().Get(dashboard.PolicyVersionHeader) != "2" {
		t.Fatalf("result = %+v (version header %q)", res.ChangeDraftView, rec.Header().Get(dashboard.PolicyVersionHeader))
	}
	e.wantHead(t, 2)
	if e.srv.policy.currentETag() == etagBefore {
		t.Error("the served policy ETag did not change")
	}

	// The version is authored by the break-glass actor, named for the draft.
	v, err := e.srv.versions.Get(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if v.Author.Kind != AuthorKindBreakglass || v.Author.Sub != "breakglass:ops" || v.Source != SourceApproval ||
		!strings.HasPrefix(v.Message, draftVersionPrefix(d.ID, d.Revision)+"emergency apply") {
		t.Errorf("version 2 = author %+v source %q message %q", v.Author, v.Source, v.Message)
	}

	// The emergency decision row carries the reason, the actor and the digest.
	got := e.view(t, d.ID)
	if len(got.ApprovalRows) != 1 {
		t.Fatalf("approval rows = %+v", got.ApprovalRows)
	}
	r := got.ApprovalRows[0]
	if r.Decision != "emergency" || r.Comment != emergencyReason || r.AuthMethod != "breakglass" || r.Approver.Sub != "breakglass:ops" ||
		r.ApproverRole != "admin" || r.DocSHA256 != d.DocSHA256 || r.Revision != d.Revision {
		t.Errorf("emergency row = %+v", r)
	}

	// One primary admin audit row, preceded by the row written before the
	// publish, followed by the policy row of the version it made.
	if n := len(okRows(e.auditRows("change.draft.emergency_apply"))); n != 1 {
		t.Errorf("successful change.draft.emergency_apply rows = %d, want 1", n)
	}
	all := e.actions()
	tail := all[len(all)-3:]
	if tail[0] != actionEmergencyBegin || tail[1] != "change.draft.emergency_apply" || tail[2] != "policy.write" {
		t.Errorf("audit tail = %v, want [%s change.draft.emergency_apply policy.write]", tail, actionEmergencyBegin)
	}
	begin := e.auditRows(actionEmergencyBegin)[0]
	if begin.AuthMethod != adminaudit.AuthMethodBreakglass || begin.Actor.Sub != "breakglass:ops" || begin.TargetRef != "draft:"+d.ID+"@r1" ||
		begin.Outcome != adminaudit.OutcomeOK || begin.Details[adminaudit.DetailOp] != "emergency_begin" {
		t.Errorf("begin row = %+v", begin)
	}
	primary := okRows(e.auditRows("change.draft.emergency_apply"))[0]
	if primary.AuthMethod != adminaudit.AuthMethodBreakglass || primary.ActorRole != "admin" || primary.Outcome != adminaudit.OutcomeOK ||
		primary.TargetRef != "draft:"+d.ID+"@r1" || primary.Details[adminaudit.DetailAppliedVersion] != "2" {
		t.Errorf("primary row = %+v", primary)
	}
	for _, in := range e.rec.inputs() {
		for k, v := range in.Details {
			if strings.Contains(v, emergencyReason) || k == "reason" {
				t.Errorf("audit row %s carries the reason in %s=%s", in.Action, k, v)
			}
		}
	}
	policyRow := e.auditRows("policy.write")
	if len(policyRow) == 0 || policyRow[len(policyRow)-1].Details[adminaudit.DetailSource] != SourceApproval || policyRow[len(policyRow)-1].Details[adminaudit.DetailOp] != "emergency_apply" {
		t.Errorf("no policy.write follow-up row with the approval source and op emergency_apply: %+v", policyRow)
	}

	// One critical Finding, keyed by the draft, and one ERROR line without the
	// reason.
	fs := e.pub.byRule("approval_bypassed")
	if len(fs) != 1 || fs[0].Severity != integration.SevCritical || fs[0].DedupKey != "approval_bypassed:"+d.ID || fs[0].Category != "security" {
		t.Fatalf("Findings = %+v", fs)
	}
	if strings.Contains(string(fs[0].Evidence), emergencyReason) {
		t.Error("the Finding carries the reason")
	}
	logs := e.logs.String()
	if n := countLines(logs, "msg=approval_bypassed"); n != 1 {
		t.Errorf("approval_bypassed log lines = %d, want 1\n%s", n, logs)
	}
	line := lineWith(logs, "msg=approval_bypassed")
	if !strings.Contains(line, "level=ERROR") || !strings.Contains(line, "draft_id="+d.ID) || !strings.Contains(line, "actor_sub=breakglass:ops") {
		t.Errorf("approval_bypassed line = %q", line)
	}
	if strings.Contains(logs, emergencyReason) {
		t.Error("the reason reached the logs")
	}

	// An applied_unreviewed draft is closed to every other path.
	e.wantErr(t, e.do("breakglass", http.MethodPost, path, body), http.StatusConflict, "illegal_transition")
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath+"/"+d.ID+"/withdraw", ""), http.StatusConflict, "illegal_transition")
	e.wantErr(t, e.do("admin2", http.MethodPost, draftsPath+"/"+d.ID+"/approve", approveBody(d.ChangeDraftView, "", "")), http.StatusConflict, "illegal_transition")
	e.wantHead(t, 2)
	if n := len(e.pub.byRule("approval_bypassed")); n != 1 {
		t.Errorf("Findings after refused repeats = %d, want 1", n)
	}
}

func countLines(logs, sub string) int {
	n := 0
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

func lineWith(logs, sub string) string {
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

// TestEmergencyApplyReason: the reason is 10 to 512 characters.
func TestEmergencyApplyReason(t *testing.T) {
	e := emergencyEnv(t)
	d := e.heldDraft(t, "reason.example.com")
	path := draftsPath + "/" + d.ID + "/emergency-apply"
	for name, body := range map[string]string{
		"missing":    `{}`,
		"9 chars":    emergencyBody("123456789"),
		"blank":      emergencyBody("                    "),
		"513 chars":  emergencyBody(strings.Repeat("x", 513)),
		"extra keys": `{"reason":"` + emergencyReason + `","skip_review":true}`,
	} {
		rec := e.do("breakglass", http.MethodPost, path, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
	e.wantHead(t, 1)
	if got := e.view(t, d.ID); got.State != "pending" || len(got.ApprovalRows) != 0 {
		t.Errorf("draft after refusals = %s with %d rows", got.State, len(got.ApprovalRows))
	}
	// 10 and 512 characters are in range.
	if rec := e.do("breakglass", http.MethodPost, path, emergencyBody("0123456789")); rec.Code != http.StatusOK {
		t.Errorf("10 chars = %d %s, want 200", rec.Code, rec.Body.String())
	}
	d2 := e.heldDraft(t, "reason2.example.com")
	e.wantErr(t, e.do("breakglass", http.MethodPost, draftsPath+"/"+d2.ID+"/emergency-apply", emergencyBody(strings.Repeat("y", 512))), http.StatusConflict, "rebase_required")
}

// TestEmergencyApplyHeadMoved: expectedHead still applies. A moved head is a 409
// rebase_required, the draft becomes needs_rebase, nothing publishes and no
// Finding is raised; the attempt is still audited.
func TestEmergencyApplyHeadMoved(t *testing.T) {
	e := emergencyEnv(t)
	d := e.heldDraft(t, "moved.example.com")
	if err := writePolicyUngated(sessionCtx("someone", "someone@example.com"), e.srv, plusAllow(t, e.srv, "theirs.example.com")); err != nil {
		t.Fatal(err)
	}
	path := draftsPath + "/" + d.ID + "/emergency-apply"
	b := e.wantErr(t, e.do("breakglass", http.MethodPost, path, emergencyBody(emergencyReason)), http.StatusConflict, "rebase_required")
	if b.Head != 2 {
		t.Errorf("head in the 409 = %d, want 2", b.Head)
	}
	e.wantHead(t, 2)
	if got := e.view(t, d.ID); got.State != "needs_rebase" {
		t.Fatalf("state = %s, want needs_rebase", got.State)
	}
	if n := len(e.pub.byRule("approval_bypassed")); n != 0 {
		t.Errorf("approval_bypassed Findings = %d, want 0 (nothing was bypassed)", n)
	}
	if len(e.auditRows(actionEmergencyBegin)) != 1 || len(e.auditRows("change.draft.emergency_apply")) != 1 {
		t.Errorf("audit rows = %v, want the attempt recorded", e.actions())
	}
	// A needs_rebase draft is a valid target; it still conflicts until rebased.
	e.wantErr(t, e.do("breakglass", http.MethodPost, path, emergencyBody(emergencyReason)), http.StatusConflict, "rebase_required")
	// After the author rebases onto the new head, the emergency apply publishes.
	if rec := e.do("u1", http.MethodPost, draftsPath+"/"+d.ID+"/rebase", ""); rec.Code != http.StatusOK {
		t.Fatalf("rebase = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do("breakglass", http.MethodPost, path, emergencyBody(emergencyReason)); rec.Code != http.StatusOK {
		t.Fatalf("emergency-apply after a rebase = %d %s", rec.Code, rec.Body.String())
	}
	e.wantHead(t, 3)
	if got := e.view(t, d.ID); got.State != "applied_unreviewed" || got.Revision != 2 {
		t.Errorf("draft = %s r%d, want applied_unreviewed r2", got.State, got.Revision)
	}
}

// TestEmergencyApplyAuditFailure: the audit row precedes the publish, so a
// recorder that cannot write stops the apply with nothing published.
func TestEmergencyApplyAuditFailure(t *testing.T) {
	e := emergencyEnv(t)
	d := e.heldDraft(t, "audit.example.com")
	e.rec.set(errors.New("disk full"), nil)
	rec := e.do("breakglass", http.MethodPost, draftsPath+"/"+d.ID+"/emergency-apply", emergencyBody(emergencyReason))
	e.rec.set(nil, nil)
	e.wantErr(t, rec, http.StatusServiceUnavailable, "admin_audit_unavailable")
	e.wantHead(t, 1)
	if got := e.view(t, d.ID); got.State != "pending" {
		t.Errorf("state = %s, want pending", got.State)
	}
	if n := len(e.pub.byRule("approval_bypassed")); n != 0 {
		t.Errorf("approval_bypassed Findings = %d, want 0", n)
	}
	// Once the recorder works again the same draft applies.
	if rec := e.do("breakglass", http.MethodPost, draftsPath+"/"+d.ID+"/emergency-apply", emergencyBody(emergencyReason)); rec.Code != http.StatusOK {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body.String())
	}
	e.wantHead(t, 2)
}

// TestEmergencyApplyRateLimited: it is not a general bypass: five claims in ten
// minutes across all break-glass sessions, then 429.
func TestEmergencyApplyRateLimited(t *testing.T) {
	e := emergencyEnv(t)
	var ids []string
	for i := range 6 {
		ids = append(ids, e.heldDraft(t, "rl"+string(rune('a'+i))+".example.com").ID)
	}
	// The first publishes and moves head; the next four conflict (they still
	// count: each claimed its draft and wrote its audit rows).
	if rec := e.do("breakglass", http.MethodPost, draftsPath+"/"+ids[0]+"/emergency-apply", emergencyBody(emergencyReason)); rec.Code != http.StatusOK {
		t.Fatalf("first = %d %s", rec.Code, rec.Body.String())
	}
	for _, id := range ids[1:5] {
		e.wantErr(t, e.do("breakglass", http.MethodPost, draftsPath+"/"+id+"/emergency-apply", emergencyBody(emergencyReason)), http.StatusConflict, "rebase_required")
	}
	rows := len(e.rec.inputs())
	e.wantErr(t, e.do("breakglass", http.MethodPost, draftsPath+"/"+ids[5]+"/emergency-apply", emergencyBody(emergencyReason)), http.StatusTooManyRequests, "emergency_rate_limited")
	if got := e.view(t, ids[5]); got.State != "pending" || len(got.ApprovalRows) != 0 {
		t.Errorf("a rate-limited call touched the draft: %s, %d rows", got.State, len(got.ApprovalRows))
	}
	if n := len(e.rec.inputs()) - rows; n != 1 {
		t.Errorf("a rate-limited call wrote %d audit rows, want just its denied row", n)
	}
	e.wantHead(t, 2)
}

// TestEmergencyReview: an OIDC admin closes the loop. A break-glass session, an
// editor and a draft with nothing to review are refused.
func TestEmergencyReview(t *testing.T) {
	e := emergencyEnv(t)
	d := e.heldDraft(t, "review.example.com")
	review := draftsPath + "/" + d.ID + "/review"
	body := `{"comment":"confirmed with the vendor, change is correct"}`

	// Nothing to review yet.
	e.wantErr(t, e.do("admin", http.MethodPost, review, body), http.StatusConflict, "illegal_transition")
	if rec := e.do("breakglass", http.MethodPost, draftsPath+"/"+d.ID+"/emergency-apply", emergencyBody(emergencyReason)); rec.Code != http.StatusOK {
		t.Fatalf("emergency-apply = %d %s", rec.Code, rec.Body.String())
	}
	e.wantErr(t, e.do("breakglass", http.MethodPost, review, body), http.StatusForbidden, "breakglass_cannot_review")
	for who, want := range map[string]int{"u1": http.StatusForbidden, "viewer": http.StatusForbidden, "": http.StatusUnauthorized} {
		if rec := e.do(who, http.MethodPost, review, body); rec.Code != want {
			t.Errorf("review as %q = %d, want %d", who, rec.Code, want)
		}
	}
	e.wantErr(t, e.do("admin", http.MethodPost, review, `{"comment":"long enough comment","revision":7}`), http.StatusConflict, "revision_changed")
	if got := e.view(t, d.ID); got.State != "applied_unreviewed" {
		t.Fatalf("state after refusals = %s", got.State)
	}

	rec := e.do("admin", http.MethodPost, review, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("review = %d %s", rec.Code, rec.Body.String())
	}
	got := e.view(t, d.ID)
	if got.State != "applied" || got.AppliedVersion != 2 || len(got.ApprovalRows) != 2 {
		t.Fatalf("draft = %s v%d with %d rows", got.State, got.AppliedVersion, len(got.ApprovalRows))
	}
	if r := got.ApprovalRows[1]; r.Decision != "post_review" || r.Approver.Sub != "admin" || r.ApproverRole != "admin" ||
		r.AuthMethod != "oidc" || r.Comment != "confirmed with the vendor, change is correct" {
		t.Errorf("post_review row = %+v", r)
	}
	if rows := e.auditRows("change.draft.review"); len(rows) == 0 || rows[len(rows)-1].Outcome != adminaudit.OutcomeOK || rows[len(rows)-1].AuthMethod != adminaudit.AuthMethodOIDC {
		t.Errorf("review audit rows = %+v", rows)
	}
	e.wantHead(t, 2)
	e.wantErr(t, e.do("admin", http.MethodPost, review, body), http.StatusConflict, "illegal_transition")
}

// TestEmergencyRoutesNeedApprovals: with approvals off the routes answer 404.
func TestEmergencyRoutesNeedApprovals(t *testing.T) {
	e := newAuthzEnv(t)
	admin := e.session(t, groupAdmin)
	for _, p := range []string{"/dashboard/api/changes/cd_1/emergency-apply", "/dashboard/api/changes/cd_1/review"} {
		rec := e.do(admin, http.MethodPost, p, `{"reason":"`+emergencyReason+`"}`)
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s with approvals off = %d, want 404", p, rec.Code)
		}
	}
}

// TestEmergencyOnlyGateMintsIt: the policy Applier refuses an emergency publish
// without an emergency Clearance, and an ordinary Clearance cannot be turned
// into one.
func TestEmergencyOnlyGateMintsIt(t *testing.T) {
	e := emergencyEnv(t)
	d := e.heldDraft(t, "mint.example.com")
	stored, err := e.srv.Approvals().Store().Get(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	a := policyApplier{s: e.srv}
	// The zero Clearance publishes nothing.
	if _, err := a.ApplyEmergency(context.Background(), stored, approvals.Clearance{}, approvals.Author{Sub: "breakglass:ops", Kind: AuthorKindBreakglass}); !errors.Is(err, approvals.ErrNotCleared) {
		t.Fatalf("ApplyEmergency with the zero Clearance = %v, want ErrNotCleared", err)
	}
	// A pending draft cannot be cleared as applied or emergency-claimed by hand.
	if _, err := e.srv.gate.ClearApplied(context.Background(), stored); !errors.Is(err, approvals.ErrNotCleared) {
		t.Fatalf("ClearApplied of a pending draft = %v, want ErrNotCleared", err)
	}
	e.wantHead(t, 1)
}

// TestWarnEmergencyApplySetup: allowEmergencyApply with nothing to use it or
// nothing to alert on is a startup WARN, and an off or absent setting is silent.
func TestWarnEmergencyApplySetup(t *testing.T) {
	routed := []integration.InstanceConfig{{Type: "webhook", Name: "oncall", Match: []integration.MatchClause{{Rule: "approval_bypassed"}}}}
	bySeverity := []integration.InstanceConfig{{Type: "webhook", Name: "oncall", Match: []integration.MatchClause{{Severity: "critical"}}}}
	unrelated := []integration.InstanceConfig{{Type: "webhook", Name: "oncall", Match: []integration.MatchClause{{Rule: "egress_blocked"}}}}
	cases := []struct {
		name         string
		allow, bg    bool
		approvalsOn  bool
		pipeline     bool
		integrations []integration.InstanceConfig
		wantBG       int
		wantAlert    int
	}{
		{"off", false, true, true, true, nil, 0, 0},
		{"approvals off", true, true, false, true, nil, 0, 0},
		{"break-glass disabled", true, false, true, true, routed, 1, 0},
		{"no pipeline", true, true, true, false, nil, 0, 1},
		{"no integrations", true, true, true, true, nil, 0, 1},
		{"an unrelated route", true, true, true, true, unrelated, 0, 1},
		{"a route by rule", true, true, true, true, routed, 0, 0},
		{"a route by severity", true, true, true, true, bySeverity, 0, 0},
		{"both missing", true, false, true, true, unrelated, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, logs := testLogger()
			s := &Server{cfg: Config{Logger: logger, Console: config.ConsoleConfig{
				Approvals:  config.ConsoleApprovals{Enabled: tc.approvalsOn, AllowEmergencyApply: tc.allow},
				BreakGlass: config.ConsoleBreakGlass{Enabled: tc.bg},
			}}}
			if tc.pipeline {
				s.pipeline = new(alertpipeline.Pipeline)
			}
			s.warnEmergencyApplySetup(tc.integrations)
			out := logs.String()
			if n := countLines(out, "level=WARN"); n != tc.wantBG+tc.wantAlert {
				t.Errorf("WARN lines = %d, want %d\n%s", n, tc.wantBG+tc.wantAlert, out)
			}
			if n := countLines(out, "console.breakGlass.enabled is false"); n != tc.wantBG {
				t.Errorf("break-glass warns = %d, want %d\n%s", n, tc.wantBG, out)
			}
			if n := countLines(out, "approval_bypassed"); n != tc.wantAlert {
				t.Errorf("alert-route warns = %d, want %d\n%s", n, tc.wantAlert, out)
			}
		})
	}
}

// okRows keeps the rows that recorded a successful request.
func okRows(rows []adminaudit.Input) []adminaudit.Input {
	var out []adminaudit.Input
	for _, r := range rows {
		if r.Outcome == adminaudit.OutcomeOK {
			out = append(out, r)
		}
	}
	return out
}

// TestEmergencyReviewIndependent: the draft's author cannot review its
// emergency apply, a second admin can, and the comment (10 or more characters)
// is required.
func TestEmergencyReviewIndependent(t *testing.T) {
	e := emergencyEnv(t)
	d := e.create(t, "admin", docWith(`{"domain":"own.example.com"}`))
	if rec := e.submit(t, "admin", d.ID); rec.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do("breakglass", http.MethodPost, draftsPath+"/"+d.ID+"/emergency-apply", emergencyBody(emergencyReason)); rec.Code != http.StatusOK {
		t.Fatalf("emergency-apply = %d %s", rec.Code, rec.Body.String())
	}
	review := draftsPath + "/" + d.ID + "/review"
	e.wantErr(t, e.do("admin", http.MethodPost, review, `{"comment":"i checked my own change"}`), http.StatusForbidden, "self_review_forbidden")
	for _, body := range []string{`{}`, `{"comment":"too short"}`, `{"comment":"          x         "}`} {
		e.wantErr(t, e.do("admin2", http.MethodPost, review, body), http.StatusBadRequest, "invalid_comment")
	}
	if got := e.view(t, d.ID); got.State != "applied_unreviewed" {
		t.Fatalf("state after refusals = %s", got.State)
	}
	if rec := e.do("admin2", http.MethodPost, review, `{"comment":"reviewed by a second admin"}`); rec.Code != http.StatusOK {
		t.Fatalf("review by another admin = %d %s", rec.Code, rec.Body.String())
	}
	if got := e.view(t, d.ID); got.State != "applied" {
		t.Errorf("state = %s, want applied", got.State)
	}
}

// TestEmergencyPublishedButNotRecorded: a bypass that published always alerts,
// even when the draft's outcome cannot be written (and again when startup
// reconcile settles it after a crash).
func TestEmergencyPublishedButNotRecorded(t *testing.T) {
	e := emergencyEnv(t)
	d := e.heldDraft(t, "lost.example.com")
	sqlDB := e.srv.cfg.State.SQL()
	if _, err := sqlDB.Exec(`CREATE TRIGGER no_unreviewed BEFORE UPDATE OF state ON change_drafts
		WHEN NEW.state = 'applied_unreviewed' BEGIN SELECT RAISE(ABORT, 'store gone'); END`); err != nil {
		t.Fatal(err)
	}
	rec := e.do("breakglass", http.MethodPost, draftsPath+"/"+d.ID+"/emergency-apply", emergencyBody(emergencyReason))
	e.wantErr(t, rec, http.StatusInternalServerError, "emergency_apply_unrecorded")
	e.wantHead(t, 2) // the version is live
	fs := e.pub.byRule("approval_bypassed")
	if len(fs) != 1 || fs[0].Severity != integration.SevCritical || fs[0].DedupKey != "approval_bypassed:"+d.ID ||
		!strings.Contains(string(fs[0].Evidence), "applied_version=2") {
		t.Fatalf("Findings = %+v, want the bypass alerted at v2", fs)
	}
	if n := countLines(e.logs.String(), "msg=approval_bypassed"); n != 1 {
		t.Errorf("approval_bypassed lines = %d, want 1", n)
	}

	// Startup reconcile repairs the draft and alerts again, marked repaired.
	if _, err := sqlDB.Exec("DROP TRIGGER no_unreviewed"); err != nil {
		t.Fatal(err)
	}
	n, err := e.srv.Approvals().Reconcile(context.Background(), e.srv.findDraftVersion)
	if err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, %v", n, err)
	}
	if got := e.view(t, d.ID); got.State != "applied_unreviewed" || got.AppliedVersion != 2 {
		t.Fatalf("draft after reconcile = %s v%d", got.State, got.AppliedVersion)
	}
	if got := countLines(e.logs.String(), "repaired=true"); got != 1 {
		t.Errorf("repaired approval_bypassed lines = %d, want 1\n%s", got, e.logs.String())
	}
	if len(e.pub.byRule("approval_bypassed")) != 1 {
		t.Error("the repair Finding was published before the pipeline was up")
	}
	e.srv.flushRepairedBypasses()
	fs = e.pub.byRule("approval_bypassed")
	if len(fs) != 2 || fs[1].DedupKey != "approval_bypassed:"+d.ID || fs[1].Severity != integration.SevCritical {
		t.Errorf("Findings after the flush = %+v", fs)
	}
	e.srv.flushRepairedBypasses()
	if len(e.pub.byRule("approval_bypassed")) != 2 {
		t.Error("a second flush re-published")
	}
}
