package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The break-glass emergency apply (W-P2-APPR-07): with
// console.approvals.allowEmergencyApply on, a break-glass session publishes a
// pending widening draft past the two-person rule. It is audited before and
// after the publish, raises a critical approval_bypassed Finding and leaves the
// draft applied_unreviewed until an OIDC admin reviews it.

func approvalsEmergencyOpts() []harness.Option {
	return []harness.Option{harness.WithApprovals(), harness.WithBreakGlass(), harness.WithEmergencyApply()}
}

const emergencyScenarioReason = "dex is down and the payments vendor is blocked"

func approvalsEmergencyApply(t *testing.T, h *harness.H) {
	h.Upstream(approvalsHost)
	ana, anaCSRF := consoleLogin(t, h, fakes.Valid("ana", "ana@example.com", harness.ConsoleEditorGroup))
	root, rootCSRF := consoleLogin(t, h, fakes.Valid("root", "root@example.com", harness.ConsoleAdminGroup))

	// ana drafts and submits a widening change; nobody approves it.
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if resp, body := consoleDo(t, ana, http.MethodGet, "/dashboard/api/policy", nil); resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &cur) != nil {
		t.Fatalf("GET policy = %d %s", resp.StatusCode, body)
	}
	doc := map[string]any{
		"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": approvalsHost}),
		"denylist":  cur.Denylist,
	}
	status, raw := draftCall(t, ana, anaCSRF, http.MethodPost, "/dashboard/api/changes", `"v1"`,
		map[string]any{"target": "policy", "message": "allow " + approvalsHost, "doc": doc})
	var d dashboard.ChangeDraftDetail
	if status != http.StatusCreated || json.Unmarshal(raw, &d) != nil || d.ID == "" {
		t.Fatalf("create draft = %d %s", status, raw)
	}
	path := "/dashboard/api/changes/" + d.ID
	if status, raw = draftCall(t, ana, anaCSRF, http.MethodPost, path+"/submit", "", nil); status != http.StatusOK {
		t.Fatalf("submit = %d %s", status, raw)
	}
	emergency := map[string]any{"reason": emergencyScenarioReason}

	// An OIDC admin is not a break-glass session: the route is refused and the
	// host stays denied.
	if status, raw = draftCall(t, root, rootCSRF, http.MethodPost, path+"/emergency-apply", "", emergency); status != http.StatusForbidden || !strings.Contains(string(raw), "breakglass_required") {
		t.Fatalf("OIDC admin emergency-apply = %d %s, want 403 breakglass_required", status, raw)
	}
	if got := connectStatus(t, h, approvalsHost+":443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s after the refused emergency apply = %d, want 403", approvalsHost, got)
	}

	// The Dex outage: only break-glass can log in. It cannot approve a draft...
	bg := h.ConsoleBrowser()
	resp, body := breakGlassPost(t, bg, harness.BreakGlassUsername, harness.BreakGlassPassword)
	sc := cookieIn(resp, consoleSessionCookie)
	if resp.StatusCode != http.StatusOK || sc == nil {
		t.Fatalf("break-glass login = %d %s", resp.StatusCode, body)
	}
	bgCSRF := controlplane.CSRFToken(sc.Value)
	approve := map[string]any{"revision": d.Revision, "doc_sha256": d.DocSHA256, "acknowledgeNoReplay": true}
	if status, raw = draftCall(t, bg, bgCSRF, http.MethodPost, path+"/approve", "", approve); status != http.StatusForbidden || !strings.Contains(string(raw), "breakglass_cannot_approve") {
		t.Fatalf("break-glass approve = %d %s, want 403 breakglass_cannot_approve", status, raw)
	}
	// ...a short reason is refused...
	if status, raw = draftCall(t, bg, bgCSRF, http.MethodPost, path+"/emergency-apply", "", map[string]any{"reason": "too short"}); status != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_reason") {
		t.Fatalf("short reason = %d %s, want 400 invalid_reason", status, raw)
	}
	// ...but with a reason it publishes version 2 and workers enforce it.
	status, raw = draftCall(t, bg, bgCSRF, http.MethodPost, path+"/emergency-apply", "", emergency)
	var res dashboard.ChangeResult
	if status != http.StatusOK || json.Unmarshal(raw, &res) != nil || res.State != "applied_unreviewed" || res.Version != 2 {
		t.Fatalf("emergency-apply = %d %s, want 200 applied_unreviewed at v2", status, raw)
	}
	h.Eventually("workers enforce the emergency-applied version", func() bool {
		return connectStatus(t, h, approvalsHost+":443") == http.StatusOK
	})

	// A break-glass session cannot close its own bypass; the OIDC admin does.
	if status, raw = draftCall(t, bg, bgCSRF, http.MethodPost, path+"/review", "", map[string]any{"comment": "self review"}); status != http.StatusForbidden || !strings.Contains(string(raw), "breakglass_cannot_review") {
		t.Fatalf("break-glass review = %d %s, want 403 breakglass_cannot_review", status, raw)
	}
	status, raw = draftCall(t, root, rootCSRF, http.MethodPost, path+"/review", "", map[string]any{"comment": "confirmed with the vendor"})
	if status != http.StatusOK || json.Unmarshal(raw, &res) != nil || res.State != "applied" {
		t.Fatalf("OIDC admin review = %d %s, want 200 applied", status, raw)
	}

	// Admin audit: the refusals, the row written before the publish, the apply,
	// the policy row it made and the review, each by the actor who did it.
	var got []string
	for _, r := range h.AdminAuditRows() {
		if strings.HasPrefix(r.Action, "change.draft.") || r.Action == "policy.write" {
			got = append(got, r.Action+":"+r.Outcome+":"+r.Sub)
		}
	}
	bgSub := "breakglass:" + harness.BreakGlassUsername
	want := []string{
		"change.draft.create:ok:ana", "change.draft.submit:ok:ana",
		"change.draft.emergency_apply:denied:root",
		"change.draft.approve:denied:" + bgSub,
		"change.draft.emergency_apply:rejected:" + bgSub, // the 400: a short reason
		"change.draft.emergency_begin:ok:" + bgSub, "change.draft.emergency_apply:ok:" + bgSub, "policy.write:ok:" + bgSub,
		"change.draft.review:denied:" + bgSub, "change.draft.review:ok:root",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("change draft audit rows =\n%v\nwant\n%v", got, want)
	}

	// One ERROR line and one critical Finding, neither with the reason.
	logs := h.Logs()
	if n := strings.Count(logs, `"msg":"approval_bypassed"`); n != 1 {
		t.Fatalf("approval_bypassed lines = %d, want 1", n)
	}
	if strings.Contains(logs, emergencyScenarioReason) {
		t.Fatal("the emergency reason reached the logs")
	}
	h.Eventually("the approval_bypassed Finding is in the alert store", func() bool {
		for _, a := range h.Alerts() {
			if a.DedupKey == "approval_bypassed:"+d.ID {
				return a.Severity == integration.SevCritical && a.Count == 1
			}
		}
		return false
	})
}
