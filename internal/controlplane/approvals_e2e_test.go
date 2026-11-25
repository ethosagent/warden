package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The approvals flow end to end (W-P2-APPR-09): one in-process control plane
// with the versioned store, approvals, the break-glass apply and a real signed
// admin audit chain, two editors (u1, u2), admins, a break-glass session and a
// worker long-polling /policy. It is the "done when" of the approvals feature;
// the unit tests beside it pin each rule on its own.

// fakeWorker is a worker pulling /policy with the CP token.
type fakeWorker struct{ h http.Handler }

// pollResult is one /policy response.
type pollResult struct {
	code    int
	etag    string
	body    string
	elapsed time.Duration
}

// poll long-polls /policy with the worker's current etag for up to wait.
func (w fakeWorker) poll(etag string, wait time.Duration) pollResult {
	start := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/policy?wait="+wait.String(), nil)
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, req)
	return pollResult{code: rec.Code, etag: strings.Trim(rec.Header().Get("ETag"), `"`), body: rec.Body.String(), elapsed: time.Since(start)}
}

// pollAsync starts a poll and returns the channel its result arrives on.
func (w fakeWorker) pollAsync(etag string, wait time.Duration) <-chan pollResult {
	ch := make(chan pollResult, 1)
	go func() { ch <- w.poll(etag, wait) }()
	return ch
}

func TestApprovalsEndToEnd(t *testing.T) {
	e := newDraftEnvOpts(t, func(a *config.ConsoleApprovals) { a.AllowEmergencyApply = true }, nil, false, true)
	ctx := context.Background()
	seedEvent(t, e)
	worker := fakeWorker{h: e.h}
	const wait = time.Second // the shortest long-poll the control plane honours

	etag1 := e.srv.policy.currentETag()
	if r := worker.poll("", 0); r.code != http.StatusOK || r.etag != etag1 {
		t.Fatalf("worker first pull = %d etag %q, want 200 %q", r.code, r.etag, etag1)
	}

	// 1. An editor widens the policy: held, 202, and the fleet sees nothing.
	h, d := e.wantHeld(t, e.put("u1", policyPath, docWith(`{"domain":"new.example.com"}`), "1"), approvals.CodeAllowAdded)
	e.wantHead(t, 1)
	if r := worker.poll(etag1, wait); r.code != http.StatusNotModified || r.elapsed < wait-100*time.Millisecond {
		t.Fatalf("worker poll while pending = %d after %s, want 304 after one full wait", r.code, r.elapsed)
	}
	if e.srv.policy.currentETag() != etag1 {
		t.Fatal("the served ETag moved while the draft was pending")
	}

	// 2. The author cannot approve; the replay runs; a second editor can.
	rp := e.settledReplay(t, h.DraftID)
	if rp.Status != approvals.ReplayDone {
		t.Fatalf("replay = %+v, want done", rp)
	}
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath+"/"+h.DraftID+"/approve", approveBody(d.ChangeDraftView, rp.ID, "")), http.StatusForbidden, "self_approval_forbidden")
	e.wantHead(t, 1)

	// 3. The approval applies in its own request and wakes the long-polling
	// worker, which sees exactly one new ETag.
	parked := worker.pollAsync(etag1, 20*time.Second)
	if rec := e.do("u2", http.MethodPost, draftsPath+"/"+h.DraftID+"/approve", approveBody(d.ChangeDraftView, rp.ID, "reviewed the replay")); rec.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	e.wantHead(t, 2)
	var etag2 string
	select {
	case r := <-parked:
		etag2 = r.etag
		if r.code != http.StatusOK || etag2 == etag1 || etag2 != e.srv.policy.currentETag() || !strings.Contains(r.body, "new.example.com") {
			t.Fatalf("parked worker got %d etag %q, want 200 with the new policy", r.code, r.etag)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the long-polling worker never saw the approved policy")
	}
	if r := worker.poll(etag2, wait); r.code != http.StatusNotModified {
		t.Errorf("worker poll after the apply = %d, want 304 (the ETag changes exactly once)", r.code)
	}

	// 4. The emergency path: a break-glass session cannot approve, may apply
	// with a reason, and an independent admin closes it with a review.
	rec := e.do("u1", http.MethodPost, draftsPath, `{"target":"policy","message":"vendor outage","doc":`+docWith(`{"domain":"new.example.com"}`, `{"domain":"vendor.example.com"}`)+`}`, matchV("2")...)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	em := decodeBody[dashboard.ChangeDraftDetail](t, rec)
	if rec := e.submit(t, "u1", em.ID); rec.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", rec.Code, rec.Body.String())
	}
	e.wantErr(t, e.do("breakglass", http.MethodPost, draftsPath+"/"+em.ID+"/approve", approveBody(em.ChangeDraftView, "", "")), http.StatusForbidden, "breakglass_cannot_approve")
	parked = worker.pollAsync(etag2, 20*time.Second)
	rec = e.do("breakglass", http.MethodPost, draftsPath+"/"+em.ID+"/emergency-apply", emergencyBody(emergencyReason))
	if rec.Code != http.StatusOK || decodeBody[dashboard.ChangeResult](t, rec).State != "applied_unreviewed" {
		t.Fatalf("emergency apply = %d %s", rec.Code, rec.Body.String())
	}
	e.wantHead(t, 3)
	var etag3 string
	select {
	case r := <-parked:
		etag3 = r.etag
		if r.code != http.StatusOK || etag3 == etag2 || !strings.Contains(r.body, "vendor.example.com") {
			t.Fatalf("worker after the emergency apply got %d etag %q", r.code, r.etag)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the long-polling worker never saw the emergency apply")
	}
	if n := len(e.pub.byRule("approval_bypassed")); n != 1 {
		t.Errorf("approval_bypassed Findings = %d, want 1", n)
	}
	if rec := e.do("admin2", http.MethodPost, draftsPath+"/"+em.ID+"/review", `{"comment":"vendor access confirmed after the incident"}`); rec.Code != http.StatusOK {
		t.Fatalf("review = %d %s", rec.Code, rec.Body.String())
	}
	if got := e.view(t, em.ID); got.State != "applied" {
		t.Errorf("draft after review = %s, want applied", got.State)
	}

	// 5. A narrowing change applies at once (200), no second person.
	rec = e.put("u1", policyPath, `{"allowlist":[{"domain":"api.openai.com"},{"domain":"new.example.com"},{"domain":"vendor.example.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"worse.example.com"}]}`, "3")
	if rec.Code != http.StatusOK {
		t.Fatalf("narrowing save = %d %s, want 200", rec.Code, rec.Body.String())
	}
	e.wantHead(t, 4)
	if r := worker.poll(etag3, 0); r.code != http.StatusOK || !strings.Contains(r.body, "worse.example.com") {
		t.Errorf("worker after the narrowing = %d, want 200 with the new deny entry", r.code)
	}

	// 6. A held llmProviders change needs an admin approver: an editor is refused.
	rec = e.put("admin", providersPath, `[{"name":"p","baseURL":"https://api.openai.com/v1","model":"gpt-4o-mini","apiKeyEnv":"OPENAI_API_KEY","timeoutSeconds":5}]`, "4")
	lh, ld := e.wantHeld(t, rec, approvals.CodeSettingsChanged)
	e.wantHead(t, 4)
	lrp := e.settledReplay(t, lh.DraftID)
	body := approveBody(ld.ChangeDraftView, "", "")
	if lrp.Status == approvals.ReplayDone {
		body = approveBody(ld.ChangeDraftView, lrp.ID, "")
	}
	e.wantErr(t, e.do("u2", http.MethodPost, draftsPath+"/"+lh.DraftID+"/approve", body), http.StatusForbidden, "role_required")
	e.wantHead(t, 4)
	if rec := e.do("admin2", http.MethodPost, draftsPath+"/"+lh.DraftID+"/approve", body); rec.Code != http.StatusOK {
		t.Fatalf("admin approve = %d %s", rec.Code, rec.Body.String())
	}
	e.wantHead(t, 5)

	// 7. The signed admin audit chain verifies offline (what `warden
	// control-plane admin-audit verify --state-dir <dir>` runs), and holds the
	// story in order.
	st, closeFn, err := adminaudit.OpenReadOnly(ctx, e.stateDir, StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFn() }()
	res, err := st.VerifyAll(ctx, adminaudit.VerifyOptions{})
	if err != nil || !res.OK {
		t.Fatalf("admin-audit verify = %+v %v, want ok", res, err)
	}
	items, err := e.audit.List(ctx, adminaudit.Filter{}, 200, 0)
	if err != nil {
		t.Fatal(err)
	}
	var okSteps, denied []string
	for i := len(items) - 1; i >= 0; i-- { // oldest first
		it := items[i]
		if !strings.HasPrefix(it.Action, "change.draft.") && !strings.HasSuffix(it.Action, ".write") {
			continue
		}
		step := it.Action + "/" + it.Actor.Sub
		if it.Outcome == adminaudit.OutcomeOK {
			okSteps = append(okSteps, step)
		} else {
			denied = append(denied, step)
		}
	}
	want := []string{
		"policy.write/u1",         // the held widening save (202)
		"change.draft.approve/u2", // the second editor approves
		"policy.write/u2",         // the version it published
		"change.draft.create/u1",  // the emergency draft
		"change.draft.submit/u1",
		actionEmergencyBegin + "/breakglass:ops", // written before anything publishes
		"change.draft.emergency_apply/breakglass:ops",
		"policy.write/breakglass:ops",
		"change.draft.review/admin2", // the independent review
		"policy.write/u1",            // the narrowing save
		"llmproviders.write/admin",   // the held llmProviders save
		"change.draft.approve/admin2",
		"policy.write/admin2", // the version the approval published
	}
	if !slices.Equal(okSteps, want) {
		t.Errorf("admin audit (ok rows, oldest first):\n got %q\nwant %q", okSteps, want)
	}
	for _, refusal := range []string{"change.draft.approve/u1", "change.draft.approve/breakglass:ops", "change.draft.approve/u2"} {
		if !slices.Contains(denied, refusal) {
			t.Errorf("no denied audit row %q in %q", refusal, denied)
		}
	}
	for _, it := range items {
		if b := string(marshalJSON(t, it)); strings.Contains(b, "vendor.example.com") || strings.Contains(b, emergencyReason) {
			t.Errorf("an audit row carries doc content or the emergency reason: %+v", it)
		}
	}
}
