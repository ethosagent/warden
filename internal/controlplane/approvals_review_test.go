package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// Review tests for W-P2-APPR-04: the replay evidence rule, expiry, role
// re-checks, a refused apply followed by a retry, and concurrent approvals.

// submitted creates and submits a draft adding domain as u1 and returns it
// with its replay settled.
func (e *draftEnv) submitted(t *testing.T, domain string) (dashboard.ChangeDraftDetail, approvals.Replay) {
	t.Helper()
	d := e.create(t, "u1", docWith(`{"domain":"`+domain+`"}`))
	if rec := e.submit(t, "u1", d.ID); rec.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", rec.Code, rec.Body.String())
	}
	return d, e.settledReplay(t, d.ID)
}

func (e *draftEnv) approve(who string, d dashboard.ChangeDraftView, replayID string) *httptest.ResponseRecorder {
	return e.do(who, http.MethodPost, draftsPath+"/"+d.ID+"/approve", approveBody(d, replayID, ""))
}

// approveAs is the Service-level approval of d by who (an editor).
func approveAs(e *draftEnv, who string, d dashboard.ChangeDraftView, replayID string) (approvals.ApproveResult, error) {
	return e.srv.Approvals().Approve(context.Background(), approvals.ApproveInput{
		ID: d.ID, Revision: d.Revision, DocSHA256: d.DocSHA256,
		Approver: approvals.Author{Iss: "https://idp.example", Sub: who, Kind: AuthorKindOIDC},
		Role:     config.RoleEditor, ReplayID: replayID, AcknowledgeNoReplay: replayID == "",
	})
}

// insertReplay stores a replay row of d at its current revision.
func insertReplay(t *testing.T, e *draftEnv, d dashboard.ChangeDraftView, status approvals.ReplayStatus) {
	t.Helper()
	now := time.Now()
	r := approvals.Replay{DraftID: d.ID, Revision: d.Revision, BaseVersion: d.BaseVersion, Status: status, StartedAt: now}
	if status.Settled() {
		r.FinishedAt = now
	}
	if _, err := sqlstore.NewReplayStore(e.srv.cfg.State.SQL()).Insert(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

// TestApproveEvidenceRules: the replay evidence an approval may cite.
func TestApproveEvidenceRules(t *testing.T) {
	seed := func(e *draftEnv) {
		if err := e.srv.central.StoreAggregatedEvent(replayEvent("api.openai.com", "allow", "/v1")); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		run  func(t *testing.T, e *draftEnv, clk *clocktest.Fake) *httptest.ResponseRecorder
	}{
		{"a replay older than replayMaxAge", func(t *testing.T, e *draftEnv, clk *clocktest.Fake) *httptest.ResponseRecorder {
			d, rp := e.submitted(t, "a.example.com")
			if rp.Status != approvals.ReplayDone {
				t.Fatalf("replay = %+v", rp)
			}
			clk.Advance(config.DefaultApprovalsReplayMaxAge + time.Minute)
			return e.approve("u2", d.ChangeDraftView, rp.ID)
		}},
		{"a replay of another draft", func(t *testing.T, e *draftEnv, _ *clocktest.Fake) *httptest.ResponseRecorder {
			d, _ := e.submitted(t, "b.example.com")
			_, other := e.submitted(t, "c.example.com")
			return e.approve("u2", d.ChangeDraftView, other.ID)
		}},
		{"a replay of an earlier revision", func(t *testing.T, e *draftEnv, _ *clocktest.Fake) *httptest.ResponseRecorder {
			d, rp := e.submitted(t, "d.example.com")
			put := `{"doc":` + docWith(`{"domain":"d.example.com"}`, `{"domain":"d2.example.com"}`) + `}`
			rec := e.do("u1", http.MethodPut, draftsPath+"/"+d.ID, put, "If-Match", `"r1"`)
			if rec.Code != http.StatusOK {
				t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
			}
			d2 := decodeBody[dashboard.ChangeDraftDetail](t, rec)
			return e.approve("u2", d2.ChangeDraftView, rp.ID)
		}},
		{"an acknowledgement while the latest replay is done", func(t *testing.T, e *draftEnv, _ *clocktest.Fake) *httptest.ResponseRecorder {
			d, rp := e.submitted(t, "e.example.com")
			if rp.Status != approvals.ReplayDone {
				t.Fatalf("replay = %+v", rp)
			}
			return e.approve("u2", d.ChangeDraftView, "")
		}},
		{"an acknowledgement while the latest replay is pending", func(t *testing.T, e *draftEnv, _ *clocktest.Fake) *httptest.ResponseRecorder {
			d, _ := e.submitted(t, "f.example.com")
			insertReplay(t, e, d.ChangeDraftView, approvals.ReplayPending)
			return e.approve("u2", d.ChangeDraftView, "")
		}},
		{"an acknowledgement while the latest replay is running", func(t *testing.T, e *draftEnv, _ *clocktest.Fake) *httptest.ResponseRecorder {
			d, _ := e.submitted(t, "g.example.com")
			insertReplay(t, e, d.ChangeDraftView, approvals.ReplayRunning)
			return e.approve("u2", d.ChangeDraftView, "")
		}},
		{"an acknowledgement when no replay row exists", func(t *testing.T, e *draftEnv, _ *clocktest.Fake) *httptest.ResponseRecorder {
			d, _ := e.submitted(t, "h.example.com")
			if _, err := e.srv.cfg.State.SQL().Exec("DELETE FROM draft_replays WHERE draft_id = ?", d.ID); err != nil {
				t.Fatal(err)
			}
			return e.approve("u2", d.ChangeDraftView, "")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := clocktest.NewFake(time.Now())
			e := newDraftEnvAt(t, nil, clk)
			seed(e)
			rec := tc.run(t, e, clk)
			e.wantErr(t, rec, http.StatusConflict, "replay_required")
			if e.head(t) != 1 {
				t.Errorf("a refused approval created version %d", e.head(t))
			}
		})
	}
}

// With no replay row, a re-run produces the evidence (or an unavailable one the
// approver may acknowledge).
func TestApproveAfterMissingReplayRerun(t *testing.T) {
	clk := clocktest.NewFake(time.Now())
	e := newDraftEnvAt(t, nil, clk)
	d, _ := e.submitted(t, "rerun.example.com")
	if _, err := e.srv.cfg.State.SQL().Exec("DELETE FROM draft_replays WHERE draft_id = ?", d.ID); err != nil {
		t.Fatal(err)
	}
	if rec := e.do("u1", http.MethodPost, draftsPath+"/"+d.ID+"/replay", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("replay = %d %s", rec.Code, rec.Body.String())
	}
	e.settledReplay(t, d.ID)
	if rec := e.approve("u2", d.ChangeDraftView, ""); rec.Code != http.StatusOK {
		t.Fatalf("approve after the re-run = %d %s", rec.Code, rec.Body.String())
	}
}

// A required role the stored classification understates is raised by the fresh
// classification against the live head.
func TestApproveRoleRaisedByFreshClassification(t *testing.T) {
	e := newDraftEnv(t, nil)
	doc := `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"}],` +
		`"settings":{"llmProviders":[{"name":"p1","baseURL":"https://api.openai.com/v1","model":"gpt-4o-mini","apiKeyEnv":"OPENAI_API_KEY"}]}}`
	d := e.create(t, "u1", doc)
	e.submit(t, "u1", d.ID)
	e.settledReplay(t, d.ID)
	if _, err := e.srv.cfg.State.SQL().Exec("UPDATE change_drafts SET required_role = 'editor' WHERE id = ?", d.ID); err != nil {
		t.Fatal(err)
	}
	b := e.wantErr(t, e.approve("u2", d.ChangeDraftView, ""), http.StatusForbidden, "role_required")
	if b.Need != "admin" || len(b.Fields) != 1 || b.Fields[0] != "llmProviders" {
		t.Errorf("role_required = %+v, want admin naming llmProviders", b)
	}
	if e.head(t) != 1 {
		t.Errorf("a refused approval created version %d", e.head(t))
	}
}

// A loader refusal on the final approve is a 422 that leaves the draft pending
// with its approval on file; once the cause is fixed the same approver's retry
// applies it.
func TestApproveRefusedApplyThenRetry(t *testing.T) {
	e := newDraftEnv(t, nil)
	d, _ := e.submitted(t, "retry.example.com")
	path := e.srv.cfg.PolicyPath
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A console block the loader refuses makes every validation fail.
	if err := os.WriteFile(path, append(append([]byte{}, good...), []byte("console:\n  auth: bogus\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	e.wantErr(t, e.approve("u2", d.ChangeDraftView, ""), http.StatusUnprocessableEntity, "invalid_policy")
	got := e.view(t, d.ID)
	if got.State != "pending" || len(got.ApprovalRows) != 1 || got.LastError == "" || e.head(t) != 1 {
		t.Fatalf("after the refused apply: state %s, %d approvals, head %d, last_error %q", got.State, len(got.ApprovalRows), e.head(t), got.LastError)
	}
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	rec := e.approve("u2", d.ChangeDraftView, "")
	if rec.Code != http.StatusOK || decodeBody[dashboard.ChangeResult](t, rec).State != "applied" || e.head(t) != 2 {
		t.Fatalf("retry = %d %s (head %d)", rec.Code, rec.Body.String(), e.head(t))
	}
}

// Two final approvals at once publish exactly one version.
func TestApproveConcurrentFinalApprovals(t *testing.T) {
	e := newDraftEnv(t, nil)
	e.seedEvents(t)
	d, rp := e.submitted(t, "race.example.com")
	var wg sync.WaitGroup
	results := make([]approvals.ApproveResult, 2)
	errs := make([]error, 2)
	for i, who := range []string{"u2", "u3"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = approveAs(e, who, d.ChangeDraftView, rp.ID)
		}()
	}
	wg.Wait()
	applied := 0
	for i := range results {
		if errs[i] == nil && results[i].Applied {
			applied++
		}
	}
	if applied != 1 || e.head(t) != 2 {
		t.Fatalf("applied %d times, head %d, errors %v; want exactly one version", applied, e.head(t), errs)
	}
	var versions int
	if err := e.srv.cfg.State.SQL().QueryRow("SELECT count(*) FROM policy_versions WHERE source = 'approval'").Scan(&versions); err != nil || versions != 1 {
		t.Errorf("approval versions = %d (%v), want 1", versions, err)
	}
}

// An open draft past its expiry cannot be approved or self-applied before the
// sweeper retires it.
func TestExpiredDraftDoesNotApply(t *testing.T) {
	clk := clocktest.NewFake(time.Now())
	e := newDraftEnvAt(t, nil, clk)
	d, rp := e.submitted(t, "late.example.com")
	n := e.create(t, "u1", `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"bad.example.com"}]}`)
	clk.Advance(config.DefaultApprovalsDraftTTL + time.Hour)

	e.wantErr(t, e.approve("u2", d.ChangeDraftView, rp.ID), http.StatusConflict, "illegal_transition")
	rec := e.submit(t, "u1", n.ID)
	e.wantErr(t, rec, http.StatusConflict, "illegal_transition")
	if e.head(t) != 1 {
		t.Errorf("an expired draft published version %d", e.head(t))
	}
	if got := e.view(t, n.ID); got.State != "draft" || len(got.ApprovalRows) != 0 {
		t.Errorf("submit of an expired narrowing draft left it %s with %d decisions, want draft and none", got.State, len(got.ApprovalRows))
	}
}

// The list reports approvals per draft from one grouped query.
func TestChangeDraftListCountsApprovals(t *testing.T) {
	e := newDraftEnv(t, func(a *config.ConsoleApprovals) { a.MinApprovals = 2 })
	e.seedEvents(t)
	d, rp := e.submitted(t, "one.example.com")
	other := e.create(t, "u1", docWith(`{"domain":"two.example.com"}`))
	if rec := e.approve("u2", d.ChangeDraftView, rp.ID); rec.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	list := decodeBody[struct {
		Drafts []dashboard.ChangeDraftView `json:"drafts"`
	}](t, e.do("viewer", http.MethodGet, draftsPath, ""))
	got := map[string]int{}
	for _, v := range list.Drafts {
		got[v.ID] = v.Approvals
	}
	if len(got) != 2 || got[d.ID] != 1 || got[other.ID] != 0 {
		t.Errorf("approvals per draft = %v, want %s:1 %s:0", got, d.ID, other.ID)
	}
}

// A doc the loader would refuse is a 422 at create and edit, before any review.
func TestChangeDraftDocValidatedEarly(t *testing.T) {
	e := newDraftEnv(t, nil)
	bad := `{"allowlist":[{"domain":""}],"denylist":[]}`
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath, `{"target":"policy","doc":`+bad+`}`, "If-Match", `"v1"`), http.StatusUnprocessableEntity, "invalid_policy")
	d := e.create(t, "u1", docWith(`{"domain":"ok.example.com"}`))
	e.wantErr(t, e.do("u1", http.MethodPut, draftsPath+"/"+d.ID, `{"doc":`+bad+`}`, "If-Match", `"r1"`), http.StatusUnprocessableEntity, "invalid_policy")
	if got := e.view(t, d.ID); got.Revision != 1 {
		t.Errorf("a refused edit made revision %d", got.Revision)
	}
}

// seedEvents gives the replays fleet events to compare, so they finish done.
func (e *draftEnv) seedEvents(t *testing.T) {
	t.Helper()
	if err := e.srv.central.StoreAggregatedEvent(replayEvent("api.openai.com", "allow", "/v1")); err != nil {
		t.Fatal(err)
	}
}

// followUpEnv is an audit-enabled control plane whose recorder a test reads.
func followUpEnv(t *testing.T) *auditEnv { return newOIDCAuditEnv(t) }

func primaryRow() adminaudit.Input {
	return adminaudit.Input{
		Actor: adminaudit.Actor{Sub: "approver", Email: "a@example.com"}, ActorRole: "editor",
		AuthMethod: adminaudit.AuthMethodOIDC, Action: "change.draft.approve", Target: "change_draft",
		Outcome: adminaudit.OutcomeOK, HTTPStatus: 200, ClientIP: "192.0.2.7", RequestID: "req-1",
	}
}

// A follow-up row names what happened, never who: the actor, role, method,
// client, request id and status come from the primary row, the outcome is ok,
// and only closed detail keys survive.
func TestAuditFollowUpsAreConstrained(t *testing.T) {
	e := followUpEnv(t)
	e.srv.recordFollowUps(context.Background(), primaryRow(), []auditFollowUp{{
		Action: "policy.write", Target: "policy", TargetRef: "policy@abc",
		Details: map[string]string{
			adminaudit.DetailSource: "approval", adminaudit.DetailAppliedVersion: "2",
			"actor": "mallory", "outcome": "denied", "free_text": "x", adminaudit.DetailOp: "bad\nvalue",
		},
		BeforeHash: "b", AfterHash: "a",
	}})
	rows := e.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Actor.Sub != "approver" || r.ActorRole != "editor" || r.AuthMethod != adminaudit.AuthMethodOIDC ||
		r.Outcome != adminaudit.OutcomeOK || r.HTTPStatus != 200 || r.ClientIP != "192.0.2.7" || r.RequestID != "req-1" {
		t.Errorf("follow-up identity = %+v, want the primary row's", r)
	}
	if len(r.Details) != 2 || r.Details[adminaudit.DetailSource] != "approval" || r.Details[adminaudit.DetailAppliedVersion] != "2" {
		t.Errorf("details = %v, want only source and applied_version", r.Details)
	}
}

// Nothing is recorded behind a primary row that is not ok, and at most two rows
// follow one request.
func TestAuditFollowUpsOnlyAfterOKAndCapped(t *testing.T) {
	e := followUpEnv(t)
	f := auditFollowUp{Action: "policy.write", Target: "policy"}
	for _, outcome := range []string{adminaudit.OutcomeDenied, adminaudit.OutcomeRejected, adminaudit.OutcomeError} {
		p := primaryRow()
		p.Outcome = outcome
		e.srv.recordFollowUps(context.Background(), p, []auditFollowUp{f})
	}
	if n := len(e.rec.inputs()); n != 0 {
		t.Fatalf("%d follow-up rows behind a non-ok primary, want none", n)
	}
	e.srv.recordFollowUps(context.Background(), primaryRow(), []auditFollowUp{f, f, f, f})
	if n := len(e.rec.inputs()); n != maxAuditFollowUps {
		t.Errorf("%d follow-up rows, want the cap of %d", n, maxAuditFollowUps)
	}
}
