package controlplane

// approvals_http.go adapts the approvals Service to the dashboard's
// ChangeDrafts routes (W-P2-APPR-04): who the caller is, the author-only
// rules, the audit annotations and the Finding a widening submit raises. The
// two-person rule itself (self approval, break-glass, role, evidence, apply)
// lives in approvals.Service.Approve.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
)

// auditTargetChangeDraft is the authz Target and state hasher name of the
// change draft routes.
const auditTargetChangeDraft = "change_draft"

// findingPolicyApprovalRequested is the rule id of the info Finding a widening
// submit publishes.
const findingPolicyApprovalRequested = "policy_approval_requested"

// errNotAuthor: only a draft's author may do this.
var errNotAuthor = errors.New("controlplane: only the draft's author may do this")

// changeDraftAPI implements dashboard.ChangeDrafts over the approvals Service.
type changeDraftAPI struct{ s *Server }

var _ dashboard.ChangeDrafts = changeDraftAPI{}

// changeDraftsAPI is the dashboard seam, nil when approvals are off.
func (s *Server) changeDraftsAPI() dashboard.ChangeDrafts {
	if s.approvals == nil {
		return nil
	}
	return changeDraftAPI{s: s}
}

func (a changeDraftAPI) svc() *approvals.Service { return a.s.approvals }

// caller resolves who is calling. A request with no signed-in identity is
// refused: approvals need an author and an approver (startup requires
// console.auth oidc, so a console request always has one). The identity the
// two-person rule compares is Principal.ActorSub: an API key acts as its
// owner, so u1's key and u1's session are the same person and the key can
// never be the second one (its Sub, apikey:<id>, is never used here).
func (a changeDraftAPI) caller(ctx context.Context) (approvals.Author, config.Role, error) {
	p, ok := PrincipalFrom(ctx)
	if !ok || p.Sub == "" {
		return approvals.Author{}, 0, &dashboard.ChangeError{Status: http.StatusUnauthorized, Code: "unauthenticated"}
	}
	au := approvals.Author{Iss: p.Iss, Sub: p.ActorSub(), Email: p.Email, Kind: AuthorKindOIDC}
	switch {
	case p.Kind == PrincipalBreakglass || p.AuthMethod == AuthorKindBreakglass:
		au.Sub = breakglassSubPrefix + strings.TrimPrefix(p.Sub, breakglassSubPrefix)
		au.Kind = AuthorKindBreakglass
	case p.Kind == PrincipalAPIKey:
		// A key without an owner has no person to attribute to: refuse it
		// rather than record an empty author.
		if p.OwnerSub == "" {
			return approvals.Author{}, 0, &dashboard.ChangeError{Status: http.StatusUnauthorized, Code: "unauthenticated"}
		}
		au.Kind = AuthorKindAPIKey
	}
	return au, principalRole(a.s.cfg.Console, p), nil
}

func sameActor(d approvals.Author, c approvals.Author) bool {
	return d.Sub == c.Sub && d.Iss == c.Iss
}

// changeErr maps a domain error to the response. Anything unknown is logged
// and answered as a fixed 500 by the dashboard.
func (a changeDraftAPI) changeErr(ctx context.Context, err error) error {
	var ce *dashboard.ChangeError
	var rr *approvals.RoleRequiredError
	var ip *dashboard.InvalidPolicyError
	var wl *dashboard.WorkersLackCapabilityError
	fail := func(status int, code string, f map[string]any) error {
		return &dashboard.ChangeError{Status: status, Code: code, Fields: f, Err: err}
	}
	switch {
	case errors.As(err, &ce):
		return err
	case errors.As(err, &wl):
		f := map[string]any{"workers": wl.Workers}
		if wl.Capability != "" {
			f["capability"] = wl.Capability
		}
		return fail(http.StatusConflict, "workers_lack_capability", f)
	case errors.Is(err, approvals.ErrNotFound):
		return fail(http.StatusNotFound, "not_found", nil)
	case errors.Is(err, errNotAuthor):
		return fail(http.StatusForbidden, "author_only", nil)
	case errors.Is(err, approvals.ErrSelfApproval):
		return fail(http.StatusForbidden, "self_approval_forbidden", nil)
	case errors.Is(err, approvals.ErrSelfReview):
		return fail(http.StatusForbidden, "self_review_forbidden", nil)
	case errors.Is(err, approvals.ErrReviewComment):
		return fail(http.StatusBadRequest, "invalid_comment", map[string]any{"min": approvals.MinReviewComment})
	case errors.Is(err, approvals.ErrEmergencyDisabled):
		return fail(http.StatusForbidden, "emergency_apply_disabled", nil)
	case errors.Is(err, approvals.ErrBreakglassRequired):
		return fail(http.StatusForbidden, "breakglass_required", nil)
	case errors.Is(err, approvals.ErrBreakglassReviewer):
		return fail(http.StatusForbidden, "breakglass_cannot_review", nil)
	case errors.Is(err, approvals.ErrEmergencyReason):
		return fail(http.StatusBadRequest, "invalid_reason", map[string]any{"min": approvals.MinEmergencyReason, "max": approvals.MaxEmergencyReason})
	case errors.Is(err, approvals.ErrEmergencyRateLimited):
		return fail(http.StatusTooManyRequests, "emergency_rate_limited", nil)
	case errors.Is(err, approvals.ErrEmergencyAudit):
		return fail(http.StatusServiceUnavailable, "admin_audit_unavailable", nil)
	case errors.Is(err, approvals.ErrBreakglassApprover):
		return fail(http.StatusForbidden, "breakglass_cannot_approve", nil)
	case errors.As(err, &rr):
		f := map[string]any{"need": rr.Need.String()}
		if len(rr.Fields) > 0 {
			f["fields"] = rr.Fields
		}
		return fail(http.StatusForbidden, "role_required", f)
	case errors.Is(err, approvals.ErrRevisionChanged), errors.Is(err, approvals.ErrStateChanged):
		return fail(http.StatusConflict, "revision_changed", nil)
	case errors.Is(err, approvals.ErrReplayRequired):
		return fail(http.StatusConflict, "replay_required", map[string]any{"detail": strings.TrimPrefix(err.Error(), approvals.ErrReplayRequired.Error()+": ")})
	case errors.Is(err, approvals.ErrRebaseRequired):
		head, _ := a.s.versions.Head(ctx)
		return fail(http.StatusConflict, "rebase_required", map[string]any{"head": head})
	case errors.Is(err, approvals.ErrDraftExpired):
		return fail(http.StatusConflict, "illegal_transition", map[string]any{"reason": "expired"})
	case errors.Is(err, approvals.ErrIllegalTransition):
		return fail(http.StatusConflict, "illegal_transition", nil)
	case errors.Is(err, approvals.ErrDuplicateDecision):
		return fail(http.StatusConflict, "already_approved", nil)
	case errors.Is(err, approvals.ErrUnclassified):
		return fail(http.StatusConflict, "unclassified", nil)
	case errors.Is(err, approvals.ErrTooManyDrafts):
		return fail(http.StatusTooManyRequests, "too_many_drafts", nil)
	case errors.Is(err, approvals.ErrUnsupportedTarget):
		return fail(http.StatusBadRequest, "unsupported_target", nil)
	case errors.Is(err, approvals.ErrReplayBusy):
		return fail(http.StatusConflict, "replay_busy", nil)
	case errors.Is(err, approvals.ErrReplayRateLimited):
		return fail(http.StatusTooManyRequests, "replay_rate_limited", nil)
	case errors.Is(err, ErrVersionNotFound):
		return fail(http.StatusBadRequest, "unknown_base_version", nil)
	case errors.As(err, &ip):
		return fail(http.StatusUnprocessableEntity, "invalid_policy", map[string]any{"detail": ip.Error()})
	}
	a.s.cfg.Logger.Error("control plane: change draft request failed", "error", err)
	return err
}

// --- views ---

// view is a draft without its doc; approvals is how many distinct approvers
// its current revision has.
func (a changeDraftAPI) view(d approvals.Draft, approved int) dashboard.ChangeDraftView {
	v := dashboard.ChangeDraftView{
		ID: d.ID, Target: string(d.Target), TargetRef: d.TargetRef, Revision: d.Revision, BaseVersion: d.BaseVersion,
		State: string(d.State), Author: dashboard.ChangeActor{Sub: d.Author.Sub, Email: d.Author.Email},
		Source: string(d.Source), Message: d.Message, DocSHA256: d.DocSHA256,
		Widening: true, Reasons: []dashboard.ChangeReason{}, RequiredRole: d.RequiredRole,
		LastError: d.LastError,
		CreatedAt: d.CreatedAt.UTC(), UpdatedAt: d.UpdatedAt.UTC(), ExpiresAt: d.ExpiresAt.UTC(),
		ApprovalsRequired: a.svc().MinApprovals(),
	}
	// An unclassified revision reports as widening: nothing can approve it.
	if c, err := approvals.DecodeClassification(d); err == nil {
		v.Widening = c.Widening
		for _, r := range c.Reasons {
			v.Reasons = append(v.Reasons, dashboard.ChangeReason{Code: r.Code, Path: r.Path, Detail: r.Detail})
		}
	}
	// Only a policy draft publishes a policy version; another target's number
	// (an agent revision) is not one and must not be read as one.
	if d.Target == approvals.TargetPolicy {
		v.AppliedVersion = d.AppliedVersion
	}
	v.Approvals = approved
	return v
}

// approvalCount is the distinct approvers of d's current revision (0 on a
// store error: the count is informational, the apply path counts for itself).
// seesEntities reports whether the caller may read the entities a non-policy
// draft names (who is blocked): admins only, as for the block list routes. An
// API key counts as the role its owner holds.
func (a changeDraftAPI) seesEntities(ctx context.Context) bool {
	p, ok := PrincipalFrom(ctx)
	return ok && principalRole(a.s.cfg.Console, p) >= config.RoleAdmin
}

func (a changeDraftAPI) approvalCount(ctx context.Context, d approvals.Draft) int {
	n, _ := a.svc().ApprovalCount(ctx, d)
	return n
}

func (a changeDraftAPI) result(ctx context.Context, d approvals.Draft, applied bool) dashboard.ChangeResult {
	res := dashboard.ChangeResult{ChangeDraftView: a.view(d, a.approvalCount(ctx, d))}
	if applied && d.Target == approvals.TargetPolicy {
		res.Version = d.AppliedVersion
	}
	return res
}

func replayView(r approvals.Replay) dashboard.ChangeReplayView {
	v := dashboard.ChangeReplayView{
		ID: r.ID, Revision: r.Revision, BaseVersion: r.BaseVersion, Status: string(r.Status),
		EventsScanned: r.EventsScanned, Truncated: r.Truncated, ErrorCode: r.ErrorCode,
		WindowFrom: r.WindowFrom.UTC(), WindowTo: r.WindowTo.UTC(),
	}
	if !r.FinishedAt.IsZero() {
		t := r.FinishedAt.UTC()
		v.FinishedAt = &t
	}
	if r.Status == approvals.ReplayDone {
		v.Result = r.Result
	}
	return v
}

func (a changeDraftAPI) detail(ctx context.Context, d approvals.Draft) (dashboard.ChangeDraftDetail, error) {
	var doc approvals.Doc
	var view any
	if d.Target == approvals.TargetPolicy {
		var err error
		if doc, err = d.PolicyDoc(); err != nil {
			return dashboard.ChangeDraftDetail{}, err
		}
		// Stored docs are redacted; redact again on the way out.
		view = redactDraftDoc(doc)
	} else {
		ad, ok := a.s.targetAdapters()[d.Target]
		if !ok {
			return dashboard.ChangeDraftDetail{}, approvals.ErrUnsupportedTarget
		}
		var err error
		if view, err = ad.View(d, a.seesEntities(ctx)); err != nil {
			return dashboard.ChangeDraftDetail{}, err
		}
	}
	rows, err := a.svc().Store().Approvals(ctx, d.ID)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, err
	}
	out := dashboard.ChangeDraftDetail{
		ChangeDraftView: a.view(d, a.approvalCount(ctx, d)),
		Doc:             view,
		ApprovalRows:    []dashboard.ChangeApprovalView{},
	}
	for _, r := range rows {
		out.ApprovalRows = append(out.ApprovalRows, dashboard.ChangeApprovalView{
			Revision: r.Revision, DocSHA256: r.DocSHA256, Decision: string(r.Decision),
			Approver:     dashboard.ChangeActor{Sub: r.ApproverSub, Email: r.ApproverEmail},
			ApproverRole: r.ApproverRole, AuthMethod: r.AuthMethod, ReplayID: r.ReplayID,
			AcknowledgeNoReplay: r.AcknowledgeNoReplay, Comment: r.Comment, At: r.At.UTC(),
		})
	}
	if rp, ok, err := a.svc().LatestReplay(ctx, d.ID, d.Revision); err == nil && ok {
		v := replayView(rp)
		out.LatestReplay = &v
	}
	return out, nil
}

// annotate attaches the draft to the request's admin audit row: its reference
// and the closed set of details (versions, reason codes, replay status), never
// doc content.
func (a changeDraftAPI) annotate(ctx context.Context, d approvals.Draft, extra map[string]string) {
	setAuditDraft(ctx, d.ID)
	details := map[string]string{adminaudit.DetailBaseVersion: strconv.FormatInt(d.BaseVersion, 10)}
	if c, err := approvals.DecodeClassification(d); err == nil {
		details[adminaudit.DetailWidening] = strconv.FormatBool(c.Widening)
		codes := make([]string, 0, len(c.Reasons))
		seen := map[string]bool{}
		for _, r := range c.Reasons {
			if !seen[r.Code] {
				seen[r.Code] = true
				codes = append(codes, r.Code)
			}
		}
		details[adminaudit.DetailReasons] = strings.Join(codes, ",")
	}
	if d.AppliedVersion > 0 {
		details[adminaudit.DetailAppliedVersion] = strconv.FormatInt(d.AppliedVersion, 10)
	}
	for k, v := range extra {
		details[k] = v
	}
	adminaudit.Annotate(ctx, "draft:"+d.ID+"@r"+strconv.Itoa(d.Revision), details)
}

// --- reads ---

// List implements dashboard.ChangeDrafts.
func (a changeDraftAPI) List(ctx context.Context, f dashboard.ChangeFilter, cursor string, limit int) ([]dashboard.ChangeDraftView, string, error) {
	flt := approvals.Filter{Target: approvals.Target(f.Target), State: approvals.State(f.State)}
	if f.Target != "" && !flt.Target.Valid() {
		return nil, "", &dashboard.ChangeError{Status: http.StatusBadRequest, Code: "invalid_target"}
	}
	if f.State != "" && !validDraftState(flt.State) {
		return nil, "", &dashboard.ChangeError{Status: http.StatusBadRequest, Code: "invalid_state"}
	}
	ds, next, err := a.svc().Store().List(ctx, flt, cursor, limit)
	if err != nil {
		return nil, "", a.changeErr(ctx, err)
	}
	counts, err := a.svc().Store().ApprovalCounts(ctx, ds)
	if err != nil {
		return nil, "", a.changeErr(ctx, err)
	}
	out := make([]dashboard.ChangeDraftView, len(ds))
	for i, d := range ds {
		out[i] = a.view(d, counts[d.ID])
	}
	return out, next, nil
}

func validDraftState(s approvals.State) bool {
	for _, st := range approvals.States() {
		if st == s {
			return true
		}
	}
	return false
}

// Get implements dashboard.ChangeDrafts.
func (a changeDraftAPI) Get(ctx context.Context, id string) (dashboard.ChangeDraftDetail, error) {
	d, err := a.svc().Store().Get(ctx, id)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, err)
	}
	out, err := a.detail(ctx, d)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, err)
	}
	return out, nil
}

// Diff implements dashboard.ChangeDrafts: the structural diff of the draft's
// current revision against its base version, both docs redacted.
func (a changeDraftAPI) Diff(ctx context.Context, id string) (dashboard.ChangeDiff, error) {
	d, err := a.svc().Store().Get(ctx, id)
	if err != nil {
		return dashboard.ChangeDiff{}, a.changeErr(ctx, err)
	}
	if d.Target != approvals.TargetPolicy {
		return a.targetDiff(ctx, d)
	}
	doc, err := d.PolicyDoc()
	if err != nil {
		return dashboard.ChangeDiff{}, a.changeErr(ctx, err)
	}
	var base policyWire
	if d.BaseVersion > 0 {
		v, err := a.s.versions.Get(ctx, d.BaseVersion)
		if err != nil {
			return dashboard.ChangeDiff{}, a.changeErr(ctx, err)
		}
		base = RedactCredentials(v.Doc)
	}
	diff, err := DiffDocs(base, RedactCredentials(policyWire{Allowlist: doc.Allowlist, Denylist: doc.Denylist, Settings: doc.Settings}))
	if err != nil {
		return dashboard.ChangeDiff{}, a.changeErr(ctx, err)
	}
	return dashboard.ChangeDiff{ID: d.ID, Revision: d.Revision, BaseVersion: d.BaseVersion, Diff: diff}, nil
}

// --- author writes ---

// decodeDoc reads a request doc strictly: unknown fields are an error.
func decodeDoc(raw json.RawMessage) (approvals.Doc, error) {
	var doc approvals.Doc
	if len(raw) == 0 {
		return doc, &dashboard.ChangeError{Status: http.StatusBadRequest, Code: "invalid_doc"}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return doc, &dashboard.ChangeError{Status: http.StatusBadRequest, Code: "invalid_doc"}
	}
	if doc.Allowlist == nil {
		doc.Allowlist = []config.AllowlistEntry{}
	}
	if doc.Denylist == nil {
		doc.Denylist = []config.DenylistEntry{}
	}
	return doc, nil
}

// Create implements dashboard.ChangeDrafts.
func (a changeDraftAPI) Create(ctx context.Context, in dashboard.ChangeCreateInput) (dashboard.ChangeDraftDetail, error) {
	au, _, err := a.caller(ctx)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, err
	}
	if approvals.Target(in.Target) != approvals.TargetPolicy {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, approvals.ErrUnsupportedTarget)
	}
	doc, err := a.decodeAndValidate(ctx, in.Doc)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, err
	}
	head, err := a.s.versions.Head(ctx)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, err)
	}
	if in.BaseVersion > head {
		return dashboard.ChangeDraftDetail{}, &dashboard.ChangeError{Status: http.StatusBadRequest, Code: "unknown_base_version"}
	}
	d, err := a.svc().CreateDraft(ctx, approvals.TargetPolicy, doc, au, approvals.Provenance{Source: approvals.SourceConsole, Message: in.Message}, in.BaseVersion)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, err)
	}
	a.annotate(ctx, d, map[string]string{adminaudit.DetailOp: "create"})
	out, err := a.detail(ctx, d)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, err)
	}
	return out, nil
}

// authored loads a draft and refuses anyone but its author.
func (a changeDraftAPI) authored(ctx context.Context, id string) (approvals.Draft, approvals.Author, error) {
	au, _, err := a.caller(ctx)
	if err != nil {
		return approvals.Draft{}, au, err
	}
	d, err := a.svc().Store().Get(ctx, id)
	if err != nil {
		return approvals.Draft{}, au, a.changeErr(ctx, err)
	}
	a.annotate(ctx, d, nil)
	if !sameActor(d.Author, au) {
		return d, au, a.changeErr(ctx, errNotAuthor)
	}
	return d, au, nil
}

// Update implements dashboard.ChangeDrafts. Only a policy draft can be edited:
// a block-list or agent draft is exactly the change its write route held, so
// the author withdraws it and makes the change again.
func (a changeDraftAPI) Update(ctx context.Context, id string, revision int, in dashboard.ChangeUpdateInput) (dashboard.ChangeDraftDetail, error) {
	cur, au, err := a.authored(ctx, id)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, err
	}
	if cur.Target != approvals.TargetPolicy {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, approvals.ErrUnsupportedTarget)
	}
	doc, err := a.decodeAndValidate(ctx, in.Doc)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, err
	}
	d, err := a.svc().UpdateDraft(ctx, id, revision, doc, in.Message, au.Sub)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, err)
	}
	a.annotate(ctx, d, map[string]string{adminaudit.DetailOp: "update"})
	out, err := a.detail(ctx, d)
	if err != nil {
		return dashboard.ChangeDraftDetail{}, a.changeErr(ctx, err)
	}
	return out, nil
}

// revisionOrCurrent resolves a transition's revision: 0 is the draft's own.
func revisionOrCurrent(rev int, d approvals.Draft) int {
	if rev == 0 {
		return d.Revision
	}
	return rev
}

// Submit implements dashboard.ChangeDrafts: a narrowing draft applies at once
// (decision self), a widening one waits for a second person and raises the
// policy_approval_requested Finding.
func (a changeDraftAPI) Submit(ctx context.Context, id string, revision int) (dashboard.ChangeResult, error) {
	d, au, err := a.authored(ctx, id)
	if err != nil {
		return dashboard.ChangeResult{}, err
	}
	policyBefore := a.s.policyHashNow(ctx)
	res, err := a.svc().SubmitOrApply(ctx, id, revisionOrCurrent(revision, d), au)
	if res.Draft.ID != "" {
		a.annotate(ctx, res.Draft, map[string]string{adminaudit.DetailOp: "submit"})
	}
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	if res.Applied {
		a.recordPolicyApply(ctx, policyBefore, res.Draft)
	} else {
		a.publishApprovalRequested(res.Draft)
	}
	return a.result(ctx, res.Draft, res.Applied), nil
}

// publishApprovalRequested raises the info Finding for a widening draft that
// now waits for a second person. The DedupKey is per draft, so a resubmit or a
// new revision does not raise a second alert.
func (a changeDraftAPI) publishApprovalRequested(d approvals.Draft) {
	c, err := approvals.DecodeClassification(d)
	if err != nil || !c.Widening {
		return
	}
	codes := make([]string, 0, len(c.Reasons))
	for _, r := range c.Reasons {
		codes = append(codes, r.Code)
	}
	a.s.publishFinding(integration.Finding{
		RuleID: findingPolicyApprovalRequested, Category: "security", Severity: integration.SevInfo,
		Summary:  "a change that widens access is waiting for a second person to approve it",
		Evidence: integration.Evidence("draft=" + d.ID + " target=" + string(d.Target) + " revision=" + strconv.Itoa(d.Revision) + " reasons=" + strings.Join(codes, ",")),
		DedupKey: findingPolicyApprovalRequested + ":" + d.ID,
		Ts:       a.s.cfg.Clock.Now(),
	})
}

// Withdraw implements dashboard.ChangeDrafts.
func (a changeDraftAPI) Withdraw(ctx context.Context, id string, revision int) (dashboard.ChangeResult, error) {
	d, au, err := a.authored(ctx, id)
	if err != nil {
		return dashboard.ChangeResult{}, err
	}
	nd, err := a.svc().Store().Withdraw(ctx, id, revisionOrCurrent(revision, d), au.Sub)
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	a.annotate(ctx, nd, map[string]string{adminaudit.DetailOp: "withdraw"})
	return a.result(ctx, nd, false), nil
}

// Rebase implements dashboard.ChangeDrafts: the draft's change (base version
// to doc) is replayed onto the live head as revision n+1. A key changed on both
// sides is a 409 rebase_conflict naming it.
func (a changeDraftAPI) Rebase(ctx context.Context, id string, revision int) (dashboard.ChangeResult, error) {
	d, au, err := a.authored(ctx, id)
	if err != nil {
		return dashboard.ChangeResult{}, err
	}
	rev := revisionOrCurrent(revision, d)
	if d.Target != approvals.TargetPolicy {
		return dashboard.ChangeResult{}, a.changeErr(ctx, approvals.ErrUnsupportedTarget)
	}
	if d.State != approvals.StateNeedsRebase {
		return dashboard.ChangeResult{}, a.changeErr(ctx, approvals.ErrIllegalTransition)
	}
	if rev != d.Revision {
		return dashboard.ChangeResult{}, a.changeErr(ctx, approvals.ErrStateChanged)
	}
	doc, err := d.PolicyDoc()
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	var base approvals.Doc
	if d.BaseVersion > 0 {
		v, err := a.s.versions.Get(ctx, d.BaseVersion)
		if err != nil {
			return dashboard.ChangeResult{}, a.changeErr(ctx, err)
		}
		base = draftDoc(RedactCredentials(v.Doc))
	}
	head, hw, err := a.s.headDoc(ctx)
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	merged, conflicts, err := mergeDocs(base, doc, draftDoc(RedactCredentials(hw)))
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	if len(conflicts) > 0 {
		return dashboard.ChangeResult{}, a.changeErr(ctx, &dashboard.ChangeError{
			Status: http.StatusConflict, Code: "rebase_conflict",
			Fields: map[string]any{"head": head, "conflicts": conflictList(conflicts)},
		})
	}
	nd, err := a.svc().RebaseDraft(ctx, id, rev, head, merged, "", au.Sub)
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	a.annotate(ctx, nd, map[string]string{adminaudit.DetailOp: "rebase"})
	return a.result(ctx, nd, false), nil
}

// --- reviewer writes ---

// Approve implements dashboard.ChangeDrafts.
func (a changeDraftAPI) Approve(ctx context.Context, id string, in dashboard.ChangeApproveInput) (dashboard.ChangeResult, error) {
	au, role, err := a.caller(ctx)
	if err != nil {
		return dashboard.ChangeResult{}, err
	}
	if d, gerr := a.svc().Store().Get(ctx, id); gerr == nil {
		a.annotate(ctx, d, map[string]string{
			adminaudit.DetailOp:           "approve",
			adminaudit.DetailAckNoReplay:  strconv.FormatBool(in.AcknowledgeNoReplay),
			adminaudit.DetailReplayStatus: a.replayStatus(ctx, d, in.ReplayID),
		})
	}
	policyBefore := a.s.policyHashNow(ctx)
	res, err := a.svc().Approve(ctx, approvals.ApproveInput{
		ID: id, Revision: in.Revision, DocSHA256: in.DocSHA256, Approver: au, Role: role,
		ReplayID: in.ReplayID, AcknowledgeNoReplay: in.AcknowledgeNoReplay, Comment: in.Comment,
	})
	if res.Draft.ID != "" {
		a.annotate(ctx, res.Draft, nil)
	}
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	if res.Applied {
		a.recordPolicyApply(ctx, policyBefore, res.Draft)
	}
	out := a.result(ctx, res.Draft, res.Applied)
	out.Approvals, out.ApprovalsRequired = res.Approvals, res.Required
	return out, nil
}

// replayStatus is the status of the replay an approval cites, or "none" /
// "acknowledged" when it cites none.
func (a changeDraftAPI) replayStatus(ctx context.Context, d approvals.Draft, replayID string) string {
	if replayID != "" {
		if rp, err := a.svc().GetReplay(ctx, replayID); err == nil {
			return string(rp.Status)
		}
		return "unknown"
	}
	if rp, ok, err := a.svc().LatestReplay(ctx, d.ID, d.Revision); err == nil && ok {
		return string(rp.Status)
	}
	return "none"
}

// Reject implements dashboard.ChangeDrafts.
func (a changeDraftAPI) Reject(ctx context.Context, id string, in dashboard.ChangeRejectInput) (dashboard.ChangeResult, error) {
	au, role, err := a.caller(ctx)
	if err != nil {
		return dashboard.ChangeResult{}, err
	}
	d, err := a.svc().Reject(ctx, approvals.RejectInput{
		ID: id, Revision: in.Revision, DocSHA256: in.DocSHA256, Approver: au, Role: role, Comment: in.Comment,
	})
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	a.annotate(ctx, d, map[string]string{adminaudit.DetailOp: "reject"})
	return a.result(ctx, d, false), nil
}

// Replay implements dashboard.ChangeDrafts: re-run the replay of the draft's
// current revision.
func (a changeDraftAPI) Replay(ctx context.Context, id string) (dashboard.ChangeReplayView, error) {
	if _, _, err := a.caller(ctx); err != nil {
		return dashboard.ChangeReplayView{}, err
	}
	if d, err := a.svc().Store().Get(ctx, id); err == nil {
		a.annotate(ctx, d, map[string]string{adminaudit.DetailOp: "replay"})
	}
	rp, err := a.svc().Replay(ctx, id)
	if err != nil {
		if a.svc().Replayer() == nil {
			return dashboard.ChangeReplayView{}, &dashboard.ChangeError{Status: http.StatusConflict, Code: "replay_unavailable", Err: err}
		}
		return dashboard.ChangeReplayView{}, a.changeErr(ctx, err)
	}
	return replayView(rp), nil
}

// --- audit state hash ---

// changeDraftHash is the change_draft state hasher: the keyed hash of
// `<id>:<revision>:<state>:<doc_sha256>` for the draft the request names (the
// path's id, or the one a create just made). "" when the request names none.
func (s *Server) changeDraftHash(ctx context.Context) (string, error) {
	id := auditDraftID(ctx)
	if id == "" || s.approvals == nil {
		return "", nil
	}
	d, err := s.approvals.Store().Get(ctx, id)
	if errors.Is(err, approvals.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return s.audit.mac(auditTargetChangeDraft, []byte(d.ID+":"+strconv.Itoa(d.Revision)+":"+string(d.State)+":"+d.DocSHA256))
}

// auditScope carries what a state hasher needs to know about the request it
// hashes for: the request path (a draft's id is in it) and the id a handler
// sets when the draft did not exist yet (a create).
type auditScope struct {
	path    string
	draftID string
	// followUps are extra rows requested after the request's own row.
	followUps []auditFollowUp
}

// maxAuditFollowUps caps the extra rows one request may add.
const maxAuditFollowUps = 2

// auditFollowUp is what a handler may ask for: the what, never the who. The
// middleware takes the actor, role, auth method, client, request id and status
// from the request's own row and records the follow-up only when that row's
// outcome is ok. Details are filtered through the closed detail set.
type auditFollowUp struct {
	Action, Target, TargetRef string
	Details                   map[string]string
	BeforeHash, AfterHash     string
	// Committed marks a row for a change that really happened although the
	// request failed afterwards. It is recorded (as outcome ok) even when the
	// request's own row is not ok. Only the emergency-apply path sets it (the
	// handler for a policy version that published but could not be recorded on
	// its draft, a non-policy Applier for its write).
	Committed bool
}

// addAuditFollowUp asks the admin audit middleware for one more row after the
// request's own.
func addAuditFollowUp(ctx context.Context, f auditFollowUp) {
	if sc, ok := ctx.Value(auditScopeKey{}).(*auditScope); ok {
		sc.followUps = append(sc.followUps, f)
	}
}

// auditFollowUps are the rows a handler asked for after its own.
func auditFollowUps(ctx context.Context) []auditFollowUp {
	if sc, ok := ctx.Value(auditScopeKey{}).(*auditScope); ok {
		return sc.followUps
	}
	return nil
}

// targetHashNow is the audit state hash of target now ("" without admin audit
// or a hasher for it).
func (s *Server) targetHashNow(ctx context.Context, target string) string {
	if s.audit == nil {
		return ""
	}
	h, _ := s.audit.stateHash(ctx, target)
	return h
}

// targetDiff is Diff of a draft of a target other than the policy.
func (a changeDraftAPI) targetDiff(ctx context.Context, d approvals.Draft) (dashboard.ChangeDiff, error) {
	ad, ok := a.s.targetAdapters()[d.Target]
	if !ok {
		return dashboard.ChangeDiff{}, a.changeErr(ctx, approvals.ErrUnsupportedTarget)
	}
	proposed, err := ad.View(d, a.seesEntities(ctx))
	if err != nil {
		return dashboard.ChangeDiff{}, a.changeErr(ctx, err)
	}
	current, err := ad.Current(ctx, d, a.seesEntities(ctx))
	if err != nil {
		return dashboard.ChangeDiff{}, a.changeErr(ctx, err)
	}
	return dashboard.ChangeDiff{
		ID: d.ID, Revision: d.Revision, BaseVersion: d.BaseVersion,
		Diff: map[string]any{"current": current, "proposed": proposed},
	}, nil
}

// policyHashNow is the policy audit hash now ("" without admin audit).
func (s *Server) policyHashNow(ctx context.Context) string {
	if s.audit == nil {
		return ""
	}
	h, _ := s.audit.stateHash(ctx, auditTargetPolicy)
	return h
}

// recordPolicyApply asks for the policy row of a draft that just published:
// the same action and target a console policy save records, with the version
// and the `approval` source, the actor being whoever made the request and the
// hashes the policy hash before and after the apply.
func (a changeDraftAPI) recordPolicyApply(ctx context.Context, before string, d approvals.Draft) {
	a.recordPolicyApplyOp(ctx, before, d, "")
}

// recordPolicyApplyOp is recordPolicyApply with the row's op detail set (an
// emergency apply says so, so history and audit tell it from an approval).
func (a changeDraftAPI) recordPolicyApplyOp(ctx context.Context, before string, d approvals.Draft, op string) {
	// Another target's Applier asks for its own row (its action, ref and hash).
	if d.Target != approvals.TargetPolicy {
		return
	}
	if f, ok := a.policyApplyFollowUp(ctx, before, d, op); ok {
		addAuditFollowUp(ctx, f)
	}
}

// policyApplyFollowUp is the policy.write row of a draft that published.
func (a changeDraftAPI) policyApplyFollowUp(ctx context.Context, before string, d approvals.Draft, op string) (auditFollowUp, bool) {
	if a.s.audit == nil || d.Target != approvals.TargetPolicy {
		return auditFollowUp{}, false
	}
	after := a.s.policyHashNow(ctx)
	ref := "policy@" + a.s.policy.currentETag()
	details := map[string]string{
		adminaudit.DetailAppliedVersion: strconv.FormatInt(d.AppliedVersion, 10),
		adminaudit.DetailSource:         SourceApproval,
	}
	if op != "" {
		details[adminaudit.DetailOp] = op
	}
	return auditFollowUp{
		Action: "policy.write", Target: auditTargetPolicy, TargetRef: ref,
		Details:    details,
		BeforeHash: before, AfterHash: after,
	}, true
}

type auditScopeKey struct{}

// withAuditScope puts a scope for path in ctx.
func withAuditScope(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, auditScopeKey{}, &auditScope{path: path})
}

// setAuditDraft records the draft a request acts on.
func setAuditDraft(ctx context.Context, id string) {
	if sc, ok := ctx.Value(auditScopeKey{}).(*auditScope); ok {
		sc.draftID = id
	}
}

// auditDraftID is the draft the request acts on, "" when there is none.
func auditDraftID(ctx context.Context) string {
	sc, ok := ctx.Value(auditScopeKey{}).(*auditScope)
	if !ok {
		return ""
	}
	if sc.draftID != "" {
		return sc.draftID
	}
	id, _ := dashboard.ChangeDraftID(sc.path)
	return id
}

// decodeAndValidate reads a request doc and dry-runs it through the config
// loader, so a doc that could never publish is a 422 now rather than at the
// approval. The check is repeated at apply, against the head then.
func (a changeDraftAPI) decodeAndValidate(ctx context.Context, raw json.RawMessage) (approvals.Doc, error) {
	doc, err := decodeDoc(raw)
	if err != nil {
		return doc, err
	}
	if err := a.s.validateDoc(policyWire{Allowlist: doc.Allowlist, Denylist: doc.Denylist, Settings: doc.Settings}); err != nil {
		return doc, a.changeErr(ctx, &dashboard.InvalidPolicyError{Err: err})
	}
	return doc, nil
}
