package controlplane

// approvals_emergency.go adapts the break-glass emergency apply and its
// post-hoc review (W-P2-APPR-07) to the dashboard routes. The rules live in
// approvals.Gate.EmergencyApply and approvals.Service.Review; this file only
// resolves the caller, writes the audit row that must precede the publish and
// raises the alert. It never publishes: the Clearance is minted by the Gate and
// consumed by the policy Applier (approvals_apply.go).

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
)

const (
	// findingApprovalBypassed is the rule id of the critical Finding every
	// emergency apply raises.
	findingApprovalBypassed = "approval_bypassed"
	// actionEmergencyBegin is the admin audit action of the row written after
	// the draft is claimed and before the publish. The request's own
	// change.draft.emergency_apply row follows it.
	actionEmergencyBegin = "change.draft.emergency_begin"
)

// EmergencyApply implements dashboard.ChangeDrafts.
func (a changeDraftAPI) EmergencyApply(ctx context.Context, id string, in dashboard.ChangeEmergencyInput) (dashboard.ChangeResult, error) {
	au, _, err := a.caller(ctx)
	if err != nil {
		return dashboard.ChangeResult{}, err
	}
	if d, gerr := a.svc().Store().Get(ctx, id); gerr == nil {
		a.annotate(ctx, d, map[string]string{adminaudit.DetailOp: "emergency_apply"})
	}
	policyBefore := a.s.policyHashNow(ctx)
	d, err := a.s.gate.EmergencyApply(ctx, approvals.EmergencyInput{
		ID: id, Revision: in.Revision, DocSHA256: in.DocSHA256, Actor: au, Reason: in.Reason,
		BeforePublish: a.recordEmergencyBegin,
	})
	if d.ID != "" {
		a.annotate(ctx, d, nil)
	}
	if err != nil {
		var pub *approvals.EmergencyPublishedError
		if errors.As(err, &pub) {
			// The version is live whatever happened to the record of it: audit and
			// alert on it, then fail the request loudly.
			if f, ok := a.policyApplyFollowUp(ctx, policyBefore, d, "emergency_apply"); ok {
				// The version is live although the request fails: record it anyway.
				f.Committed = true
				addAuditFollowUp(ctx, f)
			}
			a.s.reportBypass(au.Sub, d, false)
			a.s.cfg.Logger.Error("control plane: emergency apply published but the draft could not be recorded; startup reconcile will settle it",
				"draft_id", d.ID, "version", pub.Version, "error", pub.Err)
			return dashboard.ChangeResult{}, &dashboard.ChangeError{
				Status: http.StatusInternalServerError, Code: "emergency_apply_unrecorded",
				Fields: map[string]any{"version": pub.Version}, Err: err,
			}
		}
		return dashboard.ChangeResult{}, a.changeErr(ctx, a.s.gateError(err))
	}
	a.recordPolicyApplyOp(ctx, policyBefore, d, "emergency_apply")
	a.s.reportBypass(au.Sub, d, false)
	return a.result(ctx, d, true), nil
}

// recordEmergencyBegin writes the admin audit row that precedes the publish. It
// runs inside the request, so the admin audit lock is held; a failed write
// fails the whole emergency apply and nothing publishes. The row names the
// draft and its classification, never the reason or the doc.
func (a changeDraftAPI) recordEmergencyBegin(ctx context.Context, d approvals.Draft) error {
	au := a.s.audit
	if au == nil {
		return errAuditUnavailable
	}
	p, ok := PrincipalFrom(ctx)
	if !ok {
		return errAuditUnavailable
	}
	details := map[string]string{
		adminaudit.DetailOp:          "emergency_begin",
		adminaudit.DetailBaseVersion: strconv.FormatInt(d.BaseVersion, 10),
	}
	if c, err := approvals.DecodeClassification(d); err == nil {
		details[adminaudit.DetailWidening] = strconv.FormatBool(c.Widening)
	}
	in := adminaudit.Input{
		Actor:     adminaudit.Actor{Sub: p.Sub, Email: p.Email},
		ActorRole: config.RoleAdmin.String(), AuthMethod: adminaudit.AuthMethodBreakglass,
		Action: actionEmergencyBegin, Target: auditTargetChangeDraft,
		TargetRef: "draft:" + d.ID + "@r" + strconv.Itoa(d.Revision),
		Details:   adminaudit.FilterDetails(details), Outcome: adminaudit.OutcomeOK,
		RequestID: RequestIDFrom(ctx),
	}
	if _, err := au.rec.Record(context.WithoutCancel(ctx), in); err != nil {
		au.degraded.Store(true)
		a.s.logPersistFailed(in, err)
		a.s.publishAuditDegraded("append_failed")
		return err
	}
	return nil
}

// errAuditUnavailable: the emergency apply cannot run without admin audit.
var errAuditUnavailable = errors.New("controlplane: admin audit is not available")

// reportBypass logs the one ERROR line and raises the critical Finding of an
// emergency apply. Neither carries the reason text or the doc. repaired marks a
// bypass settled by startup reconcile after a crash.
func (s *Server) reportBypass(actorSub string, d approvals.Draft, repaired bool) {
	s.logBypass(actorSub, d, repaired)
	s.publishBypassFinding(actorSub, d)
}

func (s *Server) logBypass(actorSub string, d approvals.Draft, repaired bool) {
	attrs := []any{"draft_id", d.ID, "actor_sub", actorSub}
	if repaired {
		attrs = append(attrs, "repaired", true)
	}
	s.cfg.Logger.Error("approval_bypassed", attrs...)
}

func (s *Server) publishBypassFinding(actorSub string, d approvals.Draft) {
	s.publishFinding(integration.Finding{
		RuleID: findingApprovalBypassed, Category: "security", Severity: integration.SevCritical,
		Summary: "a change was applied by a break-glass emergency apply without a second approver",
		Evidence: integration.Evidence("draft=" + d.ID + " target=" + string(d.Target) + " revision=" + strconv.Itoa(d.Revision) +
			" applied_version=" + strconv.FormatInt(d.AppliedVersion, 10) + " actor=" + actorSub),
		DedupKey: findingApprovalBypassed + ":" + d.ID,
		Ts:       s.cfg.Clock.Now(),
	})
}

// noteRepairedBypass is the approvals Service's OnEmergencyRepaired hook: it
// logs the ERROR line of a bypass startup reconcile settled. The Finding does
// not wait in memory (Run could fail before it is sent); alertUnreviewedBypasses
// raises it from the draft table at every start.
func (s *Server) noteRepairedBypass(d approvals.Draft, actorSub string) {
	s.logBypass(actorSub, d, true)
}

// alertUnreviewedBypasses publishes one critical approval_bypassed Finding for
// every draft still applied_unreviewed. The state table is the source of truth,
// so a bypass whose alert was lost (a crash before it was sent, a start that
// failed before the alert pipeline was up) is raised again at the next start;
// the DedupKey approval_bypassed:<draft id> keeps repeats from piling up. Run
// calls it once the pipeline is ready.
func (s *Server) alertUnreviewedBypasses(ctx context.Context) {
	if s.approvals == nil {
		return
	}
	store := s.approvals.Store()
	cursor := ""
	for {
		ds, next, err := store.List(ctx, approvals.Filter{State: approvals.StateAppliedUnreviewed}, cursor, 100)
		if err != nil {
			s.cfg.Logger.Warn("control plane: cannot list unreviewed emergency applies to alert on", "error", err)
			return
		}
		for _, d := range ds {
			actor := "unknown"
			if rows, err := store.Approvals(ctx, d.ID); err == nil {
				for _, r := range rows {
					if r.Decision == approvals.DecisionEmergency && r.Revision == d.Revision {
						actor = r.ApproverSub
					}
				}
			}
			s.publishBypassFinding(actor, d)
		}
		if next == "" {
			return
		}
		cursor = next
	}
}

// Review implements dashboard.ChangeDrafts: an OIDC admin's post-hoc review of
// an emergency apply.
func (a changeDraftAPI) Review(ctx context.Context, id string, in dashboard.ChangeReviewInput) (dashboard.ChangeResult, error) {
	au, role, err := a.caller(ctx)
	if err != nil {
		return dashboard.ChangeResult{}, err
	}
	if d, gerr := a.svc().Store().Get(ctx, id); gerr == nil {
		a.annotate(ctx, d, map[string]string{adminaudit.DetailOp: "review"})
	}
	d, err := a.svc().Review(ctx, approvals.ReviewInput{
		ID: id, Revision: in.Revision, DocSHA256: in.DocSHA256, Reviewer: au, Role: role, Comment: in.Comment,
	})
	if err != nil {
		return dashboard.ChangeResult{}, a.changeErr(ctx, err)
	}
	a.annotate(ctx, d, nil)
	return a.result(ctx, d, false), nil
}

// emergencyAlertRouted reports whether any integration's alert match routes a
// critical approval_bypassed Finding.
func emergencyAlertRouted(integrations []integration.InstanceConfig) bool {
	probe := integration.Finding{
		RuleID: findingApprovalBypassed, Category: "security", Severity: integration.SevCritical,
		DedupKey: findingApprovalBypassed + ":probe",
	}
	for _, in := range integrations {
		if integration.RoutesFinding(in.Match, probe) {
			return true
		}
	}
	return false
}

// warnEmergencyApplySetup logs the advisory startup WARNs of
// console.approvals.allowEmergencyApply: it is on, but break-glass is off (the
// route could never be used) or no alert route would carry the critical
// approval_bypassed Finding (a bypass would alert no one). It is called once,
// after the alert pipeline has been built.
func (s *Server) warnEmergencyApplySetup(integrations []integration.InstanceConfig) {
	cc := s.cfg.Console
	if !cc.Approvals.Enabled || !cc.Approvals.AllowEmergencyApply {
		return
	}
	if !cc.BreakGlass.Enabled {
		s.cfg.Logger.Warn("control-plane: console.approvals.allowEmergencyApply is on but console.breakGlass.enabled is false; nobody can use the emergency apply")
	}
	switch {
	case s.pipeline == nil:
		s.cfg.Logger.Warn("control-plane: console.approvals.allowEmergencyApply is on but there is no alert pipeline; an emergency apply will not alert anyone",
			"hint", "configure integrations with an alerts.match that routes rule approval_bypassed at severity critical")
	case !emergencyAlertRouted(integrations):
		s.cfg.Logger.Warn("control-plane: console.approvals.allowEmergencyApply is on but no integration's alerts.match routes a critical approval_bypassed Finding; an emergency apply will not alert anyone",
			"hint", "add a match such as {rule: approval_bypassed} or {severity: critical} to an integration")
	}
}
