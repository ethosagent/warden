package approvals

// gate.go is the one clearance check every versioned write path goes through
// (W-P2-APPR-06). A Clearance can only be minted here (its fields are
// unexported), and the control plane's publish refuses the zero value, so a new
// write path cannot publish a version without passing a Gate method.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ethosagent/warden/internal/config"
)

var (
	// ErrNotCleared: a publish was attempted with the zero Clearance.
	ErrNotCleared = errors.New("approvals: change was not cleared to publish")
	// ErrApprovalRequired: the change needs a second person; the caller holds
	// it as a draft instead of publishing.
	ErrApprovalRequired = errors.New("approvals: the change needs approval")
	// ErrGateUnavailable: approvals are enabled but the Service is missing, so
	// nothing can be cleared. It fails closed: a broken gate never opens.
	ErrGateUnavailable = errors.New("approvals: approvals are enabled but the approval service is unavailable")
)

// clearanceKind says why a Clearance was minted.
type clearanceKind uint8

const (
	clearNone clearanceKind = iota // the zero value: not cleared
	clearDisabled
	clearNarrowing
	clearApplied
	// clearEmergency is minted only by Gate.EmergencyApply, for the one claimed
	// draft it recorded an `emergency` row for.
	clearEmergency
)

// Clearance is the right to publish one change. Only a Gate mints a non-zero
// one; the zero value clears nothing.
//
// A Clearance is bound to the doc it was minted for: Covers reports whether a
// doc is that one, and the control plane's publish refuses any other, so a
// clearance for doc A can never publish doc B.
type Clearance struct {
	kind    clearanceKind
	draftID string
	docSHA  string
}

// DocSHA256 is the digest of doc's canonical JSON, the same one a draft stores
// as doc_sha256 for a redacted doc. The caller redacts first.
func DocSHA256(doc Doc) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("approvals: encode doc: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Covers reports whether c was minted for doc (already credential-redacted).
// The zero Clearance covers nothing.
func (c Clearance) Covers(doc Doc) bool {
	if !c.Valid() {
		return false
	}
	sha, err := DocSHA256(doc)
	return err == nil && sha == c.docSHA
}

// Valid reports whether c was minted by a Gate.
func (c Clearance) Valid() bool { return c.kind != clearNone }

// Reason names why c was minted, for logs and tests: "", "disabled",
// "narrowing", "applied_draft" or "emergency".
func (c Clearance) Reason() string {
	switch c.kind {
	case clearEmergency:
		return "emergency"
	case clearDisabled:
		return "disabled"
	case clearNarrowing:
		return "narrowing"
	case clearApplied:
		return "applied_draft"
	}
	return ""
}

// Change is one proposed edit of a versioned target, as a write path sees it.
// BaseDoc and Draft are the redacted canonical docs the change goes from and
// to; a raw credential must never reach a Change.
type Change struct {
	Target Target
	// Base is the version the change was computed from (the head).
	Base    int64
	BaseDoc Doc
	Draft   Doc
	Author  Author
	Source  Source
	Message string
	// Ref and RollbackTo are the draft's provenance.
	Ref        string
	RollbackTo int64
}

// Gate mints Clearances. Build it once from console.approvals.enabled and the
// approvals Service; with approvals enabled and no Service every Clear fails
// closed.
type Gate struct {
	enabled bool
	svc     *Service
}

// NewGate returns the Gate for a control plane. enabled is
// console.approvals.enabled, svc the approvals Service (nil when it could not be
// built).
func NewGate(enabled bool, svc *Service) *Gate { return &Gate{enabled: enabled, svc: svc} }

// Enabled reports whether approvals are enforced.
func (g *Gate) Enabled() bool { return g != nil && g.enabled }

// Service returns the approvals Service, nil when approvals are disabled.
func (g *Gate) Service() *Service {
	if g == nil {
		return nil
	}
	return g.svc
}

// Clear decides whether ch may publish now. It mints a Clearance when approvals
// are disabled, or ch narrows and allowSelfApproveNarrowing is on. Otherwise it
// returns ErrApprovalRequired, and the caller holds the change with Hold. A nil
// Gate, or an enabled one with no Service, returns ErrGateUnavailable.
func (g *Gate) Clear(_ context.Context, ch Change) (Clearance, error) {
	sha, err := DocSHA256(ch.Draft)
	if err != nil {
		return Clearance{}, err
	}
	switch {
	case g == nil:
		return Clearance{}, ErrGateUnavailable
	case !g.enabled:
		return Clearance{kind: clearDisabled, docSHA: sha}, nil
	case g.svc == nil:
		return Clearance{}, ErrGateUnavailable
	case ch.Target != TargetPolicy:
		return Clearance{}, fmt.Errorf("%w: %s", ErrUnsupportedTarget, ch.Target)
	}
	if !Classify(ch.BaseDoc, ch.Draft).Widening && g.svc.cfg.AllowSelfApproveNarrowing {
		return Clearance{kind: clearNarrowing, docSHA: sha}, nil
	}
	return Clearance{}, ErrApprovalRequired
}

// ClearApplied mints the Clearance of a draft the Service is applying. It does
// not trust d: it re-reads the stored draft and requires it to be in state
// applying, classified, and at the same revision and doc digest as d, so a
// forged or stale Draft value is refused with ErrNotCleared. The Clearance
// covers the stored doc only.
func (g *Gate) ClearApplied(ctx context.Context, d Draft) (Clearance, error) {
	if g == nil || g.svc == nil {
		return Clearance{}, ErrGateUnavailable
	}
	stored, err := g.svc.Store().Get(ctx, d.ID)
	if err != nil {
		return Clearance{}, fmt.Errorf("%w: draft %s: %v", ErrNotCleared, d.ID, err)
	}
	if stored.State != StateApplying || stored.Revision != d.Revision || stored.DocSHA256 != d.DocSHA256 || stored.DocSHA256 == "" {
		return Clearance{}, fmt.Errorf("%w: draft %s is not the applying revision it claims", ErrNotCleared, d.ID)
	}
	if err := RequireClassified(stored); err != nil {
		return Clearance{}, err
	}
	return Clearance{kind: clearApplied, draftID: stored.ID, docSHA: stored.DocSHA256}, nil
}

// EmergencyApply publishes a pending or needs_rebase draft past the two-person
// rule for a break-glass session (W-P2-APPR-07), and is the only way an
// emergency Clearance is minted. In order, and each step fails closed:
//
//  1. approvals are enabled with a Service and allowEmergencyApply is on
//     (ErrGateUnavailable, ErrEmergencyDisabled);
//  2. the caller is a break-glass session (ErrBreakglassRequired) and the
//     reason is 10 to 512 characters (ErrEmergencyReason);
//  3. the draft is a classified, unexpired policy draft in pending or
//     needs_rebase, at the revision and doc the caller named;
//  4. the rate limit has room (ErrEmergencyRateLimited);
//  5. the draft is claimed (-> applying) and the `emergency` change_approvals
//     row with the reason is written in the same transaction, BEFORE anything
//     publishes;
//  6. only then is the Clearance minted, bound to that draft's doc digest, and
//     the Applier publishes with expectedHead = base version;
//  7. the draft becomes applied_unreviewed until an admin reviews it.
//
// A moved head is ErrRebaseRequired and leaves the draft needs_rebase; any
// other refused publish returns the draft to pending. The emergency row stays
// either way: an attempt is on the record.
func (g *Gate) EmergencyApply(ctx context.Context, in EmergencyInput) (Draft, error) {
	if g == nil || !g.enabled || g.svc == nil {
		return Draft{}, ErrGateUnavailable
	}
	s := g.svc
	switch {
	case !s.cfg.AllowEmergencyApply:
		return Draft{}, ErrEmergencyDisabled
	case in.Actor.Kind != AuthorKindBreakglass || strings.TrimSpace(in.Actor.Sub) == "":
		return Draft{}, ErrBreakglassRequired
	}
	if in.BeforePublish == nil {
		return Draft{}, fmt.Errorf("%w: no audit hook", ErrEmergencyAudit)
	}
	reason, err := cleanReason(in.Reason)
	if err != nil {
		return Draft{}, err
	}

	// Serialise with Apply: one publisher at a time.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	d, err := s.cfg.Store.Get(ctx, in.ID)
	if err != nil {
		return Draft{}, err
	}
	switch {
	case d.State != StatePending && d.State != StateNeedsRebase:
		return Draft{}, fmt.Errorf("%w: a %s draft cannot be emergency-applied", ErrIllegalTransition, d.State)
	case (in.Revision != 0 && in.Revision != d.Revision) || (in.DocSHA256 != "" && in.DocSHA256 != d.DocSHA256):
		return Draft{}, fmt.Errorf("%w: the draft is at revision %d", ErrRevisionChanged, d.Revision)
	case s.expired(d):
		return Draft{}, ErrDraftExpired
	}
	if err := RequireClassified(d); err != nil {
		return Draft{}, err
	}
	ap, ok := s.cfg.Appliers[d.Target].(EmergencyApplier)
	if !ok || d.Target != TargetPolicy {
		return Draft{}, fmt.Errorf("%w: %s", ErrUnsupportedTarget, d.Target)
	}
	if !s.takeEmergencySlot() {
		return Draft{}, ErrEmergencyRateLimited
	}

	claimed, err := s.cfg.Store.BeginEmergency(ctx, d.ID, DecisionInput{
		Revision: d.Revision, DocSHA256: d.DocSHA256, Decision: DecisionEmergency,
		Approver: in.Actor, ApproverRole: config.RoleAdmin.String(), Comment: reason,
	})
	if err != nil {
		if errors.Is(err, ErrStateChanged) {
			return Draft{}, fmt.Errorf("%w: %w", ErrRevisionChanged, err)
		}
		return Draft{}, err
	}
	// The outcome is recorded even when the caller's context ended: the publish
	// may already have happened.
	octx := context.WithoutCancel(ctx)
	clr, err := g.clearEmergency(ctx, claimed, in.Actor)
	if err != nil {
		g.releaseEmergency(octx, claimed, in.Actor.Sub, err)
		return Draft{}, err
	}
	// The audit record precedes the publish: if it cannot be written, nothing
	// publishes.
	if err := in.BeforePublish(ctx, claimed); err != nil {
		g.releaseEmergency(octx, claimed, in.Actor.Sub, err)
		return Draft{}, fmt.Errorf("%w: %v", ErrEmergencyAudit, err)
	}
	version, aerr := ap.ApplyEmergency(ctx, claimed, clr, in.Actor)
	switch {
	case errors.Is(aerr, ErrRebaseRequired):
		nd, merr := s.cfg.Store.MarkNeedsRebase(octx, claimed.ID, claimed.Revision, truncate(aerr.Error()), in.Actor.Sub)
		if merr != nil {
			return Draft{}, merr
		}
		return nd, ErrRebaseRequired
	case aerr != nil:
		g.releaseEmergency(octx, claimed, in.Actor.Sub, aerr)
		return Draft{}, aerr
	}
	nd, err := s.cfg.Store.MarkEmergencyApplied(octx, claimed.ID, claimed.Revision, version, in.Actor.Sub)
	if err != nil {
		nd, err = s.cfg.Store.MarkEmergencyApplied(octx, claimed.ID, claimed.Revision, version, in.Actor.Sub)
	}
	if err != nil {
		s.cfg.Logger.Error("approvals: emergency draft was published but could not be marked applied_unreviewed; reconcile will repair it",
			"draft_id", claimed.ID, "revision", claimed.Revision, "applied_version", version, "error", err)
		return Draft{}, err
	}
	return nd, nil
}

// releaseEmergency returns a claimed draft to pending after a refused publish.
func (g *Gate) releaseEmergency(ctx context.Context, d Draft, actorSub string, cause error) {
	if _, err := g.svc.Store().FailApply(ctx, d.ID, d.Revision, truncate(cause.Error()), actorSub); err != nil {
		g.svc.cfg.Logger.Error("approvals: cannot return the draft to pending after a refused emergency apply", "draft_id", d.ID, "error", err)
	}
}

// clearEmergency mints the emergency Clearance of d. It trusts nothing it is
// handed: it re-reads the stored draft and requires state applying, the same
// revision and doc digest, a classification, and the durable `emergency` row of
// this break-glass actor for exactly this revision and doc. The Clearance
// covers that doc only.
func (g *Gate) clearEmergency(ctx context.Context, d Draft, actor Author) (Clearance, error) {
	stored, err := g.svc.Store().Get(ctx, d.ID)
	if err != nil {
		return Clearance{}, fmt.Errorf("%w: draft %s: %v", ErrNotCleared, d.ID, err)
	}
	if stored.State != StateApplying || stored.Revision != d.Revision || stored.DocSHA256 != d.DocSHA256 || stored.DocSHA256 == "" {
		return Clearance{}, fmt.Errorf("%w: draft %s is not the claimed revision it names", ErrNotCleared, d.ID)
	}
	if err := RequireClassified(stored); err != nil {
		return Clearance{}, err
	}
	rows, err := g.svc.Store().Approvals(ctx, stored.ID)
	if err != nil {
		return Clearance{}, fmt.Errorf("%w: draft %s: %v", ErrNotCleared, d.ID, err)
	}
	for _, a := range rows {
		if a.Decision == DecisionEmergency && a.Revision == stored.Revision && a.DocSHA256 == stored.DocSHA256 &&
			a.ApproverIss == actor.Iss && a.ApproverSub == actor.Sub && a.AuthMethod == AuthorKindBreakglass && a.Comment != "" {
			return Clearance{kind: clearEmergency, draftID: stored.ID, docSHA: stored.DocSHA256}, nil
		}
	}
	return Clearance{}, fmt.Errorf("%w: draft %s has no recorded emergency decision", ErrNotCleared, d.ID)
}

// Hold stores ch as a draft and submits it, so a second person can approve it.
// It is what a write path does on ErrApprovalRequired. A draft that cannot be
// submitted is withdrawn again, so a failed hold leaves nothing pending.
func (g *Gate) Hold(ctx context.Context, ch Change) (Draft, error) {
	if g == nil || !g.enabled || g.svc == nil {
		return Draft{}, ErrGateUnavailable
	}
	d, err := g.svc.CreateDraft(ctx, ch.Target, ch.Draft, ch.Author, Provenance{
		Source: ch.Source, Message: ch.Message, Ref: ch.Ref, RollbackTo: ch.RollbackTo,
	}, ch.Base)
	if err != nil {
		return Draft{}, err
	}
	sub, err := g.svc.Submit(ctx, d.ID, d.Revision, ch.Author.Sub)
	if err != nil {
		if _, werr := g.svc.Store().Withdraw(context.WithoutCancel(ctx), d.ID, d.Revision, ch.Author.Sub); werr != nil {
			g.svc.cfg.Logger.Warn("approvals: cannot withdraw a draft that failed to submit", "draft_id", d.ID, "error", werr)
		}
		return Draft{}, err
	}
	return sub, nil
}
