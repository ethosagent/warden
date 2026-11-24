package approvals

// gate.go is the one clearance check every versioned write path goes through
// (W-P2-APPR-06). A Clearance can only be minted here (its fields are
// unexported), and the control plane's publish refuses the zero value, so a new
// write path cannot publish a version without passing a Gate method.

import (
	"context"
	"errors"
	"fmt"
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
	clearSystem
)

// Clearance is the right to publish one change. Only a Gate mints a non-zero
// one; the zero value clears nothing.
type Clearance struct {
	kind    clearanceKind
	draftID string
}

// Valid reports whether c was minted by a Gate.
func (c Clearance) Valid() bool { return c.kind != clearNone }

// Reason names why c was minted, for logs and tests: "", "disabled",
// "narrowing", "applied_draft" or "system".
func (c Clearance) Reason() string {
	switch c.kind {
	case clearDisabled:
		return "disabled"
	case clearNarrowing:
		return "narrowing"
	case clearApplied:
		return "applied_draft"
	case clearSystem:
		return "system"
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
	switch {
	case g == nil:
		return Clearance{}, ErrGateUnavailable
	case !g.enabled:
		return Clearance{kind: clearDisabled}, nil
	case g.svc == nil:
		return Clearance{}, ErrGateUnavailable
	case ch.Target != TargetPolicy:
		return Clearance{}, fmt.Errorf("%w: %s", ErrUnsupportedTarget, ch.Target)
	}
	if !Classify(ch.BaseDoc, ch.Draft).Widening && g.svc.cfg.AllowSelfApproveNarrowing {
		return Clearance{kind: clearNarrowing}, nil
	}
	return Clearance{}, ErrApprovalRequired
}

// ClearApplied mints the Clearance of a draft the Service is applying: only a
// draft in state applying and classified qualifies, which is what
// Service.Apply hands an Applier after BeginApply.
func (g *Gate) ClearApplied(d Draft) (Clearance, error) {
	if g == nil || g.svc == nil {
		return Clearance{}, ErrGateUnavailable
	}
	if d.State != StateApplying {
		return Clearance{}, fmt.Errorf("%w: draft %s is %s, not applying", ErrNotCleared, d.ID, d.State)
	}
	if err := RequireClassified(d); err != nil {
		return Clearance{}, err
	}
	return Clearance{kind: clearApplied, draftID: d.ID}, nil
}

// ClearSystem mints the Clearance of a system write: the initial import of the
// served YAML as version 1. It is for the control plane's own startup, never for
// a request.
func (g *Gate) ClearSystem() Clearance { return Clearance{kind: clearSystem} }

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
