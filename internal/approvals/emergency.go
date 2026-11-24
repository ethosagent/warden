package approvals

// emergency.go is the break-glass emergency apply and its post-hoc review
// (W-P2-APPR-07). The apply itself is Gate.EmergencyApply (gate.go), the only
// place an emergency Clearance is minted; this file holds what surrounds it:
// the errors, the Applier extension, the rate limit and Service.Review.
//
// An emergency apply is the one route past the two-person rule, so it is as
// narrow as the Clearance it needs: the caller is a break-glass session, the
// operator switched it on (console.approvals.allowEmergencyApply), a reason is
// on file, the clearance covers exactly the claimed draft's doc, and the
// durable `emergency` change_approvals row exists before anything publishes.
// It never becomes a general bypass: it is rate limited, and the control plane
// raises a critical Finding for every use.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ethosagent/warden/internal/config"
)

// Reason bounds, in characters.
const (
	MinEmergencyReason = 10
	MaxEmergencyReason = 512
)

// The emergency apply rate limit: at most emergencyMaxPerWindow claims in any
// emergencyWindow, counted across every break-glass session. A refused claim
// (limited, disabled, wrong caller) does not count.
const (
	emergencyWindow       = 10 * time.Minute
	emergencyMaxPerWindow = 5
)

// Emergency and review errors. Callers match with errors.Is.
var (
	// ErrEmergencyDisabled: console.approvals.allowEmergencyApply is false.
	ErrEmergencyDisabled = errors.New("approvals: emergency apply is not enabled")
	// ErrBreakglassRequired: only a break-glass session may emergency-apply.
	ErrBreakglassRequired = errors.New("approvals: emergency apply needs a break-glass session")
	// ErrEmergencyReason: the reason is not 10 to 512 characters.
	ErrEmergencyReason = errors.New("approvals: the emergency reason must be 10 to 512 characters")
	// ErrEmergencyRateLimited: too many emergency applies in the window.
	ErrEmergencyRateLimited = errors.New("approvals: too many emergency applies; wait and retry")
	// ErrEmergencyAudit: the audit record that must precede the publish could
	// not be written, so nothing was published.
	ErrEmergencyAudit = errors.New("approvals: the emergency apply audit record could not be written")
	// ErrBreakglassReviewer: a break-glass session cannot review its own bypass.
	ErrBreakglassReviewer = errors.New("approvals: a break-glass session cannot review an emergency apply")
)

// EmergencyApplier is the Applier extension an emergency apply needs: it
// publishes d with the emergency Clearance clr, as actor, through the same
// versioned publish path (expectedHead = base version) an ordinary apply uses.
type EmergencyApplier interface {
	ApplyEmergency(ctx context.Context, d Draft, clr Clearance, actor Author) (version int64, err error)
}

// EmergencyInput is one emergency apply request. Revision and DocSHA256 are
// what the operator saw; zero values mean the draft's current ones.
type EmergencyInput struct {
	ID        string
	Revision  int
	DocSHA256 string
	// Actor is the break-glass session making the call.
	Actor  Author
	Reason string
	// BeforePublish is called once the draft is claimed and its `emergency`
	// decision is on file, and before anything publishes. It writes the
	// caller's own audit record (the control plane's admin audit row); an error
	// aborts the publish and returns the draft to pending (ErrEmergencyAudit).
	// It is required, so no emergency apply can run unaudited.
	BeforePublish func(ctx context.Context, d Draft) error
}

// cleanReason trims reason and checks its bounds.
func cleanReason(reason string) (string, error) {
	r := strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(r); !utf8.ValidString(r) || n < MinEmergencyReason || n > MaxEmergencyReason {
		return "", ErrEmergencyReason
	}
	return r, nil
}

// takeEmergencySlot reserves one emergency apply in the sliding window and
// reports whether there was room. The window is in memory: a restart empties
// it, which needs host access that already is full trust.
func (s *Service) takeEmergencySlot() bool {
	now := s.cfg.Now()
	s.emMu.Lock()
	defer s.emMu.Unlock()
	kept := s.emTimes[:0]
	for _, t := range s.emTimes {
		if now.Sub(t) < emergencyWindow {
			kept = append(kept, t)
		}
	}
	s.emTimes = kept
	if len(kept) >= emergencyMaxPerWindow {
		return false
	}
	s.emTimes = append(s.emTimes, now)
	return true
}

// hasEmergencyRow reports whether d's current revision has an `emergency`
// change_approvals row, which is how Reconcile tells an interrupted emergency
// apply from an interrupted ordinary one.
func (s *Service) hasEmergencyRow(ctx context.Context, d Draft) (bool, error) {
	rows, err := s.cfg.Store.Approvals(ctx, d.ID)
	if err != nil {
		return false, err
	}
	for _, a := range rows {
		if a.Revision == d.Revision && a.DocSHA256 == d.DocSHA256 && a.Decision == DecisionEmergency {
			return true, nil
		}
	}
	return false, nil
}

// ReviewInput is one post-hoc review. Revision and DocSHA256 are what the
// reviewer saw (zero values mean the draft's current ones).
type ReviewInput struct {
	ID        string
	Revision  int
	DocSHA256 string
	Reviewer  Author
	// Role is the console role the reviewer holds now; review needs admin.
	Role    config.Role
	Comment string
}

// Review records the post-hoc review of an emergency apply and moves the draft
// from applied_unreviewed to applied. It needs an admin who is not a
// break-glass session. The draft is already live, so a review changes no
// policy; it only closes the audit loop.
func (s *Service) Review(ctx context.Context, in ReviewInput) (Draft, error) {
	switch {
	case in.Reviewer.Kind == AuthorKindBreakglass:
		return Draft{}, ErrBreakglassReviewer
	case strings.TrimSpace(in.Reviewer.Sub) == "":
		return Draft{}, errors.New("approvals: a review has no reviewer")
	case in.Role < config.RoleAdmin:
		return Draft{}, &RoleRequiredError{Need: config.RoleAdmin}
	}
	d, err := s.cfg.Store.Get(ctx, in.ID)
	if err != nil {
		return Draft{}, err
	}
	if d.State != StateAppliedUnreviewed {
		return Draft{}, fmt.Errorf("%w: a %s draft has no emergency apply to review", ErrIllegalTransition, d.State)
	}
	if (in.Revision != 0 && in.Revision != d.Revision) || (in.DocSHA256 != "" && in.DocSHA256 != d.DocSHA256) {
		return Draft{}, fmt.Errorf("%w: the draft is at revision %d", ErrRevisionChanged, d.Revision)
	}
	nd, err := s.cfg.Store.MarkReviewed(ctx, d.ID, DecisionInput{
		Revision: d.Revision, DocSHA256: d.DocSHA256, Decision: DecisionPostReview,
		Approver: in.Reviewer, ApproverRole: in.Role.String(), Comment: in.Comment,
	})
	if errors.Is(err, ErrStateChanged) {
		return Draft{}, fmt.Errorf("%w: %w", ErrRevisionChanged, err)
	}
	return nd, err
}
