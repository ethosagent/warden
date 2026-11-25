package approvals

import (
	"context"
	"encoding/json"
	"time"
)

// NewDraft is what Store.Create inserts. The store assigns ID, Revision 1,
// state draft and the timestamps.
type NewDraft struct {
	Target      Target
	TargetRef   string
	BaseVersion int64
	Author      Author
	Source      Source
	Provenance  Provenance
	Message     string
	// DocJSON is the redacted canonical doc and DocSHA256 its digest, both from
	// EncodeDoc.
	DocJSON        json.RawMessage
	DocSHA256      string
	Classification json.RawMessage
	RequiredRole   string
	ExpiresAt      time.Time
}

// UpdateInput is a new revision of a draft: Update (draft or pending) and
// Rebase (needs_rebase) both take it. ExpectedRevision is the revision the
// caller edited from; a draft that moved on returns ErrStateChanged.
type UpdateInput struct {
	ExpectedRevision int
	// BaseVersion is the new base for Rebase; Update ignores it.
	BaseVersion    int64
	Message        string
	DocJSON        json.RawMessage
	DocSHA256      string
	Classification json.RawMessage
	RequiredRole   string
}

// DecisionInput is one reviewer decision on one revision. Revision and
// DocSHA256 are what the reviewer saw; a draft that changed since returns
// ErrStateChanged.
type DecisionInput struct {
	Revision  int
	DocSHA256 string
	Decision  Decision
	Approver  Author
	// ApproverRole is the console role the approver acted under.
	ApproverRole string
	// ReplayID and AcknowledgeNoReplay are the evidence of W-P2-APPR-03.
	ReplayID            string
	AcknowledgeNoReplay bool
	Comment             string
}

// Filter narrows List. Zero fields match everything.
type Filter struct {
	Target    Target
	State     State
	AuthorSub string
}

// Store is the draft and approval persistence. Every transition is one
// transaction guarded by `UPDATE ... WHERE id=? AND state=? AND revision=?`: a
// transition the state machine forbids returns ErrIllegalTransition, a lost
// compare-and-swap ErrStateChanged, and either leaves the row unchanged. A
// Postgres store can implement it later.
//
// actorSub arguments only name who acted, for the change_draft_transition log;
// the store does no authorization (the API layer does).
type Store interface {
	// Create inserts a draft in state draft at revision 1, or returns
	// ErrTooManyDrafts when maxOpen drafts are already open.
	Create(ctx context.Context, nd NewDraft, maxOpen int) (Draft, error)
	// Get returns the draft or ErrNotFound.
	Get(ctx context.Context, id string) (Draft, error)
	// List returns drafts newest first, without DocJSON, and the cursor of the
	// next page ("" = no more).
	List(ctx context.Context, f Filter, cursor string, limit int) ([]Draft, string, error)
	// Update creates revision n+1 of a draft or pending draft and voids the
	// approvals of earlier revisions.
	Update(ctx context.Context, id string, in UpdateInput, actorSub string) (Draft, error)
	// Rebase moves a needs_rebase draft to pending at revision n+1 on a new
	// base version.
	Rebase(ctx context.Context, id string, in UpdateInput, actorSub string) (Draft, error)
	// Submit moves a draft to pending.
	Submit(ctx context.Context, id string, revision int, actorSub string) (Draft, error)
	// RecordDecision appends a change_approvals row for the current revision of
	// a pending draft. A reject also moves the draft to rejected. It returns
	// the draft and the number of distinct approve decisions the current
	// revision now has. The same approver twice returns ErrDuplicateDecision.
	RecordDecision(ctx context.Context, id string, in DecisionInput) (Draft, int, error)
	// BeginApply claims a pending draft for publishing (pending -> applying).
	// Exactly one caller wins; withdraw, update, reject and expiry are illegal
	// from applying.
	BeginApply(ctx context.Context, id string, revision int, actorSub string) (Draft, error)
	// MarkApplied moves an applying draft to applied at policy version version.
	MarkApplied(ctx context.Context, id string, revision int, version int64, actorSub string) (Draft, error)
	// MarkNeedsRebase moves an applying draft to needs_rebase with lastError.
	MarkNeedsRebase(ctx context.Context, id string, revision int, lastError, actorSub string) (Draft, error)
	// FailApply returns an applying draft to pending with lastError (the
	// publish was refused, or startup found no version for an interrupted one).
	FailApply(ctx context.Context, id string, revision int, lastError, actorSub string) (Draft, error)
	// Applying returns the drafts left in state applying, for startup reconcile.
	Applying(ctx context.Context) ([]Draft, error)
	// Withdraw moves an open draft to withdrawn.
	Withdraw(ctx context.Context, id string, revision int, actorSub string) (Draft, error)
	// ExpireDue moves every open draft whose expires_at is not after now to
	// expired and returns them.
	ExpireDue(ctx context.Context, now time.Time) ([]Draft, error)
	// Approvals returns a draft's approval rows, oldest first.
	Approvals(ctx context.Context, id string) ([]Approval, error)
	// ApprovalCounts returns, for each draft, how many distinct approvers its
	// current revision and doc have (one query, whatever len(ds)).
	ApprovalCounts(ctx context.Context, ds []Draft) (map[string]int, error)
}

// Applier publishes a draft's doc to its target. The policy Applier lives in
// internal/controlplane over the versioned publish path with
// expectedHead=base_version, so a draft can never skip validation, credential
// redaction or the policy audit row. It returns ErrRebaseRequired (possibly
// wrapped) when the target moved since the draft's base version, and the
// validation error otherwise; it must create at most one version.
type Applier interface {
	Apply(ctx context.Context, d Draft) (version int64, err error)
}
