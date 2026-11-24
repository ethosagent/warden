package approvals

import "fmt"

// State is a draft's lifecycle state.
type State string

const (
	// StateDraft: being written by its author; no one is asked to review it.
	StateDraft State = "draft"
	// StatePending: submitted, waiting for approvals.
	StatePending State = "pending"
	// StateApplying: claimed by an Apply that is publishing it. Only the
	// publish outcome (or startup reconcile) leaves it: withdraw, update, reject
	// and expiry are illegal here, so an Apply cannot race them.
	StateApplying State = "applying"
	// StateApplied: published as a policy version. Terminal.
	StateApplied State = "applied"
	// StateRejected: a reviewer refused it. Terminal.
	StateRejected State = "rejected"
	// StateNeedsRebase: the target moved after the draft was based on it.
	StateNeedsRebase State = "needs_rebase"
	// StateWithdrawn: its author took it back. Terminal.
	StateWithdrawn State = "withdrawn"
	// StateExpired: the sweeper retired it after draftTTL. Terminal.
	StateExpired State = "expired"
	// StateAppliedUnreviewed: published by an emergency apply, awaiting the
	// post-hoc review (W-P2-APPR-07).
	StateAppliedUnreviewed State = "applied_unreviewed"
)

// States lists every state, in lifecycle order.
func States() []State {
	return []State{StateDraft, StatePending, StateApplying, StateApplied, StateRejected, StateNeedsRebase, StateWithdrawn, StateExpired, StateAppliedUnreviewed}
}

// Open reports whether the state counts against maxOpenDrafts and is swept by
// the expiry sweeper.
func (s State) Open() bool {
	return s == StateDraft || s == StatePending || s == StateNeedsRebase
}

// Terminal reports whether no transition leaves the state.
func (s State) Terminal() bool {
	_, ok := transitions[s]
	return !ok
}

// Event is what moves a draft between states.
type Event string

const (
	// EventSubmit: draft -> pending.
	EventSubmit Event = "submit"
	// EventUpdate: an edit in draft or pending; same state, revision n+1,
	// earlier approvals void.
	EventUpdate Event = "update"
	// EventApprove: an approval or self-approval recorded on a pending draft.
	// The state does not change, but the write races withdraw, reject and
	// expiry through the same compare-and-swap.
	EventApprove Event = "approve"
	// EventBeginApply: pending -> applying (claims the draft before publishing).
	EventBeginApply Event = "begin_apply"
	// EventApply: applying -> applied (the publish succeeded).
	EventApply Event = "apply"
	// EventApplyFailed: applying -> pending (the publish was refused, for
	// example by validation; last_error says why).
	EventApplyFailed Event = "apply_failed"
	// EventReject: pending -> rejected.
	EventReject Event = "reject"
	// EventConflict: applying -> needs_rebase (the publish found a moved head).
	EventConflict Event = "conflict"
	// EventRebase: needs_rebase -> pending at revision n+1.
	EventRebase Event = "rebase"
	// EventWithdraw: open -> withdrawn (author).
	EventWithdraw Event = "withdraw"
	// EventExpire: open -> expired (sweeper).
	EventExpire Event = "expire"
	// EventEmergencyApply: pending | needs_rebase -> applied_unreviewed.
	EventEmergencyApply Event = "emergency_apply"
	// EventReview: applied_unreviewed -> applied (post-hoc review).
	EventReview Event = "review"
)

// transitions is the whole state machine. A state with no entry is terminal.
var transitions = map[State]map[Event]State{
	StateDraft: {
		EventSubmit:   StatePending,
		EventUpdate:   StateDraft,
		EventWithdraw: StateWithdrawn,
		EventExpire:   StateExpired,
	},
	StatePending: {
		EventUpdate:         StatePending,
		EventApprove:        StatePending,
		EventBeginApply:     StateApplying,
		EventReject:         StateRejected,
		EventWithdraw:       StateWithdrawn,
		EventExpire:         StateExpired,
		EventEmergencyApply: StateAppliedUnreviewed,
	},
	StateApplying: {
		EventApply:       StateApplied,
		EventApplyFailed: StatePending,
		EventConflict:    StateNeedsRebase,
	},
	StateNeedsRebase: {
		EventRebase:         StatePending,
		EventWithdraw:       StateWithdrawn,
		EventExpire:         StateExpired,
		EventEmergencyApply: StateAppliedUnreviewed,
	},
	StateAppliedUnreviewed: {
		EventReview: StateApplied,
	},
}

// bumpsRevision are the events that create revision n+1.
var bumpsRevision = map[Event]bool{EventUpdate: true, EventRebase: true}

// BumpsRevision reports whether ev creates a new revision (and so voids the
// approvals of earlier ones).
func BumpsRevision(ev Event) bool { return bumpsRevision[ev] }

// Transition is the pure state machine: the state ev leads to from `from`, or
// ErrIllegalTransition (wrapped with both names) when the table has none.
func Transition(from State, ev Event) (State, error) {
	if to, ok := transitions[from][ev]; ok {
		return to, nil
	}
	return from, fmt.Errorf("%w: %s from %s", ErrIllegalTransition, ev, from)
}
