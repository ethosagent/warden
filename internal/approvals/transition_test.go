package approvals_test

import (
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/approvals"
)

var allEvents = []approvals.Event{
	approvals.EventSubmit, approvals.EventUpdate, approvals.EventApprove, approvals.EventBeginApply, approvals.EventApply, approvals.EventApplyFailed, approvals.EventReject,
	approvals.EventConflict, approvals.EventRebase, approvals.EventWithdraw, approvals.EventExpire,
	approvals.EventEmergencyBegin, approvals.EventEmergencyApply, approvals.EventReview,
}

// TestDraftTransitions pins the whole table: every (state, event) pair is
// either the listed target or ErrIllegalTransition.
func TestDraftTransitions(t *testing.T) {
	type k struct {
		from approvals.State
		ev   approvals.Event
	}
	legal := map[k]approvals.State{
		{approvals.StateDraft, approvals.EventSubmit}:   approvals.StatePending,
		{approvals.StateDraft, approvals.EventUpdate}:   approvals.StateDraft,
		{approvals.StateDraft, approvals.EventWithdraw}: approvals.StateWithdrawn,
		{approvals.StateDraft, approvals.EventExpire}:   approvals.StateExpired,

		{approvals.StatePending, approvals.EventUpdate}:         approvals.StatePending,
		{approvals.StatePending, approvals.EventApprove}:        approvals.StatePending,
		{approvals.StatePending, approvals.EventBeginApply}:     approvals.StateApplying,
		{approvals.StatePending, approvals.EventReject}:         approvals.StateRejected,
		{approvals.StatePending, approvals.EventWithdraw}:       approvals.StateWithdrawn,
		{approvals.StatePending, approvals.EventExpire}:         approvals.StateExpired,
		{approvals.StatePending, approvals.EventEmergencyBegin}: approvals.StateApplying,

		{approvals.StateApplying, approvals.EventApply}:          approvals.StateApplied,
		{approvals.StateApplying, approvals.EventApplyFailed}:    approvals.StatePending,
		{approvals.StateApplying, approvals.EventConflict}:       approvals.StateNeedsRebase,
		{approvals.StateApplying, approvals.EventEmergencyApply}: approvals.StateAppliedUnreviewed,

		{approvals.StateNeedsRebase, approvals.EventRebase}:         approvals.StatePending,
		{approvals.StateNeedsRebase, approvals.EventWithdraw}:       approvals.StateWithdrawn,
		{approvals.StateNeedsRebase, approvals.EventExpire}:         approvals.StateExpired,
		{approvals.StateNeedsRebase, approvals.EventEmergencyBegin}: approvals.StateApplying,

		{approvals.StateAppliedUnreviewed, approvals.EventReview}: approvals.StateApplied,
	}
	for _, from := range approvals.States() {
		for _, ev := range allEvents {
			got, err := approvals.Transition(from, ev)
			want, ok := legal[k{from, ev}]
			switch {
			case ok && (err != nil || got != want):
				t.Errorf("Transition(%s, %s) = %s, %v; want %s", from, ev, got, err, want)
			case !ok && !errors.Is(err, approvals.ErrIllegalTransition):
				t.Errorf("Transition(%s, %s) = %s, %v; want ErrIllegalTransition", from, ev, got, err)
			case !ok && got != from:
				t.Errorf("illegal Transition(%s, %s) returned state %s, want the unchanged %s", from, ev, got, from)
			}
		}
	}
}

func TestDraftTransitionsTerminalAndOpen(t *testing.T) {
	for _, s := range []approvals.State{approvals.StateApplied, approvals.StateRejected, approvals.StateWithdrawn, approvals.StateExpired} {
		if !s.Terminal() || s.Open() {
			t.Errorf("%s: Terminal=%v Open=%v, want terminal and not open", s, s.Terminal(), s.Open())
		}
	}
	for _, s := range []approvals.State{approvals.StateDraft, approvals.StatePending, approvals.StateNeedsRebase} {
		if s.Terminal() || !s.Open() {
			t.Errorf("%s: Terminal=%v Open=%v, want open", s, s.Terminal(), s.Open())
		}
	}
	if approvals.StateApplying.Terminal() || approvals.StateApplying.Open() {
		t.Error("applying is neither terminal nor open: only the publish outcome leaves it")
	}
	if approvals.StateAppliedUnreviewed.Terminal() || approvals.StateAppliedUnreviewed.Open() {
		t.Error("applied_unreviewed is neither terminal nor open (it awaits review but holds no draft slot)")
	}
	for _, ev := range allEvents {
		if want := ev == approvals.EventUpdate || ev == approvals.EventRebase; approvals.BumpsRevision(ev) != want {
			t.Errorf("BumpsRevision(%s) = %v, want %v", ev, !want, want)
		}
	}
}

func TestDraftValidEnums(t *testing.T) {
	for _, tg := range []approvals.Target{approvals.TargetPolicy, approvals.TargetBlockedUsers, approvals.TargetAgents} {
		if !tg.Valid() {
			t.Errorf("target %s invalid", tg)
		}
	}
	if approvals.Target("x").Valid() || approvals.Source("x").Valid() || approvals.Decision("x").Valid() {
		t.Error("unknown enum values must be invalid")
	}
	for _, s := range []approvals.Source{approvals.SourceConsole, approvals.SourceRollback, approvals.SourceCLI, approvals.SourceAPI, approvals.SourceGit, approvals.SourceAdminMCP} {
		if !s.Valid() {
			t.Errorf("source %s invalid", s)
		}
	}
	for _, d := range []approvals.Decision{approvals.DecisionApprove, approvals.DecisionReject, approvals.DecisionSelf, approvals.DecisionEmergency, approvals.DecisionPostReview} {
		if !d.Valid() {
			t.Errorf("decision %s invalid", d)
		}
	}
}

func TestDraftRequireClassified(t *testing.T) {
	d := approvals.Draft{ID: "cd_x", Revision: 2}
	if err := approvals.RequireClassified(d); !errors.Is(err, approvals.ErrUnclassified) {
		t.Errorf("unclassified draft = %v, want ErrUnclassified", err)
	}
	d.RequiredRole = "editor"
	if err := approvals.RequireClassified(d); !errors.Is(err, approvals.ErrUnclassified) {
		t.Errorf("role without classification = %v, want ErrUnclassified", err)
	}
	d.Classification = []byte(`{"widening":false}`)
	if err := approvals.RequireClassified(d); err != nil {
		t.Errorf("classified draft = %v", err)
	}
	d.RequiredRole = ""
	if err := approvals.RequireClassified(d); !errors.Is(err, approvals.ErrUnclassified) {
		t.Errorf("empty role = %v, want ErrUnclassified (not editor)", err)
	}
}
