package controlplane

// approvals_blocklist.go holds block-list removals for approval (W-P2-APPR-08).
// Adding a block narrows access, so it stays the immediate kill switch;
// removing one widens it without touching the policy doc, so with
// console.approvals.enabled a removal is a pending `blocked_users` draft that a
// second admin approves. The draft's doc is the entry without its reason text;
// its target_ref is the entry id. The Applier re-reads the list and refuses a
// draft whose entry is gone or changed (ErrRebaseRequired), and removes the
// entry through BlockStore.Remove with the approver as the actor.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/dashboard"
)

// blockDraftDoc is the doc of a blocked_users draft: the entry without its
// reason (free text an operator wrote), creator or time.
type blockDraftDoc struct {
	ID    string `json:"id"`
	Sub   string `json:"sub,omitempty"`
	Email string `json:"email,omitempty"`
}

func blockDraftOf(e BlockEntry) blockDraftDoc {
	return blockDraftDoc{ID: e.ID, Sub: e.Sub, Email: e.Email}
}

func (d blockDraftDoc) json() json.RawMessage {
	b, _ := json.Marshal(d) // a struct of strings cannot fail to marshal
	return b
}

func decodeBlockDraft(raw json.RawMessage) (blockDraftDoc, error) {
	var d blockDraftDoc
	if err := json.Unmarshal(raw, &d); err != nil || d.ID == "" {
		return blockDraftDoc{}, fmt.Errorf("controlplane: block draft doc is not a block entry")
	}
	return d, nil
}

// blockTarget is the Classifier and Applier of the blocked_users target.
type blockTarget struct{ s *Server }

var (
	_ approvals.Classifier       = blockTarget{}
	_ approvals.Applier          = blockTarget{}
	_ approvals.EmergencyApplier = blockTarget{}
	_ targetAdapter              = blockTarget{}
)

// Classify: a removal always widens (it lifts a block), and needs an admin.
func (blockTarget) Classify(_ context.Context, ref string, doc json.RawMessage) (approvals.Classification, error) {
	d, err := decodeBlockDraft(doc)
	if err != nil {
		return approvals.Classification{}, err
	}
	if d.ID != ref {
		return approvals.Classification{}, errors.New("controlplane: block draft doc names another entry")
	}
	return approvals.TargetClassification([]approvals.Reason{{
		Code: approvals.CodeBlockRemoved, Path: "blocked_users:" + ref, Detail: "block list entry " + ref + " removed",
	}}), nil
}

func (b blockTarget) Apply(ctx context.Context, d approvals.Draft) (int64, error) {
	return b.apply(ctx, d, blockActor(ctx), false)
}

func (b blockTarget) ApplyEmergency(ctx context.Context, d approvals.Draft, _ approvals.Clearance, actor approvals.Author) (int64, error) {
	return b.apply(ctx, d, actor.Sub, true)
}

// apply removes the entry the draft names. The block list has no versions, so
// the draft applies at version 0.
func (b blockTarget) apply(ctx context.Context, d approvals.Draft, actor string, committed bool) (int64, error) {
	if d.Target != approvals.TargetBlockedUsers {
		return 0, fmt.Errorf("%w: %s", approvals.ErrUnsupportedTarget, d.Target)
	}
	// The Gate vouches that d is the applying, classified revision it claims.
	if _, err := b.s.gate.ClearApplied(ctx, d); err != nil {
		return 0, err
	}
	doc, err := decodeBlockDraft(d.DocJSON)
	if err != nil {
		return 0, err
	}
	entry, ok, err := b.entry(ctx, d.TargetRef)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("%w: block entry %s is already gone", approvals.ErrRebaseRequired, d.TargetRef)
	}
	if entry.Sub != doc.Sub || entry.Email != doc.Email {
		return 0, fmt.Errorf("%w: block entry %s changed since the draft", approvals.ErrRebaseRequired, d.TargetRef)
	}
	// The blocked person never approves their own unblocking.
	if isSelf(ctx, entry) {
		return 0, &dashboard.ChangeError{Status: http.StatusForbidden, Code: "self_unblock_forbidden", Err: dashboard.ErrBlockSelfUnblock}
	}
	before := b.s.targetHashNow(ctx, blockedUsersTarget)
	if err := b.s.blocks.Remove(ctx, d.TargetRef, actor); err != nil {
		if errors.Is(err, ErrNotFound) {
			return 0, fmt.Errorf("%w: block entry %s is already gone", approvals.ErrRebaseRequired, d.TargetRef)
		}
		return 0, err
	}
	addAuditFollowUp(ctx, auditFollowUp{
		Action: actionBlockedUsersRemove, Target: blockedUsersTarget, TargetRef: "block:" + d.TargetRef,
		Details: map[string]string{
			adminaudit.DetailOp: "remove", adminaudit.DetailSource: SourceApproval,
			adminaudit.DetailHasSub: boolStr(entry.Sub != ""), adminaudit.DetailHasEmail: boolStr(entry.Email != ""),
		},
		BeforeHash: before, AfterHash: b.s.targetHashNow(ctx, blockedUsersTarget), Committed: committed,
	})
	return 0, nil
}

func (b blockTarget) entry(ctx context.Context, id string) (BlockEntry, bool, error) {
	entries, err := b.s.blocks.List(ctx)
	if err != nil {
		return BlockEntry{}, false, err
	}
	for _, e := range entries {
		if e.ID == id {
			return e, true, nil
		}
	}
	return BlockEntry{}, false, nil
}

func (blockTarget) View(d approvals.Draft) (any, error) {
	doc, err := decodeBlockDraft(d.DocJSON)
	return doc, err
}

func (b blockTarget) Current(ctx context.Context, d approvals.Draft) (any, error) {
	e, ok, err := b.entry(ctx, d.TargetRef)
	if err != nil || !ok {
		return nil, err
	}
	return blockDraftOf(e), nil
}

// holdRemoval answers a block-list removal while approvals are enabled: it
// holds the removal as a draft (a *dashboard.HeldForApproval, answered 202), or
// returns nil when the removal may go ahead at once. An enabled gate with no
// approvals Service refuses (503 approvals_unavailable), never removes.
func (a blockListAPI) holdRemoval(ctx context.Context, e BlockEntry) error {
	s := a.srv
	if s == nil || !s.gate.Enabled() {
		return nil
	}
	author, err := s.writeAuthor(ctx)
	if err != nil {
		return err
	}
	ch := approvals.Change{
		Target: approvals.TargetBlockedUsers, TargetRef: e.ID, TargetDoc: blockDraftOf(e).json(),
		Author: s.draftAuthor(ctx, author), Source: approvals.SourceConsole, Message: "remove block list entry " + e.ID,
	}
	_, err = s.gate.Clear(ctx, ch)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, approvals.ErrApprovalRequired):
		return s.hold(ctx, ch)
	}
	return s.gateError(err)
}
