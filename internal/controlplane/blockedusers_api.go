package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The block list admin API's control-plane half (W-P1-BLOCK-11): the adapter
// from BlockStore to dashboard.BlockListStore. It owns what needs the caller's
// identity: created_by, the self-unblock check and the audit annotation. The
// reason text goes only into the store; it is never logged, annotated or
// hashed.

// blockedUsersTarget is the admin audit target (and state hasher name) of the
// block list.
const blockedUsersTarget = "blocked_users"

// blockedUsersCreatedByBearer is created_by for a write authorized by the CP
// admin bearer in console.auth none (the same actor the audit row records).
const blockedUsersCreatedByBearer = actorCPAdminToken

// blockListAPI adapts a BlockStore to the dashboard's BlockListStore.
type blockListAPI struct {
	store *BlockStore
}

var _ dashboard.BlockListStore = blockListAPI{}

// blockActor is the created_by string for the caller in ctx: oidc:<sub> for a
// session, breakglass:<user> for break-glass, cp-admin-token for the bearer.
func blockActor(ctx context.Context) string {
	p, ok := PrincipalFrom(ctx)
	if !ok {
		return blockedUsersCreatedByBearer
	}
	if p.Kind == PrincipalBreakglass {
		return breakglassSubPrefix + strings.TrimPrefix(p.Sub, breakglassSubPrefix)
	}
	return "oidc:" + p.Sub
}

// isSelf reports whether entry blocks the caller in ctx: its sub equals the
// Principal's sub, or its email equals the Principal's email, ignoring case. A
// caller with no Principal (the admin bearer) has no self.
func isSelf(ctx context.Context, e BlockEntry) bool {
	p, ok := PrincipalFrom(ctx)
	if !ok {
		return false
	}
	if p.Sub != "" && e.Sub != "" && (e.Sub == p.Sub || e.Sub == strings.TrimPrefix(p.Sub, breakglassSubPrefix)) {
		return true
	}
	return p.Email != "" && e.Email != "" && strings.EqualFold(e.Email, strings.TrimSpace(p.Email))
}

func toBlockView(e BlockEntry) dashboard.BlockListEntry {
	return dashboard.BlockListEntry{
		ID: e.ID, Sub: e.Sub, Email: e.Email, Reason: e.Reason, CreatedBy: e.CreatedBy,
		CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// annotateBlock attaches the entry reference and which identifiers it holds. It
// never carries a sub, an email or a reason.
func annotateBlock(ctx context.Context, op, id string, e BlockEntry) {
	adminaudit.Annotate(ctx, "block:"+id, map[string]string{
		adminaudit.DetailOp:       op,
		adminaudit.DetailHasSub:   boolStr(e.Sub != ""),
		adminaudit.DetailHasEmail: boolStr(e.Email != ""),
	})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func (a blockListAPI) List(ctx context.Context) ([]dashboard.BlockListEntry, error) {
	entries, err := a.store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]dashboard.BlockListEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, toBlockView(e))
	}
	return out, nil
}

func (a blockListAPI) Add(ctx context.Context, in dashboard.BlockListAdd) (dashboard.BlockListEntry, error) {
	actor := blockActor(ctx)
	id, err := a.store.Add(ctx, BlockEntry{Sub: in.Sub, Email: in.Email, Reason: in.Reason}, actor)
	if err != nil {
		return dashboard.BlockListEntry{}, mapBlockErr(err)
	}
	stored := BlockEntry{ID: id, Sub: strings.TrimSpace(in.Sub), Email: strings.ToLower(strings.TrimSpace(in.Email)), Reason: in.Reason, CreatedBy: actor}
	if entries, lerr := a.store.List(ctx); lerr == nil {
		for _, e := range entries {
			if e.ID == id {
				stored = e
				break
			}
		}
	}
	annotateBlock(ctx, "add", id, stored)
	return toBlockView(stored), nil
}

func (a blockListAPI) Remove(ctx context.Context, id string) error {
	entries, err := a.store.List(ctx)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.ID != id {
			continue
		}
		annotateBlock(ctx, "remove", id, e)
		if isSelf(ctx, e) {
			return dashboard.ErrBlockSelfUnblock
		}
		return mapBlockErr(a.store.Remove(ctx, id, blockActor(ctx)))
	}
	return dashboard.ErrBlockNotFound
}

// mapBlockErr maps a BlockStore error to the dashboard's. Other errors pass
// through (the handler answers a fixed 500).
func mapBlockErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrDuplicate):
		return dashboard.ErrBlockDuplicate
	case errors.Is(err, ErrTooMany):
		return dashboard.ErrBlockTooMany
	case errors.Is(err, ErrNotFound):
		return dashboard.ErrBlockNotFound
	case errors.Is(err, ErrInvalid):
		return fmt.Errorf("%w: %s", dashboard.ErrBlockInvalid, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
	default:
		return err
	}
}

// blockListNoState answers every call with state_dir_required: a control plane
// without --state-dir has no store for the list.
type blockListNoState struct{}

var _ dashboard.BlockListStore = blockListNoState{}

func (blockListNoState) List(context.Context) ([]dashboard.BlockListEntry, error) {
	return nil, dashboard.ErrBlockStateRequired
}

func (blockListNoState) Add(context.Context, dashboard.BlockListAdd) (dashboard.BlockListEntry, error) {
	return dashboard.BlockListEntry{}, dashboard.ErrBlockStateRequired
}

func (blockListNoState) Remove(context.Context, string) error {
	return dashboard.ErrBlockStateRequired
}

// blockListStore is the seam the control plane hands the dashboard.
func (s *Server) blockListStore() dashboard.BlockListStore {
	if s.blocks == nil {
		return blockListNoState{}
	}
	return blockListAPI{store: s.blocks}
}

// blockedUsersHash is the keyed hash of the block list's canonical sub/email
// pairs (sorted); reasons, ids and creators are not hashed.
func (s *Server) blockedUsersHash(ctx context.Context) (string, error) {
	if s.blocks == nil {
		return "", nil
	}
	list, err := s.blocks.Wire(ctx)
	if err != nil {
		return "", err
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Sub != list[j].Sub {
			return list[i].Sub < list[j].Sub
		}
		return list[i].Email < list[j].Email
	})
	if list == nil {
		list = []config.BlockedUser{}
	}
	return s.stateHashJSON(blockedUsersTarget, list)
}
