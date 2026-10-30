package keys

import (
	"context"
	"fmt"
)

// ResetResult is what a reset did.
type ResetResult struct {
	// Removed is how many rows the purpose had; they are all gone. It is set
	// even on an error that struck after the delete committed (a material
	// delete or the regeneration failed), so callers can tell a reset that
	// partially applied from one that changed nothing.
	Removed int
	// ActiveKID is the fresh active key's kid, set for token and bundle (the
	// ca purpose only clears: its key is imported, never generated).
	ActiveKID string
}

// Reset replaces purpose's keys: every row and every piece of private key
// material is deleted, and token and bundle get a fresh active and next key at
// once. It is `warden control-plane keys reset` (W-P2-KEYS-05), the recovery
// for a restore that brought signing_keys rows back without their material
// (the key directory is never part of a backup set). The caller must hold the
// state dir's instance lock and no other manager may be running on the same
// dir: a control plane that kept running would sign with the old keys until
// its next poll and could re-create what the reset removed. The ca purpose is
// only cleared — import a replacement with Manager.ImportKey.
func (m *Manager) Reset(ctx context.Context, purpose string, actor Actor) (ResetResult, error) {
	if !ValidPurpose(purpose) {
		return ResetResult{}, fmt.Errorf("%w: %q", ErrInvalidPurpose, purpose)
	}
	if actor == (Actor{}) {
		actor = SystemActor
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.cfg.Meta.List(ctx)
	if err != nil {
		return ResetResult{}, fmt.Errorf("keys: list signing keys: %w", err)
	}
	var kids []string
	for _, r := range all {
		if r.Purpose == purpose {
			kids = append(kids, r.KID)
		}
	}
	removed, err := m.cfg.Meta.DeletePurpose(ctx, purpose)
	if err != nil {
		return ResetResult{}, fmt.Errorf("keys: reset %s: %w", purpose, err)
	}
	// The rows are gone, so the material must not outlive them: a private key
	// on disk with no row is exactly what the startup sweep exists for, but
	// the caller hears about a delete that failed instead of leaving it
	// silent. The deletes run before anything is regenerated, so a purpose is
	// never reset only in part.
	var firstErr error
	for _, kid := range kids {
		if err := m.cfg.Store.Delete(ctx, purpose, kid); err != nil && firstErr == nil {
			firstErr = storeErr("reset", purpose, kid, err)
		}
	}
	if firstErr != nil {
		return ResetResult{Removed: removed}, firstErr
	}
	if purpose != PurposeToken && purpose != PurposeBundle {
		return ResetResult{Removed: removed}, nil
	}
	if err := m.createInitial(ctx, purpose, actor); err != nil {
		return ResetResult{Removed: removed}, fmt.Errorf("keys: reset %s: %w", purpose, err)
	}
	rows, err := m.rows(ctx, purpose)
	if err != nil {
		return ResetResult{Removed: removed}, err
	}
	active, _ := activeRow(rows)
	return ResetResult{Removed: removed, ActiveKID: active.KID}, nil
}
