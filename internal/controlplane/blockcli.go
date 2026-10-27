package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// Admin audit vocabulary of the block list's writes. The same action names are
// used by the admin API (W-P1-BLOCK-11), so a chain reads the same whichever
// path wrote the entry.
const (
	actionBlockedUsersAdd    = "blocked_users.add"
	actionBlockedUsersRemove = "blocked_users.remove"
	auditTargetBlockedUsers  = "blocked_users"
)

// The offline block-list commands (`warden control-plane block add|remove|list`).
// cmd/proxy only parses flags and maps errors to exit codes (rule C1); the
// logic is here. Writes go through BlockStore, so validation, lowercasing and
// the count and size limits are the admin API's. A running control plane picks
// the change up from BlockStore.Watch.

// RunBlockAdd stores entry as actor adminaudit.CLIActor() in the state dir and
// appends one blocked_users.add admin audit row, returning the new id. The
// audit recorder is opened first, so a missing or mismatching key aborts before
// anything is written. Should the audit append still fail, the new entry is
// removed again: a block is never left without its audit row. notice receives
// the one-line "audit not enabled" message.
func RunBlockAdd(ctx context.Context, stateDir, keyFile string, entry BlockEntry, notice io.Writer) (string, error) {
	rec, st, closeAll, err := openBlockCLI(ctx, stateDir, keyFile, notice)
	if err != nil {
		return "", err
	}
	defer closeAll()
	actor := adminaudit.CLIActor()
	id, err := st.Add(ctx, entry, actor)
	if err != nil {
		return "", err
	}
	if rec == nil {
		return id, nil
	}
	if err := recordBlockAudit(ctx, rec, actionBlockedUsersAdd, id); err != nil {
		// Roll the block back (the entry has been visible for a moment at most).
		// context.WithoutCancel: an interrupt must not leave it in place.
		if rmErr := st.Remove(context.WithoutCancel(ctx), id, actor); rmErr != nil {
			return "", fmt.Errorf("block %s was stored but its admin audit row was not appended (%v) and it could not be rolled back: %w", id, err, rmErr)
		}
		return "", fmt.Errorf("admin audit: %w; nothing was blocked", err)
	}
	return id, nil
}

// RunBlockRemove deletes the entry id and appends one blocked_users.remove
// admin audit row. An unknown id returns ErrNotFound and appends nothing. The
// audit row is appended before the delete, so a failed append deletes nothing.
func RunBlockRemove(ctx context.Context, stateDir, keyFile, id string, notice io.Writer) error {
	if _, err := os.Stat(filepath.Join(stateDir, adminaudit.StateDBFileName)); err != nil {
		return fmt.Errorf("blocklist: no control-plane state db in %s: %w", stateDir, err)
	}
	rec, st, closeAll, err := openBlockCLI(ctx, stateDir, keyFile, notice)
	if err != nil {
		return err
	}
	defer closeAll()
	entries, err := st.List(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, e := range entries {
		if e.ID == id {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	if rec != nil {
		if err := recordBlockAudit(ctx, rec, actionBlockedUsersRemove, id); err != nil {
			return fmt.Errorf("admin audit: %w; nothing was removed", err)
		}
	}
	return st.Remove(ctx, id, adminaudit.CLIActor())
}

// ListBlockedOffline returns the entries in the state dir, oldest first,
// opening the database read-only. A state dir whose database predates the block
// list has no entries.
func ListBlockedOffline(ctx context.Context, stateDir string) ([]BlockEntry, error) {
	db, err := cpstate.OpenReadOnly(ctx, filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	out, err := NewBlockStore(db, BlockStoreOptions{}).List(ctx)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return nil, nil
	}
	return out, err
}

// openBlockCLI opens the audit recorder (nil when audit was never enabled) and
// then the block store, both on the full StateMigrations list. A missing
// database is created.
func openBlockCLI(ctx context.Context, stateDir, keyFile string, notice io.Writer) (adminaudit.Recorder, *BlockStore, func(), error) {
	if stateDir == "" {
		return nil, nil, nil, errors.New("blocklist: --state-dir is required")
	}
	if fi, err := os.Stat(stateDir); err != nil || !fi.IsDir() {
		return nil, nil, nil, fmt.Errorf("blocklist: --state-dir %s is not a directory", stateDir)
	}
	rec, closeAudit, err := adminaudit.OpenForCLI(ctx, stateDir, keyFile, StateMigrations())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin audit: %w", err)
	}
	db, err := cpstate.Open(ctx, filepath.Join(stateDir, adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		if closeAudit != nil {
			_ = closeAudit()
		}
		return nil, nil, nil, err
	}
	if rec == nil && notice != nil {
		_, _ = fmt.Fprintln(notice, "admin audit is not enabled in "+stateDir+"; no audit row appended")
	}
	closeAll := func() {
		_ = db.Close()
		if closeAudit != nil {
			_ = closeAudit()
		}
	}
	return rec, NewBlockStore(db, BlockStoreOptions{}), closeAll, nil
}

// recordBlockAudit appends the admin audit row of one block-list write. The
// reason text is not recorded.
func recordBlockAudit(ctx context.Context, rec adminaudit.Recorder, action, id string) error {
	_, err := rec.Record(ctx, adminaudit.Input{
		Action:    action,
		Target:    auditTargetBlockedUsers,
		TargetRef: "block:" + id,
		Outcome:   adminaudit.OutcomeOK,
	})
	return err
}
