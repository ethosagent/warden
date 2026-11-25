package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
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
//
// With approvals enabled on the state dir (W-P2-APPR-08) it removes nothing: a
// removal widens access, so it creates a pending blocked_users draft authored
// cli:<os user> and returns its id (draftID non-empty) for a second admin to
// approve in the console. The entry stays blocked until then.
func RunBlockRemove(ctx context.Context, stateDir, keyFile, id string, notice io.Writer) (draftID string, err error) {
	if _, err := os.Stat(filepath.Join(stateDir, adminaudit.StateDBFileName)); err != nil {
		return "", fmt.Errorf("blocklist: no control-plane state db in %s: %w", stateDir, err)
	}
	rec, st, closeAll, err := openBlockCLI(ctx, stateDir, keyFile, notice)
	if err != nil {
		return "", err
	}
	defer closeAll()
	entries, err := st.List(ctx)
	if err != nil {
		return "", err
	}
	var entry *BlockEntry
	for i := range entries {
		if entries[i].ID == id {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		return "", ErrNotFound
	}
	meta, found, err := sqlstore.ReadMeta(ctx, st.db.SQL())
	if err != nil {
		return "", fmt.Errorf("block remove: cannot tell whether approvals are enabled: %w", err)
	}
	if found && meta.Enabled {
		return holdBlockRemoval(ctx, st, meta, *entry, rec)
	}
	if rec != nil {
		if err := recordBlockAudit(ctx, rec, actionBlockedUsersRemove, id); err != nil {
			return "", fmt.Errorf("admin audit: %w; nothing was removed", err)
		}
	}
	return "", st.Remove(ctx, id, adminaudit.CLIActor())
}

// offlineBlockApplier refuses every apply: the offline CLI only creates drafts,
// the running control plane applies them.
type offlineBlockApplier struct{}

func (offlineBlockApplier) Apply(context.Context, approvals.Draft) (int64, error) {
	return 0, errors.New("blocklist: the offline CLI never applies a draft")
}

// holdBlockRemoval stores the removal of entry as a pending draft and records
// its admin audit row. The entry is not touched.
func holdBlockRemoval(ctx context.Context, st *BlockStore, m sqlstore.Meta, entry BlockEntry, rec adminaudit.Recorder) (string, error) {
	svc, err := approvals.NewService(approvals.ServiceConfig{
		Store:         sqlstore.New(st.db.SQL(), time.Now, slog.New(slog.DiscardHandler)),
		Appliers:      map[approvals.Target]approvals.Applier{approvals.TargetBlockedUsers: offlineBlockApplier{}},
		Classifiers:   map[approvals.Target]approvals.Classifier{approvals.TargetBlockedUsers: blockTarget{}},
		Redact:        redactDraftDoc,
		Now:           time.Now,
		DraftTTL:      m.DraftTTL,
		MaxOpenDrafts: m.MaxOpenDrafts,
	})
	if err != nil {
		return "", err
	}
	author := approvals.Author{Sub: adminaudit.CLIActor(), Kind: AuthorKindCLI}
	created, err := svc.CreateTargetDraft(ctx, approvals.TargetDraft{
		Target: approvals.TargetBlockedUsers, Ref: entry.ID, Doc: blockDraftOf(entry).json(), Author: author,
		Prov: approvals.Provenance{Source: approvals.SourceCLI, Message: "remove block list entry " + entry.ID},
	})
	if err != nil {
		if errors.Is(err, approvals.ErrTooManyDrafts) {
			return "", fmt.Errorf("block remove: too many open change drafts (console.approvals.maxOpenDrafts is %d); resolve some first: %w", m.MaxOpenDrafts, err)
		}
		return "", err
	}
	draft, err := svc.Submit(ctx, created.ID, created.Revision, author.Sub)
	if err != nil {
		// Leave nothing half-made: withdraw the draft, as Gate.Hold does.
		if _, werr := svc.Store().Withdraw(ctx, created.ID, created.Revision, author.Sub); werr != nil {
			return "", fmt.Errorf("block remove: draft %s could not be submitted (%v) nor withdrawn: %w", created.ID, err, werr)
		}
		return "", fmt.Errorf("block remove: could not submit the draft (it was withdrawn): %w", err)
	}
	if rec == nil {
		return draft.ID, nil
	}
	if _, err := rec.Record(ctx, adminaudit.Input{
		Action:    actionBlockedUsersRemove,
		Target:    auditTargetChangeDraft,
		TargetRef: "draft:" + draft.ID + "@r" + fmt.Sprint(draft.Revision),
		Outcome:   adminaudit.OutcomeOK,
		Details:   map[string]string{adminaudit.DetailOp: "held"},
	}); err != nil {
		// Like the immediate path, nothing is left without its audit row.
		if _, werr := svc.Store().Withdraw(context.WithoutCancel(ctx), draft.ID, draft.Revision, author.Sub); werr != nil {
			return draft.ID, fmt.Errorf("admin audit: %w; draft %s could not be withdrawn: %v", err, draft.ID, werr)
		}
		return "", fmt.Errorf("admin audit: %w; the draft was withdrawn and nothing is pending", err)
	}
	return draft.ID, nil
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
	if !slices.Contains(db.Applied(), blockMigrationID) {
		return nil, nil
	}
	return NewBlockStore(db, BlockStoreOptions{}).List(ctx)
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
