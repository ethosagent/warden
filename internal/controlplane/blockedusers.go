package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
)

// The user block list lives in the control-plane state DB, outside policy
// versions, so a rollback or import can never unblock anyone. BlockStore is its
// only write path (the admin API, the offline CLI and P3 offboarding all call
// it); the blocked_users overlay merges it into the served wire.

// Errors BlockStore returns. The admin API (W-P1-BLOCK-11) maps them to
// 400, 409, 422 and 404.
var (
	ErrInvalid   = errors.New("blocklist: invalid entry")
	ErrDuplicate = errors.New("blocklist: entry already blocked")
	ErrTooMany   = errors.New("blocklist: block list is full")
	ErrNotFound  = errors.New("blocklist: entry not found")
)

// maxBlockReasonBytes caps an entry's free-text reason.
const maxBlockReasonBytes = 512

// blockedUsersOverlayName is the overlay name and the key of its fingerprint.
const blockedUsersOverlayName = "blocked_users"

// blockLoadFailedMsg is the log message and the Finding rule id of a failed
// block-list load.
const blockLoadFailedMsg = "blocklist_load_failed"

const blockMigration0001 = `
CREATE TABLE blocked_users (
    id         TEXT PRIMARY KEY,
    sub        TEXT,
    email      TEXT,
    reason     TEXT,
    created_by TEXT,
    created_at INTEGER,
    CHECK (sub IS NOT NULL OR email IS NOT NULL)
);
CREATE UNIQUE INDEX idx_blocked_users_sub ON blocked_users (sub);
CREATE UNIQUE INDEX idx_blocked_users_email ON blocked_users (email);
`

// BlockMigrations returns the cpstate migrations the block list needs, for a
// caller that opens the state DB itself. StateMigrations includes them.
func BlockMigrations() []cpstate.Migration {
	return []cpstate.Migration{{ID: "blocklist/0001", SQL: blockMigration0001}}
}

// BlockEntry is one stored block-list entry. Sub and Email are stored trimmed
// (email also lowercase); at least one is set.
type BlockEntry struct {
	ID        string
	Sub       string
	Email     string
	Reason    string
	CreatedBy string
	CreatedAt time.Time
}

// BlockStoreOptions configures NewBlockStore.
type BlockStoreOptions struct {
	// Clock stamps created_at; nil means the real clock.
	Clock clock.Clock
	// OnRefresh runs after every successful in-process mutation, before the
	// OnChange callbacks. The control plane sets it to the policy server's
	// Refresh so held long-polls wake at once. Nil for the offline CLI.
	OnRefresh func()
}

// BlockStore reads and writes the block list on the control-plane state DB. It
// needs no Server, so the offline CLI can build one.
type BlockStore struct {
	db        *cpstate.DB
	clock     clock.Clock
	onRefresh func()

	mu        sync.Mutex
	callbacks []func()
}

// NewBlockStore returns a store over db, which must have been opened with
// BlockMigrations (directly or through StateMigrations).
func NewBlockStore(db *cpstate.DB, opts BlockStoreOptions) *BlockStore {
	clk := opts.Clock
	if clk == nil {
		clk = clock.Real()
	}
	return &BlockStore{db: db, clock: clk, onRefresh: opts.OnRefresh}
}

// OnChange registers fn to run after every successful in-process mutation, after
// the policy refresh. A mutation made by another process does not run it.
func (b *BlockStore) OnChange(fn func()) {
	if fn == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.callbacks = append(b.callbacks, fn)
}

// changed runs the policy refresh and then the OnChange callbacks.
func (b *BlockStore) changed() {
	if b.onRefresh != nil {
		b.onRefresh()
	}
	b.mu.Lock()
	cbs := append([]func(){}, b.callbacks...)
	b.mu.Unlock()
	for _, fn := range cbs {
		fn()
	}
}

// List returns every entry, oldest first.
func (b *BlockStore) List(ctx context.Context) ([]BlockEntry, error) {
	rows, err := b.db.SQL().QueryContext(ctx,
		`SELECT id, sub, email, reason, created_by, created_at FROM blocked_users ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("blocklist: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []BlockEntry
	for rows.Next() {
		var e BlockEntry
		var sub, email, reason, by sql.NullString
		var at sql.NullInt64
		if err := rows.Scan(&e.ID, &sub, &email, &reason, &by, &at); err != nil {
			return nil, fmt.Errorf("blocklist: list: %w", err)
		}
		e.Sub, e.Email, e.Reason, e.CreatedBy = sub.String, email.String, reason.String, by.String
		e.CreatedAt = time.UnixMilli(at.Int64)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("blocklist: list: %w", err)
	}
	return out, nil
}

// Wire returns the list as it rides the policy wire: sub and email only,
// sorted by (sub, email), nil when empty.
func (b *BlockStore) Wire(ctx context.Context) ([]config.BlockedUser, error) {
	rows, err := b.db.SQL().QueryContext(ctx, `SELECT sub, email FROM blocked_users`)
	if err != nil {
		return nil, fmt.Errorf("blocklist: read: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanWire(rows)
}

func scanWire(rows *sql.Rows) ([]config.BlockedUser, error) {
	var out []config.BlockedUser
	for rows.Next() {
		var sub, email sql.NullString
		if err := rows.Scan(&sub, &email); err != nil {
			return nil, fmt.Errorf("blocklist: read: %w", err)
		}
		out = append(out, config.BlockedUser{Sub: sub.String, Email: email.String})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("blocklist: read: %w", err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sub != out[j].Sub {
			return out[i].Sub < out[j].Sub
		}
		return out[i].Email < out[j].Email
	})
	return out, nil
}

// Add stores entry (ID, CreatedBy and CreatedAt are ignored) and returns its id.
// actor is recorded as created_by (oidc:<sub>, cli:<user>, system:offboarding).
// The resulting list is checked with config.ValidateBlockedUsers, so the count
// and total-size limits apply. On success the policy is refreshed and the
// OnChange callbacks run.
func (b *BlockStore) Add(ctx context.Context, entry BlockEntry, actor string) (string, error) {
	sub := strings.TrimSpace(entry.Sub)
	email := strings.ToLower(strings.TrimSpace(entry.Email))
	if len(entry.Reason) > maxBlockReasonBytes {
		return "", fmt.Errorf("%w: reason exceeds %d bytes", ErrInvalid, maxBlockReasonBytes)
	}
	if strings.IndexFunc(entry.Reason, isControl) >= 0 {
		return "", fmt.Errorf("%w: reason has a control character", ErrInvalid)
	}
	if strings.TrimSpace(actor) == "" {
		return "", fmt.Errorf("%w: actor is required", ErrInvalid)
	}
	id, err := newBlockID()
	if err != nil {
		return "", err
	}
	if err := b.insert(ctx, id, sub, email, entry.Reason, actor); err != nil {
		return "", err
	}
	b.changed()
	return id, nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// insert runs Add's read-validate-write under one BEGIN IMMEDIATE transaction,
// so a concurrent writer (the CLI) cannot slip past the limits.
func (b *BlockStore) insert(ctx context.Context, id, sub, email, reason, actor string) error {
	conn, err := b.db.SQL().Conn(ctx)
	if err != nil {
		return fmt.Errorf("blocklist: connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("blocklist: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()

	rows, err := conn.QueryContext(ctx, `SELECT sub, email FROM blocked_users`)
	if err != nil {
		return fmt.Errorf("blocklist: read: %w", err)
	}
	list, err := scanWire(rows)
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, u := range list {
		if (sub != "" && u.Sub == sub) || (email != "" && u.Email == email) {
			return ErrDuplicate
		}
	}
	list = append(list, config.BlockedUser{Sub: sub, Email: email})
	sort.Slice(list, func(i, j int) bool {
		if list[i].Sub != list[j].Sub {
			return list[i].Sub < list[j].Sub
		}
		return list[i].Email < list[j].Email
	})
	if err := validateBlockList(list); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO blocked_users (id, sub, email, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, nullIfEmpty(sub), nullIfEmpty(email), reason, actor, b.clock.Now().UnixMilli()); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrDuplicate
		}
		return fmt.Errorf("blocklist: insert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("blocklist: commit: %w", err)
	}
	committed = true
	return nil
}

// validateBlockList maps config.ValidateBlockedUsers to the store's errors. The
// error text names an index or a size, never an entry value.
func validateBlockList(list []config.BlockedUser) error {
	if len(list) > config.MaxBlockedUsers {
		return fmt.Errorf("%w: %d entries exceeds the limit of %d", ErrTooMany, len(list), config.MaxBlockedUsers)
	}
	err := config.ValidateBlockedUsers(list)
	if err == nil {
		return nil
	}
	if enc, mErr := json.Marshal(list); mErr == nil && len(enc) > config.MaxBlockedUsersBytes {
		return fmt.Errorf("%w: total size %d bytes exceeds the limit of %d", ErrTooMany, len(enc), config.MaxBlockedUsersBytes)
	}
	return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
}

// Remove deletes the entry with id and returns ErrNotFound when there is none.
// actor is the caller's identity string; it is not stored (the admin audit
// records removals) but must be non-empty.
func (b *BlockStore) Remove(ctx context.Context, id, actor string) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", ErrInvalid)
	}
	res, err := b.db.SQL().ExecContext(ctx, `DELETE FROM blocked_users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("blocklist: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("blocklist: delete: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	b.changed()
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// newBlockID returns "bu_" plus 16 hex characters.
func newBlockID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("blocklist: id: %w", err)
	}
	return "bu_" + hex.EncodeToString(raw[:]), nil
}

// blockLoadReporter reports a failed block-list load once per episode: the
// first failure logs one ERROR line and publishes a high-severity Finding;
// repeats stay quiet until a load succeeds.
type blockLoadReporter struct {
	logger  *slog.Logger
	publish func(integration.Finding) // nil when there is no alert pipeline
	now     func() time.Time
	failing atomic.Bool
}

func (r *blockLoadReporter) failed() {
	if !r.failing.CompareAndSwap(false, true) {
		return
	}
	// No entry values and no error text: the log line is the signal when no
	// alert pipeline exists, and the Refresh warning carries the cause.
	r.logger.Error(blockLoadFailedMsg)
	if r.publish == nil {
		return
	}
	r.publish(integration.Finding{
		RuleID:   blockLoadFailedMsg,
		Category: "security",
		Severity: integration.SevHigh,
		Summary:  "The user block list could not be read; workers keep the last block list they were served",
		DedupKey: blockLoadFailedMsg,
		Ts:       r.now(),
	})
}

func (r *blockLoadReporter) ok() { r.failing.Store(false) }

// blockedUsersOverlay is the serve-time overlay that merges the stored block
// list into the wire. Because it is an overlay the list is never part of a
// policy version. A store error fails the load, so Refresh keeps the previous
// wire and ETag rather than serving an empty list.
func blockedUsersOverlay(store *BlockStore, rep *blockLoadReporter) wireOverlay {
	return wireOverlay{name: blockedUsersOverlayName, apply: func(ctx context.Context, w *policyWire) (string, error) {
		fp, err := withBlockedUsers(ctx, store, w)
		if err != nil {
			rep.failed()
			return "", err
		}
		rep.ok()
		return fp, nil
	}}
}

// withBlockedUsers sets w.BlockedUsers from the store and returns the list's
// fingerprint: the first 16 hex of the sha256 of the canonical list, empty when
// the list is empty.
func withBlockedUsers(ctx context.Context, store *BlockStore, w *policyWire) (string, error) {
	list, err := store.Wire(ctx)
	if err != nil {
		return "", err
	}
	if len(list) == 0 {
		w.BlockedUsers = nil
		return "", nil
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("blocklist: encode: %w", err)
	}
	w.BlockedUsers = list
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]), nil
}

// initBlockStore builds the block store and registers its overlay when the
// control plane has a state DB. It runs before the first Refresh. Without State
// it does nothing, so /policy is byte-identical to a build without the list.
func (s *Server) initBlockStore() {
	if s.cfg.State == nil {
		return
	}
	s.blocks = NewBlockStore(s.cfg.State, BlockStoreOptions{Clock: s.cfg.Clock, OnRefresh: s.policy.Refresh})
	rep := &blockLoadReporter{logger: s.cfg.Logger, now: s.cfg.Clock.Now, publish: s.publishFinding}
	if err := s.policy.addOverlay(blockedUsersOverlay(s.blocks, rep)); err != nil {
		// Unreachable: registration precedes the first Refresh and the name is
		// unique. Logged rather than ignored so a wiring change shows up.
		s.cfg.Logger.Error("control plane: blocked_users overlay not registered", "error", err)
	}
}

// publishFinding sends f to the alert pipeline's bus; a no-op without one. The
// pipeline is built after the first Refresh, so it is read per call.
func (s *Server) publishFinding(f integration.Finding) {
	if s.pipeline == nil {
		return
	}
	if m := s.pipeline.CurrentManager(); m != nil {
		m.Bus().PublishFinding(f)
	}
}
