package sqlstore

// meta.go is the approvals_meta single row (W-P2-APPR-06): the control plane
// writes it at every start, so an offline CLI (warden policy import) learns
// whether approvals are enabled, and with which draft limits, without reading
// the console config.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Meta is what the control plane last started with.
type Meta struct {
	Enabled       bool
	DraftTTL      time.Duration
	MaxOpenDrafts int
}

// metaExists reports whether the approvals_meta table exists: it does not on a
// state database that never ran with approvals enabled.
func metaExists(ctx context.Context, db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='approvals_meta'").Scan(&n)
	if err != nil {
		return false, fmt.Errorf("approvals: inspect approvals_meta: %w", err)
	}
	return n == 1, nil
}

// WriteMeta records m. A disabled m is written only when the table exists, so
// a control plane that never enabled approvals creates nothing.
func WriteMeta(ctx context.Context, db *sql.DB, m Meta, now time.Time) error {
	ok, err := metaExists(ctx, db)
	if err != nil {
		return err
	}
	if !ok {
		if !m.Enabled {
			return nil
		}
		return fmt.Errorf("approvals: approvals_meta is missing (migration %s not applied)", MetaMigrationID)
	}
	enabled := 0
	if m.Enabled {
		enabled = 1
	}
	_, err = db.ExecContext(ctx, `INSERT INTO approvals_meta (id, enabled, draft_ttl_ms, max_open_drafts, updated_at)
VALUES (1, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled, draft_ttl_ms = excluded.draft_ttl_ms,
  max_open_drafts = excluded.max_open_drafts, updated_at = excluded.updated_at`,
		enabled, m.DraftTTL.Milliseconds(), m.MaxOpenDrafts, now.UnixMilli())
	if err != nil {
		return fmt.Errorf("approvals: write approvals_meta: %w", err)
	}
	return nil
}

// ReadMeta returns the recorded Meta. found is false only when no control
// plane ever enabled approvals on this database (no table). It fails closed
// otherwise: a table with no row, or an enabled value other than 0 or 1, is an
// error, so the offline CLI refuses to import directly rather than guess.
func ReadMeta(ctx context.Context, db *sql.DB) (m Meta, found bool, err error) {
	ok, err := metaExists(ctx, db)
	if err != nil || !ok {
		return Meta{}, false, err
	}
	var enabled, ttlMS int64
	err = db.QueryRowContext(ctx, "SELECT enabled, draft_ttl_ms, max_open_drafts FROM approvals_meta WHERE id = 1").Scan(&enabled, &ttlMS, &m.MaxOpenDrafts)
	if errors.Is(err, sql.ErrNoRows) {
		return Meta{}, false, fmt.Errorf("approvals: approvals_meta exists but has no row; start the control plane once, or check the state database")
	}
	if err != nil {
		return Meta{}, false, fmt.Errorf("approvals: read approvals_meta: %w", err)
	}
	if enabled != 0 && enabled != 1 {
		return Meta{}, false, fmt.Errorf("approvals: approvals_meta.enabled is %d, want 0 or 1", enabled)
	}
	m.Enabled = enabled == 1
	m.DraftTTL = time.Duration(ttlMS) * time.Millisecond
	return m, true, nil
}
