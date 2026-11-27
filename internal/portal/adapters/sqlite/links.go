// Package sqlite is the SQLite implementation of portal.LinkRepo: the
// idp_links table on the control plane's cpstate database (W-P3-CSIG-03).
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/portal"
)

// MigrationID is the first idp_links migration; MigrationRefreshID adds the
// refresh job's columns (W-P3-OFFB-02).
const (
	MigrationID        = "idp_links/0001"
	MigrationRefreshID = "idp_links/0002"
)

// migration0001 creates idp_links. No column holds a token value: refresh_ref
// is the token's Reference (secrets.Ref(token).String()), secret_key is its
// logical key in consent.store. Times are epoch milliseconds; NULL means
// never. user_key is unique: one user key names one (iss, sub).
const migration0001 = `
CREATE TABLE idp_links (
    iss                 TEXT    NOT NULL,
    sub                 TEXT    NOT NULL,
    user_key            TEXT    NOT NULL,
    email               TEXT    NOT NULL,
    secret_key          TEXT    NOT NULL,
    refresh_ref         TEXT    NOT NULL,
    generation          INTEGER NOT NULL,
    linked_at           INTEGER NOT NULL,
    refresh_issued_at   INTEGER NOT NULL,
    relink_due_at       INTEGER NOT NULL,
    last_refresh_at     INTEGER,
    last_refresh_status TEXT    NOT NULL DEFAULT '',
    offboarded_at       INTEGER,
    PRIMARY KEY (iss, sub)
);
CREATE UNIQUE INDEX idx_idp_links_user_key ON idp_links (user_key);
`

// migration0002 adds the refresh job's record (W-P3-OFFB-02). Existing rows
// start active with no failures; rotation_pending_ref is a Reference, never a
// token; email_verified is 0 or 1. last_ok_at is epoch milliseconds or NULL.
const migration0002 = `
ALTER TABLE idp_links ADD COLUMN link_state TEXT NOT NULL DEFAULT 'active';
ALTER TABLE idp_links ADD COLUMN last_ok_at INTEGER;
ALTER TABLE idp_links ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE idp_links ADD COLUMN last_error_code TEXT NOT NULL DEFAULT '';
ALTER TABLE idp_links ADD COLUMN rotation_pending_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE idp_links ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
`

// Migrations returns the idp_links migrations. The control plane registers
// them in StateMigrations (always applied, like portal_sessions), so every
// opener of warden-cp.db passes the downgrade guard.
func Migrations() []cpstate.Migration {
	return []cpstate.Migration{{ID: MigrationID, SQL: migration0001}, {ID: MigrationRefreshID, SQL: migration0002}}
}

// Repo is portal.LinkRepo over idp_links.
type Repo struct{ db *sql.DB }

var _ portal.LinkRepo = (*Repo)(nil)

// New returns the repo over db (opened with Migrations).
func New(db *cpstate.DB) *Repo { return &Repo{db: db.SQL()} }

const cols = `iss, sub, user_key, email, secret_key, refresh_ref, generation, linked_at,
 refresh_issued_at, relink_due_at, last_refresh_at, last_refresh_status, offboarded_at,
 link_state, last_ok_at, consecutive_failures, last_error_code, rotation_pending_ref, email_verified`

type scanner interface{ Scan(dest ...any) error }

func scanLink(r scanner) (portal.IdPLink, error) {
	var l portal.IdPLink
	var linked, issued, due int64
	var lastRefresh, offboarded, lastOK sql.NullInt64
	if err := r.Scan(&l.Iss, &l.Sub, &l.UserKey, &l.Email, &l.SecretKey, &l.RefreshRef, &l.Generation,
		&linked, &issued, &due, &lastRefresh, &l.LastRefreshStatus, &offboarded,
		&l.State, &lastOK, &l.ConsecutiveFailures, &l.LastErrorCode, &l.RotationPendingRef, &l.EmailVerified); err != nil {
		return portal.IdPLink{}, err
	}
	if lastOK.Valid {
		l.LastOKAt = fromMillis(lastOK.Int64)
	}
	l.LinkedAt, l.RefreshIssuedAt, l.RelinkDueAt = fromMillis(linked), fromMillis(issued), fromMillis(due)
	if lastRefresh.Valid {
		l.LastRefreshAt = fromMillis(lastRefresh.Int64)
	}
	if offboarded.Valid {
		l.OffboardedAt = fromMillis(offboarded.Int64)
	}
	return l, nil
}

func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

// Get returns the row of (iss, sub), or portal.ErrLinkNotFound.
func (r *Repo) Get(ctx context.Context, iss, sub string) (portal.IdPLink, error) {
	l, err := scanLink(r.db.QueryRowContext(ctx, `SELECT `+cols+` FROM idp_links WHERE iss = ? AND sub = ?`, iss, sub))
	if errors.Is(err, sql.ErrNoRows) {
		return portal.IdPLink{}, portal.ErrLinkNotFound
	}
	if err != nil {
		return portal.IdPLink{}, fmt.Errorf("idp_links: get: %w", err)
	}
	return l, nil
}

// List returns every row ordered by (iss, sub).
func (r *Repo) List(ctx context.Context) ([]portal.IdPLink, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+cols+` FROM idp_links ORDER BY iss, sub`)
	if err != nil {
		return nil, fmt.Errorf("idp_links: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []portal.IdPLink
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, fmt.Errorf("idp_links: list: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("idp_links: list: %w", err)
	}
	return out, nil
}

// Upsert inserts the row with generation 1, or updates the existing one:
// generation + 1, linked_at and last_ok_at kept, the last-refresh columns and
// offboarded_at cleared, and the refresh job's record reset (link_state
// active, no failures, no error code, no pending rotation). It returns the
// stored row.
func (r *Repo) Upsert(ctx context.Context, l portal.IdPLink) (portal.IdPLink, error) {
	row := r.db.QueryRowContext(ctx, `
INSERT INTO idp_links (iss, sub, user_key, email, secret_key, refresh_ref, generation, linked_at,
    refresh_issued_at, relink_due_at, last_refresh_at, last_refresh_status, offboarded_at,
    link_state, consecutive_failures, last_error_code, rotation_pending_ref, email_verified)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL, '', NULL, 'active', 0, '', '', ?)
ON CONFLICT (iss, sub) DO UPDATE SET
    user_key = excluded.user_key,
    email = excluded.email,
    secret_key = excluded.secret_key,
    refresh_ref = excluded.refresh_ref,
    generation = idp_links.generation + 1,
    refresh_issued_at = excluded.refresh_issued_at,
    relink_due_at = excluded.relink_due_at,
    last_refresh_at = NULL,
    last_refresh_status = '',
    offboarded_at = NULL,
    link_state = 'active',
    consecutive_failures = 0,
    last_error_code = '',
    rotation_pending_ref = '',
    email_verified = excluded.email_verified
RETURNING `+cols,
		l.Iss, l.Sub, l.UserKey, l.Email, l.SecretKey, l.RefreshRef,
		l.LinkedAt.UnixMilli(), l.RefreshIssuedAt.UnixMilli(), l.RelinkDueAt.UnixMilli(), l.EmailVerified)
	out, err := scanLink(row)
	if err != nil {
		return portal.IdPLink{}, fmt.Errorf("idp_links: upsert: %w", err)
	}
	return out, nil
}

// Rotate updates refresh_ref, last_refresh_at and last_refresh_status and
// increments generation WHERE generation = expectedGeneration;
// portal.ErrStaleGeneration when no row matched (also when the row is gone).
func (r *Repo) Rotate(ctx context.Context, iss, sub string, expectedGeneration int64, refreshRef string, at time.Time, status string) error {
	res, err := r.db.ExecContext(ctx, `
UPDATE idp_links SET refresh_ref = ?, generation = generation + 1, last_refresh_at = ?, last_refresh_status = ?
WHERE iss = ? AND sub = ? AND generation = ?`,
		refreshRef, at.UnixMilli(), status, iss, sub, expectedGeneration)
	if err != nil {
		return fmt.Errorf("idp_links: rotate: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("idp_links: rotate: %w", err)
	}
	if n == 0 {
		return portal.ErrStaleGeneration
	}
	return nil
}

// nullMillis is t as epoch milliseconds, or NULL for the zero time.
func nullMillis(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixMilli(), Valid: true}
}

// SetState writes the refresh job's columns WHERE generation =
// expectedGeneration (the generation itself is unchanged);
// portal.ErrStaleGeneration when no row matched.
func (r *Repo) SetState(ctx context.Context, iss, sub string, expectedGeneration int64, st portal.RefreshState) error {
	res, err := r.db.ExecContext(ctx, `
UPDATE idp_links SET link_state = ?, last_ok_at = ?, last_refresh_at = ?, last_refresh_status = ?,
    consecutive_failures = ?, last_error_code = ?, rotation_pending_ref = ?, email = ?, email_verified = ?
WHERE iss = ? AND sub = ? AND generation = ?`,
		st.State, nullMillis(st.LastOKAt), nullMillis(st.LastRefreshAt), st.LastRefreshStatus,
		st.ConsecutiveFailures, st.LastErrorCode, st.RotationPendingRef, st.Email, st.EmailVerified,
		iss, sub, expectedGeneration)
	if err != nil {
		return fmt.Errorf("idp_links: set state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("idp_links: set state: %w", err)
	}
	if n == 0 {
		return portal.ErrStaleGeneration
	}
	return nil
}
