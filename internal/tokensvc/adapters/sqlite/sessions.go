package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/tokensvc"
)

// SessionsMigrationID is the migration that creates token_sessions.
const SessionsMigrationID = "tokensvc/0002"

// migration0002 creates the token session table. It is separate from the
// console sessions table. Times are Unix seconds. At most one live
// (revoked_at IS NULL) session exists per (idp_iss, sub, agent_id); revoked
// rows stay so a later exchange can tell a revoked session from a new one.
const migration0002 = `
CREATE TABLE token_sessions (
    sid          TEXT    NOT NULL PRIMARY KEY,
    idp_iss      TEXT    NOT NULL,
    sub          TEXT    NOT NULL,
    agent_id     TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    revoked_at   INTEGER
);
CREATE UNIQUE INDEX idx_token_sessions_live ON token_sessions (idp_iss, sub, agent_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_token_sessions_key ON token_sessions (idp_iss, sub, agent_id);
CREATE INDEX idx_token_sessions_agent ON token_sessions (agent_id);
`

// SessionMigrations returns the cpstate migrations the session store needs.
func SessionMigrations() []cpstate.Migration {
	return []cpstate.Migration{{ID: SessionsMigrationID, SQL: migration0002}}
}

// Sessions is the tokensvc.SessionStore on the cpstate database.
type Sessions struct {
	db *sql.DB
}

var _ tokensvc.SessionStore = (*Sessions)(nil)

// NewSessions returns a Sessions on db, which must have been opened with
// SessionMigrations.
func NewSessions(db *cpstate.DB) *Sessions { return &Sessions{db: db.SQL()} }

// Touch implements tokensvc.SessionStore in one transaction.
func (s *Sessions) Touch(ctx context.Context, key tokensvc.SessionKey, subjectIssuedAt, now time.Time, p tokensvc.SessionPolicy, newSID string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("tokensvc: touch session: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// A subject token issued at or before any revoke of this key is dead,
	// whether or not a newer live session exists: check before reusing or
	// creating anything.
	var revoked sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MAX(revoked_at) FROM token_sessions WHERE idp_iss = ? AND sub = ? AND agent_id = ?`,
		key.IdPIss, key.Sub, key.AgentID).Scan(&revoked); err != nil {
		return "", fmt.Errorf("tokensvc: touch session: %w", err)
	}
	if revoked.Valid && subjectIssuedAt.Unix() <= revoked.Int64 {
		return "", tokensvc.ErrSessionRevoked
	}

	var sid string
	var created, used int64
	err = tx.QueryRowContext(ctx,
		`SELECT sid, created_at, last_used_at FROM token_sessions
		 WHERE idp_iss = ? AND sub = ? AND agent_id = ? AND revoked_at IS NULL`,
		key.IdPIss, key.Sub, key.AgentID).Scan(&sid, &created, &used)
	switch {
	case err == nil:
		idleOK := p.Idle <= 0 || now.Unix()-used <= int64(p.Idle/time.Second)
		ageOK := p.Absolute <= 0 || now.Unix()-created <= int64(p.Absolute/time.Second)
		if idleOK && ageOK {
			if _, err := tx.ExecContext(ctx, `UPDATE token_sessions SET last_used_at = ? WHERE sid = ?`, now.Unix(), sid); err != nil {
				return "", fmt.Errorf("tokensvc: touch session: %w", err)
			}
			return sid, commit(tx)
		}
		// An expired session is not a revocation: drop it so a new one fits
		// the unique index.
		if _, err := tx.ExecContext(ctx, `DELETE FROM token_sessions WHERE sid = ?`, sid); err != nil {
			return "", fmt.Errorf("tokensvc: touch session: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
	default:
		return "", fmt.Errorf("tokensvc: touch session: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO token_sessions (sid, idp_iss, sub, agent_id, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)`,
		newSID, key.IdPIss, key.Sub, key.AgentID, now.Unix(), now.Unix()); err != nil {
		return "", fmt.Errorf("tokensvc: touch session: %w", err)
	}
	return newSID, commit(tx)
}

func commit(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("tokensvc: touch session: %w", err)
	}
	return nil
}

// Revoke implements tokensvc.SessionStore.
func (s *Sessions) Revoke(ctx context.Context, sid string, now time.Time) (bool, error) {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE token_sessions SET revoked_at = ? WHERE sid = ? AND revoked_at IS NULL`, now.Unix(), sid); err != nil {
		return false, fmt.Errorf("tokensvc: revoke session: %w", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_sessions WHERE sid = ?`, sid).Scan(&n); err != nil {
		return false, fmt.Errorf("tokensvc: revoke session: %w", err)
	}
	return n > 0, nil
}

// RevokeAll implements tokensvc.SessionStore.
func (s *Sessions) RevokeAll(ctx context.Context, f tokensvc.SessionFilter, now time.Time) (int64, error) {
	if f.Empty() {
		return 0, errors.New("tokensvc: revoke sessions: empty filter")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE token_sessions SET revoked_at = ?
		 WHERE revoked_at IS NULL
		   AND (? = '' OR idp_iss = ?) AND (? = '' OR sub = ?) AND (? = '' OR agent_id = ?)`,
		now.Unix(), f.IdPIss, f.IdPIss, f.Sub, f.Sub, f.AgentID, f.AgentID)
	if err != nil {
		return 0, fmt.Errorf("tokensvc: revoke sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("tokensvc: revoke sessions: %w", err)
	}
	return n, nil
}

// Purge implements tokensvc.SessionStore.
func (s *Sessions) Purge(ctx context.Context, liveCutoff, revokedCutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM token_sessions
		 WHERE (revoked_at IS NULL AND last_used_at < ?) OR (revoked_at IS NOT NULL AND revoked_at < ?)`,
		liveCutoff.Unix(), revokedCutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("tokensvc: purge sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("tokensvc: purge sessions: %w", err)
	}
	return n, nil
}
