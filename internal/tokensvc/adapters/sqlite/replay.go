// Package sqlite is the SQLite implementation of tokensvc.ReplayStore on the
// control plane's cpstate database.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/tokensvc"
)

// MigrationID is the one migration of this package.
const MigrationID = "tokensvc/0001"

// migration0001 creates the replay table. jti_hash is the hex SHA-256 of the
// jti: the raw jti is never stored. expires_at is Unix seconds, the assertion's
// exp plus the accepted skew, after which the row can no longer matter.
const migration0001 = `
CREATE TABLE token_assertion_jti (
    agent_id   TEXT    NOT NULL,
    jti_hash   TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, jti_hash)
);
CREATE INDEX idx_token_assertion_jti_expires ON token_assertion_jti (expires_at);
`

// Migrations returns the cpstate migrations the replay store needs. The
// control plane registers them in StateMigrations so every opener of
// warden-cp.db passes the downgrade guard.
func Migrations() []cpstate.Migration {
	return []cpstate.Migration{{ID: MigrationID, SQL: migration0001}}
}

// Store is the tokensvc.ReplayStore on the cpstate database.
type Store struct {
	db *sql.DB
}

var _ tokensvc.ReplayStore = (*Store)(nil)

// New returns a Store on db, which must have been opened with Migrations.
func New(db *cpstate.DB) *Store { return &Store{db: db.SQL()} }

// Consume inserts the pair with one INSERT ... ON CONFLICT DO NOTHING and
// reports whether a row was written, so two concurrent calls cannot both win.
func (s *Store) Consume(ctx context.Context, agentID, jtiHash string, expiresAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO token_assertion_jti (agent_id, jti_hash, expires_at) VALUES (?, ?, ?)
		 ON CONFLICT (agent_id, jti_hash) DO NOTHING`,
		agentID, jtiHash, expiresAt.Unix())
	if err != nil {
		return false, fmt.Errorf("tokensvc: consume assertion jti: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("tokensvc: consume assertion jti: %w", err)
	}
	return n == 1, nil
}

// Purge deletes the rows whose expires_at is before now.
func (s *Store) Purge(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM token_assertion_jti WHERE expires_at < ?`, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("tokensvc: purge assertion jti: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("tokensvc: purge assertion jti: %w", err)
	}
	return n, nil
}
