package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
)

const (
	// pendingTTL is how long a started login may take to come back.
	pendingTTL = 10 * time.Minute
	// pendingCap bounds the table so an unauthenticated /auth/login flood cannot
	// grow it without limit; above it login answers 503.
	pendingCap = 10_000
	// pendingSweepInterval is how often Server.Start deletes expired rows.
	pendingSweepInterval = time.Minute
)

// errPendingFull is returned by Put when the table is at pendingCap.
var errPendingFull = errors.New("oidc pending: table is full")

// OIDCPendingMigrations are the cpstate migrations of the pending-login table.
// Run passes them to cpstate.Open in every mode, like SessionMigrations, so
// switching console.auth never trips the downgrade guard.
func OIDCPendingMigrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID: "oidc_pending/0001",
		SQL: `CREATE TABLE oidc_pending (
  state_hash   TEXT PRIMARY KEY,
  nonce        TEXT NOT NULL,
  verifier     TEXT NOT NULL,
  next         TEXT NOT NULL,
  browser_hash TEXT NOT NULL,
  expires_at   INTEGER NOT NULL
);
CREATE INDEX oidc_pending_expires_at ON oidc_pending (expires_at);`,
	}}
}

// pendingLogin is one started, not yet completed login. The state and the
// browser token are stored only as sha256 hashes; the nonce and the PKCE
// verifier are needed back verbatim at the callback.
type pendingLogin struct {
	StateHash   string
	Nonce       string
	Verifier    string
	Next        string
	BrowserHash string
	ExpiresAt   time.Time
}

// pendingStore keeps pending logins in the cpstate database.
type pendingStore struct {
	db  *sql.DB
	now func() time.Time
}

func newPendingStore(db *sql.DB, now func() time.Time) *pendingStore {
	if now == nil {
		now = time.Now
	}
	return &pendingStore{db: db, now: now}
}

// sha256Hex is the hex sha256 of s, the stored form of the state and of the
// browser-binding token.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Put stores p with the standard TTL. It inserts only while the table holds
// fewer than pendingCap rows, in the same statement, so concurrent logins
// cannot overshoot the cap.
func (s *pendingStore) Put(ctx context.Context, p pendingLogin) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_pending (state_hash, nonce, verifier, next, browser_hash, expires_at)
		 SELECT ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM oidc_pending) < ?`,
		p.StateHash, p.Nonce, p.Verifier, p.Next, p.BrowserHash,
		s.now().Add(pendingTTL).Unix(), pendingCap)
	if err != nil {
		return fmt.Errorf("oidc pending: insert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("oidc pending: insert: %w", err)
	}
	if n == 0 {
		return errPendingFull
	}
	return nil
}

// Take consumes the row for stateHash in one DELETE ... RETURNING, so a state
// works once even under concurrent callbacks. An expired row is deleted too but
// reported as absent.
func (s *pendingStore) Take(ctx context.Context, stateHash string) (pendingLogin, bool, error) {
	var (
		p       pendingLogin
		expires int64
	)
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM oidc_pending WHERE state_hash = ?
		 RETURNING state_hash, nonce, verifier, next, browser_hash, expires_at`, stateHash).
		Scan(&p.StateHash, &p.Nonce, &p.Verifier, &p.Next, &p.BrowserHash, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return pendingLogin{}, false, nil
	}
	if err != nil {
		return pendingLogin{}, false, fmt.Errorf("oidc pending: take: %w", err)
	}
	p.ExpiresAt = time.Unix(expires, 0)
	if !s.now().Before(p.ExpiresAt) {
		return pendingLogin{}, false, nil
	}
	return p, true, nil
}

// Count returns the number of stored rows.
func (s *pendingStore) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_pending`).Scan(&n); err != nil {
		return 0, fmt.Errorf("oidc pending: count: %w", err)
	}
	return n, nil
}

// Sweep deletes every row past its expiry and returns how many it removed.
func (s *pendingStore) Sweep(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oidc_pending WHERE expires_at <= ?`, s.now().Unix())
	if err != nil {
		return 0, fmt.Errorf("oidc pending: sweep: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
