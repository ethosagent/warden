package webauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
)

const (
	// PendingTTL is how long a started login may take to come back.
	PendingTTL = 10 * time.Minute
	// PendingCap bounds the table so an unauthenticated login flood cannot
	// grow it without limit; above it Put fails with ErrPendingFull. Each
	// purpose has its own cap, so a flood on one front door's login (the
	// portal's, say) never locks the others (the console's admins) out.
	PendingCap = 10_000
	// PendingSweepInterval is how often RunSweeper deletes expired rows.
	PendingSweepInterval = time.Minute
)

// Login purposes. A pending row is consumed only by a callback of the same
// purpose, so a state minted by one front door never completes on another.
const (
	PurposeConsole = "console"
	PurposePortal  = "portal"
)

// ErrPendingFull is returned by Put when the purpose is at PendingCap.
var ErrPendingFull = errors.New("oidc pending: table is full")

// PendingMigrations are the cpstate migrations of the pending-login table.
// 0002 adds the purpose column; rows from before it are console logins.
func PendingMigrations() []cpstate.Migration {
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
	}, {
		ID: "oidc_pending/0002",
		SQL: `ALTER TABLE oidc_pending ADD COLUMN purpose TEXT NOT NULL DEFAULT 'console';
CREATE INDEX oidc_pending_purpose ON oidc_pending (purpose);`,
	}}
}

// Pending is one started, not yet completed login. The state and the browser
// token are stored only as sha256 hashes; the nonce and the PKCE verifier are
// needed back verbatim at the callback.
type Pending struct {
	StateHash   string
	Purpose     string
	Nonce       string
	Verifier    string
	Next        string
	BrowserHash string
	ExpiresAt   time.Time
}

// Pendings is the part of PendingStore a Flow uses.
type Pendings interface {
	Put(ctx context.Context, p Pending) error
	Take(ctx context.Context, stateHash, purpose string) (Pending, bool, error)
}

// PendingStore keeps pending logins in the cpstate database (a DB opened with
// PendingMigrations).
type PendingStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewPendingStore builds a store over db. A nil now uses time.Now.
func NewPendingStore(db *sql.DB, now func() time.Time) *PendingStore {
	if now == nil {
		now = time.Now
	}
	return &PendingStore{db: db, now: now}
}

// SHA256Hex is the hex sha256 of s, the stored form of the state and of the
// browser-binding token.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Put stores p with the standard TTL. It inserts only while p's purpose holds
// fewer than PendingCap rows, in the same statement, so concurrent logins
// cannot overshoot the cap; other purposes' rows do not count. A row needs a
// purpose.
func (s *PendingStore) Put(ctx context.Context, p Pending) error {
	if p.Purpose == "" {
		return errors.New("oidc pending: insert: empty purpose")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_pending (state_hash, purpose, nonce, verifier, next, browser_hash, expires_at)
		 SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM oidc_pending WHERE purpose = ?) < ?`,
		p.StateHash, p.Purpose, p.Nonce, p.Verifier, p.Next, p.BrowserHash,
		s.now().Add(PendingTTL).Unix(), p.Purpose, PendingCap)
	if err != nil {
		return fmt.Errorf("oidc pending: insert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("oidc pending: insert: %w", err)
	}
	if n == 0 {
		return ErrPendingFull
	}
	return nil
}

// Take consumes the row for stateHash in one DELETE ... RETURNING, so a state
// works once even under concurrent callbacks. Only a row of the given purpose
// matches: a row of another purpose is left in place and reported as absent.
// An expired row is deleted too but reported as absent.
func (s *PendingStore) Take(ctx context.Context, stateHash, purpose string) (Pending, bool, error) {
	var (
		p       Pending
		expires int64
	)
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM oidc_pending WHERE state_hash = ? AND purpose = ?
		 RETURNING state_hash, purpose, nonce, verifier, next, browser_hash, expires_at`, stateHash, purpose).
		Scan(&p.StateHash, &p.Purpose, &p.Nonce, &p.Verifier, &p.Next, &p.BrowserHash, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Pending{}, false, nil
	}
	if err != nil {
		return Pending{}, false, fmt.Errorf("oidc pending: take: %w", err)
	}
	p.ExpiresAt = time.Unix(expires, 0)
	if !s.now().Before(p.ExpiresAt) {
		return Pending{}, false, nil
	}
	return p, true, nil
}

// Count returns the number of stored rows of every purpose.
func (s *PendingStore) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_pending`).Scan(&n); err != nil {
		return 0, fmt.Errorf("oidc pending: count: %w", err)
	}
	return n, nil
}

// Sweep deletes every row past its expiry, of every purpose, and returns how
// many it removed.
func (s *PendingStore) Sweep(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oidc_pending WHERE expires_at <= ?`, s.now().Unix())
	if err != nil {
		return 0, fmt.Errorf("oidc pending: sweep: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// RunSweeper calls Sweep every PendingSweepInterval until ctx is done. One
// sweeper serves every purpose; a second one is harmless.
func (s *PendingStore) RunSweeper(ctx context.Context, logger *slog.Logger) {
	if s == nil {
		return
	}
	t := time.NewTicker(PendingSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := s.Sweep(ctx); err != nil {
			logger.Warn("control plane: pending login sweep failed", "error", err)
		}
	}
}
