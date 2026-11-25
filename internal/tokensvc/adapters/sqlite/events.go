package sqlite

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/tokensvc"
)

// EventsMigrationID is the migration that creates token_events and the salt.
const EventsMigrationID = "tokensvc/0003"

// migration0003 creates the issuance record. Machine events stay out of the
// hash-chained admin audit (ADR 0005). sub_hmac is the HMAC-SHA256 of the user
// under the per-CP salt: it correlates one user's rows without storing the
// subject. Times are Unix seconds. No column can hold a token, an assertion or
// a group list.
const migration0003 = `
CREATE TABLE token_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    outcome  TEXT    NOT NULL,
    reason   TEXT    NOT NULL DEFAULT '',
    agent_id TEXT    NOT NULL,
    sub_hmac TEXT    NOT NULL DEFAULT '',
    sid      TEXT    NOT NULL DEFAULT '',
    jti      TEXT    NOT NULL DEFAULT '',
    kid      TEXT    NOT NULL DEFAULT '',
    exp      INTEGER NOT NULL DEFAULT 0,
    scope    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_token_events_ts ON token_events (ts);
CREATE TABLE token_event_salt (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB    NOT NULL
);
`

// EventMigrations returns the cpstate migrations the event store needs.
func EventMigrations() []cpstate.Migration {
	return []cpstate.Migration{{ID: EventsMigrationID, SQL: migration0003}}
}

const saltBytes = 32

// Events is the tokensvc.Recorder on the cpstate database: it stores one
// token_events row per outcome and emits the warden.token.v1 log line for it.
type Events struct {
	db     *sql.DB
	logger *slog.Logger

	mu   sync.Mutex
	salt []byte
}

var _ tokensvc.Recorder = (*Events)(nil)

// NewEvents returns an Events on db, which must have been opened with
// EventMigrations. logger may be nil (no log line).
func NewEvents(db *cpstate.DB, logger *slog.Logger) *Events {
	return &Events{db: db.SQL(), logger: logger}
}

// Record implements tokensvc.Recorder. The row is written first; the log line
// follows only for a row that exists.
func (e *Events) Record(ctx context.Context, ev tokensvc.Event) error {
	subHMAC := ""
	if ev.Sub != "" {
		salt, err := e.loadSalt(ctx)
		if err != nil {
			return err
		}
		subHMAC = userHMAC(salt, ev.IdPIss, ev.Sub)
	}
	var exp int64
	if !ev.Exp.IsZero() {
		exp = ev.Exp.Unix()
	}
	if _, err := e.db.ExecContext(ctx,
		`INSERT INTO token_events (ts, outcome, reason, agent_id, sub_hmac, sid, jti, kid, exp, scope)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TS.Unix(), ev.Outcome, string(ev.Reason), ev.AgentID, subHMAC, ev.SID, ev.JTI, ev.KID, exp, ev.Scope); err != nil {
		return fmt.Errorf("tokensvc: record token event: %w", err)
	}
	if e.logger != nil {
		// sub is the pseudonym, never the IdP subject: the log is no more
		// identifying than the row.
		e.logger.LogAttrs(ctx, slog.LevelInfo, "token_exchange",
			slog.String("schema", tokensvc.EventSchema),
			slog.String("outcome", ev.Outcome), slog.String("reason", string(ev.Reason)),
			slog.String("agent", ev.AgentID), slog.String("sub", subHMAC),
			slog.String("sid", ev.SID), slog.String("jti", ev.JTI), slog.String("kid", ev.KID),
			slog.Int64("exp", exp))
	}
	return nil
}

// userHMAC is the pseudonym of a user: hex HMAC-SHA256 of idp_iss and sub.
func userHMAC(salt []byte, idpIss, sub string) string {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(idpIss))
	m.Write([]byte{0})
	m.Write([]byte(sub))
	return hex.EncodeToString(m.Sum(nil))
}

// loadSalt returns the per-CP salt, creating and persisting it on first use.
// Two control planes racing on an empty table both insert with ON CONFLICT DO
// NOTHING and then read back, so they agree on one salt.
func (e *Events) loadSalt(ctx context.Context) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.salt != nil {
		return e.salt, nil
	}
	read := func() ([]byte, error) {
		var b []byte
		err := e.db.QueryRowContext(ctx, `SELECT salt FROM token_event_salt WHERE id = 1`).Scan(&b)
		return b, err
	}
	b, err := read()
	if errors.Is(err, sql.ErrNoRows) {
		fresh := make([]byte, saltBytes)
		if _, rerr := rand.Read(fresh); rerr != nil {
			return nil, fmt.Errorf("tokensvc: token event salt: %w", rerr)
		}
		if _, ierr := e.db.ExecContext(ctx,
			`INSERT INTO token_event_salt (id, salt) VALUES (1, ?) ON CONFLICT (id) DO NOTHING`, fresh); ierr != nil {
			return nil, fmt.Errorf("tokensvc: token event salt: %w", ierr)
		}
		b, err = read()
	}
	if err != nil {
		return nil, fmt.Errorf("tokensvc: token event salt: %w", err)
	}
	if len(b) < saltBytes {
		return nil, errors.New("tokensvc: token event salt is shorter than expected")
	}
	e.salt = b
	return b, nil
}

// Purge deletes the events recorded before cutoff and returns how many.
func (e *Events) Purge(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := e.db.ExecContext(ctx, `DELETE FROM token_events WHERE ts < ?`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("tokensvc: purge token events: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("tokensvc: purge token events: %w", err)
	}
	return n, nil
}
