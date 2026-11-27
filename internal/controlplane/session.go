package controlplane

import (
	"database/sql"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/webauth"
)

// The session store lives in internal/webauth; the console's sessions are the
// `sessions` table with an auth_method column (oidc or breakglass).

// sessionSweepInterval is how often Server.Start deletes expired rows.
const sessionSweepInterval = webauth.SessionSweepInterval

// csrfLabel is the HMAC message that derives a console session's CSRF token
// from its raw id. The token is never stored.
const csrfLabel = "warden-csrf"

// consoleSessionTable is the console's session table.
func consoleSessionTable() webauth.SessionTable {
	return webauth.SessionTable{Name: "sessions", MigrationID: "sessions/0001", AuthMethod: true}
}

// SessionMigrations are the cpstate migrations of the sessions table. Run passes
// them to cpstate.Open next to every other feature's migrations.
func SessionMigrations() []cpstate.Migration { return consoleSessionTable().Migrations() }

// Session is one stored console session. It never holds the raw id: IDHash is
// the hex sha256 of it.
type Session = webauth.Session

// AuthMethodBreakglass is the auth_method of a break-glass session. Such a
// session has no idle timeout: its absolute expiry is its only limit, so
// activity never extends it.
const AuthMethodBreakglass = webauth.AuthMethodBreakglass

// CreateOptions tune one Create call. The zero value is the store's defaults.
type CreateOptions = webauth.CreateOptions

// SessionInput is what Create records about the signed-in user.
type SessionInput = webauth.SessionInput

// SessionStore keeps server-side console sessions in the cpstate database: a
// webauth.SessionStore over the console's table.
type SessionStore struct{ *webauth.SessionStore }

// NewSessionStore builds the console's store over db (a cpstate DB opened with
// SessionMigrations). A nil now uses time.Now.
func NewSessionStore(db *sql.DB, idle, absolute time.Duration, now func() time.Time) *SessionStore {
	return &SessionStore{webauth.NewSessionStore(db, consoleSessionTable(), idle, absolute, now)}
}

// hashID returns the hex sha256 of a raw session id.
func hashID(rawID string) string { return webauth.HashID(rawID) }

// CSRFToken derives the CSRF token for a raw console session id: HMAC-SHA256
// keyed by the id over the console's label. Exported for the logout and
// /auth/me endpoints.
func CSRFToken(rawID string) string { return webauth.CSRFToken([]byte(rawID), csrfLabel) }

// shortHash is the only form of a session id that may appear in logs: the first
// 8 hex characters of its hash.
func shortHash(idHash string) string { return webauth.ShortHash(idHash) }
