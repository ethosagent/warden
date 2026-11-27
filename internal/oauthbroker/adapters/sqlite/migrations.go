// Package sqlite is the SQLite oauthbroker.GrantStore on the control plane's
// cpstate database: the pending_authorizations, connect_attempts and
// oauth_grants tables and their migrations.
package sqlite

import "github.com/ethosagent/warden/internal/cpstate"

// The migration ids, in order.
const (
	PendingMigrationID = "oauthbroker/0001"
	AttemptMigrationID = "oauthbroker/0002"
	GrantMigrationID   = "oauthbroker/0003"
)

// EnabledMigrationIDs lists every broker migration, for cpstate.Enable when the
// broker is on (consent.providers set, W-P3-BRKR-03).
func EnabledMigrationIDs() []string {
	return []string{PendingMigrationID, AttemptMigrationID, GrantMigrationID}
}

// migration0001 is the long-lived intent shared with JIT (W-P3-JIT-01, which
// adds its own columns in a later migration). The request columns are filled
// only for a JIT pending and shown on the portal landing page.
const migration0001 = `CREATE TABLE pending_authorizations (
  id             TEXT    PRIMARY KEY,
  iss            TEXT    NOT NULL,
  sub            TEXT    NOT NULL,
  user_key       TEXT    NOT NULL,
  agent_id       TEXT    NULL,
  provider       TEXT    NOT NULL,
  scopes_json    TEXT    NOT NULL,
  message        TEXT    NULL,
  request_method TEXT    NULL,
  request_host   TEXT    NULL,
  request_path   TEXT    NULL,
  mcp_tool       TEXT    NULL,
  status         TEXT    NOT NULL CHECK (status IN ('pending','granted','denied','expired')),
  reason         TEXT    NULL,
  created_at     INTEGER NOT NULL, -- Unix epoch milliseconds (UTC)
  expires_at     INTEGER NOT NULL, -- Unix epoch milliseconds (UTC)
  completed_at   INTEGER NULL      -- Unix epoch milliseconds (UTC); NULL while open
);
CREATE INDEX pending_authorizations_status_expires ON pending_authorizations (status, expires_at);
CREATE INDEX pending_authorizations_user_open ON pending_authorizations (user_key, status, expires_at);`

// migration0002 holds one browser attempt, consumed once with DELETE ...
// RETURNING. state_hash is the SHA-256 of the OAuth state; verifier is the
// PKCE code_verifier (plaintext in the 0600 cpstate file, for at most ten
// minutes, like oidc_pending).
const migration0002 = `CREATE TABLE connect_attempts (
  state_hash   TEXT    PRIMARY KEY,
  pending_id   TEXT    NULL,
  iss          TEXT    NOT NULL,
  sub          TEXT    NOT NULL,
  user_key     TEXT    NOT NULL,
  provider     TEXT    NOT NULL,
  scopes_json  TEXT    NOT NULL,
  verifier     TEXT    NOT NULL,
  browser_hash TEXT    NOT NULL,
  created_at   INTEGER NOT NULL, -- Unix epoch milliseconds (UTC)
  expires_at   INTEGER NOT NULL  -- Unix epoch milliseconds (UTC)
);
CREATE INDEX connect_attempts_user_key ON connect_attempts (user_key, expires_at);
CREATE INDEX connect_attempts_expires ON connect_attempts (expires_at);`

// migration0003 is the grant metadata: one row per (user_key, provider). The
// token itself lives in consent.store; no column here can hold it. The name
// leaves "grants" to the P4 delegation grants. prev_grant_id is set when a
// reconnect replaces an active grant, so the reconciler (W-P3-BRKR-04) can
// restore that grant, whose token may still be in consent.store, instead of
// deleting a working token when the reconnect never completes.
const migration0003 = `CREATE TABLE oauth_grants (
  user_key               TEXT    NOT NULL,
  iss                    TEXT    NOT NULL,
  sub                    TEXT    NOT NULL,
  provider               TEXT    NOT NULL,
  grant_id               TEXT    NOT NULL UNIQUE,
  prev_grant_id          TEXT    NULL, -- the active grant_id a reconnect replaced, until ActivateGrant
  state                  TEXT    NOT NULL CHECK (state IN ('connecting','active','reconsent_required','revoked')),
  scopes_json            TEXT    NOT NULL,
  provider_account_id    TEXT    NULL,
  provider_account_login TEXT    NULL,
  granted_at             INTEGER NOT NULL, -- Unix epoch milliseconds (UTC)
  updated_at             INTEGER NOT NULL, -- Unix epoch milliseconds (UTC)
  last_used_at           INTEGER NULL,     -- Unix epoch milliseconds (UTC)
  revoked_at             INTEGER NULL,     -- Unix epoch milliseconds (UTC)
  UNIQUE (user_key, provider)
);
CREATE INDEX oauth_grants_state_updated ON oauth_grants (state, updated_at);`

// Migrations returns the broker migrations. They are Optional: the control
// plane registers them always (StateMigrations, so the downgrade guard knows
// the ids) and applies them only when the broker is enabled, through
// cpstate.Enable(migs, EnabledMigrationIDs()...). A control plane without
// consent.providers creates none of these tables.
func Migrations() []cpstate.Migration {
	return []cpstate.Migration{
		{ID: PendingMigrationID, Optional: true, SQL: migration0001},
		{ID: AttemptMigrationID, Optional: true, SQL: migration0002},
		{ID: GrantMigrationID, Optional: true, SQL: migration0003},
	}
}
