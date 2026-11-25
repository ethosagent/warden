// Package sqlite is the SQLite implementation of agentreg.Store on the
// control plane's cpstate database.
package sqlite

import "github.com/ethosagent/warden/internal/cpstate"

// MigrationID is the one migration of this package.
const MigrationID = "agents/0001"

// migration0001 creates the registry. Values are validated in Go, not with
// CHECK constraints, so a later phase can add a status without a table
// rebuild. agent_keys.jkt is the primary key: a key thumbprint belongs to one
// agent, whichever agent tries to claim it. There is no DELETE anywhere in
// this package (TestNoDeleteOfAgents): agent rows are permanent and keys are
// only replaced as a set by Update.
const migration0001 = `
CREATE TABLE agents (
    id                  TEXT    PRIMARY KEY,
    display_name        TEXT    NOT NULL,
    owner_iss           TEXT    NOT NULL,
    owner_sub           TEXT    NOT NULL,
    owner_email         TEXT    NOT NULL,
    allowed_groups_json TEXT    NOT NULL,
    allowed_scopes_json TEXT    NOT NULL,
    status              TEXT    NOT NULL,
    revision            INTEGER NOT NULL,
    created_at          INTEGER NOT NULL,
    created_by          TEXT    NOT NULL,
    updated_at          INTEGER NOT NULL,
    updated_by          TEXT    NOT NULL
);
CREATE TABLE agent_keys (
    jkt      TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    kid      TEXT NOT NULL,
    alg      TEXT NOT NULL,
    jwk_json TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_agent_keys_kid ON agent_keys (agent_id, kid);
`

// Migrations returns the cpstate migrations the registry needs. The control
// plane registers them in StateMigrations so every opener of warden-cp.db
// (the server, the harness, the offline CLIs) passes the downgrade guard.
func Migrations() []cpstate.Migration {
	return []cpstate.Migration{{ID: MigrationID, SQL: migration0001}}
}
