package adminaudit

import "github.com/ethosagent/warden/internal/cpstate"

// migration0001 creates the chain table and the identity side table. Values
// are validated in Go, not with CHECK constraints, so later phases can add
// auth methods or outcomes without a table rebuild. The package never issues
// UPDATE or DELETE on either table (TestNoUpdateOrDeleteStatements).
const migration0001 = `
CREATE TABLE admin_audit (
    seq          INTEGER PRIMARY KEY,
    ts_unix_nano INTEGER NOT NULL,
    actor_id     TEXT    NOT NULL,
    actor_role   TEXT    NOT NULL,
    auth_method  TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    target       TEXT    NOT NULL,
    target_ref   TEXT    NOT NULL,
    details_json TEXT    NOT NULL,
    outcome      TEXT    NOT NULL,
    http_status  INTEGER NOT NULL,
    before_hash  TEXT    NOT NULL,
    after_hash   TEXT    NOT NULL,
    client_ip    TEXT    NOT NULL,
    request_id   TEXT    NOT NULL,
    key_id       TEXT    NOT NULL,
    prev_hash    BLOB    NOT NULL,
    entry_hash   BLOB    NOT NULL,
    signature    BLOB    NOT NULL
);
CREATE INDEX idx_admin_audit_ts ON admin_audit (ts_unix_nano);
CREATE INDEX idx_admin_audit_action ON admin_audit (action);
CREATE INDEX idx_admin_audit_actor_id ON admin_audit (actor_id);
CREATE TABLE admin_audit_actor (
    seq   INTEGER PRIMARY KEY,
    sub   TEXT NOT NULL,
    email TEXT NOT NULL
);
`

// Migrations returns the cpstate migrations the admin audit store needs. The
// control plane registers them whenever it opens cpstate (W-P1-AAUD-05), so
// turning the feature off never trips the cpstate downgrade guard.
func Migrations() []cpstate.Migration {
	return []cpstate.Migration{{ID: "adminaudit/0001", SQL: migration0001}}
}
