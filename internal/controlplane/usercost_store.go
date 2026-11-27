package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The last good fleet cost block list (W-P3-PUL-08), kept in the CP state DB
// (warden-cp.db), never in the fleet analytics DB and never in a policy
// version. It lets a restarted control plane serve the list from its first
// load even while the rollup query fails, without holding back any other
// policy change. One row: the day the list is for, the list (in priority
// order, with each entry's cost, so a size cut after a restart still keeps
// the largest spenders) and its fingerprint. It holds only subs, rule names,
// days and estimated costs: no email, token or request data.

// userCostMigrationID creates user_cost_blocks. It is always applied (like
// the block list), so an older binary's downgrade guard sees it.
const userCostMigrationID = "usercost/0001"

const userCostMigration0001 = `
CREATE TABLE user_cost_blocks (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    day        TEXT NOT NULL,
    list_json  TEXT NOT NULL,
    fp         TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
`

// UserCostMigrations returns the cpstate migrations of the persisted cost
// block list. StateMigrations includes them.
func UserCostMigrations() []cpstate.Migration {
	return []cpstate.Migration{{ID: userCostMigrationID, SQL: userCostMigration0001}}
}

// maxUserCostRowBytes bounds the stored list_json a load accepts: 5000
// entries of the longest sub and rule with a cost fit well inside it.
const maxUserCostRowBytes = 4 << 20

// persistedCostBlock is one stored entry.
type persistedCostBlock struct {
	Sub     string  `json:"sub"`
	Rule    string  `json:"rule"`
	Day     string  `json:"day"`
	CostUSD float64 `json:"costUSD"`
}

// userCostStore reads and writes the single user_cost_blocks row.
type userCostStore struct {
	db  *sql.DB
	now func() time.Time
}

// save replaces the row with list for day.
func (st *userCostStore) save(ctx context.Context, day string, list []costBlock) error {
	rows := make([]persistedCostBlock, len(list))
	entries := make([]config.CostBlockedUser, len(list))
	for i, b := range list {
		rows[i] = persistedCostBlock{Sub: b.entry.Sub, Rule: b.entry.Rule, Day: b.entry.Day, CostUSD: b.cost}
		entries[i] = b.entry
	}
	js, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = st.db.ExecContext(ctx, `INSERT INTO user_cost_blocks (id, day, list_json, fp, updated_at) VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET day = excluded.day, list_json = excluded.list_json, fp = excluded.fp, updated_at = excluded.updated_at`,
		day, string(js), costBlocksFingerprint(entries), st.now().UnixMilli())
	return err
}

// load returns the stored day and list; ok is false when there is no row.
// A row that does not decode, or whose entries fail
// config.ValidateCostBlockedUsers, is an error (never a partial list).
func (st *userCostStore) load(ctx context.Context) (day string, list []costBlock, ok bool, err error) {
	var js string
	err = st.db.QueryRowContext(ctx, `SELECT day, list_json FROM user_cost_blocks WHERE id = 1`).Scan(&day, &js)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	if len(js) > maxUserCostRowBytes {
		return "", nil, false, fmt.Errorf("user_cost_blocks: list_json is %d bytes", len(js))
	}
	var rows []persistedCostBlock
	if err := json.Unmarshal([]byte(js), &rows); err != nil {
		return "", nil, false, fmt.Errorf("user_cost_blocks: decode list_json: %w", err)
	}
	if len(rows) > config.MaxCostBlockedUsers {
		return "", nil, false, fmt.Errorf("user_cost_blocks: %d entries", len(rows))
	}
	entries := make([]config.CostBlockedUser, len(rows))
	list = make([]costBlock, len(rows))
	for i, r := range rows {
		e := config.CostBlockedUser{Sub: r.Sub, Rule: r.Rule, Day: r.Day}
		b, _ := json.Marshal(e)
		entries[i] = e
		list[i] = costBlock{entry: e, cost: r.CostUSD, size: len(b) + 1}
	}
	if err := config.ValidateCostBlockedUsers(entries); err != nil {
		return "", nil, false, fmt.Errorf("user_cost_blocks: %w", err)
	}
	return day, list, true, nil
}
