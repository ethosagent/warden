package analytics

import (
	"context"
	"fmt"
	"time"
)

// UserCost is one user's estimated spend under one per-user limit rule, as
// CostByUserSince sums it. UserSub is "" for anonymous traffic (the rule is
// then the anonymous rule).
type UserCost struct {
	UserSub   string
	LimitRule string
	CostUSD   float64
}

// costByUserSinceSQL sums cost_usd by user_sub and limit_rule over events at
// or after a timestamp. Only events charged to a rule and priced above zero
// count. It names the idx_events_ts_user_rule_cost covering index: left to
// itself the planner may walk a user_sub-leading index to get the GROUP BY
// order for free, a full scan of every retained event at boot. INDEXED BY
// makes the ts range the only plan (TestCostByUserSince_Plan); the index is
// created by migrate.
const costByUserSinceSQL = `SELECT user_sub, limit_rule, SUM(cost_usd) FROM events INDEXED BY idx_events_ts_user_rule_cost
WHERE ts >= ? AND limit_rule != '' AND cost_usd > 0
GROUP BY user_sub, limit_rule`

// CostByUserSince returns the sum of cost_usd grouped by user_sub and
// limit_rule over the events stored at or after since. The worker seeds its
// daily cost ledger with it at boot, with since at the current UTC midnight
// (W-P3-PUL-04). Rows come in no particular order.
func (s *SQLiteStore) CostByUserSince(ctx context.Context, since time.Time) ([]UserCost, error) {
	rows, err := s.db.QueryContext(ctx, costByUserSinceSQL, since.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("analytics: cost by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []UserCost
	for rows.Next() {
		var c UserCost
		if err := rows.Scan(&c.UserSub, &c.LimitRule, &c.CostUSD); err != nil {
			return nil, fmt.Errorf("analytics: cost by user: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: cost by user: %w", err)
	}
	return out, nil
}
