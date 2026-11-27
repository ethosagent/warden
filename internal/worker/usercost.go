package worker

import (
	"context"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/cost"
)

// costSeedSource is the local analytics read the cost ledger seed needs:
// *analytics.SQLiteStore satisfies it.
type costSeedSource interface {
	CostByUserSince(ctx context.Context, since time.Time) ([]analytics.UserCost, error)
}

// costSeedTimeout bounds the boot-time seed query.
const costSeedTimeout = 10 * time.Second

// utcMidnight is the start of t's UTC day.
func utcMidnight(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// seedCostLedger seeds the per-user daily spend ledger (W-P3-PUL-04) from the
// local store: the sum of today's (UTC) cost_usd by user_sub and limit_rule,
// so a worker restart keeps a user who is over a cap refused. Anonymous spend
// (no sub) is keyed on this worker's agent id, as the proxy keys it. It
// returns the number of keys seeded.
func seedCostLedger(ctx context.Context, src costSeedSource, l *cost.Ledger, agentID string) (int, error) {
	since := utcMidnight(l.Now())
	ctx, cancel := context.WithTimeout(ctx, costSeedTimeout)
	defer cancel()
	rows, err := src.CostByUserSince(ctx, since)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		l.Seed(since, cost.UserKey(r.UserSub, agentID, r.LimitRule), r.CostUSD)
	}
	return len(rows), nil
}
