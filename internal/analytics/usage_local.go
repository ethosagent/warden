package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/denyreason"
)

// The standalone worker's UserUsageQuerier (W-P3-PUL-05): the same read side
// as the fleet rollup, answered with fixed, parameterized SQL over the local
// events table, so the worker dashboard's Users usage view needs no rollup.
// Events carry no retention horizon other than the events cap, so the answer
// covers whatever the store still holds in the window.

var _ UserUsageQuerier = (*SQLiteStore)(nil)

const (
	// localUsageSQL groups the window's attributed events (and the ones under
	// the anonymous rule) by UTC day, user, agent, rule and deny reason. A
	// deny with identity_groups_truncated names the rule that was SKIPPED,
	// not one that was charged, so its rule is blanked; negative costs add
	// nothing, like the rollup. Parameters: from ts, to ts (exclusive),
	// identity_groups_truncated twice, anonymous rule.
	localUsageSQL = `SELECT strftime('%Y-%m-%d', ts / 1000000000, 'unixepoch') AS day,
        user_sub, agent_id,
        CASE WHEN decision = 'deny' AND reason = ? THEN '' ELSE limit_rule END AS rule,
        MAX(user_email),
        CASE WHEN decision = 'deny' THEN reason ELSE NULL END AS deny_reason,
        COUNT(*), SUM(MAX(cost_usd, 0))
        FROM events
        WHERE ts >= ? AND ts < ? AND (user_sub != '' OR limit_rule = ?)
        GROUP BY day, user_sub, agent_id, rule, deny_reason`

	// localTodayCostSQL sums one UTC day's cost per user and rule, leaving out
	// events with no sub, no rule and the skipped-rule denies.
	localTodayCostSQL = `SELECT user_sub, limit_rule, SUM(MAX(cost_usd, 0))
        FROM events
        WHERE ts >= ? AND ts < ? AND user_sub != '' AND limit_rule != ''
          AND NOT (decision = 'deny' AND reason = ?)
        GROUP BY user_sub, limit_rule
        ORDER BY user_sub, limit_rule`
)

// UsageByUser implements UserUsageQuerier over the local events table with the
// same day-granular window, ordering and anonymous row as the fleet stores.
func (s *SQLiteStore) UsageByUser(ctx context.Context, from, to time.Time, limit int) ([]UserUsage, error) {
	start := dayStart(from)
	end := dayStart(to).AddDate(0, 0, 1)
	rows, err := s.ro.QueryContext(ctx, localUsageSQL,
		string(denyreason.IdentityGroupsTruncated), start.UnixNano(), end.UnixNano(), AnonymousLimitRule)
	if err != nil {
		return nil, fmt.Errorf("analytics: local usage by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	acc := newUsageAccumulator()
	for rows.Next() {
		var (
			r      usageRecord
			reason *string
			email  *string
		)
		if err := rows.Scan(&r.key.day, &r.key.sub, &r.key.agent, &r.key.rule, &email, &reason, &r.requests, &r.cost); err != nil {
			return nil, fmt.Errorf("analytics: local usage by user scan: %w", err)
		}
		r.key.sub = truncateUTF8(r.key.sub, maxUsageSubLen)
		r.key.agent = truncateUTF8(r.key.agent, maxUsageAgentLen)
		r.key.rule = usageRule(r.key.rule)
		if email != nil && r.key.sub != "" {
			r.email = truncateUTF8(*email, maxUsageEmailLen)
		}
		r.denies = map[string]int64{}
		if reason != nil {
			rs := *reason
			if rs == "" {
				rs = denyReasonUnspecified
			}
			addDeny(r.denies, rs, r.requests)
		}
		acc.add(r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: local usage by user rows: %w", err)
	}
	return acc.result(usageLimit(limit)), nil
}

// TodayCostByRule implements UserUsageQuerier over the local events table.
func (s *SQLiteStore) TodayCostByRule(ctx context.Context, day string) ([]UserRuleCost, error) {
	d, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return nil, fmt.Errorf("analytics: today cost by rule: bad day: %w", err)
	}
	rows, err := s.ro.QueryContext(ctx, localTodayCostSQL,
		d.UnixNano(), d.AddDate(0, 0, 1).UnixNano(), string(denyreason.IdentityGroupsTruncated))
	if err != nil {
		return nil, fmt.Errorf("analytics: local today cost by rule: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []UserRuleCost{}
	for rows.Next() {
		var c UserRuleCost
		if err := rows.Scan(&c.Sub, &c.Rule, &c.CostUSD); err != nil {
			return nil, fmt.Errorf("analytics: local today cost by rule scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: local today cost by rule rows: %w", err)
	}
	return out, nil
}

// dayStart is 00:00 UTC of t's UTC day.
func dayStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}
