package analytics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SQL over user_usage_daily (W-P3-PUL-07). Every statement is fixed text with
// bind parameters and plans as a primary-key search on day (see
// TestUsageQueryPlans); user values never reach the SQL text.
const (
	usagePruneSQL = `DELETE FROM user_usage_daily WHERE day < ?`

	usageDeniesSQL = `SELECT denies_json FROM user_usage_daily
        WHERE day = ? AND sub = ? AND agent_id = ? AND limit_rule = ?`

	// The last parameter is 1 when the event is a deny, in which case the
	// bound denies_json is the merged map; otherwise the row keeps its own.
	usageUpsertSQL = `INSERT INTO user_usage_daily
        (day, sub, agent_id, limit_rule, email, requests, denies_json, cost_usd)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(day, sub, agent_id, limit_rule) DO UPDATE SET
            requests    = user_usage_daily.requests + 1,
            cost_usd    = user_usage_daily.cost_usd + excluded.cost_usd,
            email       = CASE WHEN excluded.email != '' THEN excluded.email ELSE user_usage_daily.email END,
            denies_json = CASE WHEN ? THEN excluded.denies_json ELSE user_usage_daily.denies_json END`

	// Rows of the top-limit attributed users in [fromDay, toDay].
	usageByUserSQL = `SELECT day, sub, agent_id, limit_rule, email, requests, denies_json, cost_usd
        FROM user_usage_daily
        WHERE day >= ? AND day <= ? AND sub IN (
            SELECT sub FROM user_usage_daily
            WHERE day >= ? AND day <= ? AND sub != ''
            GROUP BY sub
            ORDER BY SUM(cost_usd) DESC, SUM(requests) DESC, sub ASC
            LIMIT ?)`

	usageAnonymousSQL = `SELECT day, sub, agent_id, limit_rule, email, requests, denies_json, cost_usd
        FROM user_usage_daily
        WHERE day >= ? AND day <= ? AND sub = ''`

	todayCostByRuleSQL = `SELECT sub, limit_rule, SUM(cost_usd)
        FROM user_usage_daily
        WHERE day = ? AND sub != '' AND limit_rule != ''
        GROUP BY sub, limit_rule
        ORDER BY sub, limit_rule`
)

// upsertUsage adds one stored event to its rollup row inside tx. Events the
// rollup does not count (no sub, not anonymous-rule) are skipped.
func upsertUsage(tx *sql.Tx, e Event, now time.Time) error {
	d, ok := usageDeltaFor(e, now)
	if !ok {
		return nil
	}
	k := d.key
	denies, isDeny := "", 0
	if d.denyReason != "" {
		var cur string
		err := tx.QueryRow(usageDeniesSQL, k.day, k.sub, k.agent, k.rule).Scan(&cur)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("analytics: fleet usage read: %w", err)
		}
		m := decodeDenies(cur)
		addDeny(m, d.denyReason, 1)
		denies, isDeny = encodeDenies(m), 1
	}
	if _, err := tx.Exec(usageUpsertSQL, k.day, k.sub, k.agent, k.rule, d.email, denies, d.cost, isDeny); err != nil {
		return fmt.Errorf("analytics: fleet usage upsert: %w", err)
	}
	return nil
}

// UsageByUser implements UserUsageQuerier with two parameterized queries on
// the read-only handle: the chosen users' rows, then the anonymous rows.
func (s *FleetSQLiteStore) UsageByUser(ctx context.Context, from, to time.Time, limit int) ([]UserUsage, error) {
	fromDay, toDay := UsageDay(from), UsageDay(to)
	n := usageLimit(limit)
	acc := newUsageAccumulator()
	if err := s.scanUsage(ctx, acc, usageByUserSQL, fromDay, toDay, fromDay, toDay, n); err != nil {
		return nil, err
	}
	if err := s.scanUsage(ctx, acc, usageAnonymousSQL, fromDay, toDay); err != nil {
		return nil, err
	}
	return acc.result(n), nil
}

func (s *FleetSQLiteStore) scanUsage(ctx context.Context, acc *usageAccumulator, q string, args ...any) error {
	rows, err := s.ro.QueryContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("analytics: usage by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			r      usageRecord
			denies string
		)
		if err := rows.Scan(&r.key.day, &r.key.sub, &r.key.agent, &r.key.rule, &r.email, &r.requests, &denies, &r.cost); err != nil {
			return fmt.Errorf("analytics: usage by user scan: %w", err)
		}
		r.denies = decodeDenies(denies)
		acc.add(r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("analytics: usage by user rows: %w", err)
	}
	return nil
}

// TodayCostByRule implements UserUsageQuerier with one parameterized query on
// the read-only handle.
func (s *FleetSQLiteStore) TodayCostByRule(ctx context.Context, day string) ([]UserRuleCost, error) {
	rows, err := s.ro.QueryContext(ctx, todayCostByRuleSQL, day)
	if err != nil {
		return nil, fmt.Errorf("analytics: today cost by rule: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []UserRuleCost{}
	for rows.Next() {
		var c UserRuleCost
		if err := rows.Scan(&c.Sub, &c.Rule, &c.CostUSD); err != nil {
			return nil, fmt.Errorf("analytics: today cost by rule scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("analytics: today cost by rule rows: %w", err)
	}
	return out, nil
}
