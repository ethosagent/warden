package analytics

import (
	"context"
	"encoding/json"
	"maps"
	"math"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"
)

// The per-user daily usage rollup (W-P3-PUL-07). Each row is keyed by
// (UTC day, user sub, agent id, limit rule) and holds the request count, the
// deny count per bounded reason and the summed estimated cost. The fleet
// stores update it in the same step as the event insert and only when the
// insert stored a new row, so a worker re-sending a batch whose ack was lost
// never double counts. The rollup is kept UsageRetentionDays regardless of
// events retention and the events cap, so fleet cost totals (W-P3-PUL-08) and
// the usage view (W-P3-PUL-05) survive events pruning.
//
// It holds only identifiers and counters: sub, email, agent id, rule name,
// deny reason enums, counts and cost. Never a URL, header, body, secret
// reference or secret value.

const (
	// AnonymousLimitRule is the reserved rule name of policy.anonymousLimit
	// (W-P3-PUL-01). Events under it carry no sub but are rolled up (sub "")
	// so anonymous spend per agent is visible.
	AnonymousLimitRule = "anonymous"
	// UsageRetentionDays is how many UTC days of rollup are kept, today
	// included.
	UsageRetentionDays = 35
	// MaxUsageUsers caps the attributed users UsageByUser returns.
	MaxUsageUsers = 1000

	// maxDenyReasons bounds the distinct reason keys per rollup row and
	// maxDenyReasonLen each key's length; anything past either is counted
	// under denyReasonOther, so a misbehaving worker cannot grow a row.
	maxDenyReasons   = 32
	maxDenyReasonLen = 64
	// denyReasonUnspecified counts deny events from workers that set no reason.
	denyReasonUnspecified = "unspecified"
	denyReasonOther       = "other"

	// Caps on the identifier columns of a rollup row (see truncateUTF8).
	maxUsageSubLen   = 255
	maxUsageEmailLen = 320
	maxUsageAgentLen = 128
	// usageRuleInvalid is the rollup key for a limit rule name outside the
	// rule-name charset or over 64 bytes (see usageRule).
	usageRuleInvalid = "!invalid"
	// maxUsageRows caps the in-memory rollup's rows; past it new keys are
	// refused and counted (CentralStore.UsageRowsRefused), existing rows keep
	// counting.
	maxUsageRows = 200000
)

// usageRuleRE is the rule-name charset: the agent-id charset W-P3-PUL-01
// uses for userLimits names.
var usageRuleRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// UserUsageQuerier is the read side of the rollup. FleetSQLiteStore answers it
// with parameterized SQL over user_usage_daily and CentralStore in Go; a later
// Postgres fleet store implements the same interface. Callers type-assert it
// from a FleetStore.
type UserUsageQuerier interface {
	// UsageByUser totals every UTC day from from's day to to's day, both
	// inclusive (the rollup is day-granular). It returns up to limit
	// attributed users (limit <= 0 or above MaxUsageUsers means
	// MaxUsageUsers) ordered by cost desc, requests desc, sub asc, chosen
	// over the whole window. When anonymous-rule usage exists in the window
	// one more row with Sub "" is appended last; it does not count towards
	// limit.
	UsageByUser(ctx context.Context, from, to time.Time, limit int) ([]UserUsage, error)
	// TodayCostByRule returns the summed cost per (sub, rule) for one UTC
	// day (UsageDay format), over every agent, sorted by sub then rule. Rows
	// with no sub (anonymous) or no rule are left out: only an attributed
	// user under a named rule can be over a dailyCostUSD cap (W-P3-PUL-08).
	TodayCostByRule(ctx context.Context, day string) ([]UserRuleCost, error)
}

var (
	_ UserUsageQuerier = (*FleetSQLiteStore)(nil)
	_ UserUsageQuerier = (*CentralStore)(nil)
)

// UserUsage is one user's totals over a window. Sub and Email are IdP claim
// values: callers must render them as text, never as markup.
type UserUsage struct {
	// Sub is the verified OIDC subject; "" only on the anonymous row.
	Sub string `json:"sub"`
	// Email is the email from the latest day in the window that had one.
	Email    string `json:"email"`
	Requests int64  `json:"requests"`
	// Denies counts deny events by bounded reason. Never nil.
	Denies  map[string]int64 `json:"denies"`
	CostUSD float64          `json:"costUSD"`
	// Agents and Rules split the totals by agent id and by limit rule ("" for
	// events no rule applied to), each ordered by cost desc, requests desc,
	// then name. Never nil.
	Agents []AgentUsage `json:"agents"`
	Rules  []RuleUsage  `json:"rules"`
}

// AgentUsage is one agent's share of a user's usage.
type AgentUsage struct {
	AgentID  string  `json:"agentID"`
	Requests int64   `json:"requests"`
	CostUSD  float64 `json:"costUSD"`
}

// RuleUsage is one limit rule's share of a user's usage.
type RuleUsage struct {
	Rule     string  `json:"rule"`
	Requests int64   `json:"requests"`
	CostUSD  float64 `json:"costUSD"`
}

// UserRuleCost is one user's estimated spend under one rule on one day.
type UserRuleCost struct {
	Sub     string  `json:"sub"`
	Rule    string  `json:"rule"`
	CostUSD float64 `json:"costUSD"`
}

// UsageDay is the rollup's day key for t: its UTC calendar date, YYYY-MM-DD.
// Day boundaries are UTC everywhere in the per-user limits feature.
func UsageDay(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// usageCutoffDay is the oldest day kept at now: rows with day < it are pruned.
func usageCutoffDay(now time.Time) string {
	return UsageDay(now.UTC().AddDate(0, 0, -(UsageRetentionDays - 1)))
}

// usageKey identifies one rollup row.
type usageKey struct {
	day, sub, agent, rule string
}

// usageDelta is what one stored event adds to its rollup row.
type usageDelta struct {
	key        usageKey
	email      string
	cost       float64
	denyReason string // "" when the event is not a deny
}

// usageDeltaFor maps a stored event to its rollup delta. ok is false for
// events the rollup does not count: no sub and not under the anonymous rule,
// or a day already past the retention horizon at now (a late batch from a
// long-offline worker, which the next prune would drop anyway). e.AgentID
// must already be the resolved agent.
func usageDeltaFor(e Event, now time.Time) (usageDelta, bool) {
	if e.UserSub == "" && e.LimitRule != AnonymousLimitRule {
		return usageDelta{}, false
	}
	// The day is the worker's event time in UTC, clamped to the CP's today:
	// a future-dated event (worker clock skew, or a sender trying to park
	// spend on a day that has not started) counts toward today.
	day := min(UsageDay(e.Timestamp), UsageDay(now))
	if day < usageCutoffDay(now) {
		return usageDelta{}, false
	}
	d := usageDelta{
		key: usageKey{
			day:   day,
			sub:   truncateUTF8(e.UserSub, maxUsageSubLen),
			agent: truncateUTF8(e.AgentID, maxUsageAgentLen),
			rule:  usageRule(e.LimitRule),
		},
		email: truncateUTF8(e.UserEmail, maxUsageEmailLen),
		cost:  e.CostUSD,
	}
	if e.UserSub == "" {
		d.email = ""
	}
	// A sender cannot lower a user's spend: negative and non-finite costs add
	// nothing.
	if d.cost < 0 || math.IsNaN(d.cost) || math.IsInf(d.cost, 0) {
		d.cost = 0
	}
	if e.Decision == "deny" {
		d.denyReason = e.Reason
		if d.denyReason == "" {
			d.denyReason = denyReasonUnspecified
		}
	}
	return d, true
}

// usageRule maps a limit rule name to its rollup key: "" and names in the
// rule-name charset (the agent-id charset, at most 64 bytes) are
// kept, anything else becomes usageRuleInvalid. That value is outside the
// charset, so it never equals a configured rule and W-P3-PUL-08 never charges
// it to a real rule's cap.
func usageRule(rule string) string {
	if rule == "" || usageRuleRE.MatchString(rule) {
		return rule
	}
	return usageRuleInvalid
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune. Caps are
// well above real values (OIDC limits sub to 255 ASCII characters); cutting
// can only merge two pathological values, which over-counts rather than lets
// spend escape a cap.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// addDeny counts one deny under reason in m, bounded by maxDenyReasons and
// maxDenyReasonLen.
func addDeny(m map[string]int64, reason string, n int64) {
	if len(reason) > maxDenyReasonLen {
		reason = denyReasonOther
	}
	if _, ok := m[reason]; !ok && len(m) >= maxDenyReasons {
		reason = denyReasonOther
	}
	m[reason] += n
}

// decodeDenies parses a denies_json value; "" and malformed values give an
// empty map (the column is written only by this package).
func decodeDenies(s string) map[string]int64 {
	m := map[string]int64{}
	if s != "" {
		_ = json.Unmarshal([]byte(s), &m)
	}
	return m
}

func encodeDenies(m map[string]int64) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

// usageRow is one rollup row's counters.
type usageRow struct {
	email    string
	requests int64
	denies   map[string]int64
	cost     float64
}

// usageRollup is the in-memory rollup behind CentralStore. The caller holds
// the store's lock.
type usageRollup struct {
	rows    map[usageKey]*usageRow
	maxRows int
	// refused counts events whose new row was refused at maxRows.
	refused uint64
	// prunedFor is the cutoff day of the last prune, so the O(rows) sweep runs
	// once per UTC day rather than on every event.
	prunedFor string
}

func newUsageRollup() *usageRollup {
	return &usageRollup{rows: map[usageKey]*usageRow{}, maxRows: maxUsageRows}
}

func (u *usageRollup) add(e Event, now time.Time) {
	d, ok := usageDeltaFor(e, now)
	if !ok {
		return
	}
	r := u.rows[d.key]
	if r == nil {
		if len(u.rows) >= u.maxRows {
			u.refused++
			return
		}
		r = &usageRow{denies: map[string]int64{}}
		u.rows[d.key] = r
	}
	r.requests++
	r.cost += d.cost
	if d.email != "" {
		r.email = d.email
	}
	if d.denyReason != "" {
		addDeny(r.denies, d.denyReason, 1)
	}
}

func (u *usageRollup) prune(now time.Time) {
	cutoff := usageCutoffDay(now)
	if cutoff == u.prunedFor {
		return
	}
	for k := range u.rows {
		if k.day < cutoff {
			delete(u.rows, k)
		}
	}
	u.prunedFor = cutoff
}

// usageRecord is one rollup row as read for aggregation.
type usageRecord struct {
	key usageKey
	usageRow
}

// usageAccumulator folds rollup rows into per-user totals.
type usageAccumulator struct {
	users  map[string]*userAgg
	byUser []string
}

type userAgg struct {
	UserUsage
	emailDay string
	agents   map[string]*AgentUsage
	rules    map[string]*RuleUsage
}

func newUsageAccumulator() *usageAccumulator {
	return &usageAccumulator{users: map[string]*userAgg{}}
}

func (a *usageAccumulator) add(r usageRecord) {
	u := a.users[r.key.sub]
	if u == nil {
		u = &userAgg{
			UserUsage: UserUsage{Sub: r.key.sub, Denies: map[string]int64{}},
			agents:    map[string]*AgentUsage{},
			rules:     map[string]*RuleUsage{},
		}
		a.users[r.key.sub] = u
		a.byUser = append(a.byUser, r.key.sub)
	}
	u.Requests += r.requests
	u.CostUSD += r.cost
	for reason, n := range r.denies {
		addDeny(u.Denies, reason, n)
	}
	if r.email != "" && r.key.day >= u.emailDay {
		u.Email, u.emailDay = r.email, r.key.day
	}
	ag := u.agents[r.key.agent]
	if ag == nil {
		ag = &AgentUsage{AgentID: r.key.agent}
		u.agents[r.key.agent] = ag
	}
	ag.Requests += r.requests
	ag.CostUSD += r.cost
	ru := u.rules[r.key.rule]
	if ru == nil {
		ru = &RuleUsage{Rule: r.key.rule}
		u.rules[r.key.rule] = ru
	}
	ru.Requests += r.requests
	ru.CostUSD += r.cost
}

// result returns up to limit attributed users ordered by cost desc, requests
// desc, sub asc, then the anonymous row (Sub "") when present.
func (a *usageAccumulator) result(limit int) []UserUsage {
	out := make([]UserUsage, 0, len(a.users))
	var anon *UserUsage
	for _, sub := range a.byUser {
		u := a.users[sub]
		u.Agents = make([]AgentUsage, 0, len(u.agents))
		for _, ag := range u.agents {
			u.Agents = append(u.Agents, *ag)
		}
		sort.Slice(u.Agents, func(i, j int) bool {
			return usageLess(u.Agents[i].CostUSD, u.Agents[j].CostUSD, u.Agents[i].Requests, u.Agents[j].Requests, u.Agents[i].AgentID, u.Agents[j].AgentID)
		})
		u.Rules = make([]RuleUsage, 0, len(u.rules))
		for _, ru := range u.rules {
			u.Rules = append(u.Rules, *ru)
		}
		sort.Slice(u.Rules, func(i, j int) bool {
			return usageLess(u.Rules[i].CostUSD, u.Rules[j].CostUSD, u.Rules[i].Requests, u.Rules[j].Requests, u.Rules[i].Rule, u.Rules[j].Rule)
		})
		if sub == "" {
			uu := u.UserUsage
			anon = &uu
			continue
		}
		out = append(out, u.UserUsage)
	}
	sort.Slice(out, func(i, j int) bool {
		return usageLess(out[i].CostUSD, out[j].CostUSD, out[i].Requests, out[j].Requests, out[i].Sub, out[j].Sub)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	if anon != nil {
		out = append(out, *anon)
	}
	return out
}

// usageLess orders by cost desc, then requests desc, then name asc.
func usageLess(ci, cj float64, ri, rj int64, ni, nj string) bool {
	if ci != cj {
		return ci > cj
	}
	if ri != rj {
		return ri > rj
	}
	return ni < nj
}

// usageLimit normalises a UsageByUser limit.
func usageLimit(limit int) int {
	if limit <= 0 || limit > MaxUsageUsers {
		return MaxUsageUsers
	}
	return limit
}

// UsageByUser implements UserUsageQuerier over the in-memory rollup.
func (c *CentralStore) UsageByUser(ctx context.Context, from, to time.Time, limit int) ([]UserUsage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fromDay, toDay := UsageDay(from), UsageDay(to)
	// Copy the window's rows under the read lock (deny maps cloned, since
	// ingest mutates them under the write lock), then aggregate and sort
	// without holding it.
	var recs []usageRecord
	c.mu.RLock()
	for k, r := range c.usage.rows {
		if k.day < fromDay || k.day > toDay {
			continue
		}
		recs = append(recs, usageRecord{key: k, usageRow: usageRow{email: r.email, requests: r.requests, cost: r.cost, denies: maps.Clone(r.denies)}})
	}
	c.mu.RUnlock()
	acc := newUsageAccumulator()
	for _, rec := range recs {
		acc.add(rec)
	}
	return acc.result(usageLimit(limit)), nil
}

// TodayCostByRule implements UserUsageQuerier over the in-memory rollup.
func (c *CentralStore) TodayCostByRule(ctx context.Context, day string) ([]UserRuleCost, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type subRule struct{ sub, rule string }
	sums := map[subRule]float64{}
	c.mu.RLock()
	for k, r := range c.usage.rows {
		if k.day != day || k.sub == "" || k.rule == "" {
			continue
		}
		sums[subRule{k.sub, k.rule}] += r.cost
	}
	c.mu.RUnlock()
	out := make([]UserRuleCost, 0, len(sums))
	for k, v := range sums {
		out = append(out, UserRuleCost{Sub: k.sub, Rule: k.rule, CostUSD: v})
	}
	sortUserRuleCosts(out)
	return out, nil
}

// UsageRowsRefused reports how many events the in-memory rollup did not count
// because it was at its row cap.
func (c *CentralStore) UsageRowsRefused() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.usage.refused
}

func sortUserRuleCosts(out []UserRuleCost) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sub != out[j].Sub {
			return out[i].Sub < out[j].Sub
		}
		return out[i].Rule < out[j].Rule
	})
}
