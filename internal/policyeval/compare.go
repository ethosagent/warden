package policyeval

import (
	"sort"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

// maxCompareGroups caps the groups kept per direction, so a replay of many
// distinct destinations cannot grow the stored result without bound. The
// events of dropped groups are summed in GroupsTruncated.
const maxCompareGroups = 500

// compareLimitations are fixed statements stored on every CompareResult so a
// reviewer reads what the replay did not model. They are constants: no event
// data, and no path separators (the stored result carries no `/`).
var compareLimitations = []string{
	"rate limits and time windows are not evaluated because they are stateful: both policies are replayed without them, and events that match an entry carrying one are counted as limit_governed",
	"the judge is not replayed: an event that matches neither list would go to the judge when it is enabled, and is counted as judge_count instead of as a plain deny",
	"identity-scoped entries use the identity recorded on the event, and an event without a valid identity is replayed as anonymous",
	"request path and method constraints are evaluated only when the event carries a url, which fleet replay does not read",
}

// CompareGroup is the events that exactly one of the two policies allows, for
// one destination and method. It holds no URL, path, query, header or group
// list.
type CompareGroup struct {
	Domain string `json:"domain"`
	Port   int    `json:"port"`
	Method string `json:"method"`
	Count  int    `json:"count"`
	// JudgeCount is how many of Count the policy that does not allow leaves to
	// the judge (no list matched) instead of denying outright: the draft's
	// NoMatch events in a changed_to_deny group, the base's in a
	// changed_to_allow group.
	JudgeCount int `json:"judge_count"`
	// LimitGoverned is how many of Count matched an entry carrying a rate limit
	// or time window on either side, whose real outcome depends on state this
	// replay does not model.
	LimitGoverned int `json:"limit_governed"`
	// AffectedUsers are the distinct users behind the events (email, else sub),
	// sorted and capped at MaxAffectedUsers; AffectedUsersTotal is the true count.
	AffectedUsers      []string `json:"affected_users"`
	AffectedUsersTotal int      `json:"affected_users_total"`
}

// CompareResult is the difference between two policies over the same events.
type CompareResult struct {
	// Events is the events evaluated; MCP events are skipped and counted in
	// SkippedMCP. Agreed is the events both policies treat alike.
	Events     int `json:"events"`
	Agreed     int `json:"agreed"`
	SkippedMCP int `json:"skipped_mcp"`
	// AnonymousCount is the disagreeing events replayed without a valid
	// recorded identity.
	AnonymousCount int `json:"anonymous_count"`
	// JudgeBase and JudgeDraft are the events each policy leaves to the judge
	// (no list matched), whether or not the other policy agrees.
	JudgeBase  int `json:"judge_base"`
	JudgeDraft int `json:"judge_draft"`
	// LimitGoverned is every evaluated event that matched an entry with a rate
	// limit or time window on either side.
	LimitGoverned   int            `json:"limit_governed"`
	ChangedToAllow  []CompareGroup `json:"changed_to_allow"`
	ChangedToDeny   []CompareGroup `json:"changed_to_deny"`
	GroupsTruncated int            `json:"groups_truncated"`
	Limitations     []string       `json:"limitations"`
}

type compareKey struct {
	domain  string
	port    int
	method  string
	toAllow bool
}

type compareAcc struct {
	count, judge, limited int
	users                 map[string]struct{}
}

// Comparer evaluates the same events under a base and a candidate policy with
// one stateless evaluator, so judge, DLP, block-list and rate-limit outcomes
// never show up as changes: only the lists differ. It is not safe for
// concurrent use.
type Comparer struct {
	base, cand *policy.Evaluator
	// baseLimited and candLimited hold only the entries that carry a rate limit
	// or time window (limits stripped), to count the events whose real outcome
	// depends on state.
	baseLimited, candLimited *policy.Evaluator
	accs                     map[compareKey]*compareAcc
	res                      CompareResult
}

// NewComparer builds a Comparer for base and candidate.
func NewComparer(base, candidate config.Policy) *Comparer {
	return &Comparer{
		base:        policy.NewEvaluator(statelessPolicy(base)),
		cand:        policy.NewEvaluator(statelessPolicy(candidate)),
		baseLimited: policy.NewEvaluator(limitedOnly(base)),
		candLimited: policy.NewEvaluator(limitedOnly(candidate)),
		accs:        map[compareKey]*compareAcc{},
	}
}

// limitedOnly keeps just the allow entries with a rate limit or time window,
// limits stripped, and no deny entries.
func limitedOnly(p config.Policy) config.Policy {
	out := config.Policy{}
	for _, e := range p.Allowlist {
		if e.RateLimit == "" && e.TimeWindow == "" {
			continue
		}
		e.RateLimit, e.TimeWindow = "", ""
		out.Allowlist = append(out.Allowlist, e)
	}
	return out
}

// Add replays one event under both policies. MCP events are skipped.
func (c *Comparer) Add(e analytics.Event) {
	if e.Protocol == "mcp" {
		c.res.SkippedMCP++
		return
	}
	rc := replayContext(e)
	bd := c.base.EvaluateFor(rc).Decision
	cd := c.cand.EvaluateFor(rc).Decision
	c.res.Events++
	if bd == policy.NoMatch {
		c.res.JudgeBase++
	}
	if cd == policy.NoMatch {
		c.res.JudgeDraft++
	}
	limited := c.baseLimited.EvaluateFor(rc).Decision == policy.Allow ||
		c.candLimited.EvaluateFor(rc).Decision == policy.Allow
	if limited {
		c.res.LimitGoverned++
	}
	// Conditional (a scoped entry without a valid identity) and NoMatch both
	// count as not allowed.
	baseAllow, candAllow := bd == policy.Allow, cd == policy.Allow
	if baseAllow == candAllow {
		c.res.Agreed++
		return
	}
	key := compareKey{domain: e.Domain, port: rc.Port, method: e.Method, toAllow: candAllow}
	acc := c.accs[key]
	if acc == nil {
		acc = &compareAcc{users: map[string]struct{}{}}
		c.accs[key] = acc
	}
	acc.count++
	if limited {
		acc.limited++
	}
	// The policy that does not allow is the one that may defer to the judge.
	if (candAllow && bd == policy.NoMatch) || (!candAllow && cd == policy.NoMatch) {
		acc.judge++
	}
	if rc.Subject == nil {
		c.res.AnonymousCount++
	} else if u := userLabel(e); u != "" {
		acc.users[u] = struct{}{}
	}
}

// Result returns the comparison so far, groups sorted by count descending then
// domain, port and method. It may be called more than once.
func (c *Comparer) Result() *CompareResult {
	out := c.res
	out.Limitations = append([]string(nil), compareLimitations...)
	out.ChangedToAllow = []CompareGroup{}
	out.ChangedToDeny = []CompareGroup{}
	for k, a := range c.accs {
		users := make([]string, 0, len(a.users))
		for u := range a.users {
			users = append(users, u)
		}
		sort.Strings(users)
		total := len(users)
		if len(users) > MaxAffectedUsers {
			users = users[:MaxAffectedUsers]
		}
		g := CompareGroup{
			Domain: k.domain, Port: k.port, Method: k.method, Count: a.count,
			JudgeCount: a.judge, LimitGoverned: a.limited,
			AffectedUsers: users, AffectedUsersTotal: total,
		}
		if k.toAllow {
			out.ChangedToAllow = append(out.ChangedToAllow, g)
		} else {
			out.ChangedToDeny = append(out.ChangedToDeny, g)
		}
	}
	for _, gs := range []*[]CompareGroup{&out.ChangedToAllow, &out.ChangedToDeny} {
		sortGroups(*gs)
		if len(*gs) > maxCompareGroups {
			for _, g := range (*gs)[maxCompareGroups:] {
				out.GroupsTruncated += g.Count
			}
			*gs = (*gs)[:maxCompareGroups]
		}
	}
	return &out
}

func sortGroups(gs []CompareGroup) {
	sort.Slice(gs, func(i, j int) bool {
		a, b := gs[i], gs[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Method < b.Method
	})
}
