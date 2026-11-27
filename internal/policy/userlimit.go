package policy

import (
	"encoding/json"
	"hash/fnv"
	"hash/maphash"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// Per-user limits (W-P3-PUL-03). The evaluator picks the ONE rule that applies
// to a request and charges that rule's fixed-window rate bucket. This file only
// answers "is there budget"; the proxy calls it after the policy allow decision
// (W-P3-PUL-09), so a limit can only turn an allow into a deny, never the
// other way round.
//
// Selection, in order: rules matching by users, then by groups, then
// agents-only rules, then defaultUserLimit; within a tier the first rule in
// list order whose match fields all match wins. A rule's tier is its first
// non-empty field of users, groups, agents; every other field it sets narrows
// it (a users rule that also lists groups needs both). Users match by exact
// sub, or by email only when the subject's email is verified. A nil subject,
// or one with an empty sub, uses only anonymousLimit, keyed by the worker's
// agent id, and is never charged to a user's bucket. When the subject's group
// list was truncated and an outranking rule missed only on its groups, the
// result is Deny with identity_groups_truncated (fail closed, as the allowlist
// does), never a fall-through to a looser rule or to no limit.
//
// Everything a match needs is compiled at policy load, so a match is a few map
// lookups and allocates nothing. Buckets live in a sharded map that load()
// never re-makes; Replace drops only the buckets of rules that were removed or
// whose definition changed.

const (
	// maxUserLimitBuckets bounds the bucket table. At the cap, after a sweep, a
	// charge that needs a new bucket is denied (fail closed) and counted.
	maxUserLimitBuckets = 100000
	// userLimitShards is the number of independently locked bucket shards.
	userLimitShards = 64
	// userLimitSweepEvery is how often a sweep pass over the shards starts; the
	// pass is amortized over the next charges, one shard per charge.
	userLimitSweepEvery = time.Minute
	// userLimitCapSweepEvery throttles the full sweep a full table triggers, so
	// a flood of new keys at the cap does not sweep on every request.
	userLimitCapSweepEvery = time.Second
	// anonBucketSub is the sub slot of an anonymous bucket key.
	anonBucketSub = "anon"
)

// UserLimitRule is what a caller outside the rate path needs about the rule
// that applies to a request: the worker's cost ledger (W-P3-PUL-04) keys on
// Name and caps at DailyCostUSD (0 means no cap).
type UserLimitRule struct {
	Name         string
	DailyCostUSD float64
	PerAgent     bool
}

// compiledUserLimit is one rule as load() compiled it.
type compiledUserLimit struct {
	name string
	// subs and emails are the users field (emails lowercased); groups are
	// exact. A nil set means the field is not set.
	subs, emails, groups map[string]struct{}
	// agents is the agents field, sorted (config caps it); a short slice
	// compares faster than a map lookup for the usual one or two ids.
	agents []string
	// domains are the match domains; domainRes[i] is the compiled regex of a
	// "~regex" domains[i] (nil for the other dialects, or a regex that did not
	// compile, which then matches nothing).
	domains      []string
	domainRes    []*regexp.Regexp
	rate         RateLimit
	hasRate      bool
	dailyCostUSD float64
	perAgent     bool
	// rank orders rules by precedence (tier, then list order); lower wins.
	rank int32
	// defHash is a hash of the rule's canonical (normalized) definition. A
	// bucket remembers the hash of the rule that opened it; a different hash
	// means the rule changed and the bucket starts over.
	defHash uint64
}

// userLimitSet is the compiled rule set of one policy. Index lists hold
// positions in rules, ascending, so the first passing entry is the first rule
// in list order.
type userLimitSet struct {
	rules   []compiledUserLimit
	bySub   map[string][]int32 // users tier, by sub
	byEmail map[string][]int32 // users tier, by lowercased email
	byGroup map[string][]int32 // groups tier, rules not narrowed by agent
	// byAgentGroup is the groups tier for rules also narrowed by agents, by
	// agent then group, so a group shared by many agent-narrowed rules costs
	// one lookup instead of a walk over every one of them.
	byAgentGroup map[string]map[string][]int32
	byAgent      map[string][]int32 // agents-only tier
	def          *compiledUserLimit
	anon         *compiledUserLimit
	// groupRules is every groups-tier rule, ascending. Only the truncated
	// group list path walks it (see truncatedCandidate).
	groupRules []int32
	// hashes is every rule's defHash by name, default and anonymous included.
	hashes map[string]uint64
}

// compileUserLimits compiles p's per-user limit rules, or returns nil when p
// has none (the evaluator's no-limits fast path).
func compileUserLimits(p config.Policy) *userLimitSet {
	if len(p.UserLimits) == 0 && p.DefaultUserLimit == nil && p.AnonymousLimit == nil {
		return nil
	}
	ls := &userLimitSet{hashes: make(map[string]uint64, len(p.UserLimits)+2)}
	add := func(m map[string][]int32, k string, i int32) map[string][]int32 {
		if m == nil {
			m = make(map[string][]int32)
		}
		m[k] = append(m[k], i)
		return m
	}
	ls.rules = make([]compiledUserLimit, 0, len(p.UserLimits))
	n := int32(len(p.UserLimits))
	for _, l := range p.UserLimits {
		i := int32(len(ls.rules))
		r := compileUserLimit(l, l.Name)
		switch {
		case len(l.Match.Users) > 0:
			r.rank = i
		case len(l.Match.Groups) > 0:
			r.rank = n + i
			ls.groupRules = append(ls.groupRules, i)
		case len(l.Match.Agents) > 0:
			r.rank = 2*n + i
		default:
			r.rank = rankNone
		}
		switch {
		case len(l.Match.Users) > 0:
			for s := range r.subs {
				ls.bySub = add(ls.bySub, s, i)
			}
			for em := range r.emails {
				ls.byEmail = add(ls.byEmail, em, i)
			}
		case len(l.Match.Groups) > 0 && len(r.agents) > 0:
			if ls.byAgentGroup == nil {
				ls.byAgentGroup = make(map[string]map[string][]int32)
			}
			for _, a := range r.agents {
				m := ls.byAgentGroup[a]
				for g := range r.groups {
					m = add(m, g, i)
				}
				ls.byAgentGroup[a] = m
			}
		case len(l.Match.Groups) > 0:
			for g := range r.groups {
				ls.byGroup = add(ls.byGroup, g, i)
			}
		case len(l.Match.Agents) > 0:
			for _, a := range r.agents {
				if len(ls.byAgent[a]) == 0 || ls.byAgent[a][len(ls.byAgent[a])-1] != i {
					ls.byAgent = add(ls.byAgent, a, i)
				}
			}
		default:
			// Config refuses a rule with no users, groups or agents; one that
			// got here anyway is indexed nowhere and never matches.
		}
		ls.rules = append(ls.rules, r)
		ls.hashes[r.name] = r.defHash
	}
	if l := p.DefaultUserLimit; l != nil {
		r := compileUserLimit(*l, config.UserLimitNameDefault)
		r.rank = 3 * n
		ls.def = &r
		ls.hashes[r.name] = r.defHash
	}
	if l := p.AnonymousLimit; l != nil {
		r := compileUserLimit(*l, config.UserLimitNameAnonymous)
		ls.anon = &r
		ls.hashes[r.name] = r.defHash
	}
	return ls
}

func compileUserLimit(l config.UserLimit, name string) compiledUserLimit {
	l.Name = name
	r := compiledUserLimit{name: name, dailyCostUSD: l.DailyCostUSD, perAgent: l.PerAgent}
	for _, u := range l.Match.Users {
		if strings.Contains(u, "@") {
			r.emails = addToSet(r.emails, strings.ToLower(u))
		} else {
			r.subs = addToSet(r.subs, u)
		}
	}
	for _, g := range l.Match.Groups {
		r.groups = addToSet(r.groups, g)
	}
	if len(l.Match.Agents) > 0 {
		r.agents = append([]string(nil), l.Match.Agents...)
	}
	if n := len(l.Match.Domains); n > 0 {
		r.domains = append([]string(nil), l.Match.Domains...)
		r.domainRes = make([]*regexp.Regexp, n)
		for i, d := range r.domains {
			if rx, ok := strings.CutPrefix(d, "~"); ok {
				if re, err := regexp.Compile(rx); err == nil {
					r.domainRes[i] = re
				}
			}
		}
	}
	if l.RateLimit != "" {
		if rl, err := ParseRateLimit(l.RateLimit); err == nil {
			r.rate, r.hasRate = rl, true
		}
	}
	r.defHash = userLimitDefHash(l)
	return r
}

func addToSet(m map[string]struct{}, v string) map[string]struct{} {
	if m == nil {
		m = make(map[string]struct{})
	}
	m[v] = struct{}{}
	return m
}

// userLimitDefHash hashes the rule's canonical definition. Config normalizes
// rules at load (match lists sorted and deduplicated), so the JSON form is
// canonical and two spellings of one rule hash alike.
func userLimitDefHash(l config.UserLimit) uint64 {
	b, err := json.Marshal(l)
	if err != nil {
		// Not reachable for this plain struct; a zero hash only means the
		// buckets of this rule are reset on the next Replace.
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}

// rankNone is the rank of no rule at all; it loses to every rule.
const rankNone = int32(1 << 30)

// match returns the rule that applies, or nil. host is already normalized.
//
// truncated is true when the subject's group list was cut (GroupsTruncated)
// and a rule that outranks the result was skipped only because none of its
// groups was in the list: the missing group may be the one the cut dropped, so
// the caller fails closed (identity_groups_truncated) instead of falling
// through to a looser rule or to no limit at all. r is then that skipped rule.
func (ls *userLimitSet) match(s *identity.Subject, agentID, host string) (r *compiledUserLimit, truncated bool) {
	r = ls.matchIndexed(s, agentID, host)
	if s == nil || s.Sub == "" || !s.GroupsTruncated {
		return r, false
	}
	c := ls.truncatedCandidate(s, agentID, host)
	if c != nil && (r == nil || c.rank < r.rank) {
		return c, true
	}
	return r, false
}

// truncatedCandidate returns the highest-precedence rule that sets groups,
// misses on them, and matches on every other field (users for a users rule,
// agents, domains), or nil. It runs only for a truncated group list, so the
// linear walk of the groups tier stays off the common path.
func (ls *userLimitSet) truncatedCandidate(s *identity.Subject, agentID, host string) *compiledUserLimit {
	var best *compiledUserLimit
	consider := func(i int32) {
		r := &ls.rules[i]
		if r.groups == nil || r.hasGroup(s) || !r.matches(tierGroups, s, agentID, host) {
			return
		}
		if best == nil || r.rank < best.rank {
			best = r
		}
	}
	for _, i := range ls.bySub[s.Sub] {
		consider(i)
	}
	if s.EmailVerified && s.Email != "" {
		for _, i := range ls.byEmail[strings.ToLower(s.Email)] {
			consider(i)
		}
	}
	if best != nil {
		return best // a users-tier rule outranks every groups-tier one
	}
	for _, i := range ls.groupRules {
		consider(i)
		if best != nil {
			return best // ascending: the first one found is the best
		}
	}
	return nil
}

// matchIndexed is the selection walk over the tier indexes.
func (ls *userLimitSet) matchIndexed(s *identity.Subject, agentID, host string) *compiledUserLimit {
	if s == nil || s.Sub == "" {
		return ls.anon
	}
	// Users tier: the lowest-index rule naming the sub or the verified email.
	best := ls.first(ls.bySub[s.Sub], -1, tierUsers, s, agentID, host)
	if s.EmailVerified && s.Email != "" {
		if i := ls.first(ls.byEmail[strings.ToLower(s.Email)], best, tierUsers, s, agentID, host); i >= 0 {
			best = i
		}
	}
	if best >= 0 {
		return &ls.rules[best]
	}
	// Groups tier: the lowest-index rule naming any of the subject's groups.
	agentGroups := ls.byAgentGroup[agentID]
	if ls.byGroup != nil || agentGroups != nil {
		for _, g := range s.Groups {
			if i := ls.first(ls.byGroup[g], best, tierGroups, s, agentID, host); i >= 0 {
				best = i
			}
			if agentGroups != nil {
				if i := ls.first(agentGroups[g], best, tierGroups, s, agentID, host); i >= 0 {
					best = i
				}
			}
		}
		if best >= 0 {
			return &ls.rules[best]
		}
	}
	if i := ls.first(ls.byAgent[agentID], -1, tierAgents, s, agentID, host); i >= 0 {
		return &ls.rules[i]
	}
	return ls.def
}

type userLimitTier uint8

const (
	tierUsers userLimitTier = iota
	tierGroups
	tierAgents
)

// first returns the first index in list below limit (limit < 0: no bound)
// whose rule fully matches, or -1. The field the list was indexed by is known
// to match and is not checked again.
func (ls *userLimitSet) first(list []int32, limit int32, tier userLimitTier, s *identity.Subject, agentID, host string) int32 {
	for _, i := range list {
		if limit >= 0 && i >= limit {
			return -1
		}
		if ls.rules[i].matches(tier, s, agentID, host) {
			return i
		}
	}
	return -1
}

// matches checks every match field of r except the one its tier index already
// satisfied.
func (r *compiledUserLimit) matches(tier userLimitTier, s *identity.Subject, agentID, host string) bool {
	if tier != tierGroups && r.groups != nil && !r.hasGroup(s) {
		return false
	}
	if tier != tierAgents && r.agents != nil && !containsString(r.agents, agentID) {
		return false
	}
	if len(r.domains) > 0 && !r.matchesDomain(host) {
		return false
	}
	return true
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (r *compiledUserLimit) hasGroup(s *identity.Subject) bool {
	for _, g := range s.Groups {
		if _, ok := r.groups[g]; ok {
			return true
		}
	}
	return false
}

// matchesDomain uses the allowlist dialect; an empty host matches nothing.
func (r *compiledUserLimit) matchesDomain(host string) bool {
	if host == "" {
		return false
	}
	for i, d := range r.domains {
		if strings.HasPrefix(d, "~") {
			if re := r.domainRes[i]; re != nil && re.MatchString(host) {
				return true
			}
			continue
		}
		if MatchDomain(d, host) {
			return true
		}
	}
	return false
}

// bucketKey is the key of a rate bucket: rule name, the user's sub (or
// anonBucketSub) and the agent id when the rule is per-agent or anonymous.
// userBucketKey renders it.
type bucketKey struct {
	rule, sub, agent string
}

func (r *compiledUserLimit) bucketKey(s *identity.Subject, agentID string) bucketKey {
	if s == nil || s.Sub == "" {
		return bucketKey{rule: r.name, sub: anonBucketSub, agent: agentID}
	}
	k := bucketKey{rule: r.name, sub: s.Sub}
	if r.perAgent {
		k.agent = agentID
	}
	return k
}

// userBucketKey renders a bucket key as `ul:<name>:<sub>` plus `:<agentID>`
// when the rule is per-agent, or `ul:anonymous:anon:<agentID>` for an
// anonymous request. It is the documented form; the table itself keys on the
// struct so a lookup never builds a string.
func userBucketKey(rule, sub, agentID string, perAgent, anon bool) string {
	if anon {
		return "ul:" + rule + ":" + anonBucketSub + ":" + agentID
	}
	if perAgent {
		return "ul:" + rule + ":" + sub + ":" + agentID
	}
	return "ul:" + rule + ":" + sub
}

// ChargeUserLimit applies the per-user limit rule that matches rc.Subject,
// agentID and rc.Domain and consumes one request from its rate budget. Over
// the limit it returns Deny with user_rate_limited, LimitRule and RetryAfter;
// otherwise Allow with LimitRule (empty when no rule applies). A truncated
// group list that may hide the applicable rule is Deny with
// identity_groups_truncated and that rule's name. A rule with no
// rateLimit (cost cap only) always allows here. With no limits configured it
// takes one read lock and allocates nothing.
func (e *Evaluator) ChargeUserLimit(rc RequestContext, agentID string) RequestVerdict {
	return e.userLimit(rc, agentID, false)
}

// PeekUserLimit is ChargeUserLimit without consuming budget and without
// opening a bucket: it denies only when the rule's existing bucket is already
// exhausted. It backs the TLS-terminated CONNECT, where the per-request charge
// is authoritative.
func (e *Evaluator) PeekUserLimit(rc RequestContext, agentID string) RequestVerdict {
	return e.userLimit(rc, agentID, true)
}

func (e *Evaluator) userLimit(rc RequestContext, agentID string, peek bool) RequestVerdict {
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()
	ls := e.userLimits
	if ls == nil {
		return RequestVerdict{Decision: Allow}
	}
	r, truncated := ls.match(rc.Subject, agentID, NormalizeHost(rc.Domain))
	if truncated {
		return RequestVerdict{Decision: Deny, Reason: denyreason.IdentityGroupsTruncated, LimitRule: r.name}
	}
	if r == nil {
		return RequestVerdict{Decision: Allow}
	}
	v := RequestVerdict{Decision: Allow, LimitRule: r.name}
	if !r.hasRate {
		return v
	}
	now := e.now().UnixNano()
	if !peek {
		e.ub.maybeSweep(now)
	}
	if ok, retry := e.ub.charge(r.bucketKey(rc.Subject, agentID), r, now, peek); !ok {
		v.Decision, v.Reason, v.RetryAfter = Deny, denyreason.UserRateLimited, retry
	}
	return v
}

// MatchUserLimit reports the rule that applies to subj on agentID for domain,
// without touching any bucket. The worker's cost cap (W-P3-PUL-04) uses it.
func (e *Evaluator) MatchUserLimit(subj *identity.Subject, agentID, domain string) (UserLimitRule, bool) {
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()
	if e.userLimits == nil {
		return UserLimitRule{}, false
	}
	// On a truncated miss this is the skipped rule, so a cost check made
	// without a charge still applies the stricter rule (fail closed).
	r, _ := e.userLimits.match(subj, agentID, NormalizeHost(domain))
	if r == nil {
		return UserLimitRule{}, false
	}
	return UserLimitRule{Name: r.name, DailyCostUSD: r.dailyCostUSD, PerAgent: r.perAgent}, true
}

// UserLimitBuckets is the number of open per-user rate buckets, for the
// warden.user_limit.buckets gauge.
func (e *Evaluator) UserLimitBuckets() int { return int(e.ub.n.Load()) }

// UserLimitCapDenials counts charges denied because the bucket table was full.
func (e *Evaluator) UserLimitCapDenials() uint64 { return e.ub.capDenied.Load() }

// costBlockKey is one fleet cost block: sub over rule on day (yyyymmdd, UTC).
type costBlockKey struct {
	sub, rule string
	day       int32
}

func civilDay(y int, m time.Month, d int) int32 { return int32(y*10000 + int(m)*100 + d) }

// compileCostBlocked builds the cost block set from the wire list. An entry
// whose day does not parse is skipped (the worker validates the list on every
// pull, so this is only a backstop).
func compileCostBlocked(list []config.CostBlockedUser) map[costBlockKey]struct{} {
	if len(list) == 0 {
		return nil
	}
	m := make(map[costBlockKey]struct{}, len(list))
	for _, c := range list {
		d, err := time.Parse(time.DateOnly, c.Day)
		if err != nil || c.Sub == "" {
			continue
		}
		m[costBlockKey{sub: c.Sub, rule: c.Rule, day: civilDay(d.Date())}] = struct{}{}
	}
	return m
}

// IsCostBlocked reports whether the control plane listed sub as over rule's
// daily cost cap for now's UTC day. Entries for any other day are ignored, so
// a block lapses at UTC midnight even when the control plane is unreachable.
func (e *Evaluator) IsCostBlocked(sub, rule string, now time.Time) bool {
	if sub == "" {
		return false
	}
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()
	if len(e.costBlocked) == 0 {
		return false
	}
	_, ok := e.costBlocked[costBlockKey{sub: sub, rule: rule, day: civilDay(now.UTC().Date())}]
	return ok
}

// userBucket is one fixed rate window.
type userBucket struct {
	count     int
	windowEnd int64 // unix nanoseconds; the window is [start, windowEnd)
	defHash   uint64
}

type bucketShard struct {
	mu sync.Mutex
	m  map[bucketKey]userBucket
}

// userBuckets is the sharded per-user bucket table. It outlives every policy
// swap; see dropChanged.
type userBuckets struct {
	seed   maphash.Seed
	max    int64
	shards [userLimitShards]bucketShard
	// n counts buckets in the table plus in-flight reservations.
	n         atomic.Int64
	capDenied atomic.Uint64
	// nextSweep is when the next sweep pass starts (unix ns); cursor is the
	// next shard the running pass sweeps (>= userLimitShards: no pass running).
	nextSweep atomic.Int64
	cursor    atomic.Int64
	// lastCapSweep is when a full table last triggered a full sweep.
	lastCapSweep atomic.Int64
}

func newUserBuckets(maxBuckets int64) *userBuckets {
	b := &userBuckets{seed: maphash.MakeSeed(), max: maxBuckets}
	for i := range b.shards {
		b.shards[i].m = make(map[bucketKey]userBucket)
	}
	b.cursor.Store(userLimitShards)
	b.lastCapSweep.Store(-int64(userLimitCapSweepEvery))
	return b
}

func (b *userBuckets) shard(k bucketKey) *bucketShard {
	h := maphash.String(b.seed, k.sub) ^ maphash.String(b.seed, k.agent)*31
	return &b.shards[h%userLimitShards]
}

// charge consumes one request from k's window (peek: only reports whether
// one is left). ok is false when the window is exhausted, or when k is new and
// the table is full after a sweep; retryAfter is then the time until the
// window ends (the rule's window for a cap denial).
func (b *userBuckets) charge(k bucketKey, r *compiledUserLimit, now int64, peek bool) (ok bool, retryAfter time.Duration) {
	sh := b.shard(k)
	reserved := false
	for {
		sh.mu.Lock()
		bk, found := sh.m[k]
		if found {
			if reserved {
				b.n.Add(-1) // another charge opened it meanwhile
			}
			if now < bk.windowEnd && bk.defHash == r.defHash {
				if bk.count >= r.rate.Limit {
					sh.mu.Unlock()
					return false, time.Duration(bk.windowEnd - now)
				}
				if !peek {
					bk.count++
					sh.m[k] = bk
				}
				sh.mu.Unlock()
				return true, 0
			}
			// Expired, or opened under an older definition of the rule.
			if !peek {
				sh.m[k] = userBucket{count: 1, windowEnd: now + int64(r.rate.Window), defHash: r.defHash}
			}
			sh.mu.Unlock()
			return true, 0
		}
		if peek {
			sh.mu.Unlock()
			return true, 0
		}
		if reserved {
			sh.m[k] = userBucket{count: 1, windowEnd: now + int64(r.rate.Window), defHash: r.defHash}
			sh.mu.Unlock()
			return true, 0
		}
		sh.mu.Unlock()
		if !b.reserve(now) {
			b.capDenied.Add(1)
			return false, r.rate.Window
		}
		reserved = true
		// The key's strings come from the request's subject; the table keeps
		// its own copies so it never pins request memory.
		k = bucketKey{rule: k.rule, sub: strings.Clone(k.sub), agent: strings.Clone(k.agent)}
	}
}

// reserve takes room for one new bucket. When the table is full it sweeps
// expired buckets (at most once per userLimitCapSweepEvery) and tries again.
func (b *userBuckets) reserve(now int64) bool {
	if b.n.Add(1) <= b.max {
		return true
	}
	b.n.Add(-1)
	last := b.lastCapSweep.Load()
	if now-last >= int64(userLimitCapSweepEvery) && b.lastCapSweep.CompareAndSwap(last, now) {
		for i := range b.shards {
			b.sweepShard(i, now)
		}
	}
	if b.n.Add(1) <= b.max {
		return true
	}
	b.n.Add(-1)
	return false
}

// maybeSweep advances the amortized sweep: once per userLimitSweepEvery a pass
// starts, and each charge during a pass sweeps one shard.
func (b *userBuckets) maybeSweep(now int64) {
	if b.cursor.Load() < userLimitShards {
		if i := b.cursor.Add(1) - 1; i < userLimitShards {
			b.sweepShard(int(i), now)
		}
		return
	}
	next := b.nextSweep.Load()
	if now < next || !b.nextSweep.CompareAndSwap(next, now+int64(userLimitSweepEvery)) {
		return
	}
	b.cursor.Store(1)
	b.sweepShard(0, now)
}

func (b *userBuckets) sweepShard(i int, now int64) {
	sh := &b.shards[i]
	sh.mu.Lock()
	for k, bk := range sh.m {
		if now >= bk.windowEnd {
			delete(sh.m, k)
			b.n.Add(-1)
		}
	}
	sh.mu.Unlock()
}

// changedUserLimits names the rules of prev that are gone from next or whose
// definition changed, or returns nil when there are none. Replace calls it
// under swapMu's write lock; it only compares the two small hash maps.
func changedUserLimits(prev, next *userLimitSet) map[string]struct{} {
	if prev == nil {
		return nil
	}
	var out map[string]struct{}
	for name, h := range prev.hashes {
		if next != nil {
			if nh, ok := next.hashes[name]; ok && nh == h {
				continue
			}
		}
		if out == nil {
			out = make(map[string]struct{})
		}
		out[name] = struct{}{}
	}
	return out
}

// dropUserBuckets deletes the buckets of the changed rules. Replace calls it
// after releasing swapMu's write lock, so the walk never stalls requests: each
// shard is visited under a read lock of swapMu plus the shard lock (the order
// charges use) and a bucket is deleted only if its rule is still absent from
// the live set or its hash still differs. A charge that already reset the
// bucket under the new definition keeps it; one that has not is reset lazily
// by the defHash check in charge, so a bucket that survives a racing walk can
// never carry an old window into a new rule.
func (e *Evaluator) dropUserBuckets(changed map[string]struct{}) {
	b := e.ub
	for i := range b.shards {
		e.swapMu.RLock()
		live := e.userLimits
		sh := &b.shards[i]
		sh.mu.Lock()
		for k, bk := range sh.m {
			if _, ok := changed[k.rule]; !ok {
				continue
			}
			if live != nil {
				if h, ok := live.hashes[k.rule]; ok && h == bk.defHash {
					continue
				}
			}
			delete(sh.m, k)
			b.n.Add(-1)
		}
		sh.mu.Unlock()
		e.swapMu.RUnlock()
	}
}
