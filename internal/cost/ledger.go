package cost

import (
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// The worker's per-user daily spend ledger (W-P3-PUL-04). The proxy adds the
// estimate of every forwarded request charged to a per-user limit rule, and
// refuses a request to a tracked destination once the user's spend under the
// rule reaches its dailyCostUSD. It holds one UTC day: the first call on a
// later day drops every previous-day key, so a cap lapses at midnight even
// with the control plane down. The worker builds it next to the Estimator,
// seeds it at boot from the local analytics store and passes it to the proxy;
// the policy evaluator never holds it.
//
// The cap is soft: requests in flight are not counted until they finish, so
// spend can overshoot by those requests (and, across a fleet, by the control
// plane's sync lag). The ledger holds rule names, subs and dollar figures only.

const (
	// MaxLedgerKeys bounds the ledger. At the cap a new key is not stored and
	// Spent reports it untracked, which the proxy treats as over the cap (fail
	// closed); existing keys keep counting.
	MaxLedgerKeys = 100000
	// MaxLedgerSubBytes is how much of a sub keys the ledger. It is the cut the
	// fleet rollup and costBlockedUsers use (255 bytes, never splitting a
	// rune), so local spend, seeded spend and wire blocks all name one key.
	MaxLedgerSubBytes = 255
)

// LedgerKey names one user's spend under one rule. User is the sub cut to
// MaxLedgerSubBytes; an anonymous request (no verified sub) has User "" and
// Agent set to the worker's agent id, so anonymous spend is keyed per agent.
type LedgerKey struct {
	User, Agent, Rule string
}

// UserKey is the ledger key of sub (or, when sub is empty, of the anonymous
// bucket of agentID) under rule. It allocates nothing.
func UserKey(sub, agentID, rule string) LedgerKey {
	if sub == "" {
		return LedgerKey{Agent: agentID, Rule: rule}
	}
	return LedgerKey{User: CutSub(sub), Rule: rule}
}

// String renders the key as `<rule>:<sub>` or `<rule>:anon:<agentID>`.
func (k LedgerKey) String() string {
	if k.User == "" {
		return k.Rule + ":anon:" + k.Agent
	}
	return k.Rule + ":" + k.User
}

// CutSub cuts sub to at most MaxLedgerSubBytes without splitting a rune.
func CutSub(sub string) string {
	n := MaxLedgerSubBytes
	if len(sub) <= n {
		return sub
	}
	for n > 0 && !utf8.RuneStart(sub[n]) {
		n--
	}
	return sub[:n]
}

// Ledger is the per-user, per-rule spend of the current UTC day. It is safe
// for concurrent use.
type Ledger struct {
	now func() time.Time
	max int

	mu  sync.Mutex
	day int32 // yyyymmdd of the UTC day m holds
	m   map[LedgerKey]float64

	refused atomic.Uint64
}

// NewLedger returns an empty ledger whose day follows now (time.Now when nil).
func NewLedger(now func() time.Time) *Ledger {
	return newLedger(now, MaxLedgerKeys)
}

func newLedger(now func() time.Time, max int) *Ledger {
	if now == nil {
		now = time.Now
	}
	return &Ledger{now: now, max: max, m: make(map[LedgerKey]float64)}
}

// Now is the ledger's clock: the proxy prices Retry-After and the fleet block
// day from the same instant the ledger keys on.
func (l *Ledger) Now() time.Time { return l.now() }

// utcDay is t's UTC date as yyyymmdd.
func utcDay(t time.Time) int32 {
	y, m, d := t.UTC().Date()
	return int32(y*10000 + int(m)*100 + d)
}

// roll moves the ledger to day when day is later than the one it holds,
// dropping every previous-day key. A clock that steps back keeps the later
// day (its spend is never forgotten early). Called with mu held.
func (l *Ledger) roll(day int32) {
	if day > l.day {
		l.day = day
		if len(l.m) > 0 {
			l.m = make(map[LedgerKey]float64)
		}
	}
}

// Add adds usd to k's spend today. A non-positive or NaN amount is ignored;
// a new key at the cap is not stored and is counted (see Refused).
func (l *Ledger) Add(k LedgerKey, usd float64) {
	if !(usd > 0) {
		return
	}
	day := utcDay(l.now())
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(day)
	l.addLocked(k, usd)
}

func (l *Ledger) addLocked(k LedgerKey, usd float64) {
	if cur, ok := l.m[k]; ok {
		l.m[k] = cur + usd
		return
	}
	if len(l.m) >= l.max {
		l.refused.Add(1)
		return
	}
	l.m[k] = usd
}

// Seed adds usd to k's spend when since falls on the ledger's current UTC
// day: the worker seeds it at boot from the local store's sum of today's
// cost (since is the midnight the sum starts at), so a restart keeps a capped
// user capped. A sum that started on another day is ignored.
func (l *Ledger) Seed(since time.Time, k LedgerKey, usd float64) {
	if !(usd > 0) {
		return
	}
	day := utcDay(l.now())
	if utcDay(since) != day {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(day)
	l.addLocked(k, usd)
}

// Spent returns k's spend today. tracked is false only when k has no entry
// because the ledger is full: its spend is unknown, and a caller enforcing a
// cap must treat it as over (fail closed).
func (l *Ledger) Spent(k LedgerKey) (usd float64, tracked bool) {
	day := utcDay(l.now())
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(day)
	if v, ok := l.m[k]; ok {
		return v, true
	}
	return 0, len(l.m) < l.max
}

// Keys is the number of keys the ledger holds today.
func (l *Ledger) Keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(utcDay(l.now()))
	return len(l.m)
}

// Refused counts new keys not stored because the ledger was full.
func (l *Ledger) Refused() uint64 { return l.refused.Load() }

// NextUTCMidnight is the start of the UTC day after t: when a day's cost cap
// lapses (the Retry-After of a user_cost_limited refusal).
func NextUTCMidnight(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
}
