package policy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// fakeClock is a settable clock for the evaluator (SetNowForTest).
type fakeClock struct{ ns atomic.Int64 }

func newFakeClock(t time.Time) *fakeClock {
	c := &fakeClock{}
	c.ns.Store(t.UnixNano())
	return c
}

func (c *fakeClock) now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *fakeClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

func ulEval(t *testing.T, p config.Policy) (*Evaluator, *fakeClock) {
	t.Helper()
	e := NewEvaluator(p)
	c := newFakeClock(time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC))
	e.SetNowForTest(c.now)
	return e, c
}

func user(sub, email string, verified bool, groups ...string) *identity.Subject {
	return &identity.Subject{Sub: sub, Email: email, EmailVerified: verified, Groups: groups}
}

func ulReq(domain string, s *identity.Subject) RequestContext {
	return RequestContext{Domain: domain, Port: 443, Scheme: SchemeHTTPS, Method: "POST", Path: "/v1/x", Subject: s}
}

func wantLimit(t *testing.T, got RequestVerdict, d Decision, rule string) {
	t.Helper()
	wantReason := denyreason.Reason("")
	if d == Deny {
		wantReason = denyreason.UserRateLimited
	}
	if got.Decision != d || got.Reason != wantReason || got.LimitRule != rule {
		t.Fatalf("verdict = {%v %q rule=%q}, want {%v %q rule=%q}", got.Decision, got.Reason, got.LimitRule, d, wantReason, rule)
	}
	if d == Deny && got.RetryAfter <= 0 {
		t.Fatalf("deny RetryAfter = %v, want > 0", got.RetryAfter)
	}
	if d == Allow && got.RetryAfter != 0 {
		t.Fatalf("allow RetryAfter = %v, want 0", got.RetryAfter)
	}
}

func engPolicy() config.Policy {
	return config.Policy{UserLimits: []config.UserLimit{
		{Name: "eng", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "2/minute"},
	}}
}

func TestChargeUserLimit(t *testing.T) {
	e, c := ulEval(t, engPolicy())
	alice := user("alice", "alice@corp.example", true, "eng")
	bob := user("bob", "bob@corp.example", true, "eng")
	const agent = "agent-a"
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), agent), Allow, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), agent), Allow, "eng")
	v := e.ChargeUserLimit(ulReq("api.openai.com", alice), agent)
	wantLimit(t, v, Deny, "eng")
	if v.RetryAfter > time.Minute {
		t.Fatalf("RetryAfter = %v, want at most the window", v.RetryAfter)
	}
	// One budget per user, not per agent or domain: bob still has his own.
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", bob), agent), Allow, "eng")
	// One budget for the rule across domains: alice is out on another host too.
	wantLimit(t, e.ChargeUserLimit(ulReq("api.anthropic.com", alice), "agent-b"), Deny, "eng")

	// Peek reports the state without charging.
	wantLimit(t, e.PeekUserLimit(ulReq("api.openai.com", alice), agent), Deny, "eng")
	wantLimit(t, e.PeekUserLimit(ulReq("api.openai.com", bob), agent), Allow, "eng")
	wantLimit(t, e.PeekUserLimit(ulReq("api.openai.com", bob), agent), Allow, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", bob), agent), Allow, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", bob), agent), Deny, "eng")

	// The window ends: alice gets a fresh budget.
	c.advance(time.Minute)
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), agent), Allow, "eng")

	// Not in eng, no default: allowed with no rule.
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", user("dave", "", false)), agent), Allow, "")
}

func TestChargeUserLimit_Precedence(t *testing.T) {
	e, _ := ulEval(t, config.Policy{
		UserLimits: []config.UserLimit{
			// The groups rule is listed first: the users tier still wins.
			{Name: "eng", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "10/minute"},
			{Name: "alice", Match: config.UserLimitMatch{Users: []string{"alice@corp.example"}}, RateLimit: "10/minute"},
			{Name: "bot", Match: config.UserLimitMatch{Agents: []string{"agent-bot"}}, RateLimit: "10/minute"},
		},
		DefaultUserLimit: &config.UserLimit{Name: config.UserLimitNameDefault, RateLimit: "10/minute"},
		AnonymousLimit:   &config.UserLimit{Name: config.UserLimitNameAnonymous, RateLimit: "10/minute"},
	})
	const agent = "agent-a"
	alice := user("alice-sub", "alice@corp.example", true, "eng")
	carol := user("carol-sub", "carol@corp.example", true, "eng")
	dave := user("dave-sub", "dave@corp.example", true)
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", alice), agent), Allow, "alice")
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", carol), agent), Allow, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", dave), agent), Allow, config.UserLimitNameDefault)
	// An unverified email never matches a users rule: alice falls to her group.
	unverified := user("alice-sub", "alice@corp.example", false, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", unverified), agent), Allow, "eng")
	// Mixed-case email in the token still matches the lowercase rule.
	upper := user("alice-sub", "Alice@Corp.Example", true)
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", upper), agent), Allow, "alice")
	// The agents-only tier sits above the default.
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", dave), "agent-bot"), Allow, "bot")
	// A nil subject uses only anonymousLimit, even on the bot agent.
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", nil), "agent-bot"), Allow, config.UserLimitNameAnonymous)
	// A subject with an empty sub is never charged to a shared "" bucket.
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", &identity.Subject{Groups: []string{"eng"}}), agent), Allow, config.UserLimitNameAnonymous)
}

func TestChargeUserLimit_SubMatch(t *testing.T) {
	e, _ := ulEval(t, config.Policy{UserLimits: []config.UserLimit{
		{Name: "by-sub", Match: config.UserLimitMatch{Users: []string{"u-1"}}, RateLimit: "1/minute"},
	}})
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", user("u-1", "", false)), "a"), Allow, "by-sub")
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", user("u-1", "", false)), "a"), Deny, "by-sub")
	wantLimit(t, e.ChargeUserLimit(ulReq("x.example.com", user("u-2", "", false)), "a"), Allow, "")
}

func TestChargeUserLimit_FirstInTierWinsAndFieldsNarrow(t *testing.T) {
	e, _ := ulEval(t, config.Policy{UserLimits: []config.UserLimit{
		// Narrowed by domain: only openai traffic.
		{Name: "eng-llm", Match: config.UserLimitMatch{Groups: []string{"eng"}, Domains: []string{"api.openai.com", "*.anthropic.com"}}, RateLimit: "10/minute"},
		// Narrowed by agent.
		{Name: "eng-ci", Match: config.UserLimitMatch{Groups: []string{"eng"}, Agents: []string{"agent-ci"}}, RateLimit: "10/minute"},
		{Name: "eng-rest", Match: config.UserLimitMatch{Groups: []string{"ops", "eng"}}, RateLimit: "10/minute"},
		{Name: "eng-shadow", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "10/minute"},
		{Name: "re", Match: config.UserLimitMatch{Groups: []string{"re"}, Domains: []string{`~^r[0-9]+\.example\.com$`}}, RateLimit: "10/minute"},
	}})
	eng := user("e1", "", false, "sales", "eng")
	for _, c := range []struct {
		domain, agent, want string
	}{
		{"api.openai.com", "agent-a", "eng-llm"},
		{"API.OpenAI.com.", "agent-a", "eng-llm"},
		{"x.anthropic.com", "agent-ci", "eng-llm"},
		{"github.com", "agent-ci", "eng-ci"},
		{"github.com", "agent-a", "eng-rest"},
	} {
		if v := e.PeekUserLimit(ulReq(c.domain, eng), c.agent); v.LimitRule != c.want {
			t.Errorf("%s via %s: rule %q, want %q", c.domain, c.agent, v.LimitRule, c.want)
		}
	}
	re := user("r", "", false, "re")
	if v := e.PeekUserLimit(ulReq("r12.example.com", re), "a"); v.LimitRule != "re" {
		t.Errorf("regex domain: rule %q, want re", v.LimitRule)
	}
	if v := e.PeekUserLimit(ulReq("rx.example.com", re), "a"); v.LimitRule != "" {
		t.Errorf("regex miss: rule %q, want none", v.LimitRule)
	}
	// List order holds across the two group indexes: a plain groups rule
	// listed first beats a later agent-narrowed one.
	e3, _ := ulEval(t, config.Policy{UserLimits: []config.UserLimit{
		{Name: "plain", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "10/minute"},
		{Name: "ci", Match: config.UserLimitMatch{Groups: []string{"eng"}, Agents: []string{"agent-ci"}}, RateLimit: "10/minute"},
	}})
	if v := e3.PeekUserLimit(ulReq("x.test", eng), "agent-ci"); v.LimitRule != "plain" {
		t.Errorf("earlier plain rule: got %q, want plain", v.LimitRule)
	}
	// A users rule narrowed by groups needs both.
	e2, _ := ulEval(t, config.Policy{UserLimits: []config.UserLimit{
		{Name: "a-eng", Match: config.UserLimitMatch{Users: []string{"a"}, Groups: []string{"eng"}}, RateLimit: "10/minute"},
	}})
	if v := e2.PeekUserLimit(ulReq("x.test", user("a", "", false, "eng")), "x"); v.LimitRule != "a-eng" {
		t.Errorf("users+groups member: rule %q", v.LimitRule)
	}
	if v := e2.PeekUserLimit(ulReq("x.test", user("a", "", false, "ops")), "x"); v.LimitRule != "" {
		t.Errorf("users+groups non-member: rule %q, want none", v.LimitRule)
	}
}

func TestChargeUserLimit_PerAgentAndAnonymous(t *testing.T) {
	e, _ := ulEval(t, config.Policy{
		UserLimits: []config.UserLimit{
			{Name: "eng", Match: config.UserLimitMatch{Groups: []string{"eng"}}, PerAgent: true, RateLimit: "1/minute"},
		},
		AnonymousLimit: &config.UserLimit{Name: config.UserLimitNameAnonymous, RateLimit: "1/minute"},
	})
	alice := user("alice", "", false, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("x.test", alice), "agent-a"), Allow, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("x.test", alice), "agent-a"), Deny, "eng")
	// PerAgent: a separate budget on another agent.
	wantLimit(t, e.ChargeUserLimit(ulReq("x.test", alice), "agent-b"), Allow, "eng")
	// Anonymous is always keyed by agent.
	wantLimit(t, e.ChargeUserLimit(ulReq("x.test", nil), "agent-a"), Allow, config.UserLimitNameAnonymous)
	wantLimit(t, e.ChargeUserLimit(ulReq("x.test", nil), "agent-a"), Deny, config.UserLimitNameAnonymous)
	wantLimit(t, e.ChargeUserLimit(ulReq("x.test", nil), "agent-b"), Allow, config.UserLimitNameAnonymous)
	// A user whose sub is literally "anon" never shares the anonymous bucket.
	e2, _ := ulEval(t, config.Policy{
		DefaultUserLimit: &config.UserLimit{Name: config.UserLimitNameDefault, RateLimit: "1/minute", PerAgent: true},
		AnonymousLimit:   &config.UserLimit{Name: config.UserLimitNameAnonymous, RateLimit: "1/minute"},
	})
	wantLimit(t, e2.ChargeUserLimit(ulReq("x.test", nil), "agent-a"), Allow, config.UserLimitNameAnonymous)
	wantLimit(t, e2.ChargeUserLimit(ulReq("x.test", user("anon", "", false)), "agent-a"), Allow, config.UserLimitNameDefault)
	if got := userBucketKey("eng", "alice", "agent-a", true, false); got != "ul:eng:alice:agent-a" {
		t.Errorf("per-agent key = %q", got)
	}
	if got := userBucketKey("eng", "alice", "agent-a", false, false); got != "ul:eng:alice" {
		t.Errorf("per-user key = %q", got)
	}
	if got := userBucketKey(config.UserLimitNameAnonymous, "", "agent-a", true, true); got != "ul:anonymous:anon:agent-a" {
		t.Errorf("anonymous key = %q", got)
	}
}

func TestChargeUserLimit_CostOnlyRule(t *testing.T) {
	e, _ := ulEval(t, config.Policy{UserLimits: []config.UserLimit{
		{Name: "eng-llm", Match: config.UserLimitMatch{Groups: []string{"eng"}}, DailyCostUSD: 5},
	}})
	alice := user("alice", "", false, "eng")
	for i := 0; i < 5; i++ {
		wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), "a"), Allow, "eng-llm")
	}
	if n := e.UserLimitBuckets(); n != 0 {
		t.Fatalf("a cost-only rule opened %d rate buckets", n)
	}
}

func TestMatchUserLimit(t *testing.T) {
	e, _ := ulEval(t, config.Policy{
		UserLimits: []config.UserLimit{
			{Name: "eng-llm", Match: config.UserLimitMatch{Groups: []string{"eng"}, Domains: []string{"api.openai.com"}}, PerAgent: true, RateLimit: "60/minute", DailyCostUSD: 5},
		},
		AnonymousLimit: &config.UserLimit{Name: config.UserLimitNameAnonymous, DailyCostUSD: 1},
	})
	r, ok := e.MatchUserLimit(user("alice", "", false, "eng"), "a", "api.openai.com")
	if !ok || r != (UserLimitRule{Name: "eng-llm", DailyCostUSD: 5, PerAgent: true}) {
		t.Fatalf("MatchUserLimit = %+v %v", r, ok)
	}
	if _, ok := e.MatchUserLimit(user("alice", "", false, "eng"), "a", "github.com"); ok {
		t.Fatal("MatchUserLimit matched outside the rule's domains")
	}
	r, ok = e.MatchUserLimit(nil, "a", "github.com")
	if !ok || r.Name != config.UserLimitNameAnonymous || r.DailyCostUSD != 1 {
		t.Fatalf("anonymous MatchUserLimit = %+v %v", r, ok)
	}
	if n := e.UserLimitBuckets(); n != 0 {
		t.Fatalf("MatchUserLimit opened %d buckets", n)
	}
}

func TestIsCostBlocked(t *testing.T) {
	e, c := ulEval(t, config.Policy{CostBlockedUsers: []config.CostBlockedUser{
		{Sub: "alice", Rule: "eng-llm", Day: "2026-11-27"},
		{Sub: "bob", Rule: "eng-llm", Day: "2026-11-26"},
		{Sub: "carol", Rule: "eng-llm", Day: "not-a-day"},
	}})
	now := c.now()
	if !e.IsCostBlocked("alice", "eng-llm", now) {
		t.Error("entry dated today is not blocked")
	}
	if e.IsCostBlocked("alice", "other", now) || e.IsCostBlocked("dave", "eng-llm", now) {
		t.Error("block leaked to another rule or user")
	}
	if e.IsCostBlocked("bob", "eng-llm", now) {
		t.Error("entry dated yesterday is blocked")
	}
	if e.IsCostBlocked("carol", "eng-llm", now) {
		t.Error("entry with a bad day is blocked")
	}
	// The day is the UTC day: 23:59 UTC is still today, 00:00 the next day is not.
	if !e.IsCostBlocked("alice", "eng-llm", time.Date(2026, 11, 27, 23, 59, 59, 0, time.UTC)) {
		t.Error("blocked lapsed before UTC midnight")
	}
	if e.IsCostBlocked("alice", "eng-llm", time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC)) {
		t.Error("block survived UTC midnight")
	}
	// A local-zone time is read as its UTC day.
	ist := time.FixedZone("IST", 5*3600+1800)
	if e.IsCostBlocked("alice", "eng-llm", time.Date(2026, 11, 28, 2, 0, 0, 0, ist)) == false {
		t.Error("02:00 IST on the 28th is 20:30 UTC on the 27th: want blocked")
	}
	if e.IsCostBlocked("", "eng-llm", now) {
		t.Error("empty sub matched")
	}
	e.Replace(config.Policy{})
	if e.IsCostBlocked("alice", "eng-llm", now) {
		t.Error("block survived a Replace that dropped it")
	}
}

func TestReplace_KeepsUserBuckets(t *testing.T) {
	base := func() config.Policy {
		return config.Policy{
			Allowlist: []config.AllowlistEntry{{Domain: "api.openai.com"}},
			UserLimits: []config.UserLimit{
				{Name: "eng", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "2/minute"},
				{Name: "ops", Match: config.UserLimitMatch{Groups: []string{"ops"}}, RateLimit: "1/minute"},
			},
		}
	}
	e, _ := ulEval(t, base())
	alice := user("alice", "", false, "eng")
	olga := user("olga", "", false, "ops")
	for i := 0; i < 2; i++ {
		wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), "a"), Allow, "eng")
	}
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), "a"), Deny, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", olga), "a"), Allow, "ops")

	// Only blockedUsers / costBlockedUsers / the allowlist change: windows stay.
	p := base()
	p.BlockedUsers = []config.BlockedUser{{Sub: "mallory"}}
	p.CostBlockedUsers = []config.CostBlockedUser{{Sub: "bob", Rule: "eng", Day: "2026-11-27"}}
	p.Allowlist = append(p.Allowlist, config.AllowlistEntry{Domain: "github.com"})
	e.Replace(p)
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), "a"), Deny, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", olga), "a"), Deny, "ops")

	// Reordering rules does not change a definition either.
	p = base()
	p.UserLimits[0], p.UserLimits[1] = p.UserLimits[1], p.UserLimits[0]
	e.Replace(p)
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), "a"), Deny, "eng")

	// Changing alice's rule's rateLimit resets her bucket, not olga's.
	p = base()
	p.UserLimits[0].RateLimit = "3/minute"
	e.Replace(p)
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", alice), "a"), Allow, "eng")
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", olga), "a"), Deny, "ops")

	// Removing a rule drops its buckets.
	before := e.UserLimitBuckets()
	p.UserLimits = p.UserLimits[:1]
	e.Replace(p)
	if got := e.UserLimitBuckets(); got != before-1 {
		t.Fatalf("buckets after removing ops = %d, want %d", got, before-1)
	}
	// Re-adding it starts fresh.
	e.Replace(base())
	wantLimit(t, e.ChargeUserLimit(ulReq("api.openai.com", olga), "a"), Allow, "ops")

	// Allowlist counters keep today's behaviour: a Replace resets them.
	e2, _ := ulEval(t, config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "r.test", RateLimit: "1/minute"}}})
	if d := e2.Evaluate("r.test", 443, SchemeHTTPS); d != Allow {
		t.Fatalf("first = %v", d)
	}
	if d := e2.Evaluate("r.test", 443, SchemeHTTPS); d != Deny {
		t.Fatalf("second = %v", d)
	}
	e2.Replace(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "r.test", RateLimit: "1/minute"}}})
	if d := e2.Evaluate("r.test", 443, SchemeHTTPS); d != Allow {
		t.Fatalf("after Replace = %v, want the allowlist window reset", d)
	}
}

func TestUserLimit_Sweep(t *testing.T) {
	e, c := ulEval(t, config.Policy{DefaultUserLimit: &config.UserLimit{Name: config.UserLimitNameDefault, RateLimit: "5/second"}})
	for i := 0; i < 500; i++ {
		e.ChargeUserLimit(ulReq("x.test", user(fmt.Sprintf("u-%d", i), "", false)), "a")
	}
	if got := e.UserLimitBuckets(); got != 500 {
		t.Fatalf("buckets = %d, want 500", got)
	}
	// Before the sweep interval nothing is swept even though windows ended.
	c.advance(2 * time.Second)
	e.ChargeUserLimit(ulReq("x.test", user("u-0", "", false)), "a")
	if got := e.UserLimitBuckets(); got != 500 {
		t.Fatalf("buckets swept early: %d", got)
	}
	// After the interval, charges sweep the shards incrementally.
	c.advance(userLimitSweepEvery)
	live := user("live", "", false)
	for i := 0; i < userLimitShards; i++ {
		e.ChargeUserLimit(ulReq("x.test", live), "a")
	}
	if got := e.UserLimitBuckets(); got != 1 {
		t.Fatalf("buckets after sweep = %d, want 1 (only the live one)", got)
	}
}

func TestUserLimit_BucketCap(t *testing.T) {
	e, c := ulEval(t, config.Policy{DefaultUserLimit: &config.UserLimit{Name: config.UserLimitNameDefault, RateLimit: "100/hour"}})
	e.ub.max = 50
	for i := 0; i < 50; i++ {
		wantLimit(t, e.ChargeUserLimit(ulReq("x.test", user(fmt.Sprintf("u-%d", i), "", false)), "a"), Allow, config.UserLimitNameDefault)
	}
	// Full of live buckets: a new key is denied fail-closed and counted.
	v := e.ChargeUserLimit(ulReq("x.test", user("new", "", false)), "a")
	wantLimit(t, v, Deny, config.UserLimitNameDefault)
	if got := e.UserLimitCapDenials(); got != 1 {
		t.Fatalf("cap denials = %d, want 1", got)
	}
	// Peek never opens a bucket and does not deny for the cap.
	wantLimit(t, e.PeekUserLimit(ulReq("x.test", user("new2", "", false)), "a"), Allow, config.UserLimitNameDefault)
	// Existing keys keep working at the cap.
	wantLimit(t, e.ChargeUserLimit(ulReq("x.test", user("u-1", "", false)), "a"), Allow, config.UserLimitNameDefault)
	// Once the windows expire, the sweep at the cap frees room.
	c.advance(time.Hour + time.Second)
	wantLimit(t, e.ChargeUserLimit(ulReq("x.test", user("new", "", false)), "a"), Allow, config.UserLimitNameDefault)
	if got := e.UserLimitBuckets(); got > 50 {
		t.Fatalf("buckets = %d over the cap", got)
	}
	if maxUserLimitBuckets != 100000 {
		t.Fatalf("maxUserLimitBuckets = %d, want 100000", maxUserLimitBuckets)
	}
}

func TestUserLimit_Concurrent(t *testing.T) {
	p := config.Policy{
		UserLimits: []config.UserLimit{
			{Name: "eng", Match: config.UserLimitMatch{Groups: []string{"eng"}}, RateLimit: "100/minute"},
		},
		AnonymousLimit: &config.UserLimit{Name: config.UserLimitNameAnonymous, RateLimit: "1000/minute"},
	}
	e, c := ulEval(t, p)
	e.ub.max = 200
	alice := user("alice", "", false, "eng")
	var allowed atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if e.ChargeUserLimit(ulReq("x.test", alice), "a").Decision == Allow {
					allowed.Add(1)
				}
				e.PeekUserLimit(ulReq("x.test", alice), "a")
				e.ChargeUserLimit(ulReq("x.test", user(fmt.Sprintf("g%d-%d", g, i), "", false, "eng")), "a")
				e.ChargeUserLimit(ulReq("x.test", nil), fmt.Sprintf("agent-%d", i))
				e.MatchUserLimit(alice, "a", "x.test")
				e.IsCostBlocked("alice", "eng", c.now())
				_ = e.UserLimitBuckets()
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			q := p
			q.BlockedUsers = []config.BlockedUser{{Sub: fmt.Sprint(i)}}
			e.Replace(q)
		}
	}()
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(stop)
	}()
	wg.Wait()
	// 400 charges for alice within one minute of fake time against 100/minute:
	// exactly 100 allowed, since Replace never reset the bucket.
	if got := allowed.Load(); got != 100 {
		t.Fatalf("alice allowed %d times, want 100", got)
	}
	if n := e.UserLimitBuckets(); n > 200 {
		t.Fatalf("buckets = %d over the cap of 200", n)
	}
}

func TestEvaluateFor_NoUserLimitAllocs(t *testing.T) {
	var es []config.AllowlistEntry
	for i := 0; i < 50; i++ {
		es = append(es, config.AllowlistEntry{Domain: fmt.Sprintf("h%d.example.com", i), Methods: []string{"GET"}})
	}
	e := evalFor(es...)
	rc := ctx("h49.example.com", "GET", nil)
	if got := testing.AllocsPerRun(100, func() { e.EvaluateFor(rc) }); got != baselineAllocsRequest {
		t.Errorf("EvaluateFor allocs = %v, want baseline %v", got, baselineAllocsRequest)
	}
	// With no limits the charge path is free.
	for name, s := range map[string]*identity.Subject{"nil": nil, "user": user("alice", "a@b.c", true, "eng")} {
		rc := ctx("h49.example.com", "GET", s)
		if got := testing.AllocsPerRun(100, func() { e.ChargeUserLimit(rc, "agent-a") }); got != 0 {
			t.Errorf("%s: ChargeUserLimit allocs with no limits = %v, want 0", name, got)
		}
		if got := testing.AllocsPerRun(100, func() { e.PeekUserLimit(rc, "agent-a") }); got != 0 {
			t.Errorf("%s: PeekUserLimit allocs with no limits = %v, want 0", name, got)
		}
		if got := testing.AllocsPerRun(100, func() { e.MatchUserLimit(s, "agent-a", "h49.example.com") }); got != 0 {
			t.Errorf("%s: MatchUserLimit allocs with no limits = %v, want 0", name, got)
		}
	}
}

// manyRules is 256 rules (the config maximum) spread across the three tiers,
// with the matching rule for the benchmark subject last in its tier.
func manyRules() config.Policy {
	var rules []config.UserLimit
	for i := 0; i < config.MaxUserLimits-3; i++ {
		m := config.UserLimitMatch{Domains: []string{fmt.Sprintf("h%d.example.com", i), "api.openai.com"}}
		switch i % 3 {
		case 0:
			m.Users = []string{fmt.Sprintf("u-%d", i), fmt.Sprintf("u%d@corp.example", i)}
		case 1:
			m.Groups = []string{fmt.Sprintf("g-%d", i), "eng"}
			m.Agents = []string{fmt.Sprintf("agent-%d", i)}
		default:
			m.Agents = []string{fmt.Sprintf("agent-%d", i)}
		}
		rules = append(rules, config.UserLimit{Name: fmt.Sprintf("r-%d", i), Match: m, RateLimit: "1000000/hour"})
	}
	rules = append(rules,
		config.UserLimit{Name: "alice", Match: config.UserLimitMatch{Users: []string{"alice@corp.example"}, Domains: []string{"api.openai.com"}}, RateLimit: "1000000/hour"},
		config.UserLimit{Name: "eng", Match: config.UserLimitMatch{Groups: []string{"eng"}}, PerAgent: true, RateLimit: "1000000/hour"},
		config.UserLimit{Name: "bot", Match: config.UserLimitMatch{Agents: []string{"agent-a"}}, RateLimit: "1000000/hour"},
	)
	return config.Policy{
		UserLimits:       rules,
		DefaultUserLimit: &config.UserLimit{Name: config.UserLimitNameDefault, RateLimit: "1000000/hour"},
		AnonymousLimit:   &config.UserLimit{Name: config.UserLimitNameAnonymous, RateLimit: "1000000/hour"},
	}
}

// benchSubject is a typical verified user: ten groups, the matching one last.
func benchSubject() *identity.Subject {
	groups := make([]string, 0, 10)
	for i := 0; i < 9; i++ {
		groups = append(groups, fmt.Sprintf("team-%d", i))
	}
	return user("carol", "carol@corp.example", true, append(groups, "eng")...)
}

func TestChargeUserLimit_ManyRulesNoAllocs(t *testing.T) {
	e := NewEvaluator(manyRules())
	rc := ulReq("api.openai.com", benchSubject())
	if v := e.ChargeUserLimit(rc, "agent-a"); v.LimitRule != "eng" {
		t.Fatalf("bench subject matched %q, want eng", v.LimitRule)
	}
	if got := testing.AllocsPerRun(1000, func() { e.ChargeUserLimit(rc, "agent-a") }); got != 0 {
		t.Errorf("ChargeUserLimit on an open bucket allocates %v, want 0", got)
	}
	nilRC := ulReq("api.openai.com", nil)
	e.ChargeUserLimit(nilRC, "agent-a")
	if got := testing.AllocsPerRun(1000, func() { e.ChargeUserLimit(nilRC, "agent-a") }); got != 0 {
		t.Errorf("anonymous ChargeUserLimit allocates %v, want 0", got)
	}
	if got := testing.AllocsPerRun(1000, func() { e.MatchUserLimit(rc.Subject, "agent-a", "api.openai.com") }); got != 0 {
		t.Errorf("MatchUserLimit allocates %v, want 0", got)
	}
	if got := testing.AllocsPerRun(1000, func() { e.IsCostBlocked("carol", "eng", time.Now()) }); got != 0 {
		t.Errorf("IsCostBlocked allocates %v, want 0", got)
	}
}

func TestChargeUserLimit_ManyRulesUnderAMicrosecond(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing check: skipped in -short and under -race")
	}
	// Best of three runs, so a busy CI host does not fail a fast path.
	best := int64(-1)
	for i := 0; i < 3; i++ {
		if ns := testing.Benchmark(BenchmarkChargeUserLimit).NsPerOp(); best < 0 || ns < best {
			best = ns
		}
	}
	if best >= 1000 {
		t.Errorf("ChargeUserLimit with %d rules = %d ns/op, want under 1000", config.MaxUserLimits, best)
	}
}

func BenchmarkChargeUserLimit(b *testing.B) {
	e := NewEvaluator(manyRules())
	rc := ulReq("api.openai.com", benchSubject())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ChargeUserLimit(rc, "agent-a")
	}
}

func BenchmarkChargeUserLimit_None(b *testing.B) {
	e := NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "api.openai.com"}}})
	rc := ulReq("api.openai.com", benchSubject())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ChargeUserLimit(rc, "agent-a")
	}
}
