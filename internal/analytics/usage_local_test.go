package analytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// The standalone worker answers UserUsageQuerier from its events table with
// the fleet's shape: per-user totals, deny reasons, agents, rules and the
// anonymous row (W-P3-PUL-05).
func TestSQLiteStoreUserUsage(t *testing.T) {
	s, err := NewSQLiteStore("file:"+filepath.Join(t.TempDir(), "warden.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	ev := func(sub, dec, reason, agent, rule string, cost float64, ts time.Time) Event {
		e := Event{Timestamp: ts, Domain: "api.openai.com", Decision: dec, Reason: reason,
			UserSub: sub, AgentID: agent, LimitRule: rule, CostUSD: cost}
		if sub != "" {
			e.UserEmail = sub + "@corp.example"
		}
		return e
	}
	evs := []Event{
		ev("alice", "allow", "", "a1", "eng", 0.25, now),
		ev("alice", "allow", "", "a1", "eng", 1.0, now),
		ev("alice", "deny", "user_rate_limited", "a1", "eng", 0, now),
		ev("alice", "deny", "identity_groups_truncated", "a2", "skipped", 0, now),
		ev("alice", "allow", "", "a2", "eng", 0.5, now.AddDate(0, 0, -2)),
		ev("alice", "allow", "", "a1", "eng", 9, now.AddDate(0, 0, -40)),
		ev("bob", "allow", "", "a1", "", 0, now),
		ev("", "allow", "", "a1", AnonymousLimitRule, 0.1, now),
		ev("", "allow", "", "a1", "", 7, now),
	}
	if err := s.StoreEventsBatch(evs); err != nil {
		t.Fatal(err)
	}
	got, err := s.UsageByUser(context.Background(), now.AddDate(0, 0, -6), now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Sub != "alice" || got[1].Sub != "bob" || got[2].Sub != "" {
		t.Fatalf("users = %+v", got)
	}
	a := got[0]
	if a.Requests != 5 || a.CostUSD != 1.75 || a.Email != "alice@corp.example" {
		t.Errorf("alice = %+v", a)
	}
	if a.Denies["user_rate_limited"] != 1 || a.Denies["identity_groups_truncated"] != 1 || len(a.Denies) != 2 {
		t.Errorf("alice denies = %v", a.Denies)
	}
	for _, r := range a.Rules {
		if r.Rule == "skipped" {
			t.Errorf("skipped-rule deny counted as a charge: %+v", a.Rules)
		}
	}
	if len(a.Agents) != 2 || a.Agents[0].AgentID != "a1" || a.Agents[0].Requests != 3 {
		t.Errorf("alice agents = %+v", a.Agents)
	}
	if got[2].Requests != 1 || got[2].CostUSD != 0.1 || got[2].Email != "" {
		t.Errorf("anonymous row = %+v (rule-less unattributed events must not count)", got[2])
	}
	limited, err := s.UsageByUser(context.Background(), now, now, 1)
	if err != nil || len(limited) != 2 || limited[0].Sub != "alice" || limited[1].Sub != "" || limited[0].Requests != 4 {
		t.Errorf("limit 1, today only = %+v err %v", limited, err)
	}
	costs, err := s.TodayCostByRule(context.Background(), UsageDay(now))
	if err != nil || len(costs) != 1 || costs[0] != (UserRuleCost{Sub: "alice", Rule: "eng", CostUSD: 1.25}) {
		t.Errorf("today cost = %+v err %v", costs, err)
	}
	if _, err := s.TodayCostByRule(context.Background(), "nope"); err == nil {
		t.Error("a malformed day must error")
	}
}
