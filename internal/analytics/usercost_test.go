package analytics

import (
	"context"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCostByUserSince(t *testing.T) {
	s, err := NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	midnight := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	ev := func(at time.Time, sub, rule string, usd float64) Event {
		return Event{Timestamp: at, Domain: "api.openai.com", Port: 443, Protocol: "https", Method: "POST",
			Decision: "allow", UserSub: sub, LimitRule: rule, CostUSD: usd}
	}
	for _, e := range []Event{
		ev(midnight.Add(time.Hour), "alice", "eng-llm", 0.006),
		ev(midnight.Add(2*time.Hour), "alice", "eng-llm", 0.006),
		ev(midnight, "alice", "other", 0.5), // at since: included
		ev(midnight.Add(time.Hour), "bob", "eng-llm", 0.001),
		ev(midnight.Add(time.Hour), "", "anonymous", 0.25),
		ev(midnight.Add(-time.Nanosecond), "alice", "eng-llm", 9), // yesterday
		ev(midnight.Add(time.Hour), "carol", "", 3),               // no rule charged
		ev(midnight.Add(time.Hour), "dave", "eng-llm", 0),         // unpriced
	} {
		if err := s.StoreEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.CostByUserSince(context.Background(), midnight)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool {
		if got[i].UserSub != got[j].UserSub {
			return got[i].UserSub < got[j].UserSub
		}
		return got[i].LimitRule < got[j].LimitRule
	})
	want := []UserCost{
		{"", "anonymous", 0.25},
		{"alice", "eng-llm", 0.012},
		{"alice", "other", 0.5},
		{"bob", "eng-llm", 0.001},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].UserSub != want[i].UserSub || got[i].LimitRule != want[i].LimitRule || math.Abs(got[i].CostUSD-want[i].CostUSD) > 1e-12 {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// An empty window is no rows, not an error.
	if got, err := s.CostByUserSince(context.Background(), midnight.Add(48*time.Hour)); err != nil || len(got) != 0 {
		t.Errorf("future since = %+v, %v", got, err)
	}
}

// The seed query is a ts range over the covering index, both on a fresh store
// (no planner statistics) and after ANALYZE over a table whose stats favour
// the user_sub-leading indexes (few users, many events), so the plan never
// depends on a no-stats tie-break. It never scans the table.
func TestCostByUserSince_Plan(t *testing.T) {
	s, err := NewSQLiteStore("file:"+filepath.Join(t.TempDir(), "warden.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	check := func(when string) {
		t.Helper()
		rows, err := s.db.Query("EXPLAIN QUERY PLAN "+costByUserSinceSQL, 0)
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(detail + "\n")
		}
		_ = rows.Close()
		p := plan.String()
		if !strings.Contains(p, "SEARCH events USING COVERING INDEX idx_events_ts_user_rule_cost (ts>?)") {
			t.Errorf("%s: plan is not a ts range over the covering index:\n%s", when, p)
		}
		if strings.Contains(p, "SCAN events") {
			t.Errorf("%s: plan scans the table or a whole index:\n%s", when, p)
		}
	}
	check("no stats")
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var batch []Event
	for i := 0; i < 2000; i++ {
		batch = append(batch, Event{Timestamp: base.Add(time.Duration(i) * time.Minute), Domain: "api.openai.com",
			Decision: "allow", UserSub: []string{"alice", "bob"}[i%2], LimitRule: "eng-llm", CostUSD: 0.001})
	}
	if err := s.StoreEventsBatch(batch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("ANALYZE"); err != nil {
		t.Fatal(err)
	}
	check("after ANALYZE")
}
