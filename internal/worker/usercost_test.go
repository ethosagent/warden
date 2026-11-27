package worker

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/cost"
)

// A worker restart reseeds the ledger from the local store: alice's spend
// today under eng-llm (two $0.006 requests) is back, so a $0.01 cap still
// refuses her; yesterday's spend and unpriced or unattributed events are not
// counted, and anonymous spend is keyed on the worker's agent id.
func TestLedgerSeedFromStore(t *testing.T) {
	now := time.Date(2026, 11, 27, 15, 0, 0, 0, time.UTC)
	midnight := utcMidnight(now)
	dsn := "file:" + filepath.Join(t.TempDir(), "warden.db")

	// Before the restart: the proxy stored these events.
	st, err := analytics.NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatal(err)
	}
	ev := func(at time.Time, sub, rule string, usd float64) analytics.Event {
		return analytics.Event{Timestamp: at, Domain: "api.openai.com", Port: 443, Protocol: "https", Method: "POST",
			Decision: "allow", UserSub: sub, LimitRule: rule, CostUSD: usd, Provider: "openai"}
	}
	for _, e := range []analytics.Event{
		ev(midnight.Add(time.Hour), "alice", "eng-llm", 0.006),
		ev(midnight.Add(2*time.Hour), "alice", "eng-llm", 0.006),
		ev(midnight.Add(-time.Minute), "bob", "eng-llm", 5), // yesterday
		ev(midnight.Add(time.Hour), "", "anonymous", 0.003),
		ev(midnight.Add(time.Hour), "carol", "", 1), // no rule charged
	} {
		if err := st.StoreEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// After the restart: a fresh store on the same file seeds a fresh ledger.
	st, err = analytics.NewSQLiteStore(dsn, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	l := cost.NewLedger(func() time.Time { return now })
	n, err := seedCostLedger(context.Background(), st, l, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("seeded %d keys, want 2 (alice/eng-llm, anonymous)", n)
	}
	const capUSD = 0.01
	if got, ok := l.Spent(cost.UserKey("alice", "agent-1", "eng-llm")); !ok || math.Abs(got-0.012) > 1e-12 || got < capUSD {
		t.Errorf("alice spent %v (%v) after restart, want 0.012 (over the $0.01 cap)", got, ok)
	}
	if got, _ := l.Spent(cost.UserKey("bob", "agent-1", "eng-llm")); got != 0 {
		t.Errorf("bob's spend from yesterday seeded: %v", got)
	}
	if got, _ := l.Spent(cost.UserKey("", "agent-1", "anonymous")); math.Abs(got-0.003) > 1e-12 {
		t.Errorf("anonymous spend = %v, want 0.003 keyed on the agent", got)
	}
	if got, _ := l.Spent(cost.UserKey("", "other-agent", "anonymous")); got != 0 {
		t.Errorf("anonymous spend leaked to another agent: %v", got)
	}

	// Past UTC midnight the seeded spend lapses.
	next := now.Add(9*time.Hour + time.Second)
	l2 := cost.NewLedger(func() time.Time { return next })
	if _, err := seedCostLedger(context.Background(), st, l2, "agent-1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := l2.Spent(cost.UserKey("alice", "agent-1", "eng-llm")); got != 0 {
		t.Errorf("yesterday's spend seeded on the next day: %v", got)
	}
}

type failingSeed struct{}

func (failingSeed) CostByUserSince(context.Context, time.Time) ([]analytics.UserCost, error) {
	return nil, errors.New("disk on fire")
}

func TestLedgerSeedFromStore_Error(t *testing.T) {
	l := cost.NewLedger(nil)
	if _, err := seedCostLedger(context.Background(), failingSeed{}, l, "a"); err == nil {
		t.Fatal("seed error swallowed")
	}
	if l.Keys() != 0 {
		t.Error("a failed seed left keys")
	}
}
