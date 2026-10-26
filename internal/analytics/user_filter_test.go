package analytics

import (
	"testing"
	"time"
)

type eventReader interface {
	GetEvents(EventFilter) ([]Event, error)
}

// userFilterStores returns the three EventFilter-honoring stores, each seeded
// with the same four events: two for alice (by sub and email), one for bob, one
// anonymous.
func userFilterStores(t *testing.T) map[string]eventReader {
	t.Helper()
	now := time.Now().UTC()
	evs := []Event{
		{Timestamp: now, Domain: "a.example", Decision: "allow", UserSub: "sub-alice", UserEmail: "alice@corp.example"},
		{Timestamp: now.Add(time.Second), Domain: "b.example", Decision: "deny", UserSub: "sub-alice", UserEmail: "alice@corp.example"},
		{Timestamp: now.Add(2 * time.Second), Domain: "c.example", Decision: "allow", UserSub: "sub-bob", UserEmail: "bob@corp.example"},
		{Timestamp: now.Add(3 * time.Second), Domain: "d.example", Decision: "allow"},
	}

	local, err := NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("local store: %v", err)
	}
	t.Cleanup(func() { _ = local.Close() })
	fleet, err := NewFleetSQLiteStore(":memory:", 0, 0)
	if err != nil {
		t.Fatalf("fleet store: %v", err)
	}
	t.Cleanup(func() { _ = fleet.Close() })
	central := NewCentralStore(0)

	for _, e := range evs {
		if err := local.StoreEvent(e); err != nil {
			t.Fatalf("local store event: %v", err)
		}
		if err := fleet.StoreAggregatedEvent(AggregatedEvent{Event: e, ProxyID: "w1"}); err != nil {
			t.Fatalf("fleet store event: %v", err)
		}
		if err := central.StoreAggregatedEvent(AggregatedEvent{Event: e, ProxyID: "w1"}); err != nil {
			t.Fatalf("central store event: %v", err)
		}
	}
	return map[string]eventReader{"local": local, "fleet": fleet, "central": central}
}

func TestUserFilter(t *testing.T) {
	cases := []struct {
		name string
		user string
		want int
	}{
		{"email exact", "alice@corp.example", 2},
		{"email case-insensitive", "Alice@Corp.Example", 2},
		{"sub exact", "sub-alice", 2},
		{"sub is case-sensitive", "SUB-ALICE", 0},
		{"other user", "bob@corp.example", 1},
		{"unknown user", "carol@corp.example", 0},
		{"no filter", "", 4},
	}
	for storeName, st := range userFilterStores(t) {
		for _, tc := range cases {
			t.Run(storeName+"/"+tc.name, func(t *testing.T) {
				got, err := st.GetEvents(EventFilter{User: tc.user})
				if err != nil {
					t.Fatalf("GetEvents: %v", err)
				}
				if len(got) != tc.want {
					t.Fatalf("User=%q: got %d events, want %d", tc.user, len(got), tc.want)
				}
				for _, e := range got {
					if tc.user != "" && e.UserSub == "" {
						t.Errorf("anonymous event leaked into User=%q", tc.user)
					}
				}
			})
		}
	}
}

// The user filter combines with the other filters (AND), including through
// AggregatedFilter's embedded EventFilter on both fleet stores.
func TestUserFilterCombinesAndAggregates(t *testing.T) {
	stores := userFilterStores(t)
	for name, st := range stores {
		got, err := st.GetEvents(EventFilter{User: "sub-alice", Decision: "deny"})
		if err != nil || len(got) != 1 || got[0].Domain != "b.example" {
			t.Fatalf("%s: user+decision: got %v, err %v", name, got, err)
		}
	}
	for _, name := range []string{"fleet", "central"} {
		agg := stores[name].(interface {
			GetAggregatedEvents(AggregatedFilter) ([]AggregatedEvent, error)
		})
		got, err := agg.GetAggregatedEvents(AggregatedFilter{EventFilter: EventFilter{User: "bob@corp.example"}, ProxyID: "w1"})
		if err != nil || len(got) != 1 || got[0].UserSub != "sub-bob" {
			t.Fatalf("%s: aggregated: got %v, err %v", name, got, err)
		}
	}
}

// A hostile value is bound as data: it matches nothing and breaks nothing.
func TestUserFilterIsParameterized(t *testing.T) {
	for _, hostile := range []string{
		"x' OR '1'='1",
		"' OR 1=1 --",
		"x'); DROP TABLE events; --",
	} {
		for storeName, st := range userFilterStores(t) {
			got, err := st.GetEvents(EventFilter{User: hostile})
			if err != nil {
				t.Fatalf("%s: User=%q: %v", storeName, hostile, err)
			}
			if len(got) != 0 {
				t.Fatalf("%s: User=%q matched %d events, want 0", storeName, hostile, len(got))
			}
			all, err := st.GetEvents(EventFilter{})
			if err != nil || len(all) != 4 {
				t.Fatalf("%s: table damaged after User=%q: %d events, err %v", storeName, hostile, len(all), err)
			}
		}
	}
}
