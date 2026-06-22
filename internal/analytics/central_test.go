package analytics

import (
	"testing"
	"time"
)

func TestCentralStore_StoreAndRetrieve(t *testing.T) {
	cs := NewCentralStore(0)
	ev := AggregatedEvent{
		Event: Event{
			Timestamp:      time.Unix(1000, 0).UTC(),
			Domain:         "api.openai.com",
			Port:           443,
			Protocol:       "https",
			Method:         "POST",
			URL:            "https://api.openai.com/v1/chat",
			Decision:       "allow",
			ResponseStatus: 200,
			SecretRef:      "sha256:abc last4:1234 len:20",
		},
		ProxyID: "proxy-1",
		AgentID: "agent-a",
	}
	if err := cs.StoreAggregatedEvent(ev); err != nil {
		t.Fatalf("StoreAggregatedEvent: %v", err)
	}
	got, err := cs.GetAggregatedEvents(AggregatedFilter{})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	g := got[0]
	if g.Domain != ev.Domain {
		t.Errorf("Domain = %q, want %q", g.Domain, ev.Domain)
	}
	if g.ProxyID != ev.ProxyID {
		t.Errorf("ProxyID = %q, want %q", g.ProxyID, ev.ProxyID)
	}
	if g.AgentID != ev.AgentID {
		t.Errorf("AgentID = %q, want %q", g.AgentID, ev.AgentID)
	}
	if g.Decision != ev.Decision {
		t.Errorf("Decision = %q, want %q", g.Decision, ev.Decision)
	}
	if !g.Timestamp.Equal(ev.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", g.Timestamp, ev.Timestamp)
	}
	if g.Port != ev.Port {
		t.Errorf("Port = %d, want %d", g.Port, ev.Port)
	}
	if g.URL != ev.URL {
		t.Errorf("URL = %q, want %q", g.URL, ev.URL)
	}
	if g.SecretRef != ev.SecretRef {
		t.Errorf("SecretRef = %q, want %q", g.SecretRef, ev.SecretRef)
	}
}

func TestCentralStore_FilterByProxyID(t *testing.T) {
	cs := NewCentralStore(0)
	base := time.Unix(2000, 0).UTC()
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base, Domain: "a.com", Decision: "allow"},
		ProxyID: "proxy-1",
	})
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base.Add(time.Second), Domain: "b.com", Decision: "deny"},
		ProxyID: "proxy-2",
	})
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base.Add(2 * time.Second), Domain: "c.com", Decision: "allow"},
		ProxyID: "proxy-1",
	})
	got, err := cs.GetAggregatedEvents(AggregatedFilter{ProxyID: "proxy-1"})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for _, g := range got {
		if g.ProxyID != "proxy-1" {
			t.Errorf("ProxyID = %q, want proxy-1", g.ProxyID)
		}
	}
}

func TestCentralStore_FilterByAgentID(t *testing.T) {
	cs := NewCentralStore(0)
	base := time.Unix(3000, 0).UTC()
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base, Domain: "a.com", Decision: "allow"},
		AgentID: "agent-a",
	})
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base.Add(time.Second), Domain: "b.com", Decision: "deny"},
		AgentID: "agent-b",
	})
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base.Add(2 * time.Second), Domain: "c.com", Decision: "allow"},
		AgentID: "agent-a",
	})
	got, err := cs.GetAggregatedEvents(AggregatedFilter{AgentID: "agent-a"})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for _, g := range got {
		if g.AgentID != "agent-a" {
			t.Errorf("AgentID = %q, want agent-a", g.AgentID)
		}
	}
}

func TestCentralStore_CombinedFilters(t *testing.T) {
	cs := NewCentralStore(0)
	base := time.Unix(4000, 0).UTC()
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base, Domain: "a.com", Decision: "allow"},
		ProxyID: "proxy-1",
	})
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base.Add(time.Second), Domain: "b.com", Decision: "deny"},
		ProxyID: "proxy-1",
	})
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event:   Event{Timestamp: base.Add(2 * time.Second), Domain: "a.com", Decision: "allow"},
		ProxyID: "proxy-2",
	})
	got, err := cs.GetAggregatedEvents(AggregatedFilter{
		EventFilter: EventFilter{Domain: "a.com"},
		ProxyID:     "proxy-1",
	})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Domain != "a.com" {
		t.Errorf("Domain = %q, want a.com", got[0].Domain)
	}
	if got[0].ProxyID != "proxy-1" {
		t.Errorf("ProxyID = %q, want proxy-1", got[0].ProxyID)
	}
}

func TestCentralStore_RetentionCap(t *testing.T) {
	cs := NewCentralStore(3)
	base := time.Unix(5000, 0).UTC()
	for i := 0; i < 5; i++ {
		_ = cs.StoreAggregatedEvent(AggregatedEvent{
			Event: Event{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				Domain:    "d.com",
				URL:       string(rune('A' + i)),
				Decision:  "allow",
			},
			ProxyID: "proxy-1",
		})
	}
	got, err := cs.GetAggregatedEvents(AggregatedFilter{})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (capped)", len(got))
	}
	// Newest three: E, D, C (oldest A, B pruned).
	want := []string{"E", "D", "C"}
	for i, w := range want {
		if got[i].URL != w {
			t.Errorf("row %d URL = %q, want %q", i, got[i].URL, w)
		}
	}
}

func TestCentralStore_ImplementsAnalyticsStore(t *testing.T) {
	var store AnalyticsStore = NewCentralStore(0)
	ev := Event{
		Timestamp: time.Unix(6000, 0).UTC(),
		Domain:    "api.openai.com",
		Decision:  "allow",
	}
	if err := store.StoreEvent(ev); err != nil {
		t.Fatalf("StoreEvent: %v", err)
	}
	got, err := store.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Domain != "api.openai.com" {
		t.Errorf("Domain = %q, want api.openai.com", got[0].Domain)
	}
	// Verify via aggregated view that ProxyID/AgentID are empty.
	cs := store.(*CentralStore)
	agg, _ := cs.GetAggregatedEvents(AggregatedFilter{})
	if agg[0].ProxyID != "" {
		t.Errorf("ProxyID = %q, want empty", agg[0].ProxyID)
	}
	if agg[0].AgentID != "" {
		t.Errorf("AgentID = %q, want empty", agg[0].AgentID)
	}
}

func TestCentralStore_NewestFirst(t *testing.T) {
	cs := NewCentralStore(0)
	base := time.Unix(7000, 0).UTC()
	for i := 0; i < 3; i++ {
		_ = cs.StoreAggregatedEvent(AggregatedEvent{
			Event: Event{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				Domain:    "d.com",
				URL:       string(rune('A' + i)),
				Decision:  "allow",
			},
		})
	}
	got, err := cs.GetAggregatedEvents(AggregatedFilter{})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	// Newest first: C, B, A.
	want := []string{"C", "B", "A"}
	for i, w := range want {
		if got[i].URL != w {
			t.Errorf("row %d URL = %q, want %q (newest first)", i, got[i].URL, w)
		}
	}
}

func TestCentralStore_SinceFilter(t *testing.T) {
	cs := NewCentralStore(0)
	base := time.Unix(8000, 0).UTC()
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event: Event{Timestamp: base, Domain: "old.com", Decision: "allow"},
	})
	_ = cs.StoreAggregatedEvent(AggregatedEvent{
		Event: Event{Timestamp: base.Add(10 * time.Second), Domain: "new.com", Decision: "allow"},
	})
	got, err := cs.GetAggregatedEvents(AggregatedFilter{
		EventFilter: EventFilter{Since: base.Add(5 * time.Second)},
	})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Domain != "new.com" {
		t.Errorf("Domain = %q, want new.com", got[0].Domain)
	}
}

func TestCentralStore_LimitFilter(t *testing.T) {
	cs := NewCentralStore(0)
	base := time.Unix(9000, 0).UTC()
	for i := 0; i < 5; i++ {
		_ = cs.StoreAggregatedEvent(AggregatedEvent{
			Event: Event{
				Timestamp: base.Add(time.Duration(i) * time.Second),
				Domain:    "d.com",
				Decision:  "allow",
			},
		})
	}
	got, err := cs.GetAggregatedEvents(AggregatedFilter{
		EventFilter: EventFilter{Limit: 2},
	})
	if err != nil {
		t.Fatalf("GetAggregatedEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
}
