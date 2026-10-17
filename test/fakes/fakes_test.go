package fakes

import (
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

func TestFakeConfigProvider(t *testing.T) {
	want := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "x"}}}
	f := &FakeConfigProvider{Policy: want}
	got, err := f.GetPolicy()
	if err != nil || len(got.Allowlist) != 1 {
		t.Fatalf("GetPolicy = %+v, %v", got, err)
	}

	ferr := &FakeConfigProvider{Err: errors.New("boom")}
	if _, err := ferr.GetPolicy(); err == nil {
		t.Error("expected error")
	}
}

func TestFakeSecretProvider(t *testing.T) {
	f := &FakeSecretProvider{Values: map[string]string{"p1": "v1"}}
	if v, err := f.GetSecret("p1"); err != nil || v != "v1" {
		t.Fatalf("GetSecret = %q, %v", v, err)
	}
	if _, err := f.GetSecret("missing"); !errors.Is(err, secrets.ErrUnknownPlaceholder) {
		t.Errorf("missing err = %v", err)
	}
	if err := f.RefreshSecrets(); err != nil {
		t.Errorf("refresh: %v", err)
	}
	if f.RefreshCount != 1 {
		t.Errorf("refresh count = %d", f.RefreshCount)
	}

	ferr := &FakeSecretProvider{RefreshErr: errors.New("down")}
	if err := ferr.RefreshSecrets(); err == nil {
		t.Error("expected refresh error")
	}
}

func TestFakeAnalyticsStore(t *testing.T) {
	f := &FakeAnalyticsStore{}
	_ = f.StoreEvent(analytics.Event{Domain: "a.com", Decision: "allow"})
	_ = f.StoreEvent(analytics.Event{Domain: "b.com", Decision: "deny", Reason: "policy_no_match"})
	_ = f.StoreEvent(analytics.Event{Domain: "a.com", Decision: "deny", Reason: "policy_denylist"})

	all, _ := f.GetEvents(analytics.EventFilter{})
	if len(all) != 3 {
		t.Fatalf("all len = %d", len(all))
	}
	// Newest first.
	if all[0].Domain != "a.com" || all[0].Decision != "deny" {
		t.Errorf("ordering: %+v", all[0])
	}
	byDomain, _ := f.GetEvents(analytics.EventFilter{Domain: "a.com"})
	if len(byDomain) != 2 {
		t.Errorf("domain filter len = %d", len(byDomain))
	}
	byDecision, _ := f.GetEvents(analytics.EventFilter{Decision: "deny"})
	if len(byDecision) != 2 {
		t.Errorf("decision filter len = %d", len(byDecision))
	}
	limited, _ := f.GetEvents(analytics.EventFilter{Limit: 1})
	if len(limited) != 1 {
		t.Errorf("limit len = %d", len(limited))
	}
}

// TestFakeAnalyticsStore_EnforcesDenyReason (#409): the fake fails the run on a
// deny recorded without a Reason, so every test using it enforces the
// deny-reason contract for free — and the contract itself is pinned here.
func TestFakeAnalyticsStore_EnforcesDenyReason(t *testing.T) {
	cases := []struct {
		name string
		e    analytics.Event
	}{
		{"deny without reason", analytics.Event{Domain: "x.com", Decision: "deny"}},
		{"block without reason", analytics.Event{Domain: "x.com", Decision: "block"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("reason-less %s event did not fail the fake", tc.e.Decision)
				}
			}()
			_ = (&FakeAnalyticsStore{}).StoreEvent(tc.e)
		})
	}
	// Allows and reason-carrying denies are untouched.
	f := &FakeAnalyticsStore{}
	_ = f.StoreEvent(analytics.Event{Domain: "a.com", Decision: "allow"})
	_ = f.StoreEvent(analytics.Event{Domain: "a.com", Decision: "deny", Reason: "policy_no_match"})
	if len(f.Events) != 2 {
		t.Errorf("len = %d, want 2", len(f.Events))
	}
}
