package scenarios

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness"
)

// userUsageAPI proves W-P3-PUL-05 end to end: events handed straight to the
// control plane's ingest (no worker proxy drives them), the per-user daily rollup (W-P3-PUL-07)
// totals them, and GET /dashboard/api/usage/users returns the per-user
// requests, denies by reason, estimated cost and the anonymous bucket.
func userUsageAPI(t *testing.T, h *harness.H) {
	now := time.Now().UTC()
	mk := func(sub, decision, reason, rule string, cost float64) analytics.Event {
		e := analytics.Event{
			Timestamp: now, Domain: "usage.example.com", Port: 443, Protocol: "https", Method: "GET",
			URL: "https://usage.example.com/", Decision: decision, Reason: reason,
			AgentID: "claude-code", LimitRule: rule, CostUSD: cost,
		}
		if sub != "" {
			e.UserSub, e.UserEmail, e.IdentityStatus = sub, sub+"@corp.example", "valid"
		}
		return e
	}
	var evs []analytics.Event
	for i := 0; i < 5; i++ {
		evs = append(evs, mk("sub-alice", "allow", "", "eng-llm", 0.25))
	}
	evs = append(evs,
		mk("sub-alice", "deny", "user_rate_limited", "eng-llm", 0),
		mk("sub-alice", "deny", "user_rate_limited", "eng-llm", 0),
		mk("sub-bob", "allow", "", "", 0),
		mk("", "allow", "", analytics.AnonymousLimitRule, 0),
		mk("", "allow", "", analytics.AnonymousLimitRule, 0),
		mk("", "allow", "", analytics.AnonymousLimitRule, 0),
	)
	if err := h.CP().IngestEvents("worker-1", evs); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var got struct {
		Users []struct {
			Sub      string           `json:"sub"`
			Requests int64            `json:"requests"`
			Denies   map[string]int64 `json:"denies"`
			CostUSD  float64          `json:"costUSD"`
		} `json:"users"`
		Unattributed struct {
			Requests int64 `json:"requests"`
		} `json:"unattributed"`
	}
	h.Eventually("the usage view to total the forwarded events", func() bool {
		got.Users = nil
		if err := h.CP().GetJSON("/dashboard/api/usage/users?window=7d", &got); err != nil {
			t.Fatalf("cp GET usage/users: %v", err)
		}
		return len(got.Users) == 2 && got.Unattributed.Requests == 3
	})
	a := got.Users[0]
	if a.Sub != "sub-alice" || a.Requests != 7 || a.Denies["user_rate_limited"] != 2 || a.CostUSD != 1.25 {
		t.Fatalf("alice = %+v, want 7 requests, 2 user_rate_limited, $1.25", a)
	}
}
