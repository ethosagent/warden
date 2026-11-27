package scenarios

import (
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Per-user limits end to end (W-P3-PUL-10): one control plane with the sqlite
// fleet store and two CA-enabled workers that forward their events to it. The
// served policy has two eng rules and an anonymous rule:
//
//	eng-llm  groups eng, api.openai.com only   dailyCostUSD 0.01 (no rate)
//	eng-all  groups eng, every other domain    rateLimit 3/hour
//	anonymousLimit                             rateLimit 1/hour
//
// The scenario proves, in order: a rate deny for alice while bob on the same
// agent continues (worker-1); an unrelated block-list change does not reset
// alice's window; a token-less request lands in the anonymous bucket; a
// streamed LLM answer is priced from the relayed bytes and alice is refused on
// worker-1 by its own ledger; worker-2, which never saw her spend, refuses her
// through the CP's signed costBlockedUsers (the fleet L1 scenario of the cost
// block path); the judge is never asked about any of it; the usage endpoint
// totals her activity; neither a token nor an email reaches the logs or the
// metrics; and the cost block lapses at the next UTC midnight.

const userLimitsUnlistedHost = "unlisted.example.com"

func userLimitsOpts() []harness.Option {
	return []harness.Option{
		harness.Fleet(2),
		harness.WithIdentity(config.IdentityModeAttribute),
		harness.WithCentralForwarding(),
		harness.WithFleetCostBlocks(),
		harness.WithControlPlaneAdminToken(),
		harness.WithFakeJudge(),
		harness.Allow(limitedHost, costCapHost),
		harness.WithUserLimits(
			[]config.UserLimit{
				{
					Name:         costCapRule,
					Match:        config.UserLimitMatch{Groups: []string{"eng"}, Domains: []string{costCapHost}},
					DailyCostUSD: 0.01,
				},
				{
					Name:      "eng-all",
					Match:     config.UserLimitMatch{Groups: []string{"eng"}},
					RateLimit: "3/hour",
				},
			},
			nil,
			&config.UserLimit{RateLimit: "1/hour"},
		),
	}
}

// userLimitsTinyLLM answers with a few bytes: a probe that prices at nothing.
func userLimitsTinyLLM(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	_, _ = io.WriteString(w, "ok")
}

func userLimitsE2E(t *testing.T, h *harness.H) {
	h.Upstream(limitedHost)
	llm := h.Upstream(costCapHost)
	llm.SetNext(http.HandlerFunc(userLimitsTinyLLM))
	h.Upstream(userLimitsUnlistedHost)
	alice := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	bob := h.MintUserToken(fakes.Valid("bob", "bob@example.com", "eng"))
	carol := h.MintUserToken(fakes.Valid("carol", "carol@example.com", "eng"))
	w1, w2 := h.AgentAt(0), h.AgentAt(1)

	// 1. Rate: alice spends her 3 requests an hour on worker-1, the 4th is a
	// 429 with Retry-After, and bob on the same agent and the same keep-alive
	// client keeps his own budget.
	for i := 1; i <= 3; i++ {
		if resp, body := limitedGet(t, w1, alice); resp.StatusCode != http.StatusOK {
			t.Fatalf("alice request %d = %d %q, want 200", i, resp.StatusCode, body)
		}
	}
	resp, body := limitedGet(t, w1, alice)
	assertUserRateLimited(t, "alice's 4th", resp, body)
	if resp, body := limitedGet(t, w1, bob); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob = %d %q, want 200 (his own budget)", resp.StatusCode, body)
	}
	// The rule's one budget spans all its domains, and an over-budget user is
	// refused before the judge is consulted for a destination no rule allows.
	resp, body = userLimitsGet(t, w1, userLimitsUnlistedHost, alice)
	assertUserRateLimited(t, "alice on an unlisted host", resp, body)

	// 2. An unrelated block-list change (carol) reaches the worker and does
	// not reset alice's window.
	h.BlockUser("carol", "")
	advanceUntil(h, time.Second, "worker-1 applies the block-list change", func() bool {
		resp, _ := limitedGet(t, w1, carol)
		return resp.StatusCode != http.StatusOK
	})
	resp, body = limitedGet(t, w1, alice)
	assertUserRateLimited(t, "alice after the block-list change", resp, body)

	// 3. No token: the request lands in the anonymous bucket (1 an hour per
	// agent), not in alice's.
	if resp, body := limitedGet(t, w1, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous request = %d %q, want 200", resp.StatusCode, body)
	}
	resp, body = limitedGet(t, w1, "")
	assertUserRateLimited(t, "second anonymous request", resp, body)

	// 4. Cost cap on worker-1: two streamed answers price at $0.006 each from
	// the bytes relayed; the third request is refused by the worker's ledger.
	llm.SetNext(http.HandlerFunc(streamedLLM))
	// The workers forward their events to the CP and drop them locally, so
	// the CP's traffic view is the record: the ledger is charged before an
	// event leaves the worker, so a priced allow there means the next request
	// sees the spend.
	for i := 1; i <= 2; i++ {
		if resp, body := costCapGet(t, w1, alice); resp.StatusCode != http.StatusOK || len(body) != costCapBodyBytes {
			t.Fatalf("alice streamed request %d = %d (%d bytes), want 200", i, resp.StatusCode, len(body))
		}
		i := i
		advanceUntil(h, 200*time.Millisecond, "alice's priced allow to reach the CP", func() bool { return pricedAllows(userLimitsFleetEvents(t, h, "alice")) == i })
	}
	resp, body = costCapGet(t, w1, alice)
	assertUserCostLimited(t, "alice's 3rd streamed request on worker-1", resp, body)
	llm.SetNext(http.HandlerFunc(userLimitsTinyLLM))

	// 5. Fleet block: worker-2 has never served alice, so its ledger is empty.
	// Within the CP's debounce plus a poll cycle the signed costBlockedUsers
	// entry reaches it and it refuses her too. The probes are tiny answers, so
	// none of them moves worker-2's own ledger.
	// The aggregator recomputes at most once per 30s of CP time.
	advanceUntil(h, 30*time.Second, "the CP to publish costBlockedUsers", func() bool {
		var pol struct {
			CostBlockedUsers []config.CostBlockedUser `json:"costBlockedUsers"`
		}
		if err := h.CP().GetJSON("/policy", &pol); err != nil {
			t.Fatalf("cp GET policy: %v", err)
		}
		return len(pol.CostBlockedUsers) == 1 && pol.CostBlockedUsers[0].Sub == "alice" && pol.CostBlockedUsers[0].Rule == costCapRule
	})
	advanceUntil(h, time.Second, "worker-2 to refuse alice through costBlockedUsers", func() bool {
		resp, body := costCapGet(t, w2, alice)
		return isUserCostLimited(resp, body)
	})
	if resp, body := costCapGet(t, w2, bob); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob on worker-2 = %d %q, want 200 (the block is alice's)", resp.StatusCode, body)
	}

	// 6. The judge was never asked about a limit denial.
	if n := h.Judge().Calls(); n != 0 {
		t.Errorf("judge calls = %d, want 0 for user_rate_limited and user_cost_limited", n)
	}

	// 7. The usage endpoint totals alice's activity from the fleet rollup.
	userLimitsAssertUsage(t, h)

	// 8. Observability: both deny reasons are counted without identity labels,
	// and no token or email reaches the logs or the metrics.
	if h.MetricsAvailable() {
		m := h.Metrics()
		for kind, want := range map[string]float64{"rate": 4, "cost": 1} {
			if got := m[harness.MetricKey("warden.user_limit.denied.total", map[string]string{"kind": kind})]; got < want {
				t.Errorf("warden.user_limit.denied.total{kind=%s} = %v, want >= %v", kind, got, want)
			}
		}
		for k := range m {
			if strings.Contains(k, "alice") || strings.Contains(k, "@") {
				t.Errorf("metric carries identity: %s", k)
			}
		}
	}
	logs := h.Logs()
	for _, secret := range []string{alice, bob, carol, "alice@example.com", "bob@example.com", "carol@example.com"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs carry %q-class identity material", secret[:min(len(secret), 5)])
		}
	}

	// 9. The block lapses at the next UTC midnight, with the CP stopped: the
	// workers ignore a costBlockedUsers entry whose day is over, and a fresh
	// token the next day is served by both.
	h.CP().Stop()
	now := h.Clock().Now().UTC()
	nextDay := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 1, 0, time.UTC)
	h.Clock().Advance(nextDay.Sub(now))
	alice2 := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	for i, cl := range []*http.Client{w1, w2} {
		cl := cl
		advanceUntil(h, time.Second, "alice to be served again the next UTC day on worker-"+string(rune('1'+i)), func() bool {
			resp, _ := costCapGet(t, cl, alice2)
			return resp.StatusCode == http.StatusOK
		})
	}
}

func userLimitsGet(t *testing.T, cl *http.Client, host, token string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/v1/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Warden-Identity", "Bearer "+token)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", host, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

// userLimitsFleetEvents is sub's events as the CP's traffic view holds them
// (what the workers forwarded).
func userLimitsFleetEvents(t *testing.T, h *harness.H, sub string) []analytics.Event {
	t.Helper()
	var evs []analytics.Event
	if err := h.CP().GetJSON("/dashboard/api/traffic?limit=1000&user="+sub, &evs); err != nil {
		t.Fatalf("cp GET traffic: %v", err)
	}
	return evs
}

// pricedAllows counts the streamed LLM answers (priced allows) in evs.
func pricedAllows(evs []analytics.Event) int {
	n := 0
	for _, e := range evs {
		if e.Domain == costCapHost && e.Decision == "allow" && e.CostUSD > 0 {
			n++
		}
	}
	return n
}

// userLimitsAssertUsage compares GET /dashboard/api/usage/users for alice with
// what her own events say: requests are the forwarded ones (allows) plus the
// limit denials, denies are broken out by reason, cost is the sum of her
// priced allows.
func userLimitsAssertUsage(t *testing.T, h *harness.H) {
	t.Helper()
	var wantReq, rate, costDeny int64
	var wantCost float64
	// Every event of alice's has been forwarded once her two cost denies (one
	// per worker) and her three rate denies are in the CP's traffic view.
	advanceUntil(h, 200*time.Millisecond, "alice's denials to reach the CP", func() bool {
		wantReq, rate, costDeny, wantCost = 0, 0, 0, 0
		for _, e := range userLimitsFleetEvents(t, h, "alice") {
			switch {
			case e.Decision == "allow":
				wantReq++
				wantCost += e.CostUSD
			case e.Reason == "user_rate_limited":
				wantReq++
				rate++
			case e.Reason == "user_cost_limited":
				wantReq++
				costDeny++
			}
		}
		return rate == 3 && costDeny == 2
	})
	if wantCost < 0.012-1e-9 {
		t.Fatalf("alice's priced spend = $%v, want the two streamed answers", wantCost)
	}
	var got struct {
		Users []struct {
			Sub       string           `json:"sub"`
			Requests  int64            `json:"requests"`
			Denies    map[string]int64 `json:"denies"`
			CostUSD   float64          `json:"costUSD"`
			LimitRule string           `json:"limitRule"`
			TopAgents []struct {
				AgentID string `json:"agentID"`
			} `json:"topAgents"`
		} `json:"users"`
		Unattributed struct {
			Requests int64 `json:"requests"`
		} `json:"unattributed"`
	}
	h.Eventually("the usage view to total alice's activity", func() bool {
		got.Users = nil
		if err := h.CP().GetJSON("/dashboard/api/usage/users?window=7d", &got); err != nil {
			t.Fatalf("cp GET usage/users: %v", err)
		}
		for _, u := range got.Users {
			if u.Sub == "alice" {
				return u.Requests == wantReq && u.Denies["user_rate_limited"] == rate &&
					u.Denies["user_cost_limited"] == costDeny && math.Abs(u.CostUSD-wantCost) < 1e-9
			}
		}
		return false
	})
	if got.Unattributed.Requests < 1 {
		t.Errorf("unattributed requests = %d, want the anonymous bucket's", got.Unattributed.Requests)
	}
	for _, u := range got.Users {
		if u.Sub == "alice" && len(u.TopAgents) == 0 {
			t.Errorf("alice has no top agents: %+v", u)
		}
	}
	_ = analytics.AnonymousLimitRule
}

// advanceUntil polls cond, moving the harness clock one step before each
// retry. A step is bounded and the poll waits a few real milliseconds between
// tries, so a slow worker never makes the fake day run away (a hot loop would
// advance hours and expire the very windows the scenario asserts).
func advanceUntil(h *harness.H, step time.Duration, desc string, cond func() bool) {
	h.Eventually(desc, func() bool {
		if cond() {
			return true
		}
		h.Clock().Advance(step)
		time.Sleep(20 * time.Millisecond)
		return false
	})
}
