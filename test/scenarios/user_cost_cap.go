package scenarios

import (
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Per-user daily cost caps (W-P3-PUL-04). The control plane serves an eng
// rule capped at $0.01 a day on the cost-tracked api.openai.com. The fake
// provider streams each answer chunked (no Content-Length), so the worker
// prices it from the bytes it relayed: $0.006 a request. Alice's third
// request is refused with 403 user_cost_limited and Retry-After to the next
// UTC midnight; bob, under the same rule, keeps his own budget. After a worker
// restart the ledger is reseeded from the worker's local events, so alice is
// still refused.

const (
	costCapHost = "api.openai.com" // priced by the worker's built-in estimator
	// 1600 bytes: 400 output tokens at openai's $0.015 per 1K = $0.006.
	costCapBodyBytes = 1600
	costCapRule      = "eng-llm"
)

func userCostCapOpts() []harness.Option {
	return []harness.Option{
		harness.WithIdentity(config.IdentityModeAttribute),
		harness.Allow(costCapHost),
		harness.WithUserLimits(
			[]config.UserLimit{{
				Name:         costCapRule,
				Match:        config.UserLimitMatch{Groups: []string{"eng"}, Domains: []string{costCapHost}},
				DailyCostUSD: 0.01,
			}},
			nil, nil,
		),
	}
}

// streamedLLM answers every request with a chunked body of costCapBodyBytes.
func streamedLLM(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "text/event-stream")
	f, _ := w.(http.Flusher)
	half := strings.Repeat("x", costCapBodyBytes/2)
	_, _ = io.WriteString(w, half)
	if f != nil {
		f.Flush()
	}
	_, _ = io.WriteString(w, half)
}

func costCapGet(t *testing.T, cl *http.Client, token string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+costCapHost+"/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Warden-Identity", "Bearer "+token)
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", costCapHost, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

func isUserCostLimited(resp *http.Response, body string) bool {
	return resp.StatusCode == http.StatusForbidden && body == `{"error":"user_cost_limited"}`
}

func assertUserCostLimited(t *testing.T, who string, resp *http.Response, body string) {
	t.Helper()
	if !isUserCostLimited(resp, body) {
		t.Fatalf("%s: status %d body %q, want 403 user_cost_limited", who, resp.StatusCode, body)
	}
	if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || n < 1 || n > 86400 {
		t.Errorf("%s: Retry-After = %q, want seconds to the next UTC midnight", who, resp.Header.Get("Retry-After"))
	}
}

func userCostCap(t *testing.T, h *harness.H) {
	up := h.Upstream(costCapHost)
	up.SetNext(http.HandlerFunc(streamedLLM))
	alice := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	bob := h.MintUserToken(fakes.Valid("bob", "bob@example.com", "eng"))
	perRequest := cost.NewEstimator().Estimate(costCapHost, 0, costCapBodyBytes).TotalCost

	// The ledger is charged once the response has been relayed, so the next
	// request waits for the previous one's allow event.
	allowsFor := func(sub string) int {
		n := 0
		for _, e := range h.Events() {
			if e.Domain == costCapHost && e.Decision == "allow" && e.UserSub == sub {
				n++
			}
		}
		return n
	}
	cl := h.Agent()
	for i := 1; i <= 2; i++ {
		if resp, body := costCapGet(t, cl, alice); resp.StatusCode != http.StatusOK || len(body) != costCapBodyBytes {
			t.Fatalf("alice request %d = %d (%d bytes), want 200", i, resp.StatusCode, len(body))
		}
		h.Eventually("alice's allow is recorded", func() bool { return allowsFor("alice") == i })
	}
	resp, body := costCapGet(t, cl, alice)
	assertUserCostLimited(t, "alice's 3rd", resp, body)
	if resp, body := costCapGet(t, cl, bob); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob = %d %q, want 200 (his own budget)", resp.StatusCode, body)
	}
	if n := len(up.Requests()); n != 3 {
		t.Errorf("provider saw %d requests, want 3 (the refusal never reaches it)", n)
	}

	var evs []analytics.Event
	h.Eventually("the allows and the refusal are recorded", func() bool {
		evs = nil
		for _, e := range h.Events() {
			if e.Domain == costCapHost && e.Method != "" {
				evs = append(evs, e)
			}
		}
		return len(evs) == 4
	})
	for _, e := range evs {
		if e.LimitRule != costCapRule {
			t.Errorf("%s event for %q: limit_rule = %q, want %q", e.Decision, e.UserSub, e.LimitRule, costCapRule)
		}
		switch e.Decision {
		case "allow":
			// The streamed answer is priced from the relayed bytes, exactly.
			if math.Abs(e.CostUSD-perRequest) > 1e-12 || e.Provider != "openai" {
				t.Errorf("allow priced %v by %q, want %v by openai", e.CostUSD, e.Provider, perRequest)
			}
		case "deny":
			if e.Reason != "user_cost_limited" || e.UserSub != "alice" || e.AgentID == "" {
				t.Errorf("deny = %+v, want alice's user_cost_limited", e)
			}
		}
	}
	if h.MetricsAvailable() {
		m := h.Metrics()
		if got := m[harness.MetricKey("warden.user_limit.denied.total", map[string]string{"kind": "cost"})]; got != 1 {
			t.Errorf("warden.user_limit.denied.total{kind=cost} = %v, want 1", got)
		}
		for k := range m {
			if strings.Contains(k, "alice") || strings.Contains(k, "bob@") {
				t.Errorf("metric carries identity: %s", k)
			}
		}
	}
	// The worker advertises the cost-cap capability.
	h.Eventually("the worker heartbeats usercost/v1", func() bool {
		h.Clock().Advance(time.Second)
		ws, err := h.CP().Workers()
		return err == nil && len(ws) > 0 && slices.Contains(ws[0].Caps, config.CapUserCostV1)
	})

	// A restart reseeds the ledger from the worker's own events.
	h.RestartWorker(0)
	cl = h.Agent()
	// Bob (one request spent) is served once the restarted worker has its
	// policy; a refusal before that is the fail-closed boot, not a charge.
	h.Eventually("the restarted worker serves bob", func() bool {
		resp, _ := costCapGet(t, cl, bob)
		return resp.StatusCode == http.StatusOK
	})
	// Alice's first request after the restart is refused: no new spend, only
	// the seeded one.
	resp, body = costCapGet(t, cl, alice)
	assertUserCostLimited(t, "alice after the restart", resp, body)
}
