package scenarios

import (
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Per-user rate limits (W-P3-PUL-09). The control plane serves a groups rule
// for eng on one host plus an anonymous rule; the worker charges every request
// with its own verified subject, so on one keep-alive client two users have
// two budgets, a request without a token falls into the anonymous bucket, and
// only the user over the limit gets 429 user_rate_limited with Retry-After.

const limitedHost = "limited.example.com"

func userRateLimitOpts() []harness.Option {
	return []harness.Option{
		harness.WithIdentity(config.IdentityModeAttribute),
		harness.Allow(limitedHost),
		harness.WithUserLimits(
			[]config.UserLimit{{
				Name:      "eng",
				Match:     config.UserLimitMatch{Groups: []string{"eng"}, Domains: []string{limitedHost}},
				RateLimit: "3/hour",
			}},
			nil,
			&config.UserLimit{RateLimit: "1/hour"},
		),
	}
}

// limitedGet sends one GET to limitedHost through cl with an optional identity
// token and returns the response with its body read and closed.
func limitedGet(t *testing.T, cl *http.Client, token string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+limitedHost+"/v1/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Warden-Identity", "Bearer "+token)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", limitedHost, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

func assertUserRateLimited(t *testing.T, who string, resp *http.Response, body string) {
	t.Helper()
	if resp.StatusCode != http.StatusTooManyRequests || body != `{"error":"user_rate_limited"}` {
		t.Fatalf("%s: status %d body %q, want 429 user_rate_limited", who, resp.StatusCode, body)
	}
	if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || n < 1 || n > 3600 {
		t.Errorf("%s: Retry-After = %q, want integer seconds in [1, 3600]", who, resp.Header.Get("Retry-After"))
	}
}

func limitedEvents(h *harness.H) []analytics.Event {
	var out []analytics.Event
	for _, e := range h.Events() {
		if e.Domain == limitedHost && e.Method != "" {
			out = append(out, e)
		}
	}
	return out
}

func userRateLimit(t *testing.T, h *harness.H) {
	up := h.Upstream(limitedHost)
	alice := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	bob := h.MintUserToken(fakes.Valid("bob", "bob@example.com", "eng"))

	// One keep-alive client carries both users; each has a budget of 3.
	cl := h.Agent()
	for i, tok := range []string{alice, bob, alice, bob, alice, bob} {
		if resp, body := limitedGet(t, cl, tok); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d %q, want 200", i, resp.StatusCode, body)
		}
	}
	resp, body := limitedGet(t, cl, alice)
	assertUserRateLimited(t, "alice's 4th", resp, body)
	// The anonymous bucket is separate: one request, then refused.
	if resp, body := limitedGet(t, h.Agent(), ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("anonymous request = %d %q, want 200", resp.StatusCode, body)
	}
	resp, body = limitedGet(t, h.Agent(), "")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second anonymous request = %d %q, want 429", resp.StatusCode, body)
	}
	if n := len(up.Requests()); n != 7 {
		t.Errorf("upstream saw %d requests, want 7 (refusals never reach it)", n)
	}

	var evs []analytics.Event
	h.Eventually("the allows and the two refusals are recorded", func() bool {
		evs = limitedEvents(h)
		return len(evs) == 9
	})
	agent := ""
	var denies []analytics.Event
	for _, e := range evs {
		if e.AgentID == "" {
			t.Errorf("event without agent_id: %+v", e)
		}
		if agent == "" {
			agent = e.AgentID
		} else if e.AgentID != agent {
			t.Errorf("agent_id %q != %q: the bound agent, never a request value", e.AgentID, agent)
		}
		want := "eng"
		if e.UserSub == "" {
			want = config.UserLimitNameAnonymous
		}
		if e.LimitRule != want {
			t.Errorf("%s event for %q: limit_rule = %q, want %q", e.Decision, e.UserSub, e.LimitRule, want)
		}
		if e.Decision == "deny" {
			denies = append(denies, e)
		}
	}
	if len(denies) != 2 || denies[0].Reason != "user_rate_limited" || denies[1].Reason != "user_rate_limited" ||
		!slices.ContainsFunc(denies, func(e analytics.Event) bool { return e.UserSub == "alice" }) {
		t.Errorf("denies = %+v, want alice's and the anonymous user_rate_limited", denies)
	}

	if h.MetricsAvailable() {
		m := h.Metrics()
		if got := m[harness.MetricKey("warden.user_limit.denied.total", map[string]string{"kind": "rate"})]; got != 2 {
			t.Errorf("warden.user_limit.denied.total{kind=rate} = %v, want 2", got)
		}
		if got := m[harness.MetricKey("warden.user_limit.buckets", nil)]; got != 3 {
			t.Errorf("warden.user_limit.buckets = %v, want 3 (alice, bob, anonymous)", got)
		}
		for k := range m {
			if strings.Contains(k, "alice") || strings.Contains(k, "bob@") {
				t.Errorf("metric carries identity: %s", k)
			}
		}
	}
	// The worker advertises the capability.
	h.Eventually("the worker heartbeats userlimits/v1", func() bool {
		// Workers heartbeat on the harness's fake clock: one beat per advance.
		h.Clock().Advance(time.Second)
		ws, err := h.CP().Workers()
		if err != nil || len(ws) == 0 {
			return false
		}
		return slices.Contains(ws[0].Caps, config.CapUserLimitsV1)
	})
}
