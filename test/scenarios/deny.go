package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/denyreason"
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
// deny event with reason policy_no_match (#409), the decision log names the
// domain, and — where the target carries the metrics oracle — the blocked
// metric counts the same refusals.
//
// The destination is the harness's "unlisted" name (h.Host): a host NO policy
// lists, so a refusal there is the default-deny reason on both targets. (The
// "evil" alias is policy-adjacent on a deployment that also denylists it, which
// would make the pinned no_match reason a stack-config fact instead.)
func defaultDeny(t *testing.T, h *harness.H) {
	host := h.Host("unlisted")
	up := h.Upstream(host)

	_, err := h.Agent().Get("https://" + host + "/steal-data")
	if err == nil {
		t.Fatal("the agent's GET to a non-allowlisted destination succeeded; default-deny is broken")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("agent error = %v, want the proxy's 403 Forbidden", err)
	}
	if got := connectStatus(t, h, host+":443"); got != http.StatusForbidden {
		t.Errorf("CONNECT status = %d, want 403", got)
	}

	denies := eventsFor(h.Events(), host, "deny")
	// The agent's GET and the explicit CONNECT are two refused tunnels.
	if len(denies) != 2 {
		t.Errorf("deny events for %s = %d, want 2 (one per refused tunnel)", host, len(denies))
	}
	for _, ev := range denies {
		if ev.Reason != string(denyreason.PolicyNoMatch) {
			t.Errorf("deny event reason = %q, want %q (#409)", ev.Reason, denyreason.PolicyNoMatch)
		}
	}
	if !strings.Contains(h.Logs(), `"decision":"deny"`) {
		t.Error("the worker's decision log has no deny line")
	}
	// One blocked count per refused tunnel, labelled with the policy reason. A
	// target without the metrics oracle (compose exports no OTel endpoint)
	// skips this leg explicitly: it is asserted where the oracle exists, never
	// silently (h.Metrics would fail the test loudly here).
	if h.MetricsAvailable() {
		blocked := harness.MetricKey("warden.blocked.total", map[string]string{"reason": string(denyreason.PolicyNoMatch)})
		h.Eventually("the policy-blocked metric to reach 2", func() bool {
			return h.Metrics()[blocked] == 2
		})
	}
	if got := len(up.Requests()); got != 0 {
		t.Errorf("the denied upstream saw %d request(s), want 0", got)
	}
}
