package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The scoped-policy scenarios (W-P1-GPOL-10). A scoped allow entry
// ({domain, groups}) now loads and is decided on every request with that
// request's verified subject; entries without groups/users behave as before.

const (
	scopedHost = "scoped.example.com"
	plainHost  = "plain.example.com"
)

// savePolicy POSTs an allowlist through the dashboard policy API.
func savePolicy(t *testing.T, h *harness.H, entries ...map[string]any) harness.CPResponse {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"allowlist": entries, "denylist": []map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := h.CP().Send(http.MethodPost, "/dashboard/api/policy", nil, raw)
	if err != nil {
		t.Fatalf("POST policy: %v", err)
	}
	return r
}

// getStatus sends one GET to host through cl, optionally with the identity
// header, and returns the status.
func getStatus(t *testing.T, cl *http.Client, host, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Warden-Identity", "Bearer "+token)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func denyCount(h *harness.H, host, reason string) int {
	n := 0
	for _, e := range h.Events() {
		if e.Decision == "deny" && e.Domain == host && e.Reason == reason {
			n++
		}
	}
	return n
}

// scopedPolicyFailClosed: the worker's identity mode is off, so no request has
// a subject. The scoped save loads (200), the scoped host is denied with
// identity_required and never reaches the upstream, and the plain entry saved
// beside it still works.
func scopedPolicyFailClosed(t *testing.T, h *harness.H) {
	scoped := h.Upstream(scopedHost)
	h.Upstream(plainHost)

	if r := savePolicy(t, h, map[string]any{"domain": scopedHost, "groups": []string{"eng"}}, map[string]any{"domain": plainHost}); r.Status != http.StatusOK {
		t.Fatalf("scoped save = %d %s, want 200", r.Status, r.Body)
	}
	h.Eventually("workers enforce the save", func() bool {
		return connectStatus(t, h, plainHost+":443") == http.StatusOK
	})
	if got := getStatus(t, h.Agent(), scopedHost, ""); got != http.StatusForbidden {
		t.Fatalf("GET %s = %d, want 403: a scoped rule never allows a request without identity", scopedHost, got)
	}
	h.Eventually("the deny is audited as identity_required", func() bool {
		return denyCount(h, scopedHost, "identity_required") == 1
	})
	if n := len(scoped.Requests()); n != 0 {
		t.Errorf("scoped upstream saw %d requests, want 0", n)
	}
	if got := getStatus(t, h.Agent(), plainHost, ""); got != http.StatusOK {
		t.Errorf("GET %s = %d, want 200", plainHost, got)
	}
}

// scopedPolicyDeferredIdentity: with identity on, one tunnel carries requests
// from different users and each is decided by its own subject, on HTTP/1.1 and
// on every h2 stream. A member is forwarded, a non-member and an anonymous
// caller get 403 (group_not_allowed / identity_required) and the upstream never
// sees them, and warden_policy_scoped_total counts the three outcomes with no
// user or group label.
func scopedPolicyDeferredIdentity(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	member := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	other := h.MintUserToken(fakes.Valid("sam", "sam@example.com", "sales"))

	if r := savePolicy(t, h, map[string]any{"domain": scopedHost, "groups": []string{"eng"}}, map[string]any{"domain": plainHost}); r.Status != http.StatusOK {
		t.Fatalf("scoped save = %d %s, want 200", r.Status, r.Body)
	}
	h.Eventually("workers enforce the save", func() bool {
		return connectStatus(t, h, plainHost+":443") == http.StatusOK
	})

	for _, tc := range []struct {
		name string
		cl   func() *http.Client
	}{{"h1", h.Agent}, {"h2", h.AgentH2}} {
		cl := tc.cl()
		if got := getStatus(t, cl, scopedHost, member); got != http.StatusOK {
			t.Fatalf("%s: member request = %d, want 200", tc.name, got)
		}
		// On h1 a deny ends the tunnel, so each refusal gets a fresh client.
		if got := getStatus(t, tc.cl(), scopedHost, other); got != http.StatusForbidden {
			t.Fatalf("%s: non-member request = %d, want 403", tc.name, got)
		}
		if got := getStatus(t, tc.cl(), scopedHost, ""); got != http.StatusForbidden {
			t.Fatalf("%s: anonymous request = %d, want 403", tc.name, got)
		}
	}
	// A member's token on CONNECT is verified there too.
	if got := getStatus(t, h.AgentWithProxyToken(member), scopedHost, ""); got != http.StatusOK {
		t.Fatalf("member via Proxy-Authorization = %d, want 200", got)
	}

	h.Eventually("every refusal is audited with its reason", func() bool {
		return denyCount(h, scopedHost, "group_not_allowed") == 2 && denyCount(h, scopedHost, "identity_required") == 2
	})
	if n := len(up.Requests()); n != 3 {
		t.Errorf("upstream saw %d requests, want 3 (members only)", n)
	}
	if h.MetricsAvailable() {
		m := h.Metrics()
		for result, want := range map[string]float64{"allow": 3, "not_member": 2, "no_identity": 2} {
			if got := m[harness.MetricKey("warden.policy.scoped.total", map[string]string{"result": result})]; got != want {
				t.Errorf("warden.policy.scoped.total{result=%s} = %v, want %v", result, got, want)
			}
		}
		for k := range m {
			if strings.HasPrefix(k, "warden.policy.scoped.total") && (strings.Contains(k, "user") || strings.Contains(k, "group")) {
				t.Errorf("scoped metric carries a user/group label: %s", k)
			}
		}
	}
}
