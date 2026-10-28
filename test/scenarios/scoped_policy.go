package scenarios

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policyeval"
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

// scopedPolicyReplayAffectedUsers (W-P1-GPOL-05): real traffic from two users
// is recorded with their verified identity, then replayed against a candidate
// that narrows the scoped rule to sales. The replay names the one user the
// change would cut off (alice, by email), counts the anonymous request apart
// and keeps every group list and token out of the report.
func scopedPolicyReplayAffectedUsers(t *testing.T, h *harness.H) {
	h.Upstream(scopedHost)
	h.Upstream(plainHost)
	alice := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	sam := h.MintUserToken(fakes.Valid("sam", "sam@example.com", "sales"))

	if r := savePolicy(t, h, map[string]any{"domain": scopedHost, "groups": []string{"eng", "sales"}}, map[string]any{"domain": plainHost}); r.Status != http.StatusOK {
		t.Fatalf("scoped save = %d %s, want 200", r.Status, r.Body)
	}
	h.Eventually("workers enforce the save", func() bool {
		return connectStatus(t, h, plainHost+":443") == http.StatusOK
	})
	for _, tok := range []string{alice, sam} {
		if got := getStatus(t, h.Agent(), scopedHost, tok); got != http.StatusOK {
			t.Fatalf("scoped request = %d, want 200", got)
		}
	}
	if got := getStatus(t, h.Agent(), plainHost, ""); got != http.StatusOK {
		t.Fatalf("anonymous plain request = %d, want 200", got)
	}
	h.Eventually("the identities are recorded", func() bool {
		n := 0
		for _, e := range h.Events() {
			if e.Domain == scopedHost && e.IdentityStatus == "valid" {
				n++
			}
		}
		return n == 2
	})

	candidate := config.Policy{Allowlist: []config.AllowlistEntry{
		{Domain: scopedHost, Groups: []string{"sales"}},
		{Domain: plainHost, Groups: []string{"sales"}},
	}}
	// Replay the requests only; the readiness probe above left CONNECT events.
	var recorded []analytics.Event
	for _, e := range h.Events() {
		if e.Method == http.MethodGet {
			recorded = append(recorded, e)
		}
	}
	res := policyeval.Evaluate(recorded, candidate)
	var users []string
	anon := 0
	for _, d := range res.NewDenies {
		users = append(users, d.AffectedUsers...)
		anon += d.AnonymousCount
	}
	if len(users) != 1 || users[0] != "alice@example.com" {
		t.Errorf("affected users = %v, want [alice@example.com]", users)
	}
	if anon != 1 || res.AnonymousCount != 1 {
		t.Errorf("anonymous = %d (result %d), want 1: the unauthenticated plain request", anon, res.AnonymousCount)
	}
	if got := fmt.Sprintf("%+v", res); strings.Contains(got, alice) || strings.Contains(got, "eng") {
		t.Errorf("replay result carries a token or group list: %s", got)
	}
}

// scopedPolicyFleetFlag (W-P1-GPOL-07): workers of this build advertise
// grouppolicy/v1, so with scoped rules served the fleet view flags only the
// legacy worker (a heartbeat without caps) as noGroupPolicy, and clears the
// flag once the policy has no scoped rules.
func scopedPolicyFleetFlag(t *testing.T, h *harness.H) {
	const legacy = "legacy-old-worker"
	if r := savePolicy(t, h, map[string]any{"domain": scopedHost, "groups": []string{"eng"}}, map[string]any{"domain": plainHost}); r.Status != http.StatusOK {
		t.Fatalf("scoped save = %d %s, want 200", r.Status, r.Body)
	}
	flags := func() (map[string]bool, bool) {
		// Workers heartbeat on the harness's fake clock: one beat per advance.
		h.Clock().Advance(time.Second)
		if r := h.CP().DoWorker(http.MethodPost, "/control/heartbeat", h.CP().Token(), legacy, `{"policyETag":"x"}`); r.Status != http.StatusNoContent {
			t.Fatalf("legacy heartbeat = %d", r.Status)
		}
		ws, err := h.CP().Workers()
		if err != nil {
			return nil, false
		}
		out := map[string]bool{}
		for _, w := range ws {
			if w.ProxyID != legacy && !slices.Contains(w.Caps, config.CapGroupPolicyV1) {
				return nil, false // the real worker has not heartbeated yet
			}
			out[w.ProxyID] = w.NoGroupPolicy
		}
		_, ok := out[legacy]
		return out, ok && len(out) > 1
	}
	var got map[string]bool
	h.Eventually("only the legacy worker is flagged noGroupPolicy", func() bool {
		var ok bool
		if got, ok = flags(); !ok {
			return false
		}
		for id, flagged := range got {
			if flagged != (id == legacy) {
				return false
			}
		}
		return true
	})

	if r := savePolicy(t, h, map[string]any{"domain": plainHost}); r.Status != http.StatusOK {
		t.Fatalf("plain save = %d %s, want 200", r.Status, r.Body)
	}
	h.Eventually("the flag clears when no scoped rule is served", func() bool {
		got, ok := flags()
		if !ok {
			return false
		}
		for _, flagged := range got {
			if flagged {
				return false
			}
		}
		return true
	})
}
