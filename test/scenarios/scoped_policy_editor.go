package scenarios

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// scopedPolicyDashboardEditor (W-P1-GPOL-08): groups and users saved through
// the dashboard policy editor come back normalized and marked scoped, are
// enforced by the worker with each request's verified subject, an invalid
// chip (empty group) is a 400 that changes nothing, and a global entry that
// makes the scoped one unreachable is reported in the GET's lint.
func scopedPolicyDashboardEditor(t *testing.T, h *harness.H) {
	up := h.Upstream(scopedHost)
	h.Upstream(plainHost)
	alice := h.MintUserToken(fakes.Valid("alice", "alice@corp.example", "eng"))
	sam := h.MintUserToken(fakes.Valid("sam", "sam@corp.example", "sales"))

	// The chip values are saved as an editor would send them: a mixed-case
	// email, and a group that is markup.
	const markup = "<script>alert(1)</script>"
	if r := savePolicy(t, h,
		map[string]any{"domain": scopedHost, "groups": []string{markup, "eng"}, "users": []string{"Alice@Corp.Example"}},
		map[string]any{"domain": plainHost}); r.Status != http.StatusOK {
		t.Fatalf("scoped save = %d %s, want 200", r.Status, r.Body)
	}

	get := func() (policyView, string) {
		t.Helper()
		resp, err := h.CP().Send(http.MethodGet, "/dashboard/api/policy", nil, nil)
		if err != nil || resp.Status != http.StatusOK {
			t.Fatalf("GET policy = %d (%v)", resp.Status, err)
		}
		var v policyView
		if err := json.Unmarshal(resp.Body, &v); err != nil {
			t.Fatal(err)
		}
		return v, string(resp.Body)
	}
	v, body := get()
	if strings.Contains(body, "<script>") {
		t.Errorf("the GET body carries a literal <script>: %s", body)
	}
	if len(v.Allowlist) != 2 || !v.Allowlist[0].Scoped || v.Allowlist[1].Scoped {
		t.Fatalf("scoped flags = %+v, want the first entry only", v.Allowlist)
	}
	if got := v.Allowlist[0].Users; len(got) != 1 || got[0] != "alice@corp.example" {
		t.Errorf("users came back %v, want [alice@corp.example]", got)
	}
	if got := v.Allowlist[0].Groups; len(got) != 2 || got[0] != markup || got[1] != "eng" {
		t.Errorf("groups came back %v, want sorted [%s eng]", got, markup)
	}
	if len(v.Lint) != 0 {
		t.Errorf("lint = %v, want none", v.Lint)
	}

	h.Eventually("workers enforce the save", func() bool {
		return connectStatus(t, h, plainHost+":443") == http.StatusOK
	})
	if got := getStatus(t, h.Agent(), scopedHost, alice); got != http.StatusOK {
		t.Fatalf("member = %d, want 200", got)
	}
	if got := getStatus(t, h.Agent(), scopedHost, sam); got != http.StatusForbidden {
		t.Fatalf("non-member = %d, want 403", got)
	}

	// An empty group is refused with the validation error; the served policy
	// is unchanged and the worker keeps enforcing the saved rule.
	r := savePolicy(t, h, map[string]any{"domain": scopedHost, "groups": []string{"eng", " "}})
	if r.Status != http.StatusBadRequest || !strings.Contains(string(r.Body), "must not be empty") {
		t.Fatalf("empty group save = %d %s, want 400 naming the empty value", r.Status, r.Body)
	}
	if _, after := get(); after != body {
		t.Errorf("served policy changed after a rejected save:\n%s\n%s", body, after)
	}
	if got := getStatus(t, h.Agent(), scopedHost, sam); got != http.StatusForbidden {
		t.Errorf("non-member after the rejected save = %d, want 403", got)
	}

	// A global wildcard over the scoped host is the shadow the lint names.
	if r := savePolicy(t, h, map[string]any{"domain": "*.example.com"},
		map[string]any{"domain": scopedHost, "groups": []string{"eng"}}); r.Status != http.StatusOK {
		t.Fatalf("shadowing save = %d %s, want 200", r.Status, r.Body)
	}
	v, _ = get()
	if len(v.Lint) != 1 || !strings.Contains(v.Lint[0], scopedHost) {
		t.Errorf("lint = %v, want one warning naming %s", v.Lint, scopedHost)
	}
	if n := len(up.Requests()); n != 1 {
		t.Errorf("scoped upstream saw %d requests, want 1 (the member)", n)
	}
}

// policyView is the part of GET /dashboard/api/policy the editor reads.
type policyView struct {
	Allowlist []struct {
		Domain string   `json:"domain"`
		Groups []string `json:"groups"`
		Users  []string `json:"users"`
		Scoped bool     `json:"scoped"`
	} `json:"allowlist"`
	Lint []string `json:"lint"`
}
