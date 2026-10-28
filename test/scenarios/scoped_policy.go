package scenarios

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// The scoped-policy fail-closed scenario (W-P1-GPOL-02): the evaluator can now
// decide a request for a subject (policy.EvaluateFor), but the proxy does not
// use it yet and the load guard still refuses identity-scoped allow entries.
// Pushing a rule with groups through the policy API is therefore a 400, the
// scoped destination stays denied at the proxy (never allowed as if global),
// and an ordinary unscoped save afterwards still applies.

const (
	scopedHost = "scoped.example.com"
	plainHost  = "plain.example.com"
)

func scopedPolicyFailClosed(t *testing.T, h *harness.H) {
	h.Upstream(scopedHost)
	h.Upstream(plainHost)
	cp := h.CP()

	save := func(entry map[string]any) harness.CPResponse {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"allowlist": []map[string]any{entry}, "denylist": []map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		r, err := cp.Send(http.MethodPost, "/dashboard/api/policy", nil, raw)
		if err != nil {
			t.Fatalf("POST policy: %v", err)
		}
		return r
	}

	if r := save(map[string]any{"domain": scopedHost, "groups": []string{"eng"}}); r.Status != http.StatusBadRequest {
		t.Fatalf("scoped save = %d %s, want 400 (not yet enforced)", r.Status, r.Body)
	}
	if got := connectStatus(t, h, scopedHost+":443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s = %d, want 403: a scoped rule must never load as a global one", scopedHost, got)
	}
	if r := save(map[string]any{"domain": plainHost}); r.Status != http.StatusOK {
		t.Fatalf("unscoped save = %d %s, want 200", r.Status, r.Body)
	}
	h.Eventually("workers enforce the unscoped save", func() bool {
		return connectStatus(t, h, plainHost+":443") == http.StatusOK
	})
	if got := connectStatus(t, h, scopedHost+":443"); got != http.StatusForbidden {
		t.Errorf("CONNECT %s = %d, want 403 after the unscoped save", scopedHost, got)
	}
}
