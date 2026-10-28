package scenarios

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
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

// The deferred-identity scenario (W-P1-GPOL-03): the CONNECT gate now decides
// with the connection's verified subject and fails closed on identity-
// conditional results, but the load guard still keeps scoped rules out, so a
// member's token must not open a scoped host. A verified member of the group
// presents a token on CONNECT: the scoped save is refused (400), the scoped
// host stays 403 with and without the token, and each refusal is audited.
func scopedPolicyDeferredIdentity(t *testing.T, h *harness.H) {
	h.Upstream(scopedHost)
	cp := h.CP()
	member := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+member))

	raw, err := json.Marshal(map[string]any{"allowlist": []map[string]any{{"domain": scopedHost, "groups": []string{"eng"}}}, "denylist": []map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := cp.Send(http.MethodPost, "/dashboard/api/policy", nil, raw); err != nil || r.Status != http.StatusBadRequest {
		t.Fatalf("scoped save = %v %v, want 400 (not yet enforced)", r.Status, err)
	}
	for _, a := range []string{auth, ""} {
		if got := h.ConnectStatusWithAuth(scopedHost+":443", a); got != http.StatusForbidden {
			t.Fatalf("CONNECT %s (token=%t) = %d, want 403", scopedHost, a != "", got)
		}
	}
	h.Eventually("every scoped CONNECT is audited as a deny", func() bool {
		n := 0
		for _, e := range h.Events() {
			if e.Decision == "deny" && e.Domain == scopedHost {
				n++
			}
		}
		return n == 2
	})
}
