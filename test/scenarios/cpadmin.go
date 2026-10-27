package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// The control plane's own admin bearer (W-P1-WTOK-07): booted with
// --admin-token-env, the control plane takes only the admin token for a
// dashboard write and only the shared worker token on the worker routes, the
// workers keep pulling policy, and neither token value reaches the logs.

func cpAdminOpts() []harness.Option {
	return []harness.Option{harness.WithControlPlaneAdminToken()}
}

func cpAdminTokenSeparatesWrites(t *testing.T, h *harness.H) {
	cp := h.CP()
	admin, worker := h.ControlPlaneAdminToken(), cp.Token()
	if admin == "" || admin == worker {
		t.Fatal("harness: the control plane admin token is unset or equals the worker token")
	}

	// Reads stay open; write the current policy back unchanged.
	code, policy, err := cp.Do(http.MethodGet, "/dashboard/api/policy", "", nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/policy = %d, %v", code, err)
	}
	for _, c := range []struct {
		name, bearer string
		want         int
	}{
		{"the worker token", worker, http.StatusUnauthorized},
		{"no bearer", "", http.StatusUnauthorized},
		{"the admin token", admin, http.StatusOK},
	} {
		code, body, err := cp.Do(http.MethodPut, "/dashboard/api/policy", c.bearer, []byte(policy))
		if err != nil {
			t.Fatalf("PUT /dashboard/api/policy with %s: %v", c.name, err)
		}
		if code != c.want {
			t.Errorf("PUT /dashboard/api/policy with %s = %d %q, want %d", c.name, code, body, c.want)
		}
	}

	// The admin token is not a worker credential.
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/policy", ""},
		{http.MethodPost, "/control/heartbeat", `{"policyETag":""}`},
		{http.MethodPost, "/central/ingest", `{"events":[]}`},
	} {
		var body []byte
		if r.body != "" {
			body = []byte(r.body)
		}
		code, _, err := cp.Do(r.method, r.path, admin, body)
		if err != nil {
			t.Fatalf("%s %s: %v", r.method, r.path, err)
		}
		if code != http.StatusUnauthorized {
			t.Errorf("%s %s with the admin token = %d, want 401", r.method, r.path, code)
		}
	}
	var pulled struct {
		Allowlist []any `json:"allowlist"`
	}
	if err := cp.GetJSON("/policy", &pulled); err != nil || len(pulled.Allowlist) == 0 {
		t.Fatalf("GET /policy with the worker token: %v (allowlist %d)", err, len(pulled.Allowlist))
	}

	logs := h.Logs()
	if strings.Contains(logs, admin) || strings.Contains(logs, worker) {
		t.Fatal("a control-plane token value reached the logs")
	}
	if strings.Contains(logs, "dashboard writes use the shared worker token") {
		t.Error("the fallback warning was logged although an admin token is set")
	}
}
