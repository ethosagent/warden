package scenarios

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/harness"
)

// Strict worker auth and the shared-token migration (W-P1-WTOK-04). Booted with
// --require-worker-tokens the control plane takes worker tokens only on the
// worker routes (the shared token the harness workers still present gets 401),
// while dashboard writes and /central/secrets take the CP's own admin token,
// and fail closed when there is none. In mixed mode the fleet view marks the
// workers still on the shared token and the log warns once per proxy id.

func strictAuthOpts() []harness.Option {
	return []harness.Option{harness.WithStrictWorkerAuth(), harness.WithControlPlaneAdminToken()}
}

func strictNoAdminOpts() []harness.Option {
	return []harness.Option{harness.WithStrictWorkerAuth()}
}

func strictWorkerAuth(t *testing.T, h *harness.H) {
	cp := h.CP()
	routes := wtokRoutes(t)
	shared, admin := cp.Token(), h.ControlPlaneAdminToken()
	a, _ := mintWorkerToken(t, h, "strict-a", "strict-worker-a")
	h.Eventually("the control plane to load the new token", func() bool {
		h.Clock().Advance(3 * time.Second)
		return cp.DoWorker(http.MethodGet, "/policy", a, "", "").Status == http.StatusOK
	})

	// The shared token, the admin token and no credential are all refused on
	// every worker route; the worker token is accepted.
	for _, rt := range routes {
		for name, bearer := range map[string]string{"shared token": shared, "admin token": admin, "no bearer": ""} {
			got := cp.DoWorker(rt.method, rt.path, bearer, "worker-1", rt.body)
			if got.Status != http.StatusUnauthorized || got.Header.Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("%s with %s = %d, want 401", rt.path, name, got.Status)
			}
		}
		if got := cp.DoWorker(rt.method, rt.path, a, "", rt.body); got.Status != rt.ok {
			t.Errorf("%s with the worker token = %d, want %d", rt.path, got.Status, rt.ok)
		}
	}

	// Dashboard writes and secret writes keep working with the admin token.
	_, policy, err := cp.Do(http.MethodGet, "/dashboard/api/policy", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, bearer string
		want         int
	}{
		{"the admin token", admin, http.StatusOK},
		{"the shared token", shared, http.StatusUnauthorized},
		{"a worker token", a, http.StatusUnauthorized},
	} {
		if code, body, err := cp.Do(http.MethodPut, "/dashboard/api/policy", c.bearer, []byte(policy)); err != nil || code != c.want {
			t.Errorf("PUT /dashboard/api/policy with %s = %d %q (%v), want %d", c.name, code, body, err, c.want)
		}
	}
	secret := []byte(`{"key":"strict-key","value":"strict-value"}`)
	for _, c := range []struct {
		name, bearer string
		want         int
	}{
		{"the admin token", admin, http.StatusNoContent},
		{"the shared token", shared, http.StatusUnauthorized},
		{"a worker token", a, http.StatusUnauthorized},
	} {
		if code, body, err := cp.Do(http.MethodPost, "/central/secrets", c.bearer, secret); err != nil || code != c.want {
			t.Errorf("POST /central/secrets with %s = %d %q (%v), want %d", c.name, code, body, err, c.want)
		}
	}

	logs := h.Logs()
	if !strings.Contains(logs, `"auth_mode":"strict"`) {
		t.Error("the startup log does not say auth_mode=strict")
	}
	if strings.Contains(logs, "dashboard writes are disabled") {
		t.Error("the fail-closed error was logged although an admin token is set")
	}
	for name, v := range map[string]string{"shared": shared, "admin": admin, "worker": a, "secret value": "strict-value"} {
		if strings.Contains(logs, v) {
			t.Errorf("the %s token value reached the logs", name)
		}
	}
}

func strictNoAdminTokenFailsClosed(t *testing.T, h *harness.H) {
	cp := h.CP()
	shared := cp.Token()
	_, policy, err := cp.Do(http.MethodGet, "/dashboard/api/policy", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, bearer := range []string{"", shared} {
		code, body, err := cp.Do(http.MethodPut, "/dashboard/api/policy", bearer, []byte(policy))
		if err != nil || code != http.StatusForbidden || !strings.Contains(body, "dashboard writes are disabled") {
			t.Errorf("PUT /dashboard/api/policy with bearer %q = %d %q (%v), want the guard's 403", bearer, code, body, err)
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		var body []byte
		if m == http.MethodPost {
			body = []byte(`{"key":"k","value":"v"}`)
		}
		if code, _, err := cp.Do(m, "/central/secrets", shared, body); err != nil || code != http.StatusNotFound {
			t.Errorf("%s /central/secrets = %d (%v), want 404 (not mounted)", m, code, err)
		}
	}
	if logs := h.Logs(); !strings.Contains(logs, "dashboard writes are disabled: set --admin-token-env") {
		t.Error("the control plane did not log the fail-closed error naming --admin-token-env")
	}
}

// legacyWorkerWarning runs on the default harness, whose workers present the
// shared token: the control plane is in mixed mode, shows the workers as legacy
// and warns once per proxy id.
func legacyWorkerWarning(t *testing.T, h *harness.H) {
	cp := h.CP()
	h.Eventually("the shared-token workers to show as legacy", func() bool {
		ws, err := cp.Workers()
		if err != nil {
			return false
		}
		for _, w := range ws {
			if w.ProxyID == "worker-1" && w.AuthKind == "legacy" && w.LegacyRequests > 0 {
				return true
			}
		}
		return false
	})
	// More requests from the same worker never repeat the warning within the hour.
	for i := 0; i < 3; i++ {
		cp.DoWorker(http.MethodGet, "/policy", cp.Token(), "worker-1", "")
	}
	logs := h.Logs()
	if n := strings.Count(logs, `"msg":"legacy worker token in use","proxy_id":"worker-1"`); n != 1 {
		t.Errorf("worker-1 warned %d times, want 1:\n%s", n, logs)
	}
	if strings.Contains(logs, cp.Token()) {
		t.Error("the shared token reached the logs")
	}
	if !strings.Contains(logs, `"auth_mode":"mixed"`) {
		t.Error("the startup log does not say auth_mode=mixed")
	}
}
