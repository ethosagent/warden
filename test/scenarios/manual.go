package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// The manual scenarios of docs/testing-guide.md, automated. Steps 1-3 live in
// swap.go and deny.go (allow_with_swap, default_deny, swap_in_body); step 6 (no
// raw secret in events) is folded into AssertCanaryNeverLeaked, which every one
// of them ends with.

// dashboardTrafficAPI is manual step 4: GET /dashboard/api/traffic on the admin
// listener lists the request the agent made.
func dashboardTrafficAPI(t *testing.T, h *harness.H) {
	h.Upstream("api.example.com")
	if status, _ := get(t, h, "https://api.example.com/v1/models", nil); status != http.StatusOK {
		t.Fatalf("GET = %d, want 200", status)
	}
	h.Events() // drain the async analytics writer so the dashboard reads a settled store

	status, body := adminDo(t, h, http.MethodGet, "/dashboard/api/traffic")
	if status != http.StatusOK {
		t.Fatalf("GET /dashboard/api/traffic = %d, want 200: %s", status, body)
	}
	listed := eventsFor(decodeEvents(t, body), "api.example.com", "allow")
	if len(listed) != 1 || listed[0].URL != "https://api.example.com/v1/models" {
		t.Errorf("traffic API lists %+v for api.example.com, want the one GET /v1/models", listed)
	}
}

// eventsRecorded is manual step 5 (and 6): allowed, swapped and denied traffic
// each leave one analytics row, the swap row references the secret by hash, and
// the sweep proves no raw value is anywhere.
func eventsRecorded(t *testing.T, h *harness.H) {
	h.Upstream("api.example.com")
	h.Upstream("evil.example.com")

	get(t, h, "https://api.example.com/plain", nil)
	get(t, h, "https://api.example.com/swapped", map[string]string{"Authorization": "Bearer " + h.Placeholder("openai")})
	if got := connectStatus(t, h, "evil.example.com:443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT to the denied host = %d, want 403", got)
	}

	evs := h.Events()
	allows := eventsFor(evs, "api.example.com", "allow")
	if len(allows) != 2 {
		t.Fatalf("allow events = %d, want 2", len(allows))
	}
	var swapped, plain int
	for _, e := range allows {
		switch {
		case strings.HasSuffix(e.URL, "/swapped"):
			swapped++
			if !strings.HasPrefix(e.SecretRef, "sha256:") {
				t.Errorf("swapped request's SecretRef = %q, want a sha256: reference", e.SecretRef)
			}
		case strings.HasSuffix(e.URL, "/plain"):
			plain++
			if e.SecretRef != "" {
				t.Errorf("unswapped request carries SecretRef %q, want none", e.SecretRef)
			}
		}
	}
	if swapped != 1 || plain != 1 {
		t.Errorf("events by path: swapped=%d plain=%d, want 1 each", swapped, plain)
	}
	if got := len(eventsFor(evs, "evil.example.com", "deny")); got != 1 {
		t.Errorf("deny events = %d, want 1", got)
	}
	h.AssertCanaryNeverLeaked()
}

// refreshSecrets is manual step 7: POST /admin/refresh-secrets answers
// "refreshed", and the next request uses the new value.
func refreshSecrets(t *testing.T, h *harness.H) {
	u := h.Upstream("api.example.com")
	auth := map[string]string{"Authorization": "Bearer " + h.Placeholder("openai")}
	newValue := harness.Canary()

	get(t, h, "https://api.example.com/before", auth)
	if got := lastRequest(t, u).Header.Get("Authorization"); got != "Bearer "+swapValue {
		t.Fatalf("before rotation the upstream saw %q, want the original value", got)
	}

	h.RotateSecret("openai", newValue)

	// The worker caches secrets (production TTL), so until the refresh it still
	// serves the old value; a refresh that does nothing would leave it so.
	get(t, h, "https://api.example.com/cached", auth)
	if got := lastRequest(t, u).Header.Get("Authorization"); got != "Bearer "+swapValue {
		t.Fatalf("between the rotation and the refresh the upstream saw %q, want the cached original value", got)
	}

	status, body := adminDo(t, h, http.MethodPost, "/admin/refresh-secrets")
	if status != http.StatusOK || string(body) != "refreshed" {
		t.Fatalf("POST /admin/refresh-secrets = %d %q, want 200 \"refreshed\"", status, body)
	}

	get(t, h, "https://api.example.com/after", auth)
	if got := lastRequest(t, u).Header.Get("Authorization"); got != "Bearer "+newValue {
		t.Errorf("after refresh the upstream saw %q, want the rotated value", got)
	}
	h.AssertCanaryNeverLeaked()
}

// healthz is manual step 8: the admin listener's liveness probe.
func healthz(t *testing.T, h *harness.H) {
	status, body := adminDo(t, h, http.MethodGet, "/healthz")
	if status != http.StatusOK || string(body) != "ok" {
		t.Fatalf("GET /healthz = %d %q, want 200 \"ok\"", status, body)
	}
}
