package scenarios

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/harness"
)

// longPollBackoff is the worker's first control-plane retry delay (the long-poll
// loop's initial backoff, run on the harness's fake clock): one "long-poll
// cycle" after a failed poll.
const longPollBackoff = time.Second

// failClosedAtBoot: a worker that boots while the control plane is down must
// DENY everything — its policy comes only from the control plane — and pick the
// policy up within one long-poll cycle once the control plane is back, with no
// restart. The worker's own local allowlist (which does list api.example.com)
// must not be a fallback.
func failClosedAtBoot(t *testing.T, h *harness.H) {
	u := h.Upstream("api.example.com")

	// 1. The control plane is down, the worker is up, and it says so.
	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT to an allowlisted host with the control plane down = %d, want 403 (fail closed)", got)
	}
	if _, err := h.Agent().Get("https://api.example.com/v1/models"); err == nil {
		t.Fatal("the agent's request succeeded before any policy arrived; the worker booted fail-OPEN")
	}
	if got := len(u.Requests()); got != 0 {
		t.Fatalf("the upstream saw %d request(s) while the worker had no policy, want 0", got)
	}
	if !strings.Contains(h.Logs(), "FAIL-CLOSED") {
		t.Error("the worker did not log that it started fail-closed")
	}

	// 2. The control plane returns. The worker's long-poll retry runs on the
	// fake clock: wait until it has failed once (so its backoff timer is armed),
	// then advance by exactly one retry delay.
	h.CP().Start()
	h.Eventually("the worker's long-poll to fail once and arm its retry", func() bool {
		return strings.Contains(h.Logs(), "control plane long-poll failed")
	})
	allowed := func() bool {
		h.Clock().Advance(longPollBackoff)
		return connectStatus(t, h, "api.example.com:443") == http.StatusOK
	}
	h.Eventually("the worker to receive policy and allow api.example.com", allowed)

	// 3. And the same request now succeeds end to end.
	if status, _ := get(t, h, "https://api.example.com/v1/models", nil); status != http.StatusOK {
		t.Fatalf("GET after the control plane returned = %d, want 200", status)
	}
	h.Eventually("the control plane to list the worker", func() bool {
		ws, err := h.CP().Workers()
		return err == nil && len(ws) == 1 && ws[0].ProxyID == "worker-1"
	})
}
