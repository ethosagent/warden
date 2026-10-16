package harness

import (
	"context"

	"github.com/ethosagent/warden/internal/clock/clocktest"
)

// Faults are the failure modes a scenario injects, all on harness time:
// control-plane outages (CPClient.Stop/Start), upstream latency and errors
// (Upstream.Delay/Fail), and time itself (Clock). None of them sleep.

// Clock returns the harness's fake clock — the SAME clock every worker was
// booted with (worker.Overrides.Clock), so Advance moves the workers' retry
// and heartbeat loops, and an Upstream.Delay's timer, deterministically.
func (h *H) Clock() *clocktest.Fake { return h.fake }

// Stop takes the control plane down (the outage fault): its Run returns, its
// listener closes, and workers see connection failures — their long-poll
// keeps the last-known policy (fail-static, not fail-open). A no-op when it
// is already down.
func (c *CPClient) Stop() {
	c.h.tb.Helper()
	if err := c.h.target.StopControlPlane(); err != nil {
		c.h.tb.Fatalf("harness: stop control plane: %v", err)
	}
}

// Start brings the control plane back on the SAME address workers were
// configured with, waiting for OnReady. Pair with Clock().Advance to let a
// worker's backoff elapse and its re-poll land. A no-op when it is already up.
func (c *CPClient) Start() {
	c.h.tb.Helper()
	if err := c.h.target.StartControlPlane(context.Background()); err != nil {
		c.h.tb.Fatalf("harness: restart control plane: %v", err)
	}
}
