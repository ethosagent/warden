//go:build e2e

package e2e

import (
	"testing"

	"github.com/ethosagent/warden/test/harness"
	"github.com/ethosagent/warden/test/harness/compose"
	"github.com/ethosagent/warden/test/scenarios"
)

// TestScenariosOnCompose runs the catalog's L2 scenarios — unchanged — against
// the compose stack through the harness Target seam (#368): one scenario body,
// two deployments. The scenario's WithSecret opts describe L1 wiring; the
// target's own secret wiring (the workers' env) supersedes them at boot, so
// the canary sweep guards the value THIS deployment actually swaps.
//
// Only scenarios flagged L2 in the catalog appear here; the rest lean on
// in-process-only levers (the fake clock, fault injection on the fakes,
// EchoHeaders, the grpc/ws fakes the stack's fake DNS does not serve) and are
// the L1 suite's alone.
//
// After each scenario, the #367 whole-stack hunt runs again over every surface
// the scenario could have touched: the agents' environments, every service's
// logs, both workers' traffic APIs, every fleet path.
func TestScenariosOnCompose(t *testing.T) {
	for _, sc := range scenarios.All {
		if !sc.L2 {
			continue
		}
		t.Run(sc.Name, func(t *testing.T) {
			opts := append([]harness.Option{harness.WithTarget(compose.New())}, sc.Opts...)
			h := harness.New(t, opts...)
			sc.Run(t, h)
			AssertCanaryNeverLeaked(t)
		})
	}
}
