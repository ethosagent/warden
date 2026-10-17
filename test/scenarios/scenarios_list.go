package scenarios

import (
	"slices"

	"github.com/ethosagent/warden/test/harness"
)

// All is the catalog: every scenario #350's harness runs in-process and #351
// runs on compose. One literal, no init() registration: adding a scenario means
// adding a line here, where a reviewer sees it.
var All = slices.Concat(
	[]Scenario{
		// The four ported integration tests (test/integration, pre-harness).
		{Name: "allowlisted_https_succeeds", Run: allowlistedHTTPSSucceeds},
		{Name: "non_allowlisted_blocked", Run: nonAllowlistedBlocked},
		{Name: "secret_swapped", Opts: swapOpts(), Run: secretSwapped},
		{Name: "decision_logging", Opts: swapOpts(), Run: decisionLogging},

		// The manual testing guide, automated (steps 6 is folded into the canary
		// sweep each of these ends with).
		{Name: "allow_with_swap", L2: true, Opts: swapOpts(), Run: allowWithSwap},
		{Name: "default_deny", L2: true, Run: defaultDeny},
		{Name: "swap_in_body", Opts: swapOpts(), Run: swapInBody},
		{Name: "dashboard_traffic_api", Run: dashboardTrafficAPI},
		{Name: "events_recorded", Opts: swapOpts(), Run: eventsRecorded},
		{Name: "refresh_secrets", Opts: swapOpts(), Run: refreshSecrets},
		{Name: "healthz", Run: healthz},

		// Fail closed: the control plane is down when the worker boots.
		{Name: "fail_closed_at_boot", Opts: []harness.Option{harness.Fleet(1), harness.ControlPlaneDownAtBoot()}, Run: failClosedAtBoot},
	},
	// Canary across protocols x allow/deny; see canary.go.
	canaryScenarios(),
)
