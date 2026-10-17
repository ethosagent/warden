//go:build e2e

// Package e2e is the L2 container suite: it drives the hermetic compose stack
// (deploy/compose/docker-compose.e2e.yml) and proves what only real
// containers can — the agent has no route out except its worker, default-deny
// holds, and no real credential reaches the agent. Every file carries the
// `e2e` build tag so `go test ./...` and scripts/check.sh never touch Docker.
//
// This file is the suite's adapter onto the compose package (#368): the stack's
// identity — project, services, networks, host ports, API paths — is named in
// ONE place now (test/harness/compose), and this file re-exports it under the
// names the #367 tests spell, plus tb-fatalf shims over the shared primitives.
// The shims are the whole point: the tests above keep their lowercase result
// fields and their helpers, and the #367 review diff stays empty.
package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/harness/compose"
)

// Stack identity — see the compose package for the one definition.
const (
	composeProject = compose.Project
	stackDeadline  = compose.StackDeadline

	cpBase       = compose.CPBase
	recorderBase = compose.RecorderBase
	recordedPath = compose.RecordedPath
	resetPath    = compose.ResetPath
	trafficPath  = compose.TrafficPath

	svcCP       = compose.SvcCP
	svcWorker1  = compose.SvcWorker1
	svcWorker2  = compose.SvcWorker2
	svcWorker3  = compose.SvcWorker3
	svcAgent1   = compose.SvcAgent1
	svcAgent2   = compose.SvcAgent2
	svcAgent3   = compose.SvcAgent3
	svcUpstream = compose.SvcUpstream

	netW1 = compose.NetW1
	netW2 = compose.NetW2
	netCP = compose.NetCP
	netT  = compose.NetT

	// Scenario constants shared with configs/config.e2e-*.yaml.
	canary      = compose.Canary
	placeholder = compose.Placeholder
	caPath      = compose.CAPath
)

var (
	composeFiles = compose.ComposeFiles
	allServices  = compose.AllServices
	fleetPaths   = compose.FleetPaths
	// workerAdmin keeps the map shape the suite spells (worker -> published
	// admin base); the values are the compose package's.
	workerAdmin = map[string]string{
		compose.SvcWorker1: compose.WorkerAdmin1,
		compose.SvcWorker2: compose.WorkerAdmin2,
		compose.SvcWorker3: compose.WorkerAdmin3,
	}
)

// Request is one request the fake upstream recorded (its /_recorded shape).
type Request = compose.Request

// cmdResult is one finished subprocess, in this suite's field spelling.
type cmdResult struct {
	stdout, stderr string
	exit           int
}

func fromCompose(r compose.Result) cmdResult {
	return cmdResult{stdout: r.Stdout, stderr: r.Stderr, exit: r.Exit}
}

// repoRoot finds the module root (the dir holding go.mod) above the cwd.
func repoRoot() (string, error) { return compose.RepoRoot() }

// run executes name in dir with a hard timeout. A process that cannot start
// or is killed by the timeout returns exit -1 with the reason in stderr.
func run(dir string, timeout time.Duration, name string, args ...string) cmdResult {
	return fromCompose(compose.Run(dir, timeout, name, args...))
}

// composeRun runs `docker compose -f … -f … args…` from the repo root: the
// #369 fleet tests' lifecycle control (stop/start/restart of one service) over
// the compose package's ComposeRun. It cannot take the old helper's bare
// `compose` name — that is the imported package's identifier in this package.
func composeRun(tb testing.TB, timeout time.Duration, args ...string) cmdResult {
	tb.Helper()
	return fromCompose(compose.ComposeRun(timeout, args...))
}

// httpClient is the CA-trusting host client the #369 fleet tests PUT policy
// with — the client compose.TryGet drives, re-exported under their name.
func httpClient() (*http.Client, error) { return compose.CAClient() }

// waitFor polls cond every 500ms until it returns true or the deadline
// passes, then fails the test with the last observation. It is the only
// waiting primitive in the package (no fixed sleeps).
func waitFor(tb testing.TB, timeout time.Duration, what string, cond func() (bool, string)) {
	tb.Helper()
	if err := pollUntil(timeout, cond); err != nil {
		tb.Fatalf("e2e: timed out after %s waiting for %s: %v", timeout, what, err)
	}
}

// pollUntil is waitFor without a testing.TB, for TestMain.
func pollUntil(timeout time.Duration, cond func() (bool, string)) error {
	return compose.PollUntil(timeout, cond)
}

// agentRun runs args inside an agent container via `docker compose exec -T`
// and returns stdout, stderr and the exit code of the command itself. A
// failure of the exec itself (compose down, bad service, missing binary) is a
// harness bug and fails here — compose.AgentRunRaw owns the classification.
func agentRun(tb testing.TB, service string, args ...string) cmdResult {
	tb.Helper()
	res, err := compose.AgentRunRaw(service, args...)
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	return fromCompose(res)
}

// agentExec runs args in the agent container and returns its stdout and exit
// code. Stderr is logged, not returned; use agentRun when a row needs it.
func agentExec(tb testing.TB, service string, args ...string) (stdout string, exit int) {
	tb.Helper()
	res := agentRun(tb, service, args...)
	if res.stderr != "" {
		tb.Logf("%s %v stderr: %s", service, args, strings.TrimSpace(res.stderr))
	}
	return res.stdout, res.exit
}

// containerIP is the service container's address on a compose network.
func containerIP(tb testing.TB, service, network string) string {
	tb.Helper()
	ip, err := compose.ContainerIP(service, network)
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	return ip
}

// networkGateway is the host-side gateway address of a compose network.
func networkGateway(tb testing.TB, network string) string {
	tb.Helper()
	gw, err := compose.NetworkGateway(network)
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	return gw
}

// canaryNeedles returns every encoding of secret a leak could take (see
// compose.Needles).
func canaryNeedles(secret string) map[string]string { return compose.Needles(secret) }

// leaksIn reports the labels of every needle found in text.
func leaksIn(text string, needles map[string]string) []string { return compose.LeaksIn(text, needles) }

// AssertCanaryNeverLeaked fails the test if the canary, in any encoding,
// appears in agentOutputs, the agents' environments, any service's logs, any
// worker's traffic API or any fleet-API path — the whole-stack hunt (#367),
// now owned by the compose package.
func AssertCanaryNeverLeaked(tb testing.TB, agentOutputs ...string) {
	tb.Helper()
	compose.AssertCanaryNeverLeaked(tb, agentOutputs...)
}
