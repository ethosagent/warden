//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// agentRun runs args inside an agent container via `docker compose exec -T`
// and returns stdout, stderr and the exit code of the command itself.
//
// Failures of the exec itself are harness bugs, not blocked traffic, so they
// fail the test here: a typo in a negative row can never look like a
// successful block. Docker reserves 125-127 for "docker/exec failed" (binary
// not found, not executable), and compose reports a missing or stopped
// service with exit 1 and "is not running" / "no such service" on stderr.
func agentRun(tb testing.TB, service string, args ...string) cmdResult {
	tb.Helper()
	res := compose(tb, 90*time.Second, append([]string{"exec", "-T", service}, args...)...)
	if res.exit < 0 || (res.exit >= 125 && res.exit <= 127) || composeExecFailed(res.stderr) {
		tb.Fatalf("e2e: exec in %s is broken (exit %d), not a network result: %v\nstderr: %s",
			service, res.exit, args, strings.TrimSpace(res.stderr))
	}
	return res
}

// composeExecFailed reports compose's own "cannot exec here" stderr, which a
// command run inside the container never produces.
func composeExecFailed(stderr string) bool {
	return strings.Contains(stderr, "is not running") || strings.Contains(stderr, "no such service")
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
	id := compose(tb, 30*time.Second, "ps", "-q", service)
	cid := strings.TrimSpace(id.stdout)
	if id.exit != 0 || cid == "" {
		tb.Fatalf("e2e: no container for %s: %s", service, id.stderr)
	}
	res := run(".", 30*time.Second, "docker", "inspect", "-f",
		`{{with index .NetworkSettings.Networks "`+network+`"}}{{.IPAddress}}{{end}}`, cid)
	ip := strings.TrimSpace(res.stdout)
	if res.exit != 0 || ip == "" {
		tb.Fatalf("e2e: %s has no address on %s: %s", service, network, res.stderr)
	}
	return ip
}

// networkGateway is the host-side gateway address of a compose network.
func networkGateway(tb testing.TB, network string) string {
	tb.Helper()
	res := run(".", 30*time.Second, "docker", "network", "inspect", "-f",
		`{{(index .IPAM.Config 0).Gateway}}`, network)
	gw := strings.TrimSpace(res.stdout)
	if res.exit != 0 || gw == "" {
		tb.Fatalf("e2e: no gateway for network %s: %s", network, res.stderr)
	}
	return gw
}
