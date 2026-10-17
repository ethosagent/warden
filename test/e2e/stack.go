//go:build e2e

// Package e2e is the L2 container suite: it drives the hermetic compose stack
// (deploy/compose/docker-compose.e2e.yml) and proves what only real
// containers can — the agent has no route out except its worker, default-deny
// holds, and no real credential reaches the agent. Every file carries the
// `e2e` build tag so `go test ./...` and scripts/check.sh never touch Docker.
//
// This file is the one place that names the stack: compose files, service
// names, networks, host ports and API paths. #368/#369 reuse it.
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Compose project and files — the same two -f files the Makefile uses.
const composeProject = "warden-e2e"

var composeFiles = []string{
	"deploy/compose/docker-compose.control-plane.yml",
	"deploy/compose/docker-compose.e2e.yml",
}

// Service names in the compose project.
const (
	svcCP       = "control-plane"
	svcWorker1  = "worker-1"
	svcWorker2  = "worker-2"
	svcAgent1   = "agent-1"
	svcAgent2   = "agent-2"
	svcUpstream = "fakeupstream"
)

// allServices is every service whose logs are scanned for the canary.
var allServices = []string{svcCP, svcWorker1, svcWorker2, svcAgent1, svcAgent2, svcUpstream}

// Networks (compose-prefixed) the agents and the control plane live on.
const (
	netW1 = composeProject + "_w1-internal"
	netW2 = composeProject + "_w2-internal"
	netCP = composeProject + "_cp-net"
)

// Host-published endpoints (all 127.0.0.1) and API paths.
const (
	cpBase       = "https://localhost:7070"
	recorderBase = "http://127.0.0.1:8081"
	recordedPath = "/_recorded"
	resetPath    = "/_reset"
	trafficPath  = "/dashboard/api/traffic" // worker admin and CP fleet view
)

// workerAdmin maps a worker service to its published admin base URL.
var workerAdmin = map[string]string{
	svcWorker1: "http://127.0.0.1:9091",
	svcWorker2: "http://127.0.0.1:9092",
}

// fleetPaths are the control plane's fleet-API reads, all scanned for the canary.
var fleetPaths = []string{
	trafficPath, "/dashboard/api/workers", "/dashboard/api/analytics",
	"/dashboard/api/mcp", "/dashboard/api/audit", "/dashboard/api/alerts",
	"/dashboard/api/endpoints", "/dashboard/api/policy",
	"/dashboard/api/integrations", "/dashboard/api/detection",
}

// Scenario constants shared with configs/config.e2e-*.yaml.
const (
	canary      = "CANARY-e2e-0123456789abcdef0123456789abcdef"
	placeholder = "example_secret_001"
	caPath      = "test/e2e/certs/proxy-ca.crt" // repo-relative; host-side trust for the CP
)

// stackDeadline bounds bring-up and readiness polling.
const stackDeadline = 120 * time.Second

// cmdResult is one finished subprocess.
type cmdResult struct {
	stdout, stderr string
	exit           int
}

// repoRoot finds the module root (the dir holding go.mod) above the cwd.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// run executes name in dir with a hard timeout. A process that cannot start
// or is killed by the timeout returns exit -1 with the reason in stderr.
func run(dir string, timeout time.Duration, name string, args ...string) cmdResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := cmdResult{stdout: out.String(), stderr: errb.String()}
	switch e := err.(type) {
	case nil:
	case *exec.ExitError:
		res.exit = e.ExitCode()
		if ctx.Err() != nil {
			res.exit = -1
			res.stderr += "\n(timed out after " + timeout.String() + ")"
		}
	default:
		res.exit = -1
		res.stderr += err.Error()
	}
	return res
}

// compose runs `docker compose -f … -f … args…` from the repo root.
func compose(tb testing.TB, timeout time.Duration, args ...string) cmdResult {
	tb.Helper()
	root, err := repoRoot()
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	full := []string{"compose"}
	for _, f := range composeFiles {
		full = append(full, "-f", f)
	}
	return run(root, timeout, "docker", append(full, args...)...)
}

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
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		ok, seen := cond()
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("last seen: %s", seen)
		}
		<-tick.C
	}
}
