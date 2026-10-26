//go:build e2e

// Package identity is the shared L2 identity stack (W-P1-DEX-04): the hermetic
// e2e stack plus Dex and seeded LDAP, brought up by `make e2e-identity-up`. It
// exists for what needs real containers or real Dex; identity behaviour tests
// run in-process on L1 (test/harness). Every file carries the `e2e` build tag
// so `go test ./...` and scripts/check.sh never touch Docker.
//
// Every test starts with requireStack(t): a missing stack is BLOCKED, never a
// pass (it fails, in CI and locally alike).
package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness/compose"
)

// stackUnavailable is why the stack cannot serve tests ("" = it can). It is
// written once by TestMain before any test runs and only read afterwards.
var stackUnavailable string

// TestMain brings the identity stack up once (`make e2e-identity-up`: build
// from source, wait healthy, hermeticity self-check), waits for it to serve,
// runs the tests and tears it down with `make e2e-identity-down`.
//
// E2E_KEEP_STACK=1 (or KEEP_STACK=1) skips the teardown; E2E_STACK_RUNNING=1
// skips bring-up and teardown (the caller owns a running stack). Unlike
// test/e2e, an unusable stack does NOT end the run: the reason is recorded and
// requireStack turns it into a BLOCKED failure, so
// the pure tests (TestStackGate) still run on a machine with no Docker.
func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	stackUnavailable = bringUp()
	// Tear down whatever this process started, even a half-up stack.
	if started && !compose.KeepStack() {
		defer compose.MakeTarget("e2e-identity-down", compose.DownDeadline)
	}
	return m.Run()
}

// started is true once this process ran `make e2e-identity-up`.
var started bool

// bringUp returns "" when the stack serves, else the reason it does not.
func bringUp() string {
	if _, err := exec.LookPath("docker"); err != nil {
		return "no docker CLI on PATH"
	}
	if res := compose.Run(".", compose.ComposeDeadline, "docker", "info"); res.Exit != 0 {
		return "the docker daemon is not reachable: " + firstLine(res.Stderr)
	}
	if !compose.ExternalStack() {
		// The project name and host ports are shared with `make e2e`: never
		// start (or later tear down) over a stack someone else owns.
		if res := compose.Run(".", compose.ProbeDeadline, "docker", "ps", "-q", "--filter", "label=com.docker.compose.project="+compose.Project); strings.TrimSpace(res.Stdout) != "" {
			return "the " + compose.Project + " project already has running containers; run `make e2e-down` or `make e2e-identity-down` first, or set E2E_STACK_RUNNING=1 to use that stack"
		}
		started = true
		if code := compose.MakeTarget("e2e-identity-up", compose.UpDeadline); code != 0 {
			return fmt.Sprintf("make e2e-identity-up failed (exit %d); its output is above", code)
		}
	}
	if err := waitStackReady(); err != nil {
		return "the identity stack is not serving: " + err.Error()
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// waitStackReady polls the CP, worker-1, Dex discovery and the CP's worker
// registry (worker-1 online = policy pulled) until compose.StackDeadline.
func waitStackReady() error {
	return compose.PollUntil(compose.StackDeadline, func() (bool, string) {
		if code, _, err := compose.TryGet(compose.CPBase + "/healthz"); err != nil || code != http.StatusOK {
			return false, fmt.Sprintf("control plane healthz: status %d err %v", code, err)
		}
		if code, _, err := compose.PlainGet(compose.WorkerAdmin1 + "/healthz"); err != nil || code != http.StatusOK {
			return false, fmt.Sprintf("worker-1 healthz: status %d err %v", code, err)
		}
		if code, _, err := compose.PlainGet(dexURL + discoveryPath); err != nil || code != http.StatusOK {
			return false, fmt.Sprintf("dex discovery: status %d err %v", code, err)
		}
		body, err := compose.FleetBody("/dashboard/api/workers")
		if err != nil {
			return false, err.Error()
		}
		var ws []struct {
			ProxyID string `json:"proxyID"`
			Online  bool   `json:"online"`
		}
		if err := json.Unmarshal(body, &ws); err != nil {
			return false, err.Error()
		}
		for _, w := range ws {
			if w.ProxyID == compose.SvcWorker1 && w.Online {
				return true, ""
			}
		}
		return false, "worker-1 is not online in the CP registry"
	})
}
