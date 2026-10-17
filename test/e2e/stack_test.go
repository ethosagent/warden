//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain brings the stack up once (`make e2e-up`: build from source, wait
// healthy, hermeticity self-check), waits on health with deadlines, runs the
// tests and tears down with `down -v`.
//
// E2E_KEEP_STACK=1 (or KEEP_STACK=1) skips the teardown for debugging.
// E2E_STACK_RUNNING=1 skips bring-up and teardown: the caller owns a running
// stack (used by the mutation drills). With the e2e tag but no usable Docker
// the package FAILS; it never skips silently.
func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	root, err := repoRoot()
	if err != nil {
		return fail("%v", err)
	}
	if res := run(root, 30*time.Second, "docker", "info"); res.exit != 0 {
		return fail("docker is not available (the e2e tag requires it): %s", strings.TrimSpace(res.stderr))
	}
	external := os.Getenv("E2E_STACK_RUNNING") == "1"
	keep := os.Getenv("KEEP_STACK") == "1" || os.Getenv("E2E_KEEP_STACK") == "1"
	if !external {
		if code := makeTarget(root, "e2e-up", 15*time.Minute); code != 0 {
			if !keep {
				makeTarget(root, "e2e-down", 5*time.Minute)
			}
			return fail("make e2e-up failed (exit %d)", code)
		}
		if !keep {
			defer makeTarget(root, "e2e-down", 5*time.Minute)
		}
	}
	if err := waitStackReady(); err != nil {
		return fail("stack not ready: %v", err)
	}
	return m.Run()
}

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "e2e: "+format+"\n", a...)
	return 1
}

// makeTarget runs `make <target>` streaming its output to stderr.
func makeTarget(root, target string, timeout time.Duration) int {
	res := run(root, timeout, "make", target)
	fmt.Fprint(os.Stderr, res.stdout, res.stderr)
	return res.exit
}

// waitStackReady polls the CP and every worker's /healthz, the recorder, and
// the CP's worker registry (every worker online = policy pulled) until the
// deadline.
func waitStackReady() error {
	urls := []string{cpBase + "/healthz", workerAdmin[svcWorker1] + "/healthz",
		workerAdmin[svcWorker2] + "/healthz", workerAdmin[svcWorker3] + "/healthz",
		recorderBase + "/_health"}
	return pollUntil(stackDeadline, func() (bool, string) {
		for _, u := range urls {
			if code, _, err := tryGet(u); err != nil || code != http.StatusOK {
				return false, fmt.Sprintf("%s: status %d err %v", u, code, err)
			}
		}
		code, body, err := tryGet(cpBase + "/dashboard/api/workers")
		if err != nil || code != http.StatusOK {
			return false, fmt.Sprintf("workers: status %d err %v", code, err)
		}
		var ws []struct {
			ProxyID string `json:"proxyID"`
			Online  bool   `json:"online"`
		}
		if err := json.Unmarshal(body, &ws); err != nil {
			return false, err.Error()
		}
		online := map[string]bool{}
		for _, w := range ws {
			online[w.ProxyID] = w.Online
		}
		if !online[svcWorker1] || !online[svcWorker2] || !online[svcWorker3] {
			return false, fmt.Sprintf("workers online: %v", online)
		}
		return true, ""
	})
}
