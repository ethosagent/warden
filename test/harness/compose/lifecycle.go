//go:build e2e

package compose

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ethosagent/warden/test/harness"
)

// The stack lifecycle. The stack is SHARED: every harness instance in one test
// binary runs on the same compose project (one scenario at a time — harness.New
// refuses t.Parallel()), and test/e2e's TestMain may have brought it up or
// declared it externally owned. Start brings it up on the first call and
// attaches otherwise; Stop tears it down on the LAST call — and only when THIS
// package ran the bring-up. The mutex keeps the refcount honest whichever
// order harnesses start and stop in.

// Target is the compose-backed harness.Target. The whole type lives behind the
// e2e tag with its methods ON PURPOSE: its only field is the `since` marker
// that isolates this harness's events from everything the SHARED stack served
// before it, written by Start below — untagged, the lint pass (which cannot
// see the e2e files) would call the field unused. The pure halves the default
// gate exercises are the package-level functions (compose.go, curl.go,
// events.go, needles.go, recorded.go); the Docker-driving halves are the other
// e2e-tagged files (docker.go, oracles.go, agentclient.go, sweep.go).
//
// One scenario at a time: harness.New refuses t.Parallel(), and each Start
// resets the recorder and re-marks `since`.
type Target struct {
	since time.Time
}

// New returns a compose-backed Target. Start brings (or attaches to) the
// stack; pair with harness.WithTarget.
func New() *Target { return &Target{} }

// Host implements harness.Target.Host: the stack's fake-DNS names.
func (t *Target) Host(alias string) (string, error) { return Host(alias) }

// TargetSecrets implements harness.TargetSecrets: the one secret the workers
// hold, superseding any WithSecret option the scenario listed for L1.
func (t *Target) TargetSecrets() []harness.SecretSpec { return SecretSpecs() }

var (
	stackMu    sync.Mutex
	stackRefs  int
	stackOwned bool // this package ran `make e2e-up` and owes the `e2e-down`
)

// KeepStack reports the debugging opt-out (KEEP_STACK=1 / E2E_KEEP_STACK=1):
// leave the stack running after the last Stop, for inspection.
func KeepStack() bool {
	return os.Getenv("KEEP_STACK") == "1" || os.Getenv("E2E_KEEP_STACK") == "1"
}

// ExternalStack reports the caller-owned mode (E2E_STACK_RUNNING=1, the
// mutation drills): this package never brings the stack up and never tears it
// down — it only attaches to what is already serving.
func ExternalStack() bool { return os.Getenv("E2E_STACK_RUNNING") == "1" }

// Start brings the stack up (or attaches to one already serving), resets the
// recorder and marks `since` — the events marker that isolates THIS harness's
// traffic from everything the shared stack served before it. It returns only
// when the whole deployment is serving and both workers have pulled policy.
func (t *Target) Start(_ context.Context) error {
	stackMu.Lock()
	defer stackMu.Unlock()
	switch {
	case stackRefs > 0:
		// Up and healthy from an earlier Start in this binary: attach.
	case CPHealthy(ProbeDeadline):
		// A stack is already serving (test/e2e's TestMain, a drill, an
		// operator): attach to it. Ownership stays with whoever brought it up.
	default:
		if ExternalStack() {
			return fmt.Errorf("compose: E2E_STACK_RUNNING=1 but no healthy control plane answered within %s", ProbeDeadline)
		}
		if MakeTarget("e2e-up", UpDeadline) != 0 {
			return fmt.Errorf("compose: make e2e-up failed; its output is above")
		}
		if err := WaitStackReady(); err != nil {
			return fmt.Errorf("compose: stack did not become healthy: %w", err)
		}
		stackOwned = true
	}
	stackRefs++
	if err := ResetRecorder(); err != nil {
		return fmt.Errorf("compose: reset the recorder: %w", err)
	}
	t.since = time.Now()
	return nil
}

// Stop drops this harness's reference; the last one tears the stack down —
// but only if this package brought it up, an opt-out env did not say otherwise,
// and every reference is really gone.
func (t *Target) Stop() error {
	stackMu.Lock()
	defer stackMu.Unlock()
	if stackRefs > 0 {
		stackRefs--
	}
	if stackRefs > 0 || !stackOwned || KeepStack() || ExternalStack() {
		return nil
	}
	stackOwned = false
	if MakeTarget("e2e-down", DownDeadline) != 0 {
		return fmt.Errorf("compose: make e2e-down failed; its output is above")
	}
	return nil
}

// ProxyAddr is worker-1's proxy INSIDE the compose network: the address the
// stack's own agents point at. It is published to nobody on the host — this
// process rides it through the agent's client (AgentClients) and probes it
// from the agent (ConnectProber), exactly the way the deployment's traffic does.
func (t *Target) ProxyAddr() string { return Proxy1 }

// ProxyAddrs lists the CONNECT workers' proxy addresses, worker-1 first.
// worker-3 is not here: its scenarios dial THROUGH the transparent listeners
// (agent-3 holds no proxy env), never an explicit proxy hop.
func (t *Target) ProxyAddrs() []string { return []string{Proxy1, Proxy2} }

// AdminAddr is worker-1's admin listener, published to the host (the same
// dashboard an operator reads). No scheme: scenarios build "http://" around it.
func (t *Target) AdminAddr() string { return WorkerAdminHost1 }

// ControlPlaneAddr is the control plane's published host:port. No scheme: the
// harness's CP client builds "https://" around it.
func (t *Target) ControlPlaneAddr() string { return CPHostPort }

// ControlPlaneToken is the token the stack's API authenticates with — the env
// var a deployment distributes it with (compose files: WARDEN_CP_TOKEN,
// default dev-token).
func (t *Target) ControlPlaneToken() (string, error) {
	if tok := os.Getenv("WARDEN_CP_TOKEN"); tok != "" {
		return tok, nil
	}
	return "dev-token", nil
}

// WorkerAdminToken is the bearer token the workers' admin dashboards need for
// writes (#425) — the env var the compose files distribute it with
// (WARDEN_ADMIN_TOKEN, default dev-admin-token).
func (t *Target) WorkerAdminToken() string {
	if tok := os.Getenv("WARDEN_ADMIN_TOKEN"); tok != "" {
		return tok
	}
	return "dev-admin-token"
}

// ControlPlaneCA is the root pool the control plane's TLS cert verifies
// against: the lab proxy CA, exactly as on the in-process target.
func (t *Target) ControlPlaneCA() (*x509.CertPool, error) { return CAPool() }

// StopControlPlane is the outage fault: `docker compose stop control-plane`,
// confirmed by the health endpoint actually going quiet (a compose stop that
// returned while the process still served would lie to the scenario).
func (t *Target) StopControlPlane() error {
	if res := ComposeRun(ComposeDeadline, "stop", SvcCP); res.Exit != 0 {
		return fmt.Errorf("compose: stop %s: exit %d: %s", SvcCP, res.Exit, res.Stderr)
	}
	return PollUntil(ComposeDeadline, func() (bool, string) {
		_, _, err := TryGet(CPBase + "/healthz")
		return err != nil, "control plane still serving"
	})
}

// StartControlPlane brings the control plane back on the SAME address the
// workers were configured with, and waits for it to serve again. A no-op when
// it is already serving.
func (t *Target) StartControlPlane(_ context.Context) error {
	if code, _, err := TryGet(CPBase + "/healthz"); err == nil && code == http.StatusOK {
		return nil
	}
	if res := ComposeRun(ComposeDeadline, "start", SvcCP); res.Exit != 0 {
		return fmt.Errorf("compose: start %s: exit %d: %s", SvcCP, res.Exit, res.Stderr)
	}
	if err := PollUntil(StackDeadline, func() (bool, string) {
		code, _, err := TryGet(CPBase + "/healthz")
		return err == nil && code == http.StatusOK, fmt.Sprintf("healthz status %d err %v", code, err)
	}); err != nil {
		return fmt.Errorf("compose: %s did not come back healthy: %w", SvcCP, err)
	}
	return nil
}
