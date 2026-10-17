// Package compose is the L2 compose Target (#368): the same harness.Target the
// L1 scenarios run against, backed by the hermetic compose stack
// (deploy/compose/docker-compose.e2e.yml) instead of in-process components. A
// scenario is written once against test/harness and runs on both.
//
// The package is split by the architecture gate: the files WITHOUT the `e2e`
// build tag are pure logic (this file, curl.go, events.go, needles.go,
// recorded.go and the Target struct's data-only methods) and are unit-tested by
// the default gate; every file that runs `docker compose` or builds an HTTP
// client carries `//go:build e2e` — exactly like test/e2e — so `go test ./...`
// and scripts/check.sh never touch Docker.
//
// test/e2e keeps every Docker-driving test on top of this package — its #367
// suite (it imports it for the stack primitives, the oracles and the leak
// needles), the shared scenarios in scenarios_test.go and this target's own
// seam round-trips in compose_target_test.go — so one TestMain-owned stack
// serves them all inside `make e2e` and the CI job.
package compose

import (
	"fmt"
	"time"

	"github.com/ethosagent/warden/test/harness"
)

// The stack's identity and addresses. These are the ONE place that names the
// compose project, services and host ports (test/e2e re-exports them).
const (
	Project = "warden-e2e"

	SvcCP       = "control-plane"
	SvcWorker1  = "worker-1"
	SvcWorker2  = "worker-2"
	SvcAgent1   = "agent-1"
	SvcAgent2   = "agent-2"
	SvcUpstream = "fakeupstream"

	// Host-published endpoints (all 127.0.0.1) and API paths. The *HostPort
	// spellings are the scheme-less host:port forms the harness.Target address
	// methods return (scenarios build "http://"/"https://" around them).
	CPBase           = "https://localhost:7070"
	CPHostPort       = "localhost:7070"
	RecorderBase     = "http://127.0.0.1:8081"
	RecordedPath     = "/_recorded"
	ResetPath        = "/_reset"
	TrafficPath      = "/dashboard/api/traffic" // worker admin and CP fleet view
	WorkerAdminHost1 = "127.0.0.1:9091"
	WorkerAdminHost2 = "127.0.0.1:9092"
	WorkerAdmin1     = "http://" + WorkerAdminHost1
	WorkerAdmin2     = "http://" + WorkerAdminHost2
	RecorderHealth   = "/_health"

	// The workers' proxy and admin ports INSIDE the compose network (the proxy
	// port is published to nobody on the host — the agent seam exists for that).
	ProxyPort = "8080"
	Proxy1    = SvcWorker1 + ":" + ProxyPort
	Proxy2    = SvcWorker2 + ":" + ProxyPort

	// Networks (compose-prefixed) the agents, workers and control plane live on.
	NetW1 = Project + "_w1-internal"
	NetW2 = Project + "_w2-internal"
	NetCP = Project + "_cp-net"

	// The deployment's secret wiring (configs/config.e2e-worker.yaml): the
	// FIXED canary the workers hold and swap, the placeholder the agents hold.
	Canary      = "CANARY-e2e-0123456789abcdef0123456789abcdef"
	Placeholder = "example_secret_001"
	EnvVar      = "EXAMPLE_SECRET"

	// CAPath is the repo-relative lab proxy CA (host-side trust for the CP);
	// AgentCABundle is the same cert inside the agent containers.
	CAPath        = "test/e2e/certs/proxy-ca.crt"
	AgentCABundle = "/etc/warden/certs/proxy-ca.crt"

	// AgentCurlMaxTime bounds one curl run inside the agent container (the
	// harness agent client's own 30s backstop is the outer bound).
	AgentCurlMaxTime = "25"

	// EventsDeadline bounds how long the events oracle waits for the async
	// analytics writer (a non-empty count must hold stable for
	// EventsStablePolls further polls, EventsTick apart, before it returns; a
	// zero count polls out the whole deadline — the workers' forward tick is
	// the slowest stage, so an empty read proves nothing before it).
	EventsDeadline    = 20 * time.Second
	EventsTick        = 500 * time.Millisecond
	EventsStablePolls = 2

	// Lifecycle budgets: the bring-up (a from-source build) is the long pole.
	UpDeadline      = 15 * time.Minute
	DownDeadline    = 5 * time.Minute
	StackDeadline   = 120 * time.Second // health poll after bring-up
	ProbeDeadline   = 3 * time.Second   // fast "is a stack already running" probe
	ComposeDeadline = 60 * time.Second  // logs/stop/start style calls
	AgentTimeout    = 90 * time.Second  // one exec in an agent container
)

// ComposeFiles are the same two -f files the Makefile passes: the base stack
// (control plane + workers) and the e2e override (agents, fake upstream,
// hermetic networks).
var ComposeFiles = []string{
	"deploy/compose/docker-compose.control-plane.yml",
	"deploy/compose/docker-compose.e2e.yml",
}

// ComposeArgs renders one `docker compose` argv for the stack.
func ComposeArgs(args ...string) []string {
	full := []string{"compose"}
	for _, f := range ComposeFiles {
		full = append(full, "-f", f)
	}
	return append(full, args...)
}

// AllServices is every service whose logs are scanned for the canary.
var AllServices = []string{SvcCP, SvcWorker1, SvcWorker2, SvcAgent1, SvcAgent2, SvcUpstream}

// FleetPaths are the control plane's fleet-API reads, all scanned for the canary.
var FleetPaths = []string{
	TrafficPath, "/dashboard/api/workers", "/dashboard/api/analytics",
	"/dashboard/api/mcp", "/dashboard/api/audit", "/dashboard/api/alerts",
	"/dashboard/api/endpoints", "/dashboard/api/policy",
	"/dashboard/api/integrations", "/dashboard/api/detection",
}

// WorkerAdminBase maps a worker service to its published admin base URL.
func WorkerAdminBase(worker string) (string, bool) {
	switch worker {
	case SvcWorker1:
		return WorkerAdmin1, true
	case SvcWorker2:
		return WorkerAdmin2, true
	}
	return "", false
}

// Host maps a well-known fake alias to the hostname the stack's fake DNS
// serves (harness.Target.Host). The stack plays the whole outside world with
// ONE TLS cert and DNS zone: api/llm/mcp/evil.example.test, with
// unlisted.example.test refusing at policy exactly like any name no policy
// lists. It serves NO gRPC or WebSocket fake (those scenarios drive
// in-process fakes directly and are L1-only), and unknown aliases do not
// exist — both refuse here, where the failure names the lever.
func Host(alias string) (string, error) {
	switch alias {
	case "api", "llm", "mcp", "evil", "unlisted":
		return alias + ".example.test", nil
	case "grpc", "ws":
		return "", fmt.Errorf("compose: the stack serves no %s.example.test fake; the %s scenarios drive an in-process fake and are in-process-only (L1)", alias, alias)
	}
	return "", fmt.Errorf("compose: Host(%q): unknown alias", alias)
}

// SecretSpecs is the deployment's secret wiring as harness.SecretSpec values:
// the one secret the workers hold (harness.TargetSecrets). The harness
// supersedes any WithSecret options with these, so the canary sweep guards the
// value THIS deployment actually swaps — never an L1-planted value.
func SecretSpecs() []harness.SecretSpec {
	return []harness.SecretSpec{{
		Name:        EnvVar,
		Placeholder: Placeholder,
		Value:       Canary,
		MatchHosts:  []string{"api.example.test", "llm.example.test"},
	}}
}
