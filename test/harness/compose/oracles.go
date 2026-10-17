//go:build e2e

package compose

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness"
)

// The harness.Target oracles on the compose stack: logs, events, the fake
// upstream's recorder and the CONNECT probe. Metrics is ABSENT — the stack
// exports no OTel endpoint — and says so loudly instead of returning an empty
// map a scenario would read as "zero" (the documented capability split, never
// a silent pass).

// LogsOf is one service's `docker compose logs --no-color`.
func LogsOf(service string) (string, error) {
	res := ComposeRun(ComposeDeadline, "logs", "--no-color", service)
	if res.Exit != 0 {
		return "", fmt.Errorf("compose: logs %s: exit %d: %s", service, res.Exit, res.Stderr)
	}
	return res.Stdout, nil
}

// Logs is everything the deployment's components logged, structured exactly as
// a deployment's stdout: every service in section-marked order (control plane,
// workers, agents, fake upstream). A logs read that fails rides IN the text —
// the Target interface returns no error here, and an oracle outage must not
// look like a clean surface.
func (t *Target) Logs() string {
	var b strings.Builder
	for _, svc := range AllServices {
		logs, err := LogsOf(svc)
		if err != nil {
			fmt.Fprintf(&b, "=== %s: LOGS READ FAILED: %v ===\n", svc, err)
			continue
		}
		fmt.Fprintf(&b, "=== %s ===\n%s", svc, logs)
	}
	return b.String()
}

// Events reads the control plane's fleet view — the read side of both workers'
// forwarded analytics (the workers write asynchronously on their own tick;
// their own traffic APIs are empty in central mode). It polls until a
// non-empty count of events at or after this harness's Start marker holds
// stable, so the events of traffic the scenario has finished making are
// visible (read-your-writes) and nothing the shared stack served before this
// harness started is in the list. An empty fleet at the deadline is returned
// with no error — zero is the caller's assertion to make, made only after the
// forward pipeline had its whole window.
func (t *Target) Events() ([]analytics.Event, error) {
	fetch := func() ([]analytics.Event, error) {
		code, body, err := TryGet(CPBase + TrafficPath + "?limit=1000")
		if err != nil {
			return nil, err
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("fleet traffic: status %d", code)
		}
		return DecodeEvents(body)
	}
	return PollEvents(fetch, t.since, EventsDeadline, EventsTick, EventsStablePolls, time.Sleep)
}

// Metrics is not supported on this target: the stack exports no OTel endpoint.
// It fails instead of returning an empty map, which a scenario would read as
// "zero events of anything" — a silent pass. Ask MetricsAvailable first and
// skip the metrics assertion explicitly on such a target.
func (t *Target) Metrics() (map[string]float64, error) {
	return nil, fmt.Errorf("compose: metrics are not supported on this target: the stack exports no OTel metrics endpoint")
}

// MetricsAvailable reports the absent metrics oracle.
func (t *Target) MetricsAvailable() bool { return false }

// UpstreamRequests returns what the stack's fake upstream recorded for host,
// oldest first, in the RecordedRequest shape the in-process fakes use
// (post-pipeline: swaps already applied). The recorder is synchronous with the
// request — it records before answering — so a read after the agent's call
// returned needs no wait.
func (t *Target) UpstreamRequests(host string) ([]harness.RecordedRequest, error) {
	recs, err := RecorderRequests()
	if err != nil {
		return nil, err
	}
	return FilterRecorded(recs, host), nil
}

// ConnectStatus sends CONNECT hostPort the way the agent's own traffic is sent
// — a curl run inside the agent container, through its worker's proxy — and
// returns the status of the proxy's reply: the policy decision itself, before
// any client library turns a refusal into an opaque transport error.
func (t *Target) ConnectStatus(hostPort string) (int, error) {
	res, err := AgentRunRaw(SvcAgent1, "curl", "-s", "-o", "/dev/null",
		"--max-time", AgentCurlMaxTime,
		"-x", "http://"+Proxy1,
		"-w", "%{http_connect}",
		"https://"+hostPort+"/")
	if err != nil {
		return 0, err
	}
	return ParseConnectStatus(res.Stdout)
}
