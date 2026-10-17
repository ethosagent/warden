//go:build e2e

package compose

import (
	"fmt"
	"testing"
)

// AssertCanaryNeverLeaked fails the test if the stack's canary, in any
// encoding, appears in:
//   - agentOutputs: the stdout the caller captured from agent commands, plus
//     each agent's environment (read here);
//   - `docker compose logs` of EVERY service;
//   - each worker's /dashboard/api/traffic;
//   - every control-plane fleet-API path.
//
// The fake upstream's recorder (GET /_recorded) is EXCLUDED on purpose: it
// stands in for the real upstream, which is the ONE place the swapped secret
// must arrive. Its container's logs ARE scanned. A sanity check proves the
// scanner can see the canary (TestCanaryScannerSeesTheRecorder in test/e2e).
func AssertCanaryNeverLeaked(tb testing.TB, agentOutputs ...string) {
	tb.Helper()
	needles := Needles(Canary)
	check := func(where, text string) {
		tb.Helper()
		if hits := LeaksIn(text, needles); len(hits) > 0 {
			tb.Errorf("canary leaked in %s (encodings: %v)", where, hits)
		}
	}
	for i, out := range agentOutputs {
		check(fmt.Sprintf("agent output #%d", i+1), out)
	}
	for _, agent := range []string{SvcAgent1, SvcAgent2, SvcAgent3} {
		res, err := AgentRunRaw(agent, "env")
		if err != nil || res.Exit != 0 {
			tb.Fatalf("compose: env in %s: %v (exit %d)", agent, err, res.Exit)
		}
		check(agent+" environment", res.Stdout)
	}
	for _, svc := range AllServices {
		logs, err := LogsOf(svc)
		if err != nil {
			tb.Fatalf("compose: logs %s: %v", svc, err)
		}
		check("logs of "+svc, logs)
	}
	for _, w := range []string{SvcWorker1, SvcWorker2, SvcWorker3} {
		body, err := WorkerTrafficBody(w)
		if err != nil {
			tb.Fatalf("compose: %v", err)
		}
		check(w+" traffic API", string(body))
	}
	for _, p := range FleetPaths {
		body, err := FleetBody(p)
		if err != nil {
			tb.Fatalf("compose: %v", err)
		}
		check("control-plane fleet API "+p, string(body))
	}
}
