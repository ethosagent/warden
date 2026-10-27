//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/harness/compose"
)

// Fleet scenarios: the control plane pushes policy to two workers, and the
// workers stay fail-closed when the control plane is gone.
//
// The policy is changed through the route the dashboard uses,
// PUT /dashboard/api/policy on the control plane. Dashboard writes need the
// control-plane bearer token (#422), so putPolicy sends it; the stack also keeps
// the port bound to 127.0.0.1 only.
//
// "Allowed" and "denied" are read from the proxy's CONNECT status: 200 means
// policy let the tunnel open, 403 means policy refused it. The fake DNS does
// not know the hosts these tests add, so the request behind an allowed CONNECT
// fails upstream (502); that is irrelevant to the policy decision under test.
//
// Every test leaves the stack as it found it (see restoreFleet), so the order
// the tests run in does not matter.

// policyPropagation bounds how long a policy change may take to reach a
// worker: one long-poll round trip, with margin.
const policyPropagation = 30 * time.Second

const (
	newHost   = "new.example.test"
	againHost = "again.example.test"
	neverHost = "never.example.test" // never allowed by any test
)

// fleetAgents pairs each agent with the worker it must go through.
var fleetAgents = []struct{ agent, worker string }{
	{svcAgent1, svcWorker1},
	{svcAgent2, svcWorker2},
}

// policyDoc is the body of the dashboard policy route (both directions).
type policyDoc struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
}

func (p policyDoc) allows(domain string) bool {
	for _, e := range p.Allowlist {
		if e.Domain == domain {
			return true
		}
	}
	return false
}

// getPolicy reads the policy a dashboard serves (the control plane's, or a
// worker's live one) from base.
func getPolicy(base string) (policyDoc, error) {
	var doc policyDoc
	code, body, err := tryGet(base + "/dashboard/api/policy")
	if err != nil {
		return doc, err
	}
	if code != http.StatusOK {
		return doc, fmt.Errorf("status %d: %.200s", code, body)
	}
	return doc, json.Unmarshal(body, &doc)
}

// putPolicy replaces the fleet policy through the control plane's dashboard route.
func putPolicy(tb testing.TB, doc policyDoc) {
	tb.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		tb.Fatal(err)
	}
	client, err := httpClient()
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut, cpBase+"/dashboard/api/policy", bytes.NewReader(body))
	if err != nil {
		tb.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	token, err := (&compose.Target{}).ControlPlaneToken()
	if err != nil {
		tb.Fatalf("e2e: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("e2e: PUT policy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("e2e: PUT /dashboard/api/policy returned %d", resp.StatusCode)
	}
}

// withAllowed is doc plus domains on the allowlist.
func (p policyDoc) withAllowed(domains ...string) policyDoc {
	out := policyDoc{Allowlist: append([]config.AllowlistEntry(nil), p.Allowlist...), Denylist: p.Denylist}
	for _, d := range domains {
		if !out.allows(d) {
			out.Allowlist = append(out.Allowlist, config.AllowlistEntry{Domain: d})
		}
	}
	return out
}

// connectStatus is the CONNECT status the agent's worker answered for host.
func connectStatus(t *testing.T, agent, host string) string {
	t.Helper()
	worker := strings.Replace(agent, "agent", "worker", 1)
	return curlProbe(t, agent, "-x", "http://"+worker+":8080", "https://"+host+"/").connect
}

// assertDecision fails unless host gets want ("200" allowed, "403" denied)
// from the agent's worker on the first try.
func assertDecision(t *testing.T, agent, host, want string) {
	t.Helper()
	if got := connectStatus(t, agent, host); got != want {
		t.Errorf("%s -> %s: CONNECT %s, want %s", agent, host, got, want)
	}
}

// waitWorkerPolicy polls a worker's own policy API until domain is (or is no
// longer) on its live allowlist.
func waitWorkerPolicy(t *testing.T, worker, domain string, want bool) {
	t.Helper()
	waitFor(t, policyPropagation, fmt.Sprintf("%s allowlist to contain %s = %v", worker, domain, want), func() (bool, string) {
		doc, err := getPolicy(workerAdmin[worker])
		if err != nil {
			return false, err.Error()
		}
		return doc.allows(domain) == want, fmt.Sprintf("allowlist %v", doc.Allowlist)
	})
}

// waitDecision polls until the agent's worker answers want for host.
func waitDecision(t *testing.T, agent, host, want string) {
	t.Helper()
	waitFor(t, policyPropagation, fmt.Sprintf("%s -> %s to be CONNECT %s", agent, host, want), func() (bool, string) {
		got := connectStatus(t, agent, host)
		return got == want, "CONNECT " + got
	})
}

// restoreFleet registers a cleanup that brings the stack back to what it was
// when the test started: every service running, the control plane serving the
// original policy, and both workers holding it. It is safe to call before the
// test stops anything. Failures here fail the test that caused them.
func restoreFleet(t *testing.T) policyDoc {
	t.Helper()
	orig, err := getPolicy(cpBase)
	if err != nil {
		t.Fatalf("e2e: read control-plane policy: %v", err)
	}
	t.Cleanup(func() {
		for _, svc := range []string{svcCP, svcWorker1, svcWorker2, svcWorker3} {
			if res := composeRun(t, 120*time.Second, "start", svc); res.exit != 0 {
				t.Errorf("e2e: restore: start %s: exit %d: %s", svc, res.exit, res.stderr)
			}
		}
		if err := waitStackReady(); err != nil {
			t.Errorf("e2e: restore: stack not ready: %v", err)
			return
		}
		putPolicy(t, orig)
		for _, w := range fleetAgents {
			err := pollUntil(policyPropagation, func() (bool, string) {
				doc, err := getPolicy(workerAdmin[w.worker])
				if err != nil {
					return false, err.Error()
				}
				same := len(doc.Allowlist) == len(orig.Allowlist) && len(doc.Denylist) == len(orig.Denylist)
				for _, e := range orig.Allowlist {
					same = same && doc.allows(e.Domain)
				}
				return same, fmt.Sprintf("allowlist %v", doc.Allowlist)
			})
			if err != nil {
				t.Errorf("e2e: restore: %s did not return to the original policy: %v", w.worker, err)
			}
		}
	})
	return orig
}

// TestFleet_PolicyReachesBothWorkers: one edit on the control plane reaches
// both workers within a long-poll and changes what each agent may reach.
func TestFleet_PolicyReachesBothWorkers(t *testing.T) {
	orig := restoreFleet(t)
	for _, w := range fleetAgents {
		assertDecision(t, w.agent, newHost, "403") // control: not allowed yet
	}

	putPolicy(t, orig.withAllowed(newHost))

	for _, w := range fleetAgents {
		waitWorkerPolicy(t, w.worker, newHost, true)
		waitDecision(t, w.agent, newHost, "200")
	}
	// The edit widened exactly one host: a neighbour and the denylist hold.
	for _, w := range fleetAgents {
		assertDecision(t, w.agent, neverHost, "403")
		assertDecision(t, w.agent, "evil.example.test", "403")
	}
}

// TestFleet_ControlPlaneStopped_FailsClosed: with the control plane gone the
// workers keep enforcing the last policy they hold. Allowed stays allowed,
// denied stays denied, and a host nobody ever allowed does not open up.
func TestFleet_ControlPlaneStopped_FailsClosed(t *testing.T) {
	orig := restoreFleet(t)
	// Give the workers a policy that differs from the config seed, so "last
	// known policy" is something they were pushed, not just booted with.
	putPolicy(t, orig.withAllowed(newHost))
	for _, w := range fleetAgents {
		waitDecision(t, w.agent, newHost, "200")
	}

	if res := composeRun(t, 120*time.Second, "stop", svcCP); res.exit != 0 {
		t.Fatalf("e2e: stop %s: exit %d: %s", svcCP, res.exit, res.stderr)
	}
	// Barrier: each worker has noticed the control plane is gone (its long
	// poll failed), so the checks below run against a worker that is really
	// orphaned, not one still holding an open poll.
	for _, w := range fleetAgents {
		waitFor(t, policyPropagation, w.worker+" to log the failed long-poll", func() (bool, string) {
			l := logs(t, w.worker)
			return strings.Contains(l, "long-poll failed; keeping last-known policy"), "no such log line yet"
		})
	}

	for _, w := range fleetAgents {
		assertDecision(t, w.agent, "api.example.test", "200") // was allowed
		assertDecision(t, w.agent, newHost, "200")            // pushed before the stop
		assertDecision(t, w.agent, "evil.example.test", "403")
		assertDecision(t, w.agent, neverHost, "403") // never allowed
		if code, _, err := tryGet(workerAdmin[w.worker] + "/healthz"); err != nil || code != http.StatusOK {
			t.Errorf("%s /healthz = %d err %v while the control plane is down; it should keep serving", w.worker, code, err)
		}
	}
}

// TestFleet_ControlPlaneRestarted_Resyncs: after the control plane comes back
// the workers reconnect and pick up a policy change made afterwards.
func TestFleet_ControlPlaneRestarted_Resyncs(t *testing.T) {
	orig := restoreFleet(t)
	if res := composeRun(t, 120*time.Second, "stop", svcCP); res.exit != 0 {
		t.Fatalf("e2e: stop %s: exit %d: %s", svcCP, res.exit, res.stderr)
	}
	for _, w := range fleetAgents {
		assertDecision(t, w.agent, againHost, "403")
	}
	if res := composeRun(t, 120*time.Second, "start", svcCP); res.exit != 0 {
		t.Fatalf("e2e: start %s: exit %d: %s", svcCP, res.exit, res.stderr)
	}
	// Ready = healthy control plane and both workers re-registered with it.
	if err := waitStackReady(); err != nil {
		t.Fatalf("e2e: control plane did not come back: %v", err)
	}

	putPolicy(t, orig.withAllowed(againHost))

	for _, w := range fleetAgents {
		waitWorkerPolicy(t, w.worker, againHost, true)
		waitDecision(t, w.agent, againHost, "200")
	}
}

// TestFleet_WorkerRestart_DecidesByPolicy: a restarted worker pulls policy
// before it serves, so the first request an agent sends is decided by the
// fleet policy, not fail-open and not the stale boot config.
func TestFleet_WorkerRestart_DecidesByPolicy(t *testing.T) {
	orig := restoreFleet(t)
	// A host only the control plane knows: if the restarted worker served
	// before its first pull, it would deny this (fail-closed) or, worse,
	// allow the unlisted one.
	putPolicy(t, orig.withAllowed(newHost))
	waitDecision(t, svcAgent1, newHost, "200")

	if res := composeRun(t, 120*time.Second, "restart", svcWorker1); res.exit != 0 {
		t.Fatalf("e2e: restart %s: exit %d: %s", svcWorker1, res.exit, res.stderr)
	}
	waitFor(t, stackDeadline, svcWorker1+" /healthz", func() (bool, string) {
		code, _, err := tryGet(workerAdmin[svcWorker1] + "/healthz")
		return err == nil && code == http.StatusOK, fmt.Sprintf("status %d err %v", code, err)
	})

	// The very first requests after /healthz: no waiting, no retry.
	assertDecision(t, svcAgent1, neverHost, "403")
	assertDecision(t, svcAgent1, "evil.example.test", "403")
	assertDecision(t, svcAgent1, newHost, "200")
	assertDecision(t, svcAgent1, "api.example.test", "200")
}

// TestFleet_EventsAttributedToWorker: each agent's request shows up in the
// control plane's fleet view once, under the worker that decided it.
func TestFleet_EventsAttributedToWorker(t *testing.T) {
	restoreFleet(t) // nothing is changed, but leave the stack provably intact
	since := time.Now()
	hosts := map[string]string{svcWorker1: "api.example.test", svcWorker2: "llm.example.test"}
	for _, w := range fleetAgents {
		assertDecision(t, w.agent, hosts[w.worker], "200")
	}

	for _, w := range fleetAgents {
		mine := hosts[w.worker]
		evs := events(t, w.worker, since, 1, func(e analytics.Event) bool {
			return e.Domain == mine && e.Decision == "allow"
		})
		n := 0
		for _, e := range evs {
			if e.Domain == mine {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: %d events for %s, want exactly 1 (%s)", w.worker, n, mine, summarize(evs))
		}
		for _, other := range fleetAgents {
			if other.worker == w.worker {
				continue
			}
			for _, e := range evs {
				if e.Domain == hosts[other.worker] {
					t.Errorf("%s's fleet events hold %s, a host only %s was asked for: %+v", w.worker, e.Domain, other.worker, e)
				}
			}
		}
	}
}

// TestFleet_DashboardPolicyWriteNeedsToken: on the real stack an unauthenticated
// or wrong-token PUT /dashboard/api/policy is refused (401) and the policy the
// workers enforce does not change (#422).
func TestFleet_DashboardPolicyWriteNeedsToken(t *testing.T) {
	client, err := httpClient()
	if err != nil {
		t.Fatalf("e2e: %v", err)
	}
	body := `{"allowlist":[{"domain":"exfil.example.test"}],"denylist":[]}`
	for _, auth := range []string{"", "Bearer wrong-token"} {
		req, err := http.NewRequest(http.MethodPut, cpBase+"/dashboard/api/policy", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("e2e: PUT policy: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("PUT /dashboard/api/policy with auth %q = %d, want 401", auth, resp.StatusCode)
		}
	}
	doc, err := getPolicy(cpBase)
	if err != nil {
		t.Fatal(err)
	}
	if doc.allows("exfil.example.test") {
		t.Fatal("a refused write still changed the fleet policy")
	}
}

// TestFleet_WorkerDashboardWriteNeedsToken: on the real stack a worker's admin
// dashboard refuses an unauthenticated or wrong-token write (401) and lets the
// worker admin token through to the handler (#425). Reads stay open.
func TestFleet_WorkerDashboardWriteNeedsToken(t *testing.T) {
	adminToken := (&compose.Target{}).WorkerAdminToken()
	// Keep-alives off, like every other host-side probe (compose.oneShot): an
	// idle keep-alive conn (two goroutines) is exactly what the harness's
	// goroutine-leak check flags as a leak.
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	for _, w := range fleetAgents {
		base, ok := compose.WorkerAdminBase(w.worker)
		if !ok {
			t.Fatalf("no admin base for %s", w.worker)
		}
		put := func(auth string) int {
			req, err := http.NewRequest(http.MethodPut, base+"/dashboard/api/detection", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("e2e: PUT %s detection: %v", w.worker, err)
			}
			_ = resp.Body.Close()
			return resp.StatusCode
		}
		for _, auth := range []string{"", "Bearer wrong-token"} {
			if c := put(auth); c != http.StatusUnauthorized {
				t.Errorf("%s: PUT /dashboard/api/detection with auth %q = %d, want 401", w.worker, auth, c)
			}
		}
		// A managed worker has no detection writer, so the handler answers 405.
		if c := put("Bearer " + adminToken); c != http.StatusMethodNotAllowed {
			t.Errorf("%s: PUT with the worker admin token = %d, want 405 from the handler", w.worker, c)
		}
		// The /admin/ routes are writers too (#430): the same token gate, and
		// with it the refresh actually runs.
		post := func(auth string) (int, string) {
			req, err := http.NewRequest(http.MethodPost, base+"/admin/refresh-secrets", nil)
			if err != nil {
				t.Fatal(err)
			}
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("e2e: POST %s refresh-secrets: %v", w.worker, err)
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		for _, auth := range []string{"", "Bearer wrong-token"} {
			if c, _ := post(auth); c != http.StatusUnauthorized {
				t.Errorf("%s: POST /admin/refresh-secrets with auth %q = %d, want 401", w.worker, auth, c)
			}
		}
		if c, body := post("Bearer " + adminToken); c != http.StatusOK || body != "refreshed" {
			t.Errorf("%s: POST /admin/refresh-secrets with the token = %d %q, want 200 \"refreshed\"", w.worker, c, body)
		}
		if _, err := getPolicy(base); err != nil {
			t.Errorf("%s: GET policy (reads stay open): %v", w.worker, err)
		}
	}
}

// workerAuthKinds reads authKind per proxy id from the control plane's fleet view.
func workerAuthKinds(t *testing.T) map[string]string {
	t.Helper()
	code, body, err := tryGet(cpBase + "/dashboard/api/workers")
	if err != nil || code != http.StatusOK {
		t.Fatalf("e2e: GET /dashboard/api/workers: status %d err %v", code, err)
	}
	var ws []struct {
		ProxyID  string `json:"proxyID"`
		AuthKind string `json:"authKind"`
	}
	if err := json.Unmarshal(body, &ws); err != nil {
		t.Fatalf("e2e: decode workers: %v", err)
	}
	out := map[string]string{}
	for _, w := range ws {
		out[w.ProxyID] = w.AuthKind
	}
	return out
}

// tokenRows lists the registered worker tokens (id by name) with the offline
// CLI, run inside the control-plane container on its state volume.
func tokenRows(t *testing.T) map[string]string {
	t.Helper()
	res := composeRun(t, 60*time.Second, "exec", "-T", svcCP, "warden", "control-plane", "token", "list", "--state-dir=/data", "--json")
	if res.exit != 0 {
		t.Fatalf("e2e: token list: exit %d: %s", res.exit, res.stderr)
	}
	var rows []struct{ ID, Name string }
	if err := json.Unmarshal([]byte(res.stdout), &rows); err != nil {
		t.Fatalf("e2e: decode token list: %v", err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Name] = r.ID
	}
	return out
}

// TestFleetPerWorkerTokens: every worker authenticates with its own token
// (authKind=token), the retired shared token and the CP's admin token are both
// refused on the worker routes (401), and bringing the stack up a second time
// registers nothing new (token create --from-env is a no-op on a known value).
func TestFleetPerWorkerTokens(t *testing.T) {
	restoreFleet(t)
	kinds := workerAuthKinds(t)
	for _, w := range []string{svcWorker1, svcWorker2, svcWorker3} {
		if kinds[w] != "token" {
			t.Errorf("%s authKind = %q, want token (all: %v)", w, kinds[w], kinds)
		}
	}

	client, err := httpClient()
	if err != nil {
		t.Fatalf("e2e: %v", err)
	}
	// The shared token the stack used to hand every worker, and the CP's admin
	// token, are not worker credentials in strict mode.
	for _, bearer := range []string{"dev-token", "dev-cp-admin-token"} {
		req, err := http.NewRequest(http.MethodGet, cpBase+"/policy", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Warden-Proxy-ID", svcWorker1)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("e2e: GET /policy: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET /policy with bearer %q = %d, want 401", bearer, resp.StatusCode)
		}
	}

	before := tokenRows(t)
	if len(before) != 3 {
		t.Fatalf("registered tokens = %v, want w1, w2 and w3", before)
	}
	if res := composeRun(t, 10*time.Minute, "up", "-d", "--no-build"); res.exit != 0 {
		t.Fatalf("e2e: second up: exit %d: %s", res.exit, res.stderr)
	}
	if err := waitStackReady(); err != nil {
		t.Fatalf("e2e: stack not ready after the second up: %v", err)
	}
	after := tokenRows(t)
	if len(after) != len(before) {
		t.Fatalf("second up changed the token rows: before %v after %v", before, after)
	}
	for name, id := range before {
		if after[name] != id {
			t.Errorf("token %s id changed across the second up: %s -> %s", name, id, after[name])
		}
	}
}
