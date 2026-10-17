//go:build e2e

package compose_test

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/test/harness"
	"github.com/ethosagent/warden/test/harness/compose"
)

// The compose target's own proof (#368): boot the harness against the stack
// and round-trip every seam the shared scenarios lean on — the agent client,
// the recorder view, the events oracle with its settle window, the CONNECT
// probe, the control-plane outage fault and the absent metrics oracle. Needs a
// usable Docker (like everything under the e2e tag).
func TestComposeTarget_AgentRoundTrip(t *testing.T) {
	h := harness.New(t, harness.WithTarget(compose.New()))

	api := h.Host("api")
	if api != "api.example.test" {
		t.Fatalf("Host(api) = %q, want the stack's fake-DNS name", api)
	}
	for _, alias := range []string{"grpc", "ws"} {
		if _, err := compose.New().Host(alias); err == nil {
			t.Errorf("Host(%s) = no error, want the in-process-only refusal", alias)
		}
	}

	// The agent seam: the placeholder the AGENT holds is the deployment's
	// (example_secret_001), whatever an L1 scenario's WithSecret named.
	ph := h.Placeholder("openai")
	if ph != compose.Placeholder {
		t.Fatalf("placeholder = %q, want the deployment's %q", ph, compose.Placeholder)
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+api+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+ph)
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("GET through agent-1: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200 through worker-1", resp.StatusCode)
	}

	// The upstream seam: the recorder saw it, swap already applied.
	reqs, err := h.Target().(harness.UpstreamReader).UpstreamRequests(api)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("recorder holds %d request(s) for %s, want 1", len(reqs), api)
	}
	if got, want := reqs[0].Header.Get("Authorization"), "Bearer "+h.Secret("openai"); got != want {
		t.Errorf("upstream Authorization = %q, want the swapped %q", got, want)
	}

	// The events oracle: exactly the one allow event this harness made — the
	// settle window proves the async writer has landed it, the since marker
	// that nothing older is in the list.
	evs := h.Events()
	var allows int
	for _, e := range evs {
		if e.Domain == api {
			allows++
			if e.Decision != "allow" {
				t.Errorf("event for %s = %s, want allow", api, e.Decision)
			}
			if e.SecretRef == "" {
				t.Error("the allow event carries no SecretRef although a secret was swapped")
			}
		}
	}
	if allows != 1 {
		t.Errorf("allow events for %s = %d, want exactly 1", api, allows)
	}

	// Metrics are ABSENT on this target, loudly.
	if h.MetricsAvailable() {
		t.Error("MetricsAvailable = true, want false: the stack exports no OTel endpoint")
	}

	h.AssertCanaryNeverLeaked()
}

// TestComposeTarget_DefaultDenyAtConnect: a name no policy lists is refused at
// CONNECT with the default-deny reason (#409), recorded as exactly one deny
// event, and never reaches the fake upstream.
func TestComposeTarget_DefaultDenyAtConnect(t *testing.T) {
	h := harness.New(t, harness.WithTarget(compose.New()))
	host := h.Host("unlisted")

	if got := h.ConnectStatus(host + ":443"); got != http.StatusForbidden {
		t.Errorf("CONNECT %s = %d, want 403", host, got)
	}
	denies := 0
	for _, e := range h.Events() {
		if e.Domain != host {
			continue
		}
		denies++
		if e.Decision != "deny" {
			t.Errorf("event for %s = %s, want deny", host, e.Decision)
		}
		if e.Reason != string(denyreason.PolicyNoMatch) {
			t.Errorf("deny reason = %q, want %q (#409)", e.Reason, denyreason.PolicyNoMatch)
		}
	}
	if denies != 1 {
		t.Errorf("deny events for %s = %d, want exactly 1", host, denies)
	}
	reqs, err := h.Target().(harness.UpstreamReader).UpstreamRequests(host)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Errorf("the denied host reached the upstream: %+v", reqs)
	}
}

// TestComposeTarget_ControlPlaneOutage: the outage fault stops and restarts the
// control plane on the SAME address, an allowed call rides the outage on the
// workers' cached policy, and the probe surfaces the quiet window instead of
// papering over it. Its harness also proves the ATTACH path: the stack is
// already serving from the test above, so this Start must not bring a second
// one up.
func TestComposeTarget_ControlPlaneOutage(t *testing.T) {
	h := harness.New(t, harness.WithTarget(compose.New()))
	api := h.Host("api")
	target := h.Target()

	if err := target.StopControlPlane(); err != nil {
		t.Fatalf("stop the control plane: %v", err)
	}
	// The fault is real: the control plane is quiet. (The worker, not the CP,
	// answers the agent — that resilience is the next assertion.)
	if _, _, err := compose.TryGet(compose.CPBase + "/healthz"); err == nil {
		t.Error("the control plane still serves /healthz; the outage fault did not take")
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+api+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("GET during the outage: %v (the worker must ride it on cached policy)", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET during the outage = %d, want 200 on the worker's cached policy", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := target.StartControlPlane(ctx); err != nil {
		t.Fatalf("restart the control plane: %v", err)
	}
	if got := h.ConnectStatus(h.Host("evil") + ":443"); got != http.StatusForbidden {
		t.Errorf("CONNECT after the restart = %d, want 403 (policy serving again)", got)
	}
}
