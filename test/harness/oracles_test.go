package harness

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
)

// TestOracles_AllowedRequestLeavesTraces is the Task C acceptance flow: one
// allowed request through the worker leaves EXACTLY one allow event in
// analytics, a "decision" line in the structured logs, and the request
// counter at 1 — each oracle reading through the production packages.
func TestOracles_AllowedRequestLeavesTraces(t *testing.T) {
	h := New(t, WithSecret("openai", Canary()))
	llm := h.FakeLLM()

	// The placeholder rides the request the way an agent would send it; the
	// worker swaps it for the real env-resolved value on the way upstream.
	req, err := http.NewRequest(http.MethodGet, "https://llm.example.com/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.Placeholder("openai"))
	resp, err := h.Agent().Do(req)
	if err != nil {
		t.Fatalf("GET through the worker: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", resp.StatusCode)
	}

	// Events: the async analytics writer flushes off the request path — poll.
	h.Eventually("one allow event to land in the analytics store", func() bool {
		return countDecision(h.Events(), "allow") == 1
	})
	events := h.Events()
	if events[0].Decision != "allow" || events[0].Domain != "llm.example.com" || events[0].Protocol != "https" {
		t.Errorf("event = decision=%q domain=%q protocol=%q, want allow/llm.example.com/https",
			events[0].Decision, events[0].Domain, events[0].Protocol)
	}

	// Logs: the worker's structured decision line.
	logs := h.Logs()
	if !strings.Contains(logs, "egress decision") {
		t.Errorf("logs do not contain an egress decision line:\n%s", tail(logs, 2000))
	}
	if !strings.Contains(logs, `"decision":"allow"`) {
		t.Errorf("logs do not record the allow decision:\n%s", tail(logs, 2000))
	}

	// Metrics: the request counter, exactly 1, under its stable key.
	h.Eventually("the request counter metric to reach 1", func() bool {
		return h.Metrics()[MetricKey("warden.requests.total", map[string]string{
			"decision": "allow",
			"protocol": "https",
		})] == 1
	})

	// The swap left its fingerprints in the right places: the fake saw the real
	// value, the analytics event carries only the placeholder NAME.
	if auth := llm.AuthHeaders(); len(auth) != 1 || auth[0] != "Bearer "+h.secrets[0].value {
		t.Errorf("upstream Authorization = %v, want the swapped value", auth)
	}
	if countDecision(h.Events(), "allow") == 1 {
		if got := events[0].SecretRef; got != "" && strings.Contains(got, h.secrets[0].value) {
			t.Errorf("analytics event SecretRef carries the raw secret value: %q", got)
		}
	}
}

// TestOracles_CPClientFleetView proves the CP oracle: the fleet view lists the
// booted worker, and a bogus path surfaces as an error (not a silent decode).
func TestOracles_CPClientFleetView(t *testing.T) {
	h := New(t, Local())
	h.Eventually("the worker to appear in the fleet view", func() bool {
		workers, err := h.CP().Workers()
		return err == nil && len(workers) == 1
	})
	workers, err := h.CP().Workers()
	if err != nil {
		t.Fatalf("Workers(): %v", err)
	}
	if workers[0].ProxyID != "worker-1" {
		t.Errorf("fleet view ProxyID = %q, want worker-1", workers[0].ProxyID)
	}

	var v map[string]any
	if err := h.CP().GetJSON("/dashboard/api/nope", &v); err == nil {
		t.Error("GetJSON on an unknown path = nil error, want an error")
	}
}

// TestEvents_ImmediateAfterTraffic pins the deterministic events oracle: N
// requests, then h.Events() — called IMMEDIATELY, no Eventually — returns
// exactly N events. H.Events() drains each worker's async analytics writer
// (the assembly-only Flush seam) before reading, so a scenario never outwaits
// the writer's 250ms flush tick.
func TestEvents_ImmediateAfterTraffic(t *testing.T) {
	const n = 5
	h := New(t, WithSecret("openai", Canary()))
	h.FakeLLM() // registers llm.example.com — the GET below must have somewhere to go

	for i := 0; i < n; i++ {
		req, err := http.NewRequest(http.MethodGet, "https://llm.example.com/v1/chat/completions", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+h.Placeholder("openai"))
		resp, err := h.Agent().Do(req)
		if err != nil {
			t.Fatalf("GET %d through the worker: %v", i+1, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %d = %d, want 200", i+1, resp.StatusCode)
		}
	}

	events := h.Events() // the very next statement — no wait of any kind
	if len(events) != n {
		t.Fatalf("Events() immediately after %d requests = %d events, want exactly %d", n, len(events), n)
	}
	for _, e := range events {
		if e.Decision != "allow" || e.Domain != "llm.example.com" {
			t.Errorf("event decision=%q domain=%q, want allow/llm.example.com", e.Decision, e.Domain)
		}
	}
}

// countDecision counts events with the given decision.
func countDecision(events []analytics.Event, decision string) int {
	count := 0
	for _, e := range events {
		if e.Decision == decision {
			count++
		}
	}
	return count
}
