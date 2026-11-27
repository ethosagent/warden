package scenarios

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness"
)

// fleetAgentID proves W-P3-PUL-07 end to end: an event a worker forwards with
// its agent id and limit rule reaches the control plane's real ingest endpoint
// and the fleet traffic API returns both under the event's own keys
// (agent_id, limit_rule), the same keys the worker dashboard uses, with no
// second agent key. Before #291 the fleet store dropped the agent id.
func fleetAgentID(t *testing.T, h *harness.H) {
	ev := analytics.Event{
		Timestamp: time.Now().UTC(), Domain: "agent-id.example.com", Port: 443, Protocol: "https",
		Method: "GET", URL: "https://agent-id.example.com/", Decision: "allow",
		UserSub: "sub-alice", UserEmail: "alice@corp.example", IdentityStatus: "valid",
		AgentID: "claude-code", LimitRule: "eng-llm", CostUSD: 0.25,
	}
	if err := h.CP().IngestEvents("worker-1", []analytics.Event{ev}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var raw []map[string]any
	h.Eventually("the fleet traffic API to list the forwarded event", func() bool {
		raw = nil
		if err := h.CP().GetJSON("/dashboard/api/traffic?user=sub-alice", &raw); err != nil {
			t.Fatalf("cp GET traffic: %v", err)
		}
		return len(raw) == 1
	})
	got := raw[0]
	if got["agent_id"] != "claude-code" || got["limit_rule"] != "eng-llm" {
		t.Fatalf("fleet event agent_id=%v limit_rule=%v, want claude-code/eng-llm", got["agent_id"], got["limit_rule"])
	}
	for k := range got {
		if strings.EqualFold(k, "agentid") {
			t.Errorf("fleet event carries a second agent key %q", k)
		}
	}
	b, _ := json.Marshal(got)
	if strings.Count(string(b), "claude-code") != 1 {
		t.Errorf("agent id appears more than once: %s", b)
	}
}
