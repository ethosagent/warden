package controlplane

import (
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// containsAny reports whether s contains any of subs (case-insensitive), used to
// assert leaky fields never reach the bounded Summary/Evidence strings.
func containsAny(s string, subs ...string) string {
	low := strings.ToLower(s)
	for _, sub := range subs {
		if sub != "" && strings.Contains(low, strings.ToLower(sub)) {
			return sub
		}
	}
	return ""
}

func TestBridgeEvent_Block(t *testing.T) {
	ts := time.Now()
	e := analytics.Event{
		Timestamp:   ts,
		Domain:      "evil.example.com",
		Method:      "POST",
		Decision:    "block",
		Reason:      "mcp_tool_denied",
		Tool:        "shell",
		URL:         "https://evil.example.com/exfil?token=SECRET123&q=body",
		JudgeReason: "the model tried to leak the API key value abc123",
	}
	f, ok := bridgeEvent("worker-7", e)
	if !ok {
		t.Fatal("block event should produce a finding")
	}
	if f.RuleID != "egress_blocked" {
		t.Errorf("RuleID = %q, want egress_blocked", f.RuleID)
	}
	if f.Category != "security" {
		t.Errorf("Category = %q, want security", f.Category)
	}
	if f.Severity != integration.SevMedium {
		t.Errorf("Severity = %v, want medium", f.Severity)
	}
	if f.DedupKey != "egress_blocked:evil.example.com" {
		t.Errorf("DedupKey = %q, want egress_blocked:evil.example.com (worker NOT in key)", f.DedupKey)
	}
	if f.Subject.Worker != "worker-7" || f.Subject.Domain != "evil.example.com" {
		t.Errorf("Subject = %+v, want worker-7 / evil.example.com", f.Subject)
	}
	if !f.Ts.Equal(ts) {
		t.Errorf("Ts = %v, want %v", f.Ts, ts)
	}
	// EGRESS HYGIENE: no url/query/body/judgeReason may reach the bounded strings.
	leak := "token=SECRET123 /exfil?q=body abc123 the model tried"
	if hit := containsAny(f.Summary, "SECRET123", "exfil", "abc123", "the model tried", "?"); hit != "" {
		t.Fatalf("Summary %q leaked %q (must contain only bounded enum fields); %s", f.Summary, hit, leak)
	}
	if hit := containsAny(string(f.Evidence), "SECRET123", "exfil", "abc123", "the model tried", "?"); hit != "" {
		t.Fatalf("Evidence %q leaked %q; %s", f.Evidence, hit, leak)
	}
}

func TestBridgeEvent_ReasonMedium(t *testing.T) {
	e := analytics.Event{Domain: "api.foo.com", Reason: "mcp_schema_drift", Tool: "search"}
	f, ok := bridgeEvent("w1", e)
	if !ok {
		t.Fatal("reason event should produce a finding")
	}
	if f.RuleID != "mcp_schema_drift" {
		t.Errorf("RuleID = %q, want mcp_schema_drift", f.RuleID)
	}
	if f.Severity != integration.SevMedium {
		t.Errorf("Severity = %v, want medium", f.Severity)
	}
	if f.DedupKey != "mcp_schema_drift:api.foo.com" {
		t.Errorf("DedupKey = %q", f.DedupKey)
	}
}

func TestBridgeEvent_ReasonPoisonHigh(t *testing.T) {
	// A poisoning/exfil reason escalates to SevHigh; tool-keyed when no domain.
	e := analytics.Event{Reason: "mcp_poisoning", Tool: "notes"}
	f, ok := bridgeEvent("w1", e)
	if !ok {
		t.Fatal("poison event should produce a finding")
	}
	if f.Severity != integration.SevHigh {
		t.Errorf("Severity = %v, want high for a poisoning reason", f.Severity)
	}
	if f.DedupKey != "mcp_poisoning:notes" {
		t.Errorf("DedupKey = %q, want tool-keyed when domain is empty", f.DedupKey)
	}
}

func TestBridgeEvent_BenignAllow(t *testing.T) {
	e := analytics.Event{Domain: "api.openai.com", Decision: "allow", Method: "GET"}
	if _, ok := bridgeEvent("w1", e); ok {
		t.Fatal("a benign allow with no reason must NOT produce a finding")
	}
}
