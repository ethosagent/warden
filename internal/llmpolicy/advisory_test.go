package llmpolicy

import (
	"reflect"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

func TestAnalyzeWithEvents(t *testing.T) {
	mock := &mockLLM{
		response: `[{"type":"add_deny","domain":"evil.com","reason":"suspicious traffic","severity":"high"}]`,
	}
	advisor := NewAdvisor(mock)

	events := []analytics.Event{
		{Timestamp: time.Now(), Domain: "api.example.com", Decision: "allow", Method: "GET"},
		{Timestamp: time.Now(), Domain: "evil.com", Decision: "deny", Method: "POST"},
		{Timestamp: time.Now(), Domain: "evil.com", Decision: "deny", Method: "GET"},
	}
	policy := config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "api.example.com"},
		},
	}

	recs, err := advisor.Analyze(events, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	if recs[0].Type != "add_deny" {
		t.Errorf("expected type add_deny, got %q", recs[0].Type)
	}
	if recs[0].Domain != "evil.com" {
		t.Errorf("expected domain evil.com, got %q", recs[0].Domain)
	}
	if recs[0].Severity != "high" {
		t.Errorf("expected severity high, got %q", recs[0].Severity)
	}
}

func TestAnalyzeEmptyEvents(t *testing.T) {
	mock := &mockLLM{response: `[]`}
	advisor := NewAdvisor(mock)

	recs, err := advisor.Analyze(nil, config.Policy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recs != nil {
		t.Fatalf("expected nil recommendations for empty events, got %v", recs)
	}
	if mock.calls() != 0 {
		t.Fatal("should not call LLM with empty events")
	}
}

func TestRecommendationStructFields(t *testing.T) {
	// Verify that Recommendation does NOT contain "policy" or "modify" fields.
	rt := reflect.TypeOf(Recommendation{})
	forbidden := []string{"policy", "modify", "Policy", "Modify"}
	for _, name := range forbidden {
		if _, found := rt.FieldByName(name); found {
			t.Errorf("Recommendation should not have field %q", name)
		}
	}

	// Verify the expected fields exist.
	expected := []string{"Type", "Domain", "Reason", "Severity"}
	for _, name := range expected {
		if _, found := rt.FieldByName(name); !found {
			t.Errorf("Recommendation missing expected field %q", name)
		}
	}
}
