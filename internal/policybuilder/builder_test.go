package policybuilder

import (
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"gopkg.in/yaml.v3"
)

// makeEvents generates n events for the given domain/port with the given HTTP status.
func makeEvents(t *testing.T, domain string, port int, method string, status int, n int) []analytics.Event {
	t.Helper()
	events := make([]analytics.Event, n)
	for i := range events {
		events[i] = analytics.Event{
			Domain:         domain,
			Port:           port,
			Method:         method,
			ResponseStatus: status,
		}
	}
	return events
}

func TestBuild_ThreeDomainsSortedByCount(t *testing.T) {
	var events []analytics.Event
	events = append(events, makeEvents(t, "api.example.com", 443, "GET", 200, 30)...)
	events = append(events, makeEvents(t, "cdn.example.com", 443, "GET", 200, 10)...)
	events = append(events, makeEvents(t, "auth.example.com", 443, "POST", 200, 20)...)

	suggestions := Build(events, 1)

	if len(suggestions) != 3 {
		t.Fatalf("expected 3 suggestions, got %d", len(suggestions))
	}
	if suggestions[0].Domain != "api.example.com" {
		t.Errorf("expected first suggestion to be api.example.com, got %s", suggestions[0].Domain)
	}
	if suggestions[0].Count != 30 {
		t.Errorf("expected first count 30, got %d", suggestions[0].Count)
	}
	if suggestions[1].Domain != "auth.example.com" {
		t.Errorf("expected second suggestion to be auth.example.com, got %s", suggestions[1].Domain)
	}
	if suggestions[1].Count != 20 {
		t.Errorf("expected second count 20, got %d", suggestions[1].Count)
	}
	if suggestions[2].Domain != "cdn.example.com" {
		t.Errorf("expected third suggestion to be cdn.example.com, got %s", suggestions[2].Domain)
	}
	if suggestions[2].Count != 10 {
		t.Errorf("expected third count 10, got %d", suggestions[2].Count)
	}
}

func TestBuild_BelowMinCountFiltered(t *testing.T) {
	var events []analytics.Event
	events = append(events, makeEvents(t, "api.example.com", 443, "GET", 200, 10)...)
	events = append(events, makeEvents(t, "rare.example.com", 443, "GET", 200, 2)...)

	suggestions := Build(events, 5)

	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion (rare filtered), got %d", len(suggestions))
	}
	if suggestions[0].Domain != "api.example.com" {
		t.Errorf("expected api.example.com, got %s", suggestions[0].Domain)
	}
}

func TestBuild_SuccessRateComputed(t *testing.T) {
	var events []analytics.Event
	// 7 successes + 3 failures = 70% success rate
	events = append(events, makeEvents(t, "api.example.com", 443, "GET", 200, 7)...)
	events = append(events, makeEvents(t, "api.example.com", 443, "GET", 500, 3)...)

	suggestions := Build(events, 1)

	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	if suggestions[0].SuccessRate != 70 {
		t.Errorf("expected 70%% success rate, got %.1f%%", suggestions[0].SuccessRate)
	}
}

func TestBuild_ConfidenceLevels(t *testing.T) {
	tests := []struct {
		name      string
		count     int
		successes int
		failures  int
		wantConf  string
	}{
		{
			name:      "high: >20 count, >90% success",
			successes: 25,
			failures:  1,
			wantConf:  "high",
		},
		{
			name:      "medium: >5 count, >70% success",
			successes: 8,
			failures:  2,
			wantConf:  "medium",
		},
		{
			name:      "low: <=5 count",
			successes: 3,
			failures:  0,
			wantConf:  "low",
		},
		{
			name:      "low: >20 count but <=90% success",
			successes: 15,
			failures:  10,
			wantConf:  "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var events []analytics.Event
			events = append(events, makeEvents(t, "test.example.com", 443, "GET", 200, tt.successes)...)
			events = append(events, makeEvents(t, "test.example.com", 443, "GET", 500, tt.failures)...)

			suggestions := Build(events, 1)
			if len(suggestions) != 1 {
				t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
			}
			if suggestions[0].Confidence != tt.wantConf {
				t.Errorf("expected confidence %q, got %q (count=%d, successRate=%.1f%%)",
					tt.wantConf, suggestions[0].Confidence, suggestions[0].Count, suggestions[0].SuccessRate)
			}
		})
	}
}

func TestBuild_DefaultPort(t *testing.T) {
	events := []analytics.Event{
		{Domain: "api.example.com", Port: 0, Method: "GET", ResponseStatus: 200},
		{Domain: "api.example.com", Port: 0, Method: "GET", ResponseStatus: 200},
	}

	suggestions := Build(events, 1)

	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	if suggestions[0].Port != 443 {
		t.Errorf("expected default port 443, got %d", suggestions[0].Port)
	}
}

func TestBuild_TopMethod(t *testing.T) {
	var events []analytics.Event
	events = append(events, makeEvents(t, "api.example.com", 443, "GET", 200, 5)...)
	events = append(events, makeEvents(t, "api.example.com", 443, "POST", 200, 3)...)

	suggestions := Build(events, 1)

	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	if suggestions[0].Method != "GET" {
		t.Errorf("expected top method GET, got %s", suggestions[0].Method)
	}
}

func TestFormatYAML_Empty(t *testing.T) {
	output := FormatYAML(nil)
	if !strings.Contains(output, "No suggestions") {
		t.Errorf("expected 'No suggestions' message, got: %s", output)
	}
}

func TestFormatYAML_ValidYAML(t *testing.T) {
	suggestions := []Suggestion{
		{Domain: "api.example.com", Port: 443, Count: 30, SuccessRate: 95, Confidence: "high"},
		{Domain: "cdn.example.com", Port: 8080, Count: 10, SuccessRate: 80, Confidence: "medium"},
	}

	output := FormatYAML(suggestions)

	// Parse the YAML to verify it's valid.
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("FormatYAML produced invalid YAML: %v\nOutput:\n%s", err, output)
	}

	// Check structure: policy.allowlist exists and has 2 entries.
	policy, ok := parsed["policy"]
	if !ok {
		t.Fatal("expected 'policy' key in YAML output")
	}
	policyMap, ok := policy.(map[string]any)
	if !ok {
		t.Fatalf("expected policy to be a map, got %T", policy)
	}
	allowlist, ok := policyMap["allowlist"]
	if !ok {
		t.Fatal("expected 'allowlist' key under policy")
	}
	entries, ok := allowlist.([]any)
	if !ok {
		t.Fatalf("expected allowlist to be a list, got %T", allowlist)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 allowlist entries, got %d", len(entries))
	}
}

func TestFormatYAML_NonStandardPort(t *testing.T) {
	suggestions := []Suggestion{
		{Domain: "api.example.com", Port: 8443, Count: 10, SuccessRate: 90, Confidence: "medium"},
	}

	output := FormatYAML(suggestions)

	if !strings.Contains(output, "port: 8443") {
		t.Errorf("expected 'port: 8443' in output for non-standard port, got:\n%s", output)
	}
}
