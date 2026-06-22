package policyeval

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// makeEvents is a test helper that builds a slice of events.
func makeEvents(t *testing.T, specs []struct {
	domain   string
	port     int
	protocol string
	method   string
	decision string
}) []analytics.Event {
	t.Helper()
	var events []analytics.Event
	for _, s := range specs {
		events = append(events, analytics.Event{
			Timestamp: time.Now(),
			Domain:    s.domain,
			Port:      s.port,
			Protocol:  s.protocol,
			Method:    s.method,
			Decision:  s.decision,
		})
	}
	return events
}

func TestEvaluate_SamePolicy(t *testing.T) {
	// Policy allows api.openai.com:443, denies everything else.
	pol := config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "api.openai.com"},
		},
	}

	events := makeEvents(t, []struct {
		domain   string
		port     int
		protocol string
		method   string
		decision string
	}{
		{"api.openai.com", 443, "https", "GET", "allow"},
		{"api.openai.com", 443, "https", "POST", "allow"},
		{"evil.example.com", 443, "https", "GET", "deny"},
	})

	result := Evaluate(events, pol)

	if result.TotalEvents != 3 {
		t.Errorf("TotalEvents = %d, want 3", result.TotalEvents)
	}
	if result.Agreed != 3 {
		t.Errorf("Agreed = %d, want 3", result.Agreed)
	}
	if len(result.NewAllows) != 0 {
		t.Errorf("NewAllows = %d entries, want 0", len(result.NewAllows))
	}
	if len(result.NewDenies) != 0 {
		t.Errorf("NewDenies = %d entries, want 0", len(result.NewDenies))
	}
}

func TestEvaluate_LoosenedPolicy(t *testing.T) {
	// Original policy denied evil.example.com, but candidate now allows it.
	pol := config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "api.openai.com"},
			{Domain: "evil.example.com"}, // newly allowed
		},
	}

	events := makeEvents(t, []struct {
		domain   string
		port     int
		protocol string
		method   string
		decision string
	}{
		{"api.openai.com", 443, "https", "GET", "allow"},
		{"evil.example.com", 443, "https", "POST", "deny"}, // was denied
		{"evil.example.com", 443, "https", "POST", "deny"}, // was denied
	})

	result := Evaluate(events, pol)

	if result.TotalEvents != 3 {
		t.Errorf("TotalEvents = %d, want 3", result.TotalEvents)
	}
	if result.Agreed != 1 {
		t.Errorf("Agreed = %d, want 1", result.Agreed)
	}
	if len(result.NewAllows) != 1 {
		t.Fatalf("NewAllows = %d entries, want 1", len(result.NewAllows))
	}
	if result.NewAllows[0].Domain != "evil.example.com" {
		t.Errorf("NewAllows[0].Domain = %q, want %q", result.NewAllows[0].Domain, "evil.example.com")
	}
	if result.NewAllows[0].Count != 2 {
		t.Errorf("NewAllows[0].Count = %d, want 2", result.NewAllows[0].Count)
	}
	if result.NewAllows[0].Decision != "deny" {
		t.Errorf("NewAllows[0].Decision = %q, want %q", result.NewAllows[0].Decision, "deny")
	}
	if len(result.NewDenies) != 0 {
		t.Errorf("NewDenies = %d entries, want 0", len(result.NewDenies))
	}
}

func TestEvaluate_TightenedPolicy(t *testing.T) {
	// Original policy allowed api.openai.com, but candidate removes it.
	pol := config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "api.anthropic.com"}, // only this remains
		},
	}

	events := makeEvents(t, []struct {
		domain   string
		port     int
		protocol string
		method   string
		decision string
	}{
		{"api.openai.com", 443, "https", "GET", "allow"},    // was allowed, now denied
		{"api.openai.com", 443, "https", "POST", "allow"},   // was allowed, now denied
		{"api.anthropic.com", 443, "https", "GET", "allow"}, // still allowed
		{"evil.example.com", 443, "https", "GET", "deny"},   // still denied
	})

	result := Evaluate(events, pol)

	if result.TotalEvents != 4 {
		t.Errorf("TotalEvents = %d, want 4", result.TotalEvents)
	}
	if result.Agreed != 2 {
		t.Errorf("Agreed = %d, want 2", result.Agreed)
	}
	if len(result.NewAllows) != 0 {
		t.Errorf("NewAllows = %d entries, want 0", len(result.NewAllows))
	}
	if len(result.NewDenies) == 0 {
		t.Fatal("NewDenies is empty, want at least 1 entry")
	}
	// Check that we have new denies for api.openai.com
	found := false
	for _, d := range result.NewDenies {
		if d.Domain == "api.openai.com" {
			found = true
			if d.Decision != "allow" {
				t.Errorf("NewDenies for api.openai.com: Decision = %q, want %q", d.Decision, "allow")
			}
		}
	}
	if !found {
		t.Error("expected NewDenies to contain api.openai.com")
	}
}

func TestEvaluate_EmptyEvents(t *testing.T) {
	pol := config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "api.openai.com"},
		},
	}

	result := Evaluate(nil, pol)

	if result.TotalEvents != 0 {
		t.Errorf("TotalEvents = %d, want 0", result.TotalEvents)
	}
	if result.Agreed != 0 {
		t.Errorf("Agreed = %d, want 0", result.Agreed)
	}
	if len(result.NewAllows) != 0 {
		t.Errorf("NewAllows = %d entries, want 0", len(result.NewAllows))
	}
	if len(result.NewDenies) != 0 {
		t.Errorf("NewDenies = %d entries, want 0", len(result.NewDenies))
	}
}

func TestEvaluate_PortInference(t *testing.T) {
	// Events with port 0 should have port inferred from protocol.
	// An allowlist entry with port 0 infers port based on request scheme,
	// so {Domain: "example.com"} matches :443 for HTTPS and :80 for HTTP.
	pol := config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "example.com"}, // port 0 -> inferred per scheme
		},
	}

	events := makeEvents(t, []struct {
		domain   string
		port     int
		protocol string
		method   string
		decision string
	}{
		{"example.com", 0, "https", "GET", "allow"}, // port inferred to 443, candidate allows -> agree
		{"example.com", 0, "http", "GET", "allow"},  // port inferred to 80, candidate allows -> agree
	})

	result := Evaluate(events, pol)

	if result.TotalEvents != 2 {
		t.Errorf("TotalEvents = %d, want 2", result.TotalEvents)
	}
	if result.Agreed != 2 {
		t.Errorf("Agreed = %d, want 2", result.Agreed)
	}
}

func TestEvaluate_MixedDiffs(t *testing.T) {
	// Candidate both loosens and tightens.
	pol := config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "new-api.example.com"}, // newly allowed
			// api.openai.com removed         // newly denied
		},
	}

	events := makeEvents(t, []struct {
		domain   string
		port     int
		protocol string
		method   string
		decision string
	}{
		{"api.openai.com", 443, "https", "GET", "allow"},      // now denied
		{"new-api.example.com", 443, "https", "POST", "deny"}, // now allowed
		{"unknown.example.com", 443, "https", "GET", "deny"},  // still denied
	})

	result := Evaluate(events, pol)

	if result.TotalEvents != 3 {
		t.Errorf("TotalEvents = %d, want 3", result.TotalEvents)
	}
	if result.Agreed != 1 {
		t.Errorf("Agreed = %d, want 1", result.Agreed)
	}
	if len(result.NewAllows) != 1 {
		t.Fatalf("NewAllows = %d entries, want 1", len(result.NewAllows))
	}
	if result.NewAllows[0].Domain != "new-api.example.com" {
		t.Errorf("NewAllows[0].Domain = %q, want %q", result.NewAllows[0].Domain, "new-api.example.com")
	}
	if len(result.NewDenies) != 1 {
		t.Fatalf("NewDenies = %d entries, want 1", len(result.NewDenies))
	}
	if result.NewDenies[0].Domain != "api.openai.com" {
		t.Errorf("NewDenies[0].Domain = %q, want %q", result.NewDenies[0].Domain, "api.openai.com")
	}
}
