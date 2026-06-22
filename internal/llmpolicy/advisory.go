package llmpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// Advisor reads audit logs and generates recommendations for humans.
type Advisor struct {
	client LLMClient
	now    func() time.Time
}

// NewAdvisor creates an Advisor. It NEVER modifies policy -- it only returns
// recommendations.
func NewAdvisor(client LLMClient) *Advisor {
	return &Advisor{client: client, now: time.Now}
}

// Recommendation is a suggested policy change.
type Recommendation struct {
	Type     string `json:"type"` // "add_allow", "add_deny", "investigate"
	Domain   string `json:"domain"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"` // "high", "medium", "low"
}

// Analyze reads events and produces recommendations.
func (a *Advisor) Analyze(events []analytics.Event, currentPolicy config.Policy) ([]Recommendation, error) {
	if len(events) == 0 {
		return nil, nil
	}

	summary := a.summarizeEvents(events, currentPolicy)

	prompt := fmt.Sprintf(
		"You are a security advisor reviewing network traffic for an agent proxy.\n\n"+
			"Traffic summary:\n%s\n\n"+
			"Current allowlist domains: %s\n\n"+
			"Based on this traffic, recommend policy changes. "+
			"Respond with JSON array: [{\"type\": \"add_allow\" or \"add_deny\" or \"investigate\", "+
			"\"domain\": \"...\", \"reason\": \"...\", \"severity\": \"high\" or \"medium\" or \"low\"}]",
		summary, formatAllowlist(currentPolicy),
	)

	resp, err := a.client.Evaluate(prompt)
	if err != nil {
		return nil, fmt.Errorf("llmpolicy: advisor LLM call: %w", err)
	}

	var recs []Recommendation
	if err := json.Unmarshal([]byte(strings.TrimSpace(resp)), &recs); err != nil {
		return nil, fmt.Errorf("llmpolicy: advisor parse response: %w", err)
	}

	return recs, nil
}

// summarizeEvents produces a human-readable summary of traffic patterns.
func (a *Advisor) summarizeEvents(events []analytics.Event, _ config.Policy) string {
	type domainStats struct {
		total   int
		denied  int
		allowed int
	}
	stats := make(map[string]*domainStats)
	for _, e := range events {
		s, ok := stats[e.Domain]
		if !ok {
			s = &domainStats{}
			stats[e.Domain] = s
		}
		s.total++
		if e.Decision == "deny" {
			s.denied++
		} else {
			s.allowed++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Total events: %d\n", len(events))
	for domain, s := range stats {
		fmt.Fprintf(&b, "- %s: %d total (%d allowed, %d denied)\n",
			domain, s.total, s.allowed, s.denied)
	}
	return b.String()
}

// formatAllowlist renders the current allowlist domains for the prompt.
func formatAllowlist(p config.Policy) string {
	domains := make([]string, len(p.Allowlist))
	for i, e := range p.Allowlist {
		domains[i] = e.Domain
	}
	if len(domains) == 0 {
		return "(none)"
	}
	return strings.Join(domains, ", ")
}
