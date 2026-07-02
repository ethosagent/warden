// Package policybuilder turns observed analytics events into suggested default-deny
// allowlist entries, so an operator can bootstrap or tighten policy from real
// traffic. It is advisory only — it emits YAML suggestions and never mutates policy.
package policybuilder

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ethosagent/warden/internal/analytics"
)

// Suggestion is a single suggested allowlist entry from observed traffic.
type Suggestion struct {
	Domain      string
	Port        int
	Method      string // most common method, or empty
	Count       int
	SuccessRate float64 // percentage of 2xx responses
	Confidence  string  // "high", "medium", "low"
}

// Build analyzes events and generates policy suggestions.
func Build(events []analytics.Event, minCount int) []Suggestion {
	type domainPortKey struct {
		domain string
		port   int
	}

	type stats struct {
		count     int
		successes int
		methods   map[string]int
	}

	grouped := make(map[domainPortKey]*stats)

	for _, e := range events {
		port := e.Port
		if port == 0 {
			port = 443 // default
		}
		key := domainPortKey{domain: e.Domain, port: port}
		s, ok := grouped[key]
		if !ok {
			s = &stats{methods: make(map[string]int)}
			grouped[key] = s
		}
		s.count++
		if e.ResponseStatus >= 200 && e.ResponseStatus <= 299 {
			s.successes++
		}
		if e.Method != "" {
			s.methods[e.Method]++
		}
	}

	var suggestions []Suggestion
	for key, s := range grouped {
		if s.count < minCount {
			continue
		}

		successRate := 0.0
		if s.count > 0 {
			successRate = float64(s.successes) / float64(s.count) * 100
		}

		// Determine most common method.
		var topMethod string
		var topMethodCount int
		for m, c := range s.methods {
			if c > topMethodCount {
				topMethod = m
				topMethodCount = c
			}
		}

		// Assign confidence.
		confidence := "low"
		if s.count > 20 && successRate > 90 {
			confidence = "high"
		} else if s.count > 5 && successRate > 70 {
			confidence = "medium"
		}

		suggestions = append(suggestions, Suggestion{
			Domain:      key.domain,
			Port:        key.port,
			Method:      topMethod,
			Count:       s.count,
			SuccessRate: successRate,
			Confidence:  confidence,
		})
	}

	// Sort by count descending.
	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Count > suggestions[j].Count
	})

	return suggestions
}

// FormatYAML outputs valid config YAML from suggestions.
func FormatYAML(suggestions []Suggestion) string {
	if len(suggestions) == 0 {
		return "# No suggestions — insufficient traffic data.\n"
	}

	var b strings.Builder
	b.WriteString("# Policy suggestions from observed traffic\n")
	b.WriteString("# Review and merge into your config.yaml\n")
	b.WriteString("policy:\n")
	b.WriteString("  allowlist:\n")
	for _, s := range suggestions {
		portSuffix := ""
		if s.Port != 0 && s.Port != 443 {
			portSuffix = fmt.Sprintf("\n      port: %d", s.Port)
		}
		fmt.Fprintf(&b, "    - domain: \"%s\"%s       # %d requests, %.0f%% success [%s]\n",
			s.Domain, portSuffix, s.Count, s.SuccessRate, s.Confidence)
	}

	return b.String()
}
