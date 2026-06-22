package audit

import "strings"

// Framework identifies a compliance framework.
type Framework string

const (
	FrameworkOWASP Framework = "owasp"
	FrameworkMITRE Framework = "mitre"
)

// Mapping ties a proxy event category to compliance framework controls.
type Mapping struct {
	Framework Framework
	ControlID string // e.g. "T1048" (MITRE), "A01:2021" (OWASP)
	Title     string
	Category  string // event category this maps to
}

// Mapper tags events with compliance mappings.
type Mapper struct {
	mappings []Mapping
}

// NewMapper creates a Mapper pre-loaded with built-in compliance mappings.
func NewMapper() *Mapper {
	return &Mapper{
		mappings: builtinMappings(),
	}
}

// builtinMappings returns the default set of compliance mappings.
func builtinMappings() []Mapping {
	return []Mapping{
		// MITRE ATT&CK
		{Framework: FrameworkMITRE, ControlID: "T1048", Title: "Exfiltration Over Alternative Protocol", Category: "exfiltration"},
		{Framework: FrameworkMITRE, ControlID: "T1071", Title: "Application Layer Protocol", Category: "protocol"},
		{Framework: FrameworkMITRE, ControlID: "T1552", Title: "Unsecured Credentials", Category: "credential-leakage"},
		{Framework: FrameworkMITRE, ControlID: "T1059", Title: "Command and Scripting Interpreter", Category: "prompt-injection"},
		// OWASP Top 10 for LLM (2025)
		{Framework: FrameworkOWASP, ControlID: "LLM01", Title: "Prompt Injection", Category: "prompt-injection"},
		{Framework: FrameworkOWASP, ControlID: "LLM02", Title: "Insecure Output Handling", Category: "credential-leakage"},
		{Framework: FrameworkOWASP, ControlID: "LLM06", Title: "Excessive Agency", Category: "excessive-agency"},
		{Framework: FrameworkOWASP, ControlID: "LLM07", Title: "System Prompt Leakage", Category: "system-prompt-override"},
	}
}

// MapEvent returns the compliance mappings applicable to the given event
// parameters. It checks the decision, protocol, and any detection labels.
func (m *Mapper) MapEvent(decision, protocol string, detections []string) []Mapping {
	var result []Mapping
	seen := make(map[string]bool) // ControlID dedup

	add := func(mapping Mapping) {
		if !seen[mapping.ControlID] {
			seen[mapping.ControlID] = true
			result = append(result, mapping)
		}
	}

	// Decision-based: denied requests map to exfiltration attempt
	if decision == "deny" {
		for _, mapping := range m.mappings {
			if mapping.Category == "exfiltration" {
				add(mapping)
			}
		}
	}

	// Detection-based mappings
	for _, det := range detections {
		detLower := strings.ToLower(det)
		for _, mapping := range m.mappings {
			switch mapping.Category {
			case "prompt-injection":
				if strings.Contains(detLower, "injection") || strings.Contains(detLower, "prompt") {
					add(mapping)
				}
			case "credential-leakage":
				if strings.Contains(detLower, "credential") || strings.Contains(detLower, "secret") || strings.Contains(detLower, "leak") {
					add(mapping)
				}
			case "excessive-agency":
				if strings.Contains(detLower, "tool") || strings.Contains(detLower, "mcp") || strings.Contains(detLower, "agency") {
					add(mapping)
				}
			case "system-prompt-override":
				if strings.Contains(detLower, "system") && strings.Contains(detLower, "prompt") {
					add(mapping)
				}
			}
		}
	}

	// Protocol-based: all proxied traffic maps to Application Layer Protocol
	if protocol != "" {
		for _, mapping := range m.mappings {
			if mapping.Category == "protocol" {
				add(mapping)
			}
		}
	}

	return result
}
