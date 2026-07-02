package config

import (
	"fmt"
	"strings"
)

// IntegrationInstance is one configured outbound alert integration (webhook,
// Slack, …). It is a PLAIN config type: internal/config deliberately does NOT
// import internal/integration, so config stays free of that coupling — the cmd
// layer maps these to the integration package's InstanceConfig/MatchClause at
// wire-up. Config is opaque and passed through untouched; secrets inside it stay
// as ${ENV} strings and are expanded later by the integration at Start.
type IntegrationInstance struct {
	// Type selects a factory from the integration registry (e.g. "webhook").
	Type string
	// Name identifies the instance (multiple instances of one Type are allowed).
	Name string
	// Config is the instance's own opaque settings, decoded by the integration.
	Config map[string]any
	// Match is the routing predicate. AND across a clause's non-empty keys, OR
	// across the list. An EMPTY Match means match-NONE (explicit opt-in).
	Match []IntegrationMatch
}

// IntegrationMatch is one alerts.match clause. Matchable keys are
// {severity, category, domain, rule}; empty keys are ignored.
type IntegrationMatch struct {
	Severity string
	Category string
	Domain   string
	Rule     string
}

// rawIntegration mirrors one on-disk `integrations:` list item. KnownFields(true)
// is strict, so this MUST be registered or configs carrying the block fail to
// parse. `config` is an opaque map passed through untouched — secrets inside it
// stay as ${ENV} strings and are expanded later by the integration at Start.
type rawIntegration struct {
	Type   string                `yaml:"type"`
	Name   string                `yaml:"name"`
	Config map[string]any        `yaml:"config"`
	Match  []rawIntegrationMatch `yaml:"match"`
}

type rawIntegrationMatch struct {
	Severity string `yaml:"severity"`
	Category string `yaml:"category"`
	Domain   string `yaml:"domain"`
	Rule     string `yaml:"rule"`
}

// parseIntegrations converts the raw integrations list into typed config. The
// `config` map is passed through untouched (opaque, secrets stay as ${ENV}); no
// defaults are applied — structural validation happens in validateIntegrations.
func parseIntegrations(raw []rawIntegration) []IntegrationInstance {
	if len(raw) == 0 {
		return nil
	}
	out := make([]IntegrationInstance, 0, len(raw))
	for _, r := range raw {
		inst := IntegrationInstance{Type: r.Type, Name: r.Name, Config: r.Config}
		for _, m := range r.Match {
			// rawIntegrationMatch and IntegrationMatch are field-identical; a direct
			// conversion keeps the two in lockstep (staticcheck S1016).
			inst.Match = append(inst.Match, IntegrationMatch(m))
		}
		out = append(out, inst)
	}
	return out
}

// validateIntegrations checks each configured integration instance structurally:
// non-empty type + name, names unique, and a valid severity in every match
// clause that sets one. It deliberately does NOT require the type to be
// registered — registration lives in the binary (a blank import), not in config —
// so an unknown type is a wiring concern surfaced at manager Start, not here.
func validateIntegrations(insts []IntegrationInstance) error {
	seen := make(map[string]struct{}, len(insts))
	for i, inst := range insts {
		if strings.TrimSpace(inst.Type) == "" {
			return fmt.Errorf("config: integrations[%d]: type is required", i)
		}
		if strings.TrimSpace(inst.Name) == "" {
			return fmt.Errorf("config: integrations[%d]: name is required", i)
		}
		if _, dup := seen[inst.Name]; dup {
			return fmt.Errorf("config: integrations[%d]: duplicate name %q", i, inst.Name)
		}
		seen[inst.Name] = struct{}{}
		for j, m := range inst.Match {
			if strings.TrimSpace(m.Severity) == "" {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(m.Severity)) {
			case "info", "low", "medium", "high", "critical":
			default:
				return fmt.Errorf("config: integrations[%d].match[%d]: invalid severity %q; must be info, low, medium, high, or critical", i, j, m.Severity)
			}
		}
	}
	return nil
}
