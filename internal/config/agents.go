package config

import (
	"fmt"
	"strings"
)

// AgentPolicy is one agent's natural-language policy text.
type AgentPolicy struct {
	ID     string
	Policy string
	// Identity is this agent's identity mode override: "", off or attribute.
	Identity string
}

type rawAgent struct {
	ID       string `yaml:"id"`
	Policy   string `yaml:"policy"`
	Identity string `yaml:"identity"`
}

// validateAgents enforces that agent ids are present and unique. Agent policies
// may be configured even when the judge is disabled (they are simply unused).
func validateAgents(agents []AgentPolicy) error {
	seen := make(map[string]struct{}, len(agents))
	for i, a := range agents {
		if strings.TrimSpace(a.ID) == "" {
			return fmt.Errorf("config: agents[%d]: id is required", i)
		}
		if _, dup := seen[a.ID]; dup {
			return fmt.Errorf("config: agents: duplicate id %q", a.ID)
		}
		if err := validateIdentityMode(fmt.Sprintf("agents[%d].identity", i), a.Identity); err != nil {
			return err
		}
		seen[a.ID] = struct{}{}
	}
	return nil
}
