package config

import (
	"fmt"
	"sort"

	"github.com/ethosagent/warden/internal/agentid"
)

// MaxRegisteredAgents caps the agent registry (internal/agentreg): rows are
// never deleted, so the cap bounds the table, the policy wire's agent list
// and the cost of every list read. Create returns an error at the cap.
const MaxRegisteredAgents = 1000

// MaxPrincipals and MaxPrincipalBytes are the limits a group list obeys: at
// most MaxPrincipals values of at most MaxPrincipalBytes bytes each.
const (
	MaxPrincipals     = maxPrincipals
	MaxPrincipalBytes = maxPrincipalBytes
)

// NormalizeGroups canonicalizes a group list exactly as the policy rule
// groups are (W-P1-GPOL-01): values are trimmed, empty ones rejected, the list
// is deduplicated and sorted, and group names stay exact and case-sensitive.
// The error names only a position and a limit, never a value. The agent
// registry uses it for allowed_groups so the registry and policy agree on
// what a group is.
func NormalizeGroups(in []string) ([]string, error) {
	return normalizePrincipalList("groups", in, false)
}

// Limits on a RegisteredAgent's key thumbprints: an agent has at most two keys
// (two during a rotation) and an RFC 7638 SHA-256 thumbprint is 43 base64url
// characters.
const (
	maxRegisteredAgentJKT = 2
	registeredAgentJKTLen = 43
)

// Registered agent statuses on the policy wire (agentreg.Status values).
const (
	RegisteredAgentActive   = "active"
	RegisteredAgentDisabled = "disabled"
)

// RegisteredAgent is the worker's view of one registered agent: its id, its
// status and the thumbprints of its public keys. Owner, groups, scopes and key
// documents never leave the control plane. It rides the policy wire as
// registeredAgents; YAML cannot set it.
type RegisteredAgent struct {
	ID     string   `json:"id"`
	Status string   `json:"status"`
	JKT    []string `json:"jkt"`
}

// SortRegisteredAgents orders list by id, in place.
func SortRegisteredAgents(list []RegisteredAgent) {
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
}

// ValidateRegisteredAgents checks a list sorted by id: ids pass agentid.ValidID
// and are unique, status is active or disabled, each agent has 1 or 2
// thumbprints of 43 base64url characters, and no thumbprint is shared (within
// or across agents). The control plane runs it before serving and workers run
// it on every pull, so the control plane never serves a list a worker would
// reject. Errors name an index and a limit, never a value.
func ValidateRegisteredAgents(list []RegisteredAgent) error {
	if len(list) > MaxRegisteredAgents {
		return fmt.Errorf("config: registeredAgents: %d entries exceeds the limit of %d", len(list), MaxRegisteredAgents)
	}
	jkts := make(map[string]struct{}, len(list))
	for i, a := range list {
		if err := agentid.ValidID(a.ID); err != nil {
			return fmt.Errorf("config: registeredAgents[%d]: invalid id", i)
		}
		if i > 0 && list[i-1].ID >= a.ID {
			return fmt.Errorf("config: registeredAgents[%d]: ids must be unique and sorted", i)
		}
		if a.Status != RegisteredAgentActive && a.Status != RegisteredAgentDisabled {
			return fmt.Errorf("config: registeredAgents[%d]: status must be active or disabled", i)
		}
		if len(a.JKT) == 0 || len(a.JKT) > maxRegisteredAgentJKT {
			return fmt.Errorf("config: registeredAgents[%d]: jkt must hold 1 to %d thumbprints", i, maxRegisteredAgentJKT)
		}
		for j, t := range a.JKT {
			if !validThumbprint(t) {
				return fmt.Errorf("config: registeredAgents[%d].jkt[%d]: not a %d-character base64url thumbprint", i, j, registeredAgentJKTLen)
			}
			if _, dup := jkts[t]; dup {
				return fmt.Errorf("config: registeredAgents[%d].jkt[%d]: thumbprint is not unique", i, j)
			}
			jkts[t] = struct{}{}
		}
	}
	return nil
}

func validThumbprint(s string) bool {
	if len(s) != registeredAgentJKTLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
