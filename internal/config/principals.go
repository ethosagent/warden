package config

import (
	"fmt"
	"sort"
	"strings"
)

const (
	// maxPrincipals caps each of a rule's groups and users lists.
	maxPrincipals = 256
	// maxPrincipalBytes caps one group or user value.
	maxPrincipalBytes = 256
	// ReservedScopedAgentID is the wire sentinel W-P1-GPOL-06 uses for an
	// identity-scoped MCP condition; it is never a valid agent id in config.
	ReservedScopedAgentID = "!identity-scoped"
)

// normalizePrincipals validates and canonicalizes a rule's groups and users.
// Each value is trimmed, empty values are rejected, and each list is
// deduplicated and sorted. A user containing "@" is an email and is
// lowercased; any other user is an exact IdP sub. Groups are exact,
// case-sensitive literals. path names the rule (for example
// "policy.allowlist[2]"); errors name the offending field path, such as
// "policy.allowlist[2].groups[1]".
func normalizePrincipals(path string, groups, users []string) ([]string, []string, error) {
	g, err := normalizePrincipalList(path+".groups", groups, false)
	if err != nil {
		return nil, nil, err
	}
	u, err := normalizePrincipalList(path+".users", users, true)
	if err != nil {
		return nil, nil, err
	}
	return g, u, nil
}

func normalizePrincipalList(path string, in []string, users bool) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxPrincipals {
		return nil, fmt.Errorf("config: %s: %d values exceeds the limit of %d", path, len(in), maxPrincipals)
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for i, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, fmt.Errorf("config: %s[%d]: value must not be empty", path, i)
		}
		if len(v) > maxPrincipalBytes {
			return nil, fmt.Errorf("config: %s[%d]: value is %d bytes, over the limit of %d", path, i, len(v), maxPrincipalBytes)
		}
		if users && strings.Contains(v, "@") {
			v = strings.ToLower(v)
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

// rejectUnenforcedPrincipals is the fail-closed guard: until the evaluator
// (allow entries) and the MCP gateway (allowWhen) enforce groups/users, a rule
// that sets them is refused at load rather than parsed and treated as global.
func rejectUnenforcedPrincipals(path string, groups, users []string) error {
	if len(groups) > 0 {
		return fmt.Errorf("config: %s.groups: not yet enforced; remove it (a scoped rule must never load as a global one)", path)
	}
	if len(users) > 0 {
		return fmt.Errorf("config: %s.users: not yet enforced; remove it (a scoped rule must never load as a global one)", path)
	}
	return nil
}
