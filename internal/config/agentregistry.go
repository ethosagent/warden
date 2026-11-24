package config

// MaxRegisteredAgents caps the agent registry (internal/agentreg): rows are
// never deleted, so the cap bounds the table, the policy wire's agent list
// and the cost of every list read. Create returns an error at the cap.
const MaxRegisteredAgents = 1000

// NormalizeGroups canonicalizes a group list exactly as the policy rule
// groups are (W-P1-GPOL-01): values are trimmed, empty ones rejected, the list
// is deduplicated and sorted, and group names stay exact and case-sensitive.
// The error names only a position and a limit, never a value. The agent
// registry uses it for allowed_groups so the registry and policy agree on
// what a group is.
func NormalizeGroups(in []string) ([]string, error) {
	return normalizePrincipalList("groups", in, false)
}
