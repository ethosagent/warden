package controlplane

import "github.com/ethosagent/warden/internal/config"

// projectScoped returns w in its served, fail-closed shape (W-P1-GPOL-06). A
// worker that predates group policy decodes the body leniently and would drop
// "groups"/"users", reading a scoped rule as a global one. So:
//
//   - allow entries with groups/users leave Allowlist for ScopedAllowlist (with
//     their original indexes in ScopedAllowPos), which an old worker ignores:
//     the host then matches nothing and is denied;
//   - an MCP tool whose allowWhen has groups/users is served with the
//     ReservedScopedAgentID sentinel in AllowWhen, which no agent satisfies, and
//     the real condition in AllowWhenScoped.
//
// A new worker merges both back (config.parseRemotePolicy). w is not modified;
// projecting an already projected wire changes nothing; a policy without scoped rules is returned unchanged, so its body and ETag stay
// byte-identical.
func projectScoped(w policyWire) policyWire {
	if plain, scoped, pos := splitScopedAllow(w.Allowlist); len(scoped) > 0 {
		w.Allowlist, w.ScopedAllowlist, w.ScopedAllowPos = plain, scoped, pos
	}
	w.Settings = projectScopedMCP(w.Settings)
	return w
}

func isScopedEntry(e config.AllowlistEntry) bool { return len(e.Groups) > 0 || len(e.Users) > 0 }

func splitScopedAllow(in []config.AllowlistEntry) (plain, scoped []config.AllowlistEntry, pos []int) {
	hasScoped := false
	for _, e := range in {
		if isScopedEntry(e) {
			hasScoped = true
			break
		}
	}
	if !hasScoped {
		return in, nil, nil
	}
	plain = make([]config.AllowlistEntry, 0, len(in))
	for i, e := range in {
		if isScopedEntry(e) {
			scoped = append(scoped, e)
			pos = append(pos, i)
			continue
		}
		plain = append(plain, e)
	}
	return plain, scoped, pos
}

// projectScopedMCP returns s with every scoped tool condition projected. s is
// copied before any change, so a shared settings value is never mutated.
func projectScopedMCP(s *config.SettingsWire) *config.SettingsWire {
	if s == nil || s.MCP == nil || s.MCP.Tools == nil {
		return s
	}
	scoped := false
	for _, tc := range s.MCP.Tools.Constraints {
		if tc.AllowWhen != nil && (len(tc.AllowWhen.Groups) > 0 || len(tc.AllowWhen.Users) > 0) {
			scoped = true
			break
		}
	}
	if !scoped {
		return s
	}
	out := s.DeepCopy()
	cons := out.MCP.Tools.Constraints
	for tool, tc := range cons {
		if tc.AllowWhen == nil || (len(tc.AllowWhen.Groups) == 0 && len(tc.AllowWhen.Users) == 0) {
			continue
		}
		tc.AllowWhenScoped = tc.AllowWhen
		tc.AllowWhen = &config.MCPToolCondition{AgentID: config.ReservedScopedAgentID}
		cons[tool] = tc
	}
	return out
}
