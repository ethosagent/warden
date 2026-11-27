package oauthbroker

import (
	"sort"
	"strings"
)

// ParseScopes splits a scope string on spaces and commas (providers differ:
// Google returns space separated, GitHub comma separated), dropping empty
// items. The result is sorted and de-duplicated; scope strings are compared
// exactly (they are case-sensitive).
func ParseScopes(s string) []string {
	return normalizeScopes(strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n' || r == '\r'
	}))
}

// CapScopes splits requested into the scopes inside the cap (allowed) and the
// ones outside it. Both results are sorted and de-duplicated. Callers must
// treat a non-empty rejected as an error and never widen the request: the cap
// is the operator's ceiling for every caller (portal, agent JIT request).
func CapScopes(requested, allowed []string) (capped, rejected []string) {
	in := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		in[a] = struct{}{}
	}
	for _, r := range normalizeScopes(requested) {
		if _, ok := in[r]; ok {
			capped = append(capped, r)
		} else {
			rejected = append(rejected, r)
		}
	}
	return capped, rejected
}

// JoinScopes renders scopes as the space separated wire form, sorted.
func JoinScopes(scopes []string) string {
	return strings.Join(normalizeScopes(scopes), " ")
}

// UnionScopes returns the sorted union of a and b.
func UnionScopes(a, b []string) []string {
	return normalizeScopes(append(append([]string(nil), a...), b...))
}

func normalizeScopes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}
