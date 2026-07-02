package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config is the per-instance opaque settings handed to Integration.Start. The
// integration decodes Raw into its own typed struct via Decode.
type Config struct {
	Name string
	Raw  map[string]any
}

// Decode round-trips Raw through JSON into dst (which must be a pointer). This
// gives each integration a typed view of its config without this package
// knowing any integration's schema.
func (c Config) Decode(dst any) error {
	b, err := json.Marshal(c.Raw)
	if err != nil {
		return fmt.Errorf("integration: encode config %q: %w", c.Name, err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("integration: decode config %q: %w", c.Name, err)
	}
	return nil
}

// InstanceConfig is what the operator declares — one per configured integration.
type InstanceConfig struct {
	// Type selects a factory from the registry.
	Type string
	// Name identifies the instance (multiple instances of one Type are allowed).
	Name string
	// Config is the instance's own opaque settings, decoded by the integration.
	Config map[string]any
	// Match is the routing predicate (alerts.match). An EMPTY Match means
	// match-NONE — explicit opt-in, consistent with Warden's default-deny.
	Match []MatchClause
}

// MatchClause is one alerts.match entry. Within a clause its non-empty keys are
// AND-ed; the []MatchClause list is OR-ed (see matchAny). Matchable keys are
// {severity, category, domain, rule}.
type MatchClause struct {
	// Severity matches Alert.Severity.String() (case-insensitive).
	Severity string
	// Category matches Alert.Category (case-insensitive).
	Category string
	// Domain matches Subject.Domain (exact).
	Domain string
	// Rule matches the DedupKey's rule-id prefix (the part before the first
	// ':'), e.g. Rule "error_rate" matches DedupKey "error_rate:api.foo.com".
	Rule string
}

// matches reports whether a satisfies every non-empty key in this clause. An
// all-empty clause matches NOTHING (not everything) — a vacuous-true match
// would silently subscribe an instance to every alert, contrary to default-deny.
func (m MatchClause) matches(a Alert) bool {
	empty := true
	if m.Severity != "" {
		empty = false
		if !strings.EqualFold(m.Severity, a.Severity.String()) {
			return false
		}
	}
	if m.Category != "" {
		empty = false
		if !strings.EqualFold(m.Category, a.Category) {
			return false
		}
	}
	if m.Domain != "" {
		empty = false
		if m.Domain != a.Subject.Domain {
			return false
		}
	}
	if m.Rule != "" {
		empty = false
		if m.Rule != ruleIDFromDedupKey(a.DedupKey) {
			return false
		}
	}
	return !empty
}

// matchAny reports whether any clause matches a. It returns FALSE when clauses
// is empty (match-none), enforcing explicit opt-in routing.
func matchAny(clauses []MatchClause, a Alert) bool {
	for _, c := range clauses {
		if c.matches(a) {
			return true
		}
	}
	return false
}

// expandEnv resolves ${VAR} / $VAR references in a config secret field from the
// process environment. We deliberately follow the repo's existing ${ENV}
// mechanism (see internal/worker/wiring.go's expandEnv), NOT the plan sketch's
// {fromEnv:} object form, because "${ENV}" IS the established Warden convention.
// Expansion is best-effort: unset vars expand to empty (integrations validate
// required fields themselves) — we never hard-fail here.
func expandEnv(s string) string {
	return os.Expand(s, os.Getenv)
}
