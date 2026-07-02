// Package dlp implements the per-class per-destination egress rule evaluator for
// outbound request-body DLP. Evaluate is a PURE function of (classes, destination,
// rules): it never touches the proxy, so the precedence matrix is unit-testable in
// isolation. It is restriction-only — it decides an action among allow/block/
// redact/monitor for already-statically-allowed traffic and can never widen a
// static deny (static allow/deny runs upstream at CONNECT time).
package dlp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/scan"
)

// Verdict is the evaluator's decision for a request: the winning Action and a
// BOUNDED identifier of the rule that produced it (a rule index, a class-default
// key, or "default"). Rule is safe for events/logs — it is never content.
type Verdict struct {
	Action string
	Rule   string
}

// restrictiveRank orders actions from most to least restrictive:
// block > redact > monitor > allow. Deny-wins ties (equal specificity, and across
// the classes of one body) resolve by this rank.
func restrictiveRank(a string) int {
	switch a {
	case config.DLPActionBlock:
		return 3
	case config.DLPActionRedact:
		return 2
	case config.DLPActionMonitor:
		return 1
	default: // allow / unknown
		return 0
	}
}

// Evaluate resolves the action for a body carrying classes sent to destination
// under cfg. Precedence (deterministic, order-independent in the rules file):
//
//  1. Static allow/deny is upstream and untouchable — Evaluate only ever RESTRICTS
//     already-allowed traffic; the mode floor is "allow", never a widening.
//  2. Per class, the most-specific matching rule/default wins. Specificity is
//     (destination tier, then class tier): exact-dest rule > wildcard/regex-dest
//     rule > class-default (a no-`to` rule or a dlp.classes entry) > mode default;
//     within a destination tier, exact class > class glob > "*".
//  3. Deny-wins on ties (equal destination AND class tier) and ACROSS classes: the
//     body takes the most restrictive resolved action among all its classes.
//
// A body with no classes (or no cfg policy) resolves to allow/"default".
func Evaluate(classes []scan.DataClass, destination string, cfg config.DLPConfig) Verdict {
	result := Verdict{Action: config.DLPActionAllow, Rule: "default"}
	seeded := false
	for _, c := range classes {
		v := resolveClass(c, destination, cfg)
		// Deny-wins across classes: keep the most restrictive; on equal rank keep the
		// first (deterministic for a given class order).
		if !seeded || restrictiveRank(v.Action) > restrictiveRank(result.Action) {
			result = v
			seeded = true
		}
	}
	return result
}

// resolveClass finds the single most-specific rule/default for one class at one
// destination, breaking ties by deny-wins. See Evaluate for the precedence.
func resolveClass(class scan.DataClass, dest string, cfg config.DLPConfig) Verdict {
	// Seed with the mode default: allow, at the lowest tier (0,0). Any real match
	// (rule or class-default, all at tier >= 1) outranks it.
	best := Verdict{Action: config.DLPActionAllow, Rule: "default"}
	bestDest, bestClass := 0, 0

	consider := func(action, rule string, destTier, classTier int) {
		if destTier < bestDest {
			return
		}
		if destTier == bestDest {
			if classTier < bestClass {
				return
			}
			if classTier == bestClass && restrictiveRank(action) <= restrictiveRank(best.Action) {
				return
			}
		}
		best = Verdict{Action: action, Rule: rule}
		bestDest, bestClass = destTier, classTier
	}

	for i, r := range cfg.Rules {
		classTier, ok := classSpecificity(r.Class, class)
		if !ok {
			continue
		}
		if len(r.To) == 0 {
			// Class-default rule (no destination): applies everywhere, tier 1.
			consider(r.Action, fmt.Sprintf("rule[%d]", i), 1, classTier)
			continue
		}
		matched, exact := matchDestinations(r.To, dest)
		if !matched {
			continue
		}
		destTier := 2 // wildcard/regex destination
		if exact {
			destTier = 3 // exact destination — most specific
		}
		consider(r.Action, fmt.Sprintf("rule[%d]", i), destTier, classTier)
	}

	// dlp.classes defaults share the class-default tier (1). Iterate sorted so the
	// reported rule id is deterministic regardless of map order.
	for _, key := range sortedKeys(cfg.Classes) {
		classTier, ok := classSpecificity(key, class)
		if !ok {
			continue
		}
		consider(cfg.Classes[key].Action, "classes["+key+"]", 1, classTier)
	}

	return best
}

// classSpecificity reports whether spec matches class and, if so, its class-tier:
// exact class (2) > "<family>.*" glob (1) > "*" (0). A non-matching spec returns
// (0, false).
func classSpecificity(spec string, class scan.DataClass) (int, bool) {
	c := string(class)
	switch spec {
	case c:
		return 2, true
	case "*":
		return 0, true
	default:
		if prefix, ok := strings.CutSuffix(spec, ".*"); ok {
			if strings.HasPrefix(c, prefix+".") {
				return 1, true
			}
		}
		return 0, false
	}
}

// matchDestinations reports whether dest matches any pattern in to (via the shared
// policy matcher) and whether any MATCHING pattern was exact (no wildcard/regex) —
// so an exact-destination match outranks a wildcard one.
func matchDestinations(to []string, dest string) (matched, exact bool) {
	for _, pattern := range to {
		if !policy.MatchDomain(pattern, dest) {
			continue
		}
		matched = true
		if !strings.HasPrefix(pattern, "~") && !strings.Contains(pattern, "*") {
			exact = true
		}
	}
	return matched, exact
}

// sortedKeys returns the class-default map keys in sorted order for deterministic
// rule attribution.
func sortedKeys(m map[string]config.DLPClassDefault) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
