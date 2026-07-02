// Package policyeval replays recorded analytics events against a candidate policy
// and diffs the outcomes, surfacing security regressions (was denied, now allowed)
// and availability regressions (was allowed, now denied) before the policy ships.
package policyeval

import (
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

// EvalResult summarizes the diff between recorded decisions and a candidate policy.
type EvalResult struct {
	TotalEvents int
	Agreed      int
	NewAllows   []EvalDiff // was denied, now allowed (security regression)
	NewDenies   []EvalDiff // was allowed, now denied (availability regression)
}

// EvalDiff represents a group of events where the candidate policy disagrees.
type EvalDiff struct {
	Domain   string
	Port     int
	Method   string
	Count    int
	Decision string // original decision
}

// Evaluate replays events against a candidate policy and diffs outcomes.
func Evaluate(events []analytics.Event, candidate config.Policy) *EvalResult {
	// Strip rate limits and time windows for stateless replay
	replayPolicy := candidate.DeepCopy()
	for i := range replayPolicy.Allowlist {
		replayPolicy.Allowlist[i].RateLimit = ""
		replayPolicy.Allowlist[i].TimeWindow = ""
	}
	eval := policy.NewEvaluator(replayPolicy)
	result := &EvalResult{TotalEvents: len(events)}

	// Track diffs grouped by (domain, port, method, type).
	type diffKey struct {
		domain   string
		port     int
		method   string
		diffType string // "new_allow" or "new_deny"
	}
	diffs := make(map[diffKey]int)

	for _, e := range events {
		// Determine scheme from protocol or port.
		scheme := policy.SchemeHTTPS
		if e.Protocol == "http" {
			scheme = policy.SchemeHTTP
		}

		port := e.Port
		if port == 0 {
			if scheme == policy.SchemeHTTP {
				port = 80
			} else {
				port = 443
			}
		}

		candidateDecision := eval.Evaluate(e.Domain, port, scheme)
		// Replay scores the STATIC policy outcome only (no judge in offline
		// replay): a NoMatch would be default-denied, so collapse it to "deny"
		// to compare against the historically recorded allow/deny decision.
		candidateStr := candidateDecision.String()
		if candidateDecision == policy.NoMatch {
			candidateStr = "deny"
		}

		if candidateStr == e.Decision {
			result.Agreed++
			continue
		}

		if e.Decision == "deny" && candidateStr == "allow" {
			key := diffKey{domain: e.Domain, port: port, method: e.Method, diffType: "new_allow"}
			diffs[key]++
		} else if e.Decision == "allow" && candidateStr == "deny" {
			key := diffKey{domain: e.Domain, port: port, method: e.Method, diffType: "new_deny"}
			diffs[key]++
		}
	}

	// Convert grouped diffs to slices.
	for key, count := range diffs {
		d := EvalDiff{
			Domain:   key.domain,
			Port:     key.port,
			Method:   key.method,
			Count:    count,
			Decision: map[string]string{"new_allow": "deny", "new_deny": "allow"}[key.diffType],
		}
		if key.diffType == "new_allow" {
			result.NewAllows = append(result.NewAllows, d)
		} else {
			result.NewDenies = append(result.NewDenies, d)
		}
	}

	return result
}
