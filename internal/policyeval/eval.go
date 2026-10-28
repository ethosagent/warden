// Package policyeval replays recorded analytics events against a candidate policy
// and diffs the outcomes, surfacing security regressions (was denied, now allowed)
// and availability regressions (was allowed, now denied) before the policy ships.
package policyeval

import (
	"net/url"
	"sort"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
)

// EvalResult summarizes the diff between recorded decisions and a candidate policy.
type EvalResult struct {
	TotalEvents int
	Agreed      int
	NewAllows   []EvalDiff // was denied, now allowed (security regression)
	NewDenies   []EvalDiff // was allowed, now denied (availability regression)
	// AnonymousCount totals the disagreeing events replayed without a valid
	// recorded identity, across NewAllows and NewDenies.
	AnonymousCount int
}

// MaxAffectedUsers caps EvalDiff.AffectedUsers; AffectedUsersTotal keeps the
// true count.
const MaxAffectedUsers = 20

// EvalDiff represents a group of events where the candidate policy disagrees.
type EvalDiff struct {
	Domain   string
	Port     int
	Method   string
	Count    int
	Decision string // original decision
	// AffectedUsers are the distinct users behind the disagreeing events (the
	// email, else the sub), sorted and capped at MaxAffectedUsers. Only sub or
	// email: never a token or a group list.
	AffectedUsers      []string
	AffectedUsersTotal int
	// AnonymousCount is the disagreeing events with no valid recorded identity
	// (replayed as anonymous), so pre-identity traffic is not read as user impact.
	AnonymousCount int
}

// replaySubject builds the policy subject from the identity recorded on e, only
// when that identity was valid. Recorded groups are a point-in-time snapshot.
func replaySubject(e analytics.Event) *identity.Subject {
	if e.IdentityStatus != string(identity.StatusValid) {
		return nil
	}
	return &identity.Subject{
		Sub:             e.UserSub,
		Email:           e.UserEmail,
		EmailVerified:   e.UserEmail != "",
		Groups:          e.UserGroups,
		GroupsTruncated: e.UserGroupsTruncated,
	}
}

// diffAcc accumulates one (domain, port, method, type) group.
type diffAcc struct {
	count     int
	users     map[string]struct{}
	anonymous int
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
	diffs := make(map[diffKey]*diffAcc)

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

		// Replay the per-request form (#371) when the event recorded a method and
		// a parseable URL, so candidate method/path constraints are exercised.
		// The event URL is the full "https://host/path?query" form the proxy
		// records; EscapedPath() recovers the raw path component exactly as it
		// was matched live. Without either piece the replay is destination-only
		// (constraints could-match), matching the granularity that was recorded.
		method := e.Method
		path := ""
		if u, err := url.Parse(e.URL); err == nil {
			path = u.EscapedPath()
		}
		if method == "" || path == "" {
			method, path = "", ""
		}
		subject := replaySubject(e)
		candidateDecision := eval.EvaluateFor(policy.RequestContext{
			Domain: e.Domain, Port: port, Scheme: scheme, Method: method, Path: path, Subject: subject,
		}).Decision
		// Replay scores the STATIC policy outcome only (no judge in offline
		// replay): a NoMatch would be default-denied, and a Conditional (a
		// scoped entry without a valid identity) is a deny too, so collapse
		// both to "deny" to compare against the recorded allow/deny decision.
		candidateStr := candidateDecision.String()
		if candidateDecision == policy.NoMatch || candidateDecision == policy.Conditional {
			candidateStr = "deny"
		}

		if candidateStr == e.Decision {
			result.Agreed++
			continue
		}

		var key diffKey
		switch {
		case e.Decision == "deny" && candidateStr == "allow":
			key = diffKey{domain: e.Domain, port: port, method: e.Method, diffType: "new_allow"}
		case e.Decision == "allow" && candidateStr == "deny":
			key = diffKey{domain: e.Domain, port: port, method: e.Method, diffType: "new_deny"}
		default:
			continue
		}
		acc := diffs[key]
		if acc == nil {
			acc = &diffAcc{users: map[string]struct{}{}}
			diffs[key] = acc
		}
		acc.count++
		if subject == nil {
			acc.anonymous++
			result.AnonymousCount++
		} else if u := userLabel(e); u != "" {
			acc.users[u] = struct{}{}
		}
	}

	// Convert grouped diffs to slices.
	for key, acc := range diffs {
		users := make([]string, 0, len(acc.users))
		for u := range acc.users {
			users = append(users, u)
		}
		sort.Strings(users)
		total := len(users)
		if len(users) > MaxAffectedUsers {
			users = users[:MaxAffectedUsers]
		}
		d := EvalDiff{
			Domain: key.domain,
			Port:   key.port,
			Method: key.method,
			Count:  acc.count,

			AffectedUsers:      users,
			AffectedUsersTotal: total,
			AnonymousCount:     acc.anonymous,
			Decision:           map[string]string{"new_allow": "deny", "new_deny": "allow"}[key.diffType],
		}
		if key.diffType == "new_allow" {
			result.NewAllows = append(result.NewAllows, d)
		} else {
			result.NewDenies = append(result.NewDenies, d)
		}
	}

	return result
}

// userLabel names the user behind e for the report: the email, else the sub.
func userLabel(e analytics.Event) string {
	if e.UserEmail != "" {
		return e.UserEmail
	}
	return e.UserSub
}
