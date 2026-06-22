// Package policy implements the default-deny allowlist evaluator. A
// destination is permitted only if it matches an allowlist entry; everything
// else is denied. This default-deny posture is a core security invariant and
// must never be weakened.
package policy

import (
	"strings"

	"github.com/ethosagent/warden/internal/config"
)

// Scheme identifies the request scheme, used to infer the default port when an
// allowlist entry omits one.
type Scheme int

const (
	// SchemeHTTPS infers port 443 when a port is omitted.
	SchemeHTTPS Scheme = iota
	// SchemeHTTP infers port 80 when a port is omitted.
	SchemeHTTP
)

// Default ports inferred per scheme.
const (
	defaultHTTPSPort = 443
	defaultHTTPPort  = 80
)

// inferredPort returns the effective port for an allowlist entry: its explicit
// port, or the scheme default when omitted (zero).
func inferredPort(entryPort int, scheme Scheme) int {
	if entryPort != 0 {
		return entryPort
	}
	if scheme == SchemeHTTP {
		return defaultHTTPPort
	}
	return defaultHTTPSPort
}

// Decision is the outcome of evaluating a destination.
type Decision int

const (
	// Deny is the default outcome for any destination not on the allowlist.
	Deny Decision = iota
	// Allow means the destination matched an allowlist entry.
	Allow
)

// String renders a decision for logging.
func (d Decision) String() string {
	if d == Allow {
		return "allow"
	}
	return "deny"
}

// Evaluator decides whether a destination is allowed under a policy. It is
// constructed once from a Policy and is safe for concurrent reads.
type Evaluator struct {
	allowlist []config.AllowlistEntry
}

// NewEvaluator builds an Evaluator from a policy's allowlist.
func NewEvaluator(p config.Policy) *Evaluator {
	return &Evaluator{allowlist: append([]config.AllowlistEntry(nil), p.Allowlist...)}
}

// Evaluate returns Allow only if (domain, port) matches an allowlist entry
// under the given scheme; otherwise Deny (default-deny). Domain matching is
// case-insensitive and supports a leading "*." wildcard on entries.
func (e *Evaluator) Evaluate(domain string, port int, scheme Scheme) Decision {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, entry := range e.allowlist {
		if inferredPort(entry.Port, scheme) != port {
			continue
		}
		if domainMatches(entry.Domain, domain) {
			return Allow
		}
	}
	return Deny
}

// domainMatches reports whether host matches pattern. A pattern of the form
// "*.example.com" matches any single-or-multi-label subdomain of example.com
// (but not example.com itself). Otherwise an exact, case-insensitive match.
func domainMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return host != suffix && strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}
