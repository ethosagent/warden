// Package policy implements the default-deny allowlist evaluator. A
// destination is permitted only if it matches an allowlist entry; everything
// else is denied. This default-deny posture is a core security invariant and
// must never be weakened.
package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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
// constructed once from a Policy and is safe for concurrent use.
type Evaluator struct {
	allowlist  []config.AllowlistEntry
	denylist   []config.DenylistEntry
	regexCache map[string]*regexp.Regexp

	// Rate limiting (fixed-window).
	mu         sync.Mutex
	rateLimits map[int]parsedRateLimit // index into allowlist -> parsed limit
	counters   map[string]*rateState   // key: "pattern:port" -> state

	// Time-window rules.
	timeWindows map[int]parsedTimeWindow // index into allowlist -> parsed window

	// For testability.
	now func() time.Time
}

type parsedRateLimit struct {
	limit  int
	window time.Duration
}

type rateState struct {
	count     int
	windowEnd time.Time
}

type parsedTimeWindow struct {
	startHour int
	endHour   int
}

// NewEvaluator builds an Evaluator from a policy.
func NewEvaluator(p config.Policy) *Evaluator {
	e := &Evaluator{
		allowlist:   append([]config.AllowlistEntry(nil), p.Allowlist...),
		denylist:    append([]config.DenylistEntry(nil), p.Denylist...),
		regexCache:  make(map[string]*regexp.Regexp),
		rateLimits:  make(map[int]parsedRateLimit),
		counters:    make(map[string]*rateState),
		timeWindows: make(map[int]parsedTimeWindow),
		now:         time.Now,
	}

	// Pre-compile regexes from allowlist and denylist.
	for _, entry := range e.allowlist {
		if strings.HasPrefix(entry.Domain, "~") {
			re, err := regexp.Compile(entry.Domain[1:])
			if err == nil {
				e.regexCache[entry.Domain] = re
			}
		}
	}
	for _, entry := range e.denylist {
		if strings.HasPrefix(entry.Domain, "~") {
			re, err := regexp.Compile(entry.Domain[1:])
			if err == nil {
				e.regexCache[entry.Domain] = re
			}
		}
	}

	// Parse rate limits.
	for i, entry := range e.allowlist {
		if entry.RateLimit != "" {
			if rl, err := parseRateLimit(entry.RateLimit); err == nil {
				e.rateLimits[i] = rl
			}
		}
	}

	// Parse time windows.
	for i, entry := range e.allowlist {
		if entry.TimeWindow != "" {
			if tw, err := parseTimeWindow(entry.TimeWindow); err == nil {
				e.timeWindows[i] = tw
			}
		}
	}

	return e
}

// Evaluate returns Allow only if (domain, port) matches an allowlist entry
// under the given scheme and passes rate-limit / time-window checks; otherwise
// Deny (default-deny). The denylist is checked first — deny wins on conflict.
func (e *Evaluator) Evaluate(domain string, port int, scheme Scheme) Decision {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Denylist checked first — deny wins on conflict.
	for _, entry := range e.denylist {
		if inferredPort(entry.Port, scheme) == port && e.domainMatches(entry.Domain, domain) {
			return Deny
		}
	}

	// Then check allowlist.
	for i, entry := range e.allowlist {
		if inferredPort(entry.Port, scheme) != port {
			continue
		}
		if !e.domainMatches(entry.Domain, domain) {
			continue
		}

		// Time window check (hours in server local time).
		// If this entry fails, try next entry.
		if tw, ok := e.timeWindows[i]; ok {
			hour := e.now().Hour()
			if tw.startHour <= tw.endHour {
				if hour < tw.startHour || hour >= tw.endHour {
					continue
				}
			} else {
				// Wrap-around (e.g. 22-6 means 22:00-06:00)
				if hour < tw.startHour && hour >= tw.endHour {
					continue
				}
			}
		}

		// Rate limit check — if this entry is exhausted, try next entry.
		if rl, ok := e.rateLimits[i]; ok {
			key := fmt.Sprintf("%s:%d", entry.Domain, inferredPort(entry.Port, scheme))
			if !e.checkRateLimit(key, rl) {
				continue
			}
		}

		return Allow
	}
	return Deny
}

// domainMatches reports whether host matches pattern. Supports:
//   - "~<regex>" — regex match
//   - "*.example.com" — wildcard subdomain match
//   - exact match (case-insensitive)
func (e *Evaluator) domainMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	// Regex match: ~<pattern>
	if strings.HasPrefix(pattern, "~") {
		if re, ok := e.regexCache[pattern]; ok {
			return re.MatchString(host)
		}
		return false
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return host != suffix && strings.HasSuffix(host, "."+suffix)
	}
	return pattern == host
}

func (e *Evaluator) checkRateLimit(key string, rl parsedRateLimit) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	state, ok := e.counters[key]
	if !ok || now.After(state.windowEnd) {
		e.counters[key] = &rateState{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}
	state.count++
	return state.count <= rl.limit
}

func parseRateLimit(s string) (parsedRateLimit, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return parsedRateLimit{}, fmt.Errorf("invalid rate limit format: %q", s)
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n <= 0 {
		return parsedRateLimit{}, fmt.Errorf("invalid rate limit count: %q", parts[0])
	}
	var d time.Duration
	switch parts[1] {
	case "second":
		d = time.Second
	case "minute":
		d = time.Minute
	case "hour":
		d = time.Hour
	default:
		return parsedRateLimit{}, fmt.Errorf("invalid rate limit period: %q", parts[1])
	}
	return parsedRateLimit{limit: n, window: d}, nil
}

// parseTimeWindow parses "HH-HH" format. Hours are in server local time.
func parseTimeWindow(s string) (parsedTimeWindow, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return parsedTimeWindow{}, fmt.Errorf("invalid time window format: %q", s)
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 || start > 23 {
		return parsedTimeWindow{}, fmt.Errorf("invalid start hour: %q", parts[0])
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil || end < 0 || end > 23 {
		return parsedTimeWindow{}, fmt.Errorf("invalid end hour: %q", parts[1])
	}
	return parsedTimeWindow{startHour: start, endHour: end}, nil
}
