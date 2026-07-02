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
	// Deny is an explicit deny — the destination matched a denylist entry.
	// It is the zero value so existing callers that treat "!= Allow" as deny
	// keep their default-deny posture unchanged.
	Deny Decision = iota
	// Allow means the destination matched an allowlist entry.
	Allow
	// NoMatch means the destination matched neither the denylist nor the
	// allowlist. It is distinct from Deny so the pipeline can route ambiguous
	// requests to the LLM judge when enabled. Callers that compare against
	// Allow still default-deny on NoMatch (NoMatch != Allow), so behaviour is
	// unchanged when the judge is disabled.
	NoMatch
)

// String renders a decision for logging.
func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case NoMatch:
		return "no-match"
	default:
		return "deny"
	}
}

// Evaluator decides whether a destination is allowed under a policy. It is
// constructed once from a Policy and is safe for concurrent use.
type Evaluator struct {
	// swapMu guards the policy-derived state below so a control-plane poll can
	// atomically Replace it while requests are being evaluated. Evaluate takes a
	// read lock; Replace takes the write lock. This never weakens default-deny:
	// a swap only exchanges one validated allow/deny set for another.
	swapMu     sync.RWMutex
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
	e := &Evaluator{now: time.Now}
	e.load(p)
	return e
}

// Replace atomically swaps the evaluator's allow/deny policy with p, so a
// control-plane poll can apply updated policy without restarting the proxy.
// In-flight Evaluate calls either see the old policy fully or the new policy
// fully — never a mix. This preserves the default-deny invariant: p is a
// validated policy and a swap only exchanges one allow/deny set for another.
// Rate-limit counters are reset, so a policy change starts fresh windows.
func (e *Evaluator) Replace(p config.Policy) {
	e.swapMu.Lock()
	defer e.swapMu.Unlock()
	e.load(p)
}

// CurrentPolicy returns a snapshot of the evaluator's live allow/deny lists.
// It reflects the most recent Replace (control-plane hot-reload), so callers
// such as the dashboard can display the policy actually being enforced rather
// than a startup snapshot. Only allow/deny are returned — the evaluator never
// holds secrets.
func (e *Evaluator) CurrentPolicy() config.Policy {
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()
	return config.Policy{
		Allowlist: append([]config.AllowlistEntry(nil), e.allowlist...),
		Denylist:  append([]config.DenylistEntry(nil), e.denylist...),
	}
}

// load (re)builds the policy-derived state from p. NewEvaluator calls it before
// the evaluator is shared (no lock needed); Replace calls it under swapMu.
func (e *Evaluator) load(p config.Policy) {
	allowlist := append([]config.AllowlistEntry(nil), p.Allowlist...)
	denylist := append([]config.DenylistEntry(nil), p.Denylist...)
	regexCache := make(map[string]*regexp.Regexp)
	rateLimits := make(map[int]parsedRateLimit)
	timeWindows := make(map[int]parsedTimeWindow)

	// Pre-compile regexes from allowlist and denylist.
	for _, entry := range allowlist {
		if strings.HasPrefix(entry.Domain, "~") {
			if re, err := regexp.Compile(entry.Domain[1:]); err == nil {
				regexCache[entry.Domain] = re
			}
		}
	}
	for _, entry := range denylist {
		if strings.HasPrefix(entry.Domain, "~") {
			if re, err := regexp.Compile(entry.Domain[1:]); err == nil {
				regexCache[entry.Domain] = re
			}
		}
	}

	// Parse rate limits and time windows (indexed into allowlist).
	for i, entry := range allowlist {
		if entry.RateLimit != "" {
			if rl, err := parseRateLimit(entry.RateLimit); err == nil {
				rateLimits[i] = rl
			}
		}
		if entry.TimeWindow != "" {
			if tw, err := parseTimeWindow(entry.TimeWindow); err == nil {
				timeWindows[i] = tw
			}
		}
	}

	e.allowlist = allowlist
	e.denylist = denylist
	e.regexCache = regexCache
	e.rateLimits = rateLimits
	e.timeWindows = timeWindows
	// Reset rate-limit counters: a policy swap starts fresh fixed windows.
	e.mu.Lock()
	e.counters = make(map[string]*rateState)
	e.mu.Unlock()
}

// Evaluate returns Allow if (domain, port) matches an allowlist entry under the
// given scheme and passes rate-limit / time-window checks; Deny if it matches a
// denylist entry; and NoMatch if it matches neither. The denylist is checked
// first — deny wins on conflict. Callers that compare against Allow still
// default-deny on NoMatch, preserving the default-deny invariant; NoMatch
// exists only so the pipeline can optionally consult the LLM judge.
func (e *Evaluator) Evaluate(domain string, port int, scheme Scheme) Decision {
	// Read-lock the policy-derived state so a concurrent Replace can't swap it
	// mid-evaluation. This is a read lock: concurrent Evaluate calls do not
	// contend with each other, only with a (rare) Replace.
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Denylist checked first — deny wins on conflict.
	for _, entry := range e.denylist {
		if inferredPort(entry.Port, scheme) == port && e.domainMatches(entry.Domain, domain) {
			return Deny
		}
	}

	// Then check allowlist. matchedEntry tracks whether the destination matched
	// an allowlist entry by domain+port even if a rate-limit / time-window guard
	// later rejected it: such a request is an explicit Deny (the destination IS
	// allowlisted, just throttled), never NoMatch — it must not reach the judge.
	matchedEntry := false
	for i, entry := range e.allowlist {
		if inferredPort(entry.Port, scheme) != port {
			continue
		}
		if !e.domainMatches(entry.Domain, domain) {
			continue
		}
		matchedEntry = true

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
	if matchedEntry {
		// Destination is allowlisted but every matching entry rejected it via a
		// rate-limit / time-window guard: explicit Deny, not judge-eligible.
		return Deny
	}
	return NoMatch
}

// domainMatches reports whether host matches pattern. Supports:
//   - "~<regex>" — regex match (served from the evaluator's precompiled cache)
//   - "*.example.com" — wildcard subdomain match
//   - exact match (case-insensitive)
//
// The regex path uses the evaluator's precompiled cache (hot allow/deny path); the
// wildcard/exact path delegates to MatchDomain so the two callers share ONE
// dialect.
func (e *Evaluator) domainMatches(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	// Regex match: ~<pattern> — served from the precompiled cache.
	if strings.HasPrefix(pattern, "~") {
		if re, ok := e.regexCache[pattern]; ok {
			return re.MatchString(host)
		}
		return false
	}
	return MatchDomain(pattern, host)
}

// MatchDomain reports whether host matches pattern using the SAME destination
// dialect the allow/deny evaluator uses: "~regex", "*.suffix" wildcard, or exact
// (case-insensitive). It is exported so the DLP rule evaluator reuses this ONE
// matcher instead of forking a second dialect. Regex patterns are compiled on each
// call (DLP rule sets are small and destination-regex is rare); a malformed regex
// never matches. The hot allow/deny path keeps its precompiled cache via
// domainMatches.
func MatchDomain(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if rx, ok := strings.CutPrefix(pattern, "~"); ok {
		re, err := regexp.Compile(rx)
		if err != nil {
			return false
		}
		return re.MatchString(host)
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
