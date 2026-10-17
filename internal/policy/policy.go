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

// Bounded deny reasons for #371 method/path constraints. They ride the
// analytics Event.Reason field: a closed enum of fixed identifiers, never
// request content. The empty reason means a deny that is not a constraint
// violation (denylist hit, or an exhausted rate-limit / time-window guard) —
// callers render that as their generic "policy" reason.
const (
	// ReasonPathNotCanonical: the raw request path contains a dot segment or an
	// encoded separator, so the bytes being matched and the resource the origin
	// serves could differ. Denied whenever the destination has a paths
	// constraint, before any pattern matching.
	ReasonPathNotCanonical = "path_not_canonical"
	// ReasonMethodNotAllowed: the request method is not in the matched entry's
	// `methods` list.
	ReasonMethodNotAllowed = "method_not_allowed"
	// ReasonPathNotAllowed: the request path matches no pattern in the matched
	// entry's `paths` list.
	ReasonPathNotAllowed = "path_not_allowed"
)

// RequestVerdict is the per-request outcome of EvaluateRequest: the decision
// plus, for constraint denies, the bounded reason behind it.
type RequestVerdict struct {
	Decision Decision
	Reason   string
}

// evalMode selects how evaluate treats #371 constraints and rate-limit
// accounting. The three callers need exactly three combinations:
//
//   - evalTunnel: the legacy destination-only Evaluate — constraints
//     could-match and the rate limit COUNTS (today's tunnel-level accounting,
//     pinned by existing tests and unchanged).
//   - evalConnect: the CONNECT gate — constraints could-match (admission only;
//     the per-request check is authoritative) and the rate limit PEEKS, so a
//     tunnel that turns out to violate a constraint does not consume budget.
//   - evalRequest: the per-request check — constraints are enforced and the
//     rate limit counts. Each request is counted exactly once.
type evalMode uint8

const (
	evalTunnel evalMode = iota
	evalConnect
	evalRequest
)

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
// holds secrets. Entries are copied including their #371 constraint slices.
func (e *Evaluator) CurrentPolicy() config.Policy {
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()
	return config.Policy{
		Allowlist: cloneAllowlist(e.allowlist),
		Denylist:  append([]config.DenylistEntry(nil), e.denylist...),
	}
}

// cloneAllowlist copies entries AND their constraint slices, so a snapshot can
// never alias the live policy's Methods/Paths backing arrays.
func cloneAllowlist(entries []config.AllowlistEntry) []config.AllowlistEntry {
	out := append([]config.AllowlistEntry(nil), entries...)
	for i := range out {
		out[i].Methods = append([]string(nil), entries[i].Methods...)
		out[i].Paths = append([]string(nil), entries[i].Paths...)
	}
	return out
}

// load (re)builds the policy-derived state from p. NewEvaluator calls it before
// the evaluator is shared (no lock needed); Replace calls it under swapMu.
func (e *Evaluator) load(p config.Policy) {
	allowlist := cloneAllowlist(p.Allowlist)
	denylist := append([]config.DenylistEntry(nil), p.Denylist...)
	regexCache := make(map[string]*regexp.Regexp)
	rateLimits := make(map[int]parsedRateLimit)
	timeWindows := make(map[int]parsedTimeWindow)

	// Pre-compile regexes from allowlist and denylist. The cache is keyed by the
	// RAW pattern: in a "~regex" a trailing '.' is a regex metacharacter, not a
	// DNS trailing dot, so normalising it would collapse two entries that differ
	// only by that dot onto one key and let the later compile win (#397).
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
//
// Destination-only: method/path constraints (#371) could-match (any entry for
// the destination admits it) and the rate limit counts per tunnel, exactly as
// before #371. Per-request enforcement is EvaluateRequest's job.
func (e *Evaluator) Evaluate(domain string, port int, scheme Scheme) Decision {
	return e.evaluate(domain, port, scheme, "", "", evalTunnel).Decision
}

// EvaluateRequest evaluates ONE request against the policy (#371). method/path
// must be exactly what goes upstream: the method as sent (case-sensitive;
// entries were uppercased at config load) and the RAW percent-encoded path —
// URL.EscapedPath() on HTTP/1.1, the :path pseudo-header on HTTP/2 — with no
// decoding on either side.
//
//   - method != "" (request mode): entries with `methods`/`paths` enforce them;
//     a destination match that violates them is an explicit Deny (never
//     NoMatch, so it cannot reach the LLM judge), and the rate limit counts
//     only requests that matched the rule's own constraints.
//   - method == "" (destination-only — the CONNECT gate): constraints
//     could-match and the rate limit is peeked, not consumed; the per-request
//     evaluation is authoritative and counts exactly once.
//
// Constraint order inside an entry is time window → method → path → rate
// limit, so a constraint-violating request never consumes rate-limit budget.
func (e *Evaluator) EvaluateRequest(domain string, port int, scheme Scheme, method, path string) RequestVerdict {
	mode := evalRequest
	if method == "" {
		mode = evalConnect
	}
	return e.evaluate(domain, port, scheme, method, path, mode)
}

// evaluate is the single core behind Evaluate and EvaluateRequest.
func (e *Evaluator) evaluate(domain string, port int, scheme Scheme, method, path string, mode evalMode) RequestVerdict {
	// Read-lock the policy-derived state so a concurrent Replace can't swap it
	// mid-evaluation. This is a read lock: concurrent Evaluate calls do not
	// contend with each other, only with a (rare) Replace.
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()

	enforce := mode == evalRequest
	count := mode != evalConnect

	// ONE host normalisation for the whole evaluation (#397): everything below
	// — deny, the canonical-path pre-pass, allow, rate-limit keys — sees this
	// same normalised form. A host that is only dots (or empty) normalises to
	// nothing the policy can name: deny fail-closed instead of matching it
	// against anything (an allow-everything regex would otherwise admit it),
	// and as an explicit Deny it can never reach the judge.
	domain = NormalizeHost(domain)
	if domain == "" {
		return RequestVerdict{Decision: Deny}
	}

	// Denylist checked first — deny wins on conflict.
	for _, entry := range e.denylist {
		if inferredPort(entry.Port, scheme) == port && e.domainMatches(entry.Domain, domain) {
			return RequestVerdict{Decision: Deny}
		}
	}

	// #371 canonical-path pre-pass. If ANY paths-constrained entry covers this
	// destination, a non-canonical raw path is denied before pattern matching:
	// any-match-wins must not let a sibling entry carry a path whose bytes we
	// match but whose resource the origin normalizes to something else.
	if enforce && !isCanonicalPath(path) {
		for _, entry := range e.allowlist {
			if len(entry.Paths) > 0 &&
				inferredPort(entry.Port, scheme) == port &&
				e.domainMatches(entry.Domain, domain) {
				return RequestVerdict{Decision: Deny, Reason: ReasonPathNotCanonical}
			}
		}
	}

	// Then check allowlist. matchedEntry tracks whether the destination matched
	// an allowlist entry by domain+port even if a constraint / rate-limit /
	// time-window guard later rejected it: such a request is an explicit Deny
	// (the destination IS allowlisted, just not like this), never NoMatch — it
	// must not reach the judge.
	matchedEntry := false
	var methodViolated, pathViolated bool
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

		// #371 method constraint — case-sensitive against the method as sent
		// (config load uppercased the entry side).
		if enforce && len(entry.Methods) > 0 {
			if !containsMethod(entry.Methods, method) {
				methodViolated = true
				continue
			}
		}

		// #371 path constraint — raw, percent-encoded byte matching.
		if enforce && len(entry.Paths) > 0 {
			if !pathMatchesAny(entry.Paths, path) {
				pathViolated = true
				continue
			}
		}

		// Rate limit check — reached only when this entry's constraints (if
		// any) passed, so a denied request never consumes budget. If this entry
		// is exhausted, try next entry.
		if rl, ok := e.rateLimits[i]; ok {
			key := fmt.Sprintf("%s:%d", rateLimitPattern(entry.Domain), inferredPort(entry.Port, scheme))
			if count {
				if !e.checkRateLimit(key, rl) {
					continue
				}
			} else if !e.peekRateLimit(key, rl) {
				continue
			}
		}

		return RequestVerdict{Decision: Allow}
	}
	if matchedEntry {
		// Destination is allowlisted but every matching entry rejected it. A
		// constraint violation names itself; guard rejections (rate limit /
		// time window) keep the empty reason. Explicit Deny either way — not
		// judge-eligible.
		switch {
		case pathViolated:
			return RequestVerdict{Decision: Deny, Reason: ReasonPathNotAllowed}
		case methodViolated:
			return RequestVerdict{Decision: Deny, Reason: ReasonMethodNotAllowed}
		}
		return RequestVerdict{Decision: Deny}
	}
	return RequestVerdict{Decision: NoMatch}
}

// containsMethod reports whether method is in the entry's allowed set. Entries
// are uppercased at config load and the request side arrives exactly as sent,
// so this comparison is intentionally case-sensitive.
func containsMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// pathMatchesAny reports whether the raw path matches at least one pattern —
// any-match-wins within an entry, same as every other constraint list.
func pathMatchesAny(patterns []string, path string) bool {
	for _, pat := range patterns {
		if matchPath(pat, path) {
			return true
		}
	}
	return false
}

// NormalizeHost returns the canonical form of a destination host used for
// EVERY host comparison in policy evaluation: lower-case, with ALL trailing
// dots removed. "Example.COM." and "example.com..." both normalise to
// "example.com", so a rule matches regardless of how many trailing dots the
// request carried (#397: the previous one-dot trims let "bad.corp.test..."
// miss its deny rule and fall through to the judge). A host that is only dots
// — or empty — normalises to "": callers must deny it outright (fail closed),
// never match it against a rule.
//
// NormalizeHost is for HOSTS, never for "~regex" PATTERNS: in a regex a
// trailing '.' is a metacharacter, not a DNS trailing dot, and stripping it
// changes (or breaks) the expression. Regex patterns are matched verbatim
// against the normalised host.
func NormalizeHost(host string) string {
	return strings.ToLower(strings.TrimRight(host, "."))
}

// rateLimitPattern returns the pattern that names an allowlist entry's
// rate-limit bucket: non-regex patterns are normalised so "api.example.com" and
// "api.example.com." share ONE bucket (#397), while a "~regex" pattern is used
// raw — normalising it would merge two regexes that differ only by a trailing
// '.' metacharacter onto one bucket.
func rateLimitPattern(pattern string) string {
	if strings.HasPrefix(pattern, "~") {
		return pattern
	}
	return NormalizeHost(pattern)
}

// domainMatches reports whether host matches pattern. Supports:
//   - "~<regex>" — regex match (served from the evaluator's precompiled cache)
//   - "*.example.com" — wildcard subdomain match
//   - exact match (case-insensitive)
//
// host arrives already normalised by evaluate — the one place the host side is
// normalised (#397). The regex path looks the pattern up by its RAW source (the
// key load() stored) and matches it against the normalised host — a trailing
// '.' in a regex is a metacharacter, never a DNS dot. The wildcard/exact path
// delegates to MatchDomain, which normalises the pattern itself, so the two
// callers share ONE dialect.
func (e *Evaluator) domainMatches(pattern, host string) bool {
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
// (case-insensitive). The HOST side goes through NormalizeHost, so the match
// never depends on trailing dots or case (#397) and an empty or dots-only host —
// the normalised form of nothing — matches nothing. The PATTERN side is
// normalised only for the non-regex dialects: a "~regex" pattern is compiled
// and matched verbatim, because its trailing '.' is a metacharacter, not a DNS
// dot (#397). It is exported so the DLP rule evaluator reuses this ONE matcher
// instead of forking a second dialect. Regex patterns are compiled on each call
// (DLP rule sets are small and destination-regex is rare); a malformed regex
// never matches. The hot allow/deny path keeps its precompiled cache via
// domainMatches.
func MatchDomain(pattern, host string) bool {
	host = NormalizeHost(host)
	if host == "" {
		return false
	}
	if rx, ok := strings.CutPrefix(pattern, "~"); ok {
		re, err := regexp.Compile(rx)
		if err != nil {
			return false
		}
		return re.MatchString(host)
	}
	pattern = NormalizeHost(pattern)
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

// peekRateLimit reports whether the rate limit HAS room without consuming a
// slot. It backs the CONNECT gate (evalConnect): tunnel admission must not
// count a request — the per-request evaluation counts exactly once.
func (e *Evaluator) peekRateLimit(key string, rl parsedRateLimit) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	state, ok := e.counters[key]
	if !ok || now.After(state.windowEnd) {
		return true // a fresh window would start — room exists
	}
	return state.count < rl.limit
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

// HostMatcher matches a destination host against a fixed pattern set using the
// SAME dialect as the allow/deny evaluator ("~regex", "*.suffix", exact). Regexes
// are compiled once at construction so per-request matching (e.g. secret scoping)
// does not recompile; wildcard/exact delegate to MatchDomain, the one shared
// dialect. A nil *HostMatcher matches nothing.
type HostMatcher struct {
	patterns []string
	regexes  map[string]*regexp.Regexp
}

// NewHostMatcher compiles patterns; a malformed "~regex" is an error. Regexes
// compile from their RAW source, keyed by it — a trailing '.' is a regex
// metacharacter, never a DNS trailing dot (#397); Matches normalises the host,
// never the pattern.
func NewHostMatcher(patterns []string) (*HostMatcher, error) {
	m := &HostMatcher{patterns: append([]string(nil), patterns...), regexes: map[string]*regexp.Regexp{}}
	for _, raw := range patterns {
		if rx, ok := strings.CutPrefix(raw, "~"); ok {
			re, err := regexp.Compile(rx)
			if err != nil {
				return nil, fmt.Errorf("policy: invalid host regex %q: %w", raw, err)
			}
			m.regexes[raw] = re
		}
	}
	return m, nil
}

// Matches reports whether host matches any pattern. host goes through
// NormalizeHost (#397), so the match never depends on trailing dots or case;
// a host that is only dots — or empty — matches nothing.
func (m *HostMatcher) Matches(host string) bool {
	if m == nil {
		return false
	}
	host = NormalizeHost(host)
	if host == "" {
		return false
	}
	for _, raw := range m.patterns {
		if re, ok := m.regexes[raw]; ok {
			if re.MatchString(host) {
				return true
			}
			continue
		}
		if MatchDomain(raw, host) {
			return true
		}
	}
	return false
}
