package config

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/agentid"
)

// Limits on per-user limit rules and the wire-only cost block list.
const (
	// MaxUserLimits bounds policy.userLimits.
	MaxUserLimits = 256
	// MaxCostBlockedUsers bounds the signed costBlockedUsers list the control
	// plane serves (W-P3-PUL-08).
	MaxCostBlockedUsers = 5000
	// MaxUserLimitDailyCostUSD bounds one rule's dailyCostUSD, so a typo cannot
	// become an effectively unbounded cap.
	MaxUserLimitDailyCostUSD = 1e6

	// UserLimitNameDefault and UserLimitNameAnonymous are the names reserved for
	// the two single rules; a userLimits entry cannot use them.
	UserLimitNameDefault   = "default"
	UserLimitNameAnonymous = "anonymous"

	maxUserLimitDomains   = 256
	maxCostBlockedSubSize = 255
	costBlockedDayLayout  = "2006-01-02"
)

// UserLimit is one per-user limit rule: a rate limit and/or a daily
// estimated-cost cap, applied to the requests its Match selects. Nothing
// enforces it yet (see unenforcedUserLimits).
type UserLimit struct {
	// Name identifies the rule in buckets, the decision log and cost blocks.
	// Required and unique in userLimits; empty on defaultUserLimit and
	// anonymousLimit, which are named by their key.
	Name  string         `yaml:"name,omitempty" json:"name,omitempty"`
	Match UserLimitMatch `yaml:"match,omitempty" json:"match,omitzero"`
	// PerAgent gives each agent its own budget instead of one budget per user.
	PerAgent bool `yaml:"perAgent,omitempty" json:"perAgent,omitempty"`
	// RateLimit is "N/second|minute|hour", the allowlist format.
	RateLimit string `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	// DailyCostUSD is the estimated spend cap per UTC day; 0 means no cap.
	DailyCostUSD float64 `yaml:"dailyCostUSD,omitempty" json:"dailyCostUSD,omitempty"`
}

// UserLimitMatch selects the requests a rule applies to. Users and Groups use
// the allowlist principal normalizer (an email matches only a verified one);
// Domains use the allowlist domain dialect and empty means all domains.
type UserLimitMatch struct {
	Users   []string `yaml:"users,omitempty" json:"users,omitempty"`
	Groups  []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	Agents  []string `yaml:"agents,omitempty" json:"agents,omitempty"`
	Domains []string `yaml:"domains,omitempty" json:"domains,omitempty"`
}

// IsZero reports whether no match field is set (json omitzero).
func (m UserLimitMatch) IsZero() bool {
	return len(m.Users) == 0 && len(m.Groups) == 0 && len(m.Agents) == 0 && len(m.Domains) == 0
}

// CostBlockedUser is one wire-only fleet cost block: the user (sub) is over
// the named rule's daily cap on Day (YYYY-MM-DD, UTC). The control plane
// computes the list; it is never read from local YAML and never stored in a
// policy version.
type CostBlockedUser struct {
	Sub  string `json:"sub"`
	Rule string `json:"rule"`
	Day  string `json:"day"`
}

// DeepCopy returns a copy sharing no memory with m.
func (m UserLimitMatch) DeepCopy() UserLimitMatch {
	return UserLimitMatch{
		Users:   append([]string(nil), m.Users...),
		Groups:  append([]string(nil), m.Groups...),
		Agents:  append([]string(nil), m.Agents...),
		Domains: append([]string(nil), m.Domains...),
	}
}

// DeepCopy returns a copy sharing no memory with l.
func (l UserLimit) DeepCopy() UserLimit {
	l.Match = l.Match.DeepCopy()
	return l
}

func copyUserLimitPtr(l *UserLimit) *UserLimit {
	if l == nil {
		return nil
	}
	c := l.DeepCopy()
	return &c
}

func copyUserLimits(in []UserLimit) []UserLimit {
	if in == nil {
		return nil
	}
	out := make([]UserLimit, len(in))
	for i, l := range in {
		out[i] = l.DeepCopy()
	}
	return out
}

// allowUnenforcedUserLimits lifts the not-yet-enforced guard. It is false in
// production; W-P3-PUL-09 (rateLimit) and W-P3-PUL-04 (dailyCostUSD) replace
// the guard with the real enforcement. Tests set it to exercise the wire. It
// is atomic because a test in another package lifts it while background
// reloads of earlier tests may still be reading it.
var allowUnenforcedUserLimits atomic.Bool

// LiftUserLimitsGuardForTesting lifts the not-yet-enforced guard until t's
// cleanup runs. It is for tests in other packages (the control plane's cost
// block and capability gate tests, W-P3-PUL-08) that must hold a dailyCostUSD
// rule before the enforcing tickets remove the guard; production code never
// calls it. Tests that use it must not run in parallel with tests expecting
// the guard.
func LiftUserLimitsGuardForTesting(t interface{ Cleanup(func()) }) {
	allowUnenforcedUserLimits.Store(true)
	t.Cleanup(func() { allowUnenforcedUserLimits.Store(false) })
}

// NormalizeUserLimits normalizes and validates the per-user limit rules in p:
// userLimits, defaultUserLimit and anonymousLimit. Users, groups, agents and
// domains are stored trimmed, deduplicated and sorted, and the two single
// rules get their reserved names, so the served body and its ETag do not
// depend on how the operator spelled them. The rules are copied first and p is
// updated only on success, so no caller's slice or pointer is mutated. The
// YAML loader and parseRemotePolicy call it; errors name the field path
// (policy.userLimits[i].rateLimit) and never a user or group value.
func NormalizeUserLimits(p *Policy) error {
	c := *p
	c.UserLimits = copyUserLimits(p.UserLimits)
	c.DefaultUserLimit = copyUserLimitPtr(p.DefaultUserLimit)
	c.AnonymousLimit = copyUserLimitPtr(p.AnonymousLimit)
	if err := normalizeUserLimitsInPlace(&c); err != nil {
		return err
	}
	p.UserLimits, p.DefaultUserLimit, p.AnonymousLimit = c.UserLimits, c.DefaultUserLimit, c.AnonymousLimit
	return nil
}

// ValidateUserLimits checks the per-user limit rules in p without changing p.
// validate calls it, and the control plane can too.
func ValidateUserLimits(p Policy) error {
	return NormalizeUserLimits(&p)
}

func normalizeUserLimitsInPlace(p *Policy) error {
	if len(p.UserLimits) > MaxUserLimits {
		return fmt.Errorf("config: policy.userLimits: %d rules exceeds the limit of %d", len(p.UserLimits), MaxUserLimits)
	}
	seen := make(map[string]struct{}, len(p.UserLimits))
	for i := range p.UserLimits {
		path := fmt.Sprintf("policy.userLimits[%d]", i)
		l := &p.UserLimits[i]
		if err := agentid.ValidID(l.Name); err != nil {
			return fmt.Errorf("config: %s.name: must be 1 to %d characters of letters, digits, '.', '_', ':' or '-'", path, agentid.MaxIDLen)
		}
		if l.Name == UserLimitNameDefault || l.Name == UserLimitNameAnonymous {
			return fmt.Errorf("config: %s.name: %q is reserved for the single %sUserLimit rule", path, l.Name, l.Name)
		}
		if _, dup := seen[l.Name]; dup {
			return fmt.Errorf("config: %s.name: duplicate rule name", path)
		}
		seen[l.Name] = struct{}{}
		m, err := normalizeUserLimitMatch(path+".match", l.Match)
		if err != nil {
			return err
		}
		l.Match = m
		if err := validateUserLimitLimits(path, *l); err != nil {
			return err
		}
		// Without users, groups or agents a rule would match every request
		// ahead of defaultUserLimit; that is what defaultUserLimit is for.
		if len(l.Match.Users) == 0 && len(l.Match.Groups) == 0 && len(l.Match.Agents) == 0 {
			return fmt.Errorf("config: %s.match: needs users, groups or agents (domains only narrow); use defaultUserLimit for a rule that applies to everyone", path)
		}
	}
	if err := validateSingleUserLimit("policy.defaultUserLimit", UserLimitNameDefault, p.DefaultUserLimit); err != nil {
		return err
	}
	return validateSingleUserLimit("policy.anonymousLimit", UserLimitNameAnonymous, p.AnonymousLimit)
}

// validateSingleUserLimit checks defaultUserLimit or anonymousLimit: no match,
// and a name that is empty (it is then set to the reserved one) or the
// reserved one.
func validateSingleUserLimit(path, reserved string, l *UserLimit) error {
	if l == nil {
		return nil
	}
	if l.Name != "" && l.Name != reserved {
		return fmt.Errorf("config: %s.name: must be empty or %q", path, reserved)
	}
	l.Name = reserved
	if !l.Match.IsZero() {
		return fmt.Errorf("config: %s.match: not allowed; this rule applies to every request it is the fallback for", path)
	}
	return validateUserLimitLimits(path, *l)
}

func validateUserLimitLimits(path string, l UserLimit) error {
	if l.RateLimit == "" && l.DailyCostUSD == 0 {
		return fmt.Errorf("config: %s: rateLimit or dailyCostUSD is required", path)
	}
	if l.RateLimit != "" {
		if err := validateRateLimit(path+".rateLimit", l.RateLimit); err != nil {
			return err
		}
	}
	// The negated form also rejects NaN, which YAML can spell.
	if !(l.DailyCostUSD >= 0 && l.DailyCostUSD <= MaxUserLimitDailyCostUSD) {
		return fmt.Errorf("config: %s.dailyCostUSD: must be 0 (no cap) or more than 0 and at most %g", path, MaxUserLimitDailyCostUSD)
	}
	return nil
}

func normalizeUserLimitMatch(path string, m UserLimitMatch) (UserLimitMatch, error) {
	g, u, err := normalizePrincipals(path, m.Groups, m.Users)
	if err != nil {
		return UserLimitMatch{}, err
	}
	agents, err := normalizeAgentList(path+".agents", m.Agents)
	if err != nil {
		return UserLimitMatch{}, err
	}
	domains, err := normalizeUserLimitDomains(path+".domains", m.Domains)
	if err != nil {
		return UserLimitMatch{}, err
	}
	return UserLimitMatch{Users: u, Groups: g, Agents: agents, Domains: domains}, nil
}

func normalizeAgentList(path string, in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxPrincipals {
		return nil, fmt.Errorf("config: %s: %d values exceeds the limit of %d", path, len(in), maxPrincipals)
	}
	out := make([]string, 0, len(in))
	for i, v := range in {
		if err := agentid.ValidID(v); err != nil {
			return nil, fmt.Errorf("config: %s[%d]: not a valid agent id", path, i)
		}
		out = append(out, v)
	}
	return sortDedup(out), nil
}

func normalizeUserLimitDomains(path string, in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxUserLimitDomains {
		return nil, fmt.Errorf("config: %s: %d values exceeds the limit of %d", path, len(in), maxUserLimitDomains)
	}
	out := make([]string, 0, len(in))
	for i, d := range in {
		d = strings.TrimSpace(d)
		// A regex keeps its case (lowercasing would change `\S`); the other
		// forms are matched case-insensitively, so they are stored lower.
		if !strings.HasPrefix(d, "~") {
			d = strings.ToLower(d)
		}
		if err := validateDomainPattern(fmt.Sprintf("%s[%d]", path, i), d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return sortDedup(out), nil
}

func sortDedup(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// unenforcedUserLimits is the fail-closed guard: until W-P3-PUL-09 enforces
// rate limits and W-P3-PUL-04 enforces cost caps, a config that carries a
// rule would be silently ignored, so it is refused instead.
func unenforcedUserLimits(p Policy) error {
	if allowUnenforcedUserLimits.Load() {
		return nil
	}
	switch {
	case len(p.UserLimits) > 0:
		return fmt.Errorf("config: policy.userLimits: not yet enforced; remove it until a release that enforces per-user limits")
	case p.DefaultUserLimit != nil:
		return fmt.Errorf("config: policy.defaultUserLimit: not yet enforced; remove it until a release that enforces per-user limits")
	case p.AnonymousLimit != nil:
		return fmt.Errorf("config: policy.anonymousLimit: not yet enforced; remove it until a release that enforces per-user limits")
	}
	return nil
}

// ValidateCostBlockedUsers checks the wire-only cost block list: at most
// MaxCostBlockedUsers entries, each with a non-empty sub of at most 255 bytes
// and no control character, a rule name in the rule-name charset (the
// reserved names included) and a YYYY-MM-DD day. The control plane runs it
// before serving and workers on every pull, so a bad row is rejected whole and
// the worker keeps its last good policy. Errors name the index, never the sub.
func ValidateCostBlockedUsers(list []CostBlockedUser) error {
	if len(list) > MaxCostBlockedUsers {
		return fmt.Errorf("config: costBlockedUsers: %d entries exceeds the limit of %d", len(list), MaxCostBlockedUsers)
	}
	for i, e := range list {
		if e.Sub == "" || strings.TrimSpace(e.Sub) == "" {
			return fmt.Errorf("config: costBlockedUsers[%d].sub: is required", i)
		}
		if len(e.Sub) > maxCostBlockedSubSize {
			return fmt.Errorf("config: costBlockedUsers[%d].sub: exceeds %d bytes", i, maxCostBlockedSubSize)
		}
		if hasControlRune(e.Sub) {
			return fmt.Errorf("config: costBlockedUsers[%d].sub: control character not allowed", i)
		}
		if err := agentid.ValidID(e.Rule); err != nil {
			return fmt.Errorf("config: costBlockedUsers[%d].rule: not a valid rule name", i)
		}
		if d, err := time.Parse(costBlockedDayLayout, e.Day); err != nil || d.Format(costBlockedDayLayout) != e.Day {
			return fmt.Errorf("config: costBlockedUsers[%d].day: want a YYYY-MM-DD date", i)
		}
	}
	return nil
}

// LintUserLimits returns warnings about per-user limit rules that are valid
// but probably not what the operator meant: rules in one tier whose matches
// overlap (the first in list order wins, so a later one is partly or wholly
// unreachable), a dailyCostUSD with no CA configured (cost is measured only on
// terminated TLS), and agents whose identity mode is not require (a strict
// per-user guarantee needs it). Pure; warnings carry rule and agent names
// only, never a user, group or domain value. Nil when there is nothing to say.
func LintUserLimits(p Policy) []string {
	if len(p.UserLimits) == 0 && p.DefaultUserLimit == nil && p.AnonymousLimit == nil {
		return nil
	}
	var out []string
	for i, a := range p.UserLimits {
		for _, b := range p.UserLimits[i+1:] {
			if userLimitsOverlap(a, b) {
				out = append(out, fmt.Sprintf("userLimits %q and %q overlap in the %s tier; the first in list order wins where both match",
					a.Name, b.Name, userLimitTier(a)))
			}
		}
	}
	if p.TLS.CACert == "" {
		for _, l := range userLimitRules(p) {
			if l.DailyCostUSD > 0 {
				out = append(out, fmt.Sprintf("userLimits %q sets dailyCostUSD but no CA is configured; cost is measured only on TLS-terminated traffic, so the cap cannot be enforced", l.Name))
			}
		}
	}
	for _, id := range lintUserLimitAgents(p) {
		if mode, _ := EffectiveIdentityMode(id, p.Agents, p.Identity); mode != IdentityModeRequire {
			out = append(out, fmt.Sprintf("agent %q has identity mode %q, not %q; per-user limits cannot be strict for it, since a request without a verified identity falls into the anonymous bucket",
				id, mode, IdentityModeRequire))
		}
	}
	return out
}

// userLimitRules lists every rule: userLimits, then default, then anonymous.
func userLimitRules(p Policy) []UserLimit {
	out := append([]UserLimit(nil), p.UserLimits...)
	if p.DefaultUserLimit != nil {
		out = append(out, *p.DefaultUserLimit)
	}
	if p.AnonymousLimit != nil {
		out = append(out, *p.AnonymousLimit)
	}
	for i := range out {
		if out[i].Name == "" {
			// A rule not yet through NormalizeUserLimits: name it by position.
			out[i].Name = "#" + fmt.Sprint(i)
		}
	}
	return out
}

// lintUserLimitAgents is the sorted set of agent ids the limits can touch: the
// configured agents plus those named in a rule's match.
func lintUserLimitAgents(p Policy) []string {
	set := map[string]struct{}{}
	for _, a := range p.Agents {
		set[a.ID] = struct{}{}
	}
	for _, l := range p.UserLimits {
		for _, id := range l.Match.Agents {
			set[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// userLimitTier names the precedence tier a rule sits in: rules matching by
// users, then by groups, then agents-only rules.
func userLimitTier(l UserLimit) string {
	switch {
	case len(l.Match.Users) > 0:
		return "users"
	case len(l.Match.Groups) > 0:
		return "groups"
	}
	return "agents"
}

// userLimitsOverlap reports whether two rules in one tier can both match a
// request. Undecidable cases (a regex domain against another pattern) are not
// reported.
func userLimitsOverlap(a, b UserLimit) bool {
	if userLimitTier(a) != userLimitTier(b) {
		return false
	}
	switch userLimitTier(a) {
	case "users":
		if !intersects(a.Match.Users, b.Match.Users) {
			return false
		}
	case "groups":
		if !intersects(a.Match.Groups, b.Match.Groups) {
			return false
		}
	}
	if len(a.Match.Agents) > 0 && len(b.Match.Agents) > 0 && !intersects(a.Match.Agents, b.Match.Agents) {
		return false
	}
	return domainSetsOverlap(a.Match.Domains, b.Match.Domains)
}

func intersects(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

// domainSetsOverlap: an empty set means every domain.
func domainSetsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, x := range a {
		for _, y := range b {
			if domainCovers(x, y) || domainCovers(y, x) {
				return true
			}
		}
	}
	return false
}
