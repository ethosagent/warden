// Package approvals decides which policy changes need a second person
// (W-P2-APPR-02 onward). Classify is a pure function over two canonical policy
// docs: it never reads a clock, a store or the network, so the draft API, the
// single clearance check and the apply path can all call it and agree.
package approvals

import (
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

// Reason codes. A change is widening exactly when it has at least one reason.
const (
	CodeAllowAdded          = "allow.added"              // an allow entry with no narrower base counterpart
	CodeAllowScopeWide      = "allow.scope_widened"      // same domain and port, groups/users no longer a subset
	CodeAllowRateRelaxed    = "allow.rate_relaxed"       // same domain and port, rateLimit looser, removed, unparseable or split
	CodeAllowTimeRelaxed    = "allow.time_relaxed"       // same domain and port, timeWindow wider, removed or unparseable
	CodeAllowConstraint     = "allow.constraint_widened" // same domain and port, methods or paths less restricted
	CodeAllowRemovedToJudge = "allow.removed_to_judge"   // a constrained entry removed: its explicit deny becomes a judge-eligible no-match
	CodeDenyRemoved         = "deny.removed"             // a deny entry removed or changed
	CodeSettingsChanged     = "settings.changed"
	// CodeUserLimitsChanged is any change to a per-user limit key
	// (userLimits, defaultUserLimit, anonymousLimit). A limit change can move a
	// user to a looser rule through precedence, so every change is widening
	// (no containment analysis); Path is the key, never a rule's users,
	// groups or values.
	CodeUserLimitsChanged = "user_limits.changed"
)

// Reason says why a change counts as widening. Path and Detail hold only a
// destination (domain and port) or a settings JSON path, never a settings
// value, a group or user name, or a credential.
type Reason struct {
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

// Classification is the verdict on a change from base to draft.
type Classification struct {
	// Widening is true when the draft can reach more, or send credentials
	// somewhere new. A change that is not widening applies without a second
	// person.
	Widening bool `json:"widening"`
	// Reasons is sorted by (Code, Path, Detail) and empty when not widening.
	Reasons []Reason `json:"reasons"`
	// RequiredRole is the role an approver needs: admin when any changed
	// settings path is outside the editor set, otherwise editor.
	RequiredRole config.Role `json:"requiredRole"`
}

// Classify decides whether going from base to draft widens access or changes
// where credentials go. It is pure and deterministic: no I/O. The order of
// entries in either doc does not change the result, except for a destination
// with a shared rate bucket (two or more rate-limited unscoped entries on one
// host and port), where the evaluator's entry order decides which entry opens
// the bucket and so any reorder is reported (allow.rate_relaxed); #648 tracks
// fixing that in the evaluator. There is no regex or wildcard containment
// analysis: an allow key that is new is widening however narrow it looks.
// Anything it does not recognise counts as widening.
func Classify(base, draft Doc) Classification {
	var reasons []Reason
	reasons = append(reasons, classifyAllow(base.Allowlist, draft.Allowlist)...)
	reasons = append(reasons, classifyDeny(base.Denylist, draft.Denylist)...)
	reasons = append(reasons, classifyUserLimits(base, draft)...)

	role := config.RoleEditor
	bm, errB := settingsMap(base.Settings)
	dm, errD := settingsMap(draft.Settings)
	if errB != nil || errD != nil {
		// Cannot compare: fail closed.
		reasons = append(reasons, Reason{Code: CodeSettingsChanged, Path: "settings", Detail: "settings could not be compared"})
		role = config.RoleAdmin
	} else {
		changes, admin := diffSettings(bm, dm)
		for _, c := range changes {
			reasons = append(reasons, Reason{Code: CodeSettingsChanged, Path: c.Path, Detail: "settings path " + c.Path + " " + c.Kind})
		}
		if admin {
			role = config.RoleAdmin
		}
	}

	sort.Slice(reasons, func(i, j int) bool {
		a, b := reasons[i], reasons[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Detail < b.Detail
	})
	reasons = slices.Compact(reasons)
	if reasons == nil {
		reasons = []Reason{} // marshal as [], never null
	}
	return Classification{Widening: len(reasons) > 0, Reasons: reasons, RequiredRole: role}
}

// classifyUserLimits reports each per-user limit key that differs between
// base and draft (JSON equality of the normalized rules). An unencodable value
// fails closed as changed.
func classifyUserLimits(base, draft Doc) []Reason {
	var out []Reason
	for _, k := range []struct {
		path string
		a, b any
	}{
		{"userLimits", base.UserLimits, draft.UserLimits},
		{"defaultUserLimit", base.DefaultUserLimit, draft.DefaultUserLimit},
		{"anonymousLimit", base.AnonymousLimit, draft.AnonymousLimit},
	} {
		if !jsonEqual(k.a, k.b) {
			out = append(out, Reason{Code: CodeUserLimitsChanged, Path: k.path, Detail: k.path + " changed"})
		}
	}
	return out
}

// jsonEqual reports whether a and b have the same JSON encoding, treating an
// empty list as absent. An encoding error is never equal.
func jsonEqual(a, b any) bool {
	ea, errA := json.Marshal(a)
	eb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	norm := func(b []byte) string {
		if s := string(b); s != "[]" {
			return s
		}
		return "null"
	}
	return norm(ea) == norm(eb)
}

func destPath(list, domain string, port int) string {
	return list + ":" + domain + ":" + strconv.Itoa(port)
}

func destDetail(domain string, port int) string {
	return "domain=" + domain + " port=" + strconv.Itoa(port)
}

// allowSig is the full identity of an allow entry: its DiffKey plus every
// attribute the key leaves out, so two entries with the same signature are
// interchangeable.
func allowSig(e config.AllowlistEntry) string {
	var b strings.Builder
	b.WriteString(e.DiffKey())
	b.WriteString("|m=")
	b.WriteString(sortedJoin(e.Methods))
	b.WriteString("|p=")
	b.WriteString(sortedJoin(e.Paths))
	b.WriteString("|rl=")
	b.WriteString(strconv.Quote(e.RateLimit))
	b.WriteString("|tw=")
	b.WriteString(strconv.Quote(e.TimeWindow))
	return b.String()
}

func sortedJoin(vs []string) string {
	c := slices.Clone(vs)
	slices.Sort(c)
	for i, v := range c {
		c[i] = strconv.Quote(v)
	}
	return strings.Join(c, ",")
}

type allowGroup struct {
	e     config.AllowlistEntry
	count int
}

// allowDelta returns, per signature, the draft count minus the base count with
// one representative entry.
func allowDelta(base, draft []config.AllowlistEntry) map[string]*allowGroup {
	m := make(map[string]*allowGroup, len(base)+len(draft))
	add := func(e config.AllowlistEntry, d int) {
		s := allowSig(e)
		g := m[s]
		if g == nil {
			g = &allowGroup{e: e}
			m[s] = g
		}
		g.count += d
	}
	for _, e := range base {
		add(e, -1)
	}
	for _, e := range draft {
		add(e, 1)
	}
	return m
}

type sigEntry struct {
	sig string
	e   config.AllowlistEntry
}

func classifyAllow(base, draft []config.AllowlistEntry) []Reason {
	added := map[string][]sigEntry{}   // domain|port -> entries only in draft
	removed := map[string][]sigEntry{} // domain|port -> entries only in base
	for sig, g := range allowDelta(base, draft) {
		k := g.e.Domain + "|" + strconv.Itoa(g.e.Port)
		for n := g.count; n > 0; n-- {
			added[k] = append(added[k], sigEntry{sig, g.e})
		}
		for n := g.count; n < 0; n++ {
			removed[k] = append(removed[k], sigEntry{sig, g.e})
		}
	}
	reasons := sharedBucketReasons(base, draft)
	inDraft := make(map[string]bool, len(draft))
	for _, e := range draft {
		inDraft[e.Domain+"|"+strconv.Itoa(e.Port)] = true
	}

	for k, rs := range removed {
		// An entry with a deny-producing attribute (groups, users, methods,
		// paths, rateLimit, timeWindow) answers an explicit Deny for a request
		// it does not admit, which is not judge-eligible. Once no entry for the
		// destination is left that becomes no-match, which the proxy defers to
		// the judge (workers may configure one locally whatever settings.judge
		// says). The same removal also drops the canonical-path pre-pass a
		// paths constraint triggers. A plain unconstrained entry removed stays
		// narrowing.
		if inDraft[k] {
			continue
		}
		for _, r := range rs {
			if constrained(r.e) {
				reasons = append(reasons, Reason{CodeAllowRemovedToJudge, destPath("allowlist", r.e.Domain, r.e.Port), destDetail(r.e.Domain, r.e.Port)})
			}
		}
	}
	for k, as := range added {
		rs := removed[k]
		slices.SortFunc(rs, func(a, b sigEntry) int { return strings.Compare(a.sig, b.sig) })
		slices.SortFunc(as, func(a, b sigEntry) int { return strings.Compare(a.sig, b.sig) })
		used := make([]bool, len(rs))
		for _, a := range as {
			path := destPath("allowlist", a.e.Domain, a.e.Port)
			detail := destDetail(a.e.Domain, a.e.Port)
			if len(rs) == 0 {
				reasons = append(reasons, Reason{CodeAllowAdded, path, detail})
				continue
			}
			// Each scoped entry owns a rate bucket and an exhausted one falls
			// through to the next entry, so one removed rate-limited entry may
			// justify only ONE added rate-limited entry: pair 1:1.
			needsOwn := a.e.RateLimit != ""
			match := -1
			var best []string
			for i, r := range rs {
				codes := widenedBy(a.e, r.e)
				if len(codes) == 0 {
					if needsOwn && r.e.RateLimit != "" && used[i] {
						codes = []string{CodeAllowRateRelaxed}
					} else {
						if !needsOwn || r.e.RateLimit == "" {
							match = i
							break // an unlimited base entry needs no consuming
						}
						if match < 0 {
							match = i
						}
						continue
					}
				}
				if match < 0 && (best == nil || len(codes) < len(best)) {
					best = codes
				}
			}
			if match >= 0 {
				if needsOwn && rs[match].e.RateLimit != "" {
					used[match] = true
				}
				continue
			}
			for _, c := range best {
				reasons = append(reasons, Reason{c, path, detail})
			}
		}
	}
	return reasons
}

// constrained reports whether the entry can answer an explicit Deny for a
// request on its destination.
func constrained(e config.AllowlistEntry) bool {
	return scoped(e) || len(e.Methods) > 0 || len(e.Paths) > 0 || e.RateLimit != "" || e.TimeWindow != ""
}

// widenedBy returns the reason codes for which the new entry a is wider than
// the removed entry r on the same domain and port; none means a is no wider.
func widenedBy(a, r config.AllowlistEntry) []string {
	var codes []string
	// A rate-limited entry that gains a scope gets a bucket of its own, so a
	// new scope can multiply the effective rate: report it as relaxed.
	if a.RateLimit != "" && r.RateLimit != "" && scoped(a) && !scoped(r) {
		codes = append(codes, CodeAllowRateRelaxed)
	}
	if !scopeNoWider(a, r) {
		codes = append(codes, CodeAllowScopeWide)
	}
	if !rateNoWider(a.RateLimit, r.RateLimit) {
		codes = append(codes, CodeAllowRateRelaxed)
	}
	if !timeNoWider(a.TimeWindow, r.TimeWindow) {
		codes = append(codes, CodeAllowTimeRelaxed)
	}
	if !subsetOrUnrestricted(a.Methods, r.Methods) || !subsetOrUnrestricted(a.Paths, r.Paths) {
		codes = append(codes, CodeAllowConstraint)
	}
	return codes
}

func scoped(e config.AllowlistEntry) bool { return len(e.Groups) > 0 || len(e.Users) > 0 }

// scopeNoWider: an unscoped base admits everyone, so any new scope is no
// wider. A scoped base is only matched by a scoped entry whose groups and
// users are each a subset.
func scopeNoWider(a, r config.AllowlistEntry) bool {
	if !scoped(r) {
		return true
	}
	return scoped(a) && subset(a.Groups, r.Groups) && subset(a.Users, r.Users)
}

func subset(a, b []string) bool {
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}
	return true
}

// subsetOrUnrestricted: an empty list is "unrestricted", so it is the widest.
func subsetOrUnrestricted(a, r []string) bool {
	if len(r) == 0 {
		return true
	}
	return len(a) > 0 && subset(a, r)
}

// rateNoWider reports whether the new rateLimit a is as tight as or tighter
// than the old one r. No limit is the loosest; an unparseable new value is
// widening, an unchanged one is not.
func rateNoWider(a, r string) bool {
	if a == r {
		return true
	}
	if a == "" {
		return false
	}
	al, err := policy.ParseRateLimit(a)
	if err != nil {
		return false
	}
	if r == "" {
		return true
	}
	rl, err := policy.ParseRateLimit(r)
	if err != nil {
		return false
	}
	// No wider only when neither the count nor the burst grows: 2/minute to
	// 120/hour has a lower average but admits a 120-request burst.
	return al.Limit <= rl.Limit && al.Window >= rl.Window
}

// timeNoWider reports whether the hours admitted by a are a subset of those
// admitted by r. No window is all day; an unparseable new value is widening.
func timeNoWider(a, r string) bool {
	if a == r {
		return true
	}
	if a == "" {
		return false
	}
	am, err := policy.TimeWindowHours(a)
	if err != nil {
		return false
	}
	if r == "" {
		return true
	}
	rm, err := policy.TimeWindowHours(r)
	if err != nil {
		return false
	}
	return am&^rm == 0
}

// classifyDeny: a deny entry that is gone from the draft (removed, or changed
// to another domain or port) unblocks something, so it widens. Adding one
// narrows. Duplicates are a multiset, so dropping one of two still counts.
func classifyDeny(base, draft []config.DenylistEntry) []Reason {
	counts := map[string]int{}
	ents := map[string]config.DenylistEntry{}
	for _, e := range base {
		k := e.DiffKey()
		counts[k]--
		ents[k] = e
	}
	for _, e := range draft {
		counts[e.DiffKey()]++
	}
	var reasons []Reason
	for k, c := range counts {
		if c < 0 {
			e := ents[k]
			reasons = append(reasons, Reason{CodeDenyRemoved, destPath("denylist", e.Domain, e.Port), destDetail(e.Domain, e.Port)})
		}
	}
	return reasons
}

// sharedBucketReasons covers the unscoped rate buckets. Unscoped entries with
// the same normalised domain and effective port (port 0 draws on both 443 and
// 80; "D.com" and "d.com" are one) share ONE bucket: whichever entry opens it
// sets the window, and a request that fails one entry and falls through to
// the next is charged again. So when such a bucket holds two or more
// rate-limited entries on either side, any change to the bucket's set of
// entries can change every member's effective rate, and entries cannot be
// judged one at a time: report allow.rate_relaxed. The evaluator's semantics
// are not changed; this errs on the side of a second person.
func sharedBucketReasons(base, draft []config.AllowlistEntry) []Reason {
	group := func(es []config.AllowlistEntry) map[string][]string {
		m := map[string][]string{}
		for _, e := range es {
			if e.RateLimit == "" || scoped(e) {
				continue
			}
			for _, k := range policy.RateBucketKeys(e.Domain, e.Port) {
				m[k] = append(m[k], allowSig(e))
			}
		}
		for k := range m {
			slices.Sort(m[k])
		}
		return m
	}
	bg, dg := group(base), group(draft)
	var reasons []Reason
	emit := func(k string) {
		i := strings.LastIndex(k, ":")
		port, _ := strconv.Atoi(k[i+1:])
		reasons = append(reasons, Reason{CodeAllowRateRelaxed, destPath("allowlist", k[:i], port), destDetail(k[:i], port)})
	}
	for k := range union(bg, dg) {
		b, d := bg[k], dg[k]
		if (len(b) < 2 && len(d) < 2) || slices.Equal(b, d) {
			continue
		}
		emit(k)
	}
	// The evaluator walks entries in order: a request that fails one entry
	// falls through (and is charged) to the next, and the entry that opens a
	// shared bucket sets its window. So for a host and port with a shared
	// bucket the ordered sequence of every entry that could match it must be
	// unchanged. Not modelled: any difference, including a reorder, is
	// reported (#648 tracks fixing the evaluator so order stops mattering).
	for k := range union(bg, dg) {
		if len(bg[k]) < 2 && len(dg[k]) < 2 {
			continue
		}
		if !slices.Equal(candidateSeq(base, k), candidateSeq(draft, k)) {
			emit(k)
		}
	}
	return slices.Compact(sortedReasons(reasons))
}

// candidateSeq returns, in doc order, the signature of every allow entry that
// could match the bucket key k: same literal key, or a regex or wildcard entry
// on that port (treated as possibly matching), or anything when k itself is a
// regex or wildcard pattern.
func candidateSeq(es []config.AllowlistEntry, k string) []string {
	i := strings.LastIndex(k, ":")
	host := k[:i]
	port, _ := strconv.Atoi(k[i+1:])
	patternKey := strings.HasPrefix(host, "~") || strings.HasPrefix(host, "*.")
	var out []string
	for _, e := range es {
		if e.Port != 0 && e.Port != port {
			continue
		}
		pattern := strings.HasPrefix(e.Domain, "~") || strings.HasPrefix(e.Domain, "*.")
		if patternKey || pattern || slices.Contains(policy.RateBucketKeys(e.Domain, e.Port), k) {
			out = append(out, allowSig(e))
		}
	}
	return out
}

func sortedReasons(rs []Reason) []Reason {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Detail < b.Detail
	})
	return rs
}

func union(a, b map[string][]string) map[string]struct{} {
	out := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}
