package approvals

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

// Reason codes. A change is widening exactly when it has at least one reason.
const (
	CodeAllowAdded       = "allow.added"              // an allow entry with no narrower base counterpart
	CodeAllowScopeWide   = "allow.scope_widened"      // same domain and port, groups/users no longer a subset
	CodeAllowRateRelaxed = "allow.rate_relaxed"       // same domain and port, rateLimit looser, removed or unparseable
	CodeAllowTimeRelaxed = "allow.time_relaxed"       // same domain and port, timeWindow wider, removed or unparseable
	CodeAllowConstraint  = "allow.constraint_widened" // same domain and port, methods or paths less restricted
	CodeDenyRemoved      = "deny.removed"             // a deny entry removed or changed
	CodeSettingsChanged  = "settings.changed"
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
// where credentials go. It is pure and deterministic: no I/O, and the order of
// entries in either doc does not change the result. There is no regex or
// wildcard containment analysis: an allow key that is new is widening however
// narrow it looks. Anything it does not recognise counts as widening.
func Classify(base, draft Doc) Classification {
	var reasons []Reason
	reasons = append(reasons, classifyAllow(base.Allowlist, draft.Allowlist)...)
	reasons = append(reasons, classifyDeny(base.Denylist, draft.Denylist)...)

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
	return Classification{Widening: len(reasons) > 0, Reasons: reasons, RequiredRole: role}
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
	var reasons []Reason
	for k, as := range added {
		rs := removed[k]
		slices.SortFunc(rs, func(a, b sigEntry) int { return strings.Compare(a.sig, b.sig) })
		for _, a := range as {
			path := destPath("allowlist", a.e.Domain, a.e.Port)
			detail := destDetail(a.e.Domain, a.e.Port)
			if len(rs) == 0 {
				reasons = append(reasons, Reason{CodeAllowAdded, path, detail})
				continue
			}
			// Narrowing when some removed entry on the same destination is at
			// least as wide; otherwise report the closest one's reasons.
			var best []string
			for i, r := range rs {
				codes := widenedBy(a.e, r.e)
				if len(codes) == 0 {
					best = nil
					break
				}
				if i == 0 || len(codes) < len(best) {
					best = codes
				}
			}
			for _, c := range best {
				reasons = append(reasons, Reason{c, path, detail})
			}
		}
	}
	return reasons
}

// widenedBy returns the reason codes for which the new entry a is wider than
// the removed entry r on the same domain and port; none means a is no wider.
func widenedBy(a, r config.AllowlistEntry) []string {
	var codes []string
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
	al, aw, err := policy.ParseRateLimit(a)
	if err != nil {
		return false
	}
	if r == "" {
		return true
	}
	rl, rw, err := policy.ParseRateLimit(r)
	if err != nil {
		return false
	}
	// al/aw <= rl/rw  <=>  al*rw <= rl*aw
	return int64(al)*int64(rw) <= int64(rl)*int64(aw)
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
