package config

import (
	"fmt"
	"regexp"
	"strings"
)

// maxLintPattern bounds a domain pattern echoed into a warning so a long regex
// cannot blow up a log line.
const maxLintPattern = 64

// LintScoped returns one warning per group/user-scoped allow entry that an
// unscoped entry already shadows (W-P1-GPOL-12): the unscoped entry admits
// everyone for the same destination, so the scope never restricts anything.
// An unscoped entry shadows a scoped one when its domain pattern covers the
// scoped entry's (same pattern, or a "*.suffix" / "~regex" pattern that
// provably covers it), its port covers the scoped port, and its methods and
// paths are not narrower. An unscoped entry with a timeWindow or rateLimit is
// never treated as shadowing: it does not admit everyone unconditionally.
//
// Pure: no I/O and no dependency on the evaluator, so the domain dialect
// (exact, "*.suffix", "~regex") is mirrored here. Coverage is decided
// conservatively: when it cannot be proven (a regex against a wildcard, say)
// no warning is produced. Warnings carry entry indexes and domain patterns
// only, never a group or user value. The result is in allowlist order (nil
// when nothing is shadowed).
func LintScoped(p Policy) []string {
	var out []string
	for i, s := range p.Allowlist {
		if !s.scoped() {
			continue
		}
		for j, u := range p.Allowlist {
			if j == i || u.scoped() || !entryShadows(u, s) {
				continue
			}
			out = append(out, fmt.Sprintf(
				"allowlist[%d] (%s, %s) is shadowed by allowlist[%d] (%s), which admits everyone",
				i, lintPattern(s.Domain), s.scopeLabel(), j, lintPattern(u.Domain)))
			break
		}
	}
	return out
}

func (e AllowlistEntry) scoped() bool { return len(e.Groups) > 0 || len(e.Users) > 0 }

// scopeLabel names the kinds of scope on a scoped entry, never their values.
func (e AllowlistEntry) scopeLabel() string {
	switch {
	case len(e.Groups) > 0 && len(e.Users) > 0:
		return "groups+users"
	case len(e.Groups) > 0:
		return "groups"
	}
	return "users"
}

func lintPattern(d string) string {
	if len(d) > maxLintPattern {
		return strings.ToValidUTF8(d[:maxLintPattern], "") + "..."
	}
	return d
}

// entryShadows reports whether the unscoped entry u admits every request the
// scoped entry s could admit.
func entryShadows(u, s AllowlistEntry) bool {
	if u.TimeWindow != "" || u.RateLimit != "" {
		return false
	}
	if !portCovers(u.Port, s.Port) || !domainCovers(u.Domain, s.Domain) {
		return false
	}
	return methodsCover(u.Methods, s.Methods) && pathsCover(u.Paths, s.Paths)
}

// portCovers: a zero port means 80 or 443 depending on the scheme.
func portCovers(u, s int) bool {
	if u == s {
		return true
	}
	return u == 0 && (s == 80 || s == 443)
}

func lintHost(d string) string { return strings.TrimRight(strings.ToLower(d), ".") }

// domainCovers reports whether every host matched by pattern s is matched by
// pattern u, in the exact / "*.suffix" / "~regex" dialect.
func domainCovers(u, s string) bool {
	if u == s {
		return true
	}
	if rx, ok := strings.CutPrefix(u, "~"); ok {
		// A regex is only checked against an exact host; against a wildcard or
		// another regex coverage is undecidable, so stay silent.
		if strings.HasPrefix(s, "~") || strings.Contains(s, "*") {
			return false
		}
		re, err := regexp.Compile(rx)
		return err == nil && re.MatchString(lintHost(s))
	}
	if strings.HasPrefix(s, "~") {
		return false
	}
	u, s = lintHost(u), lintHost(s)
	if u == s {
		return true
	}
	suffix, ok := strings.CutPrefix(u, "*.")
	if !ok {
		return false
	}
	if sSuffix, sw := strings.CutPrefix(s, "*."); sw {
		return sSuffix == suffix || strings.HasSuffix(sSuffix, "."+suffix)
	}
	return s != suffix && strings.HasSuffix(s, "."+suffix)
}

// methodsCover: an empty list is unrestricted; otherwise s must be a non-empty
// subset of u.
func methodsCover(u, s []string) bool {
	if len(u) == 0 {
		return true
	}
	if len(s) == 0 {
		return false
	}
	for _, m := range s {
		found := false
		for _, x := range u {
			if x == m {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// pathsCover: an empty list is unrestricted; otherwise every s pattern must be
// covered by some u pattern (identical, or under a "/prefix/*" of u).
func pathsCover(u, s []string) bool {
	if len(u) == 0 {
		return true
	}
	if len(s) == 0 {
		return false
	}
	for _, sp := range s {
		found := false
		for _, up := range u {
			if pathCovers(up, sp) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func pathCovers(u, s string) bool {
	if u == s {
		return true
	}
	prefix, ok := strings.CutSuffix(u, "/*")
	if !ok || strings.Contains(prefix, "*") {
		return false
	}
	s = strings.TrimSuffix(s, "/*")
	return s == prefix || strings.HasPrefix(s, prefix+"/")
}
