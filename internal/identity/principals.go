package identity

import "strings"

// MatchResult is the outcome of matching a Subject against a rule's principals.
type MatchResult uint8

const (
	// NoIdentity: there is no verified subject (nil), so no principal can match.
	NoIdentity MatchResult = iota
	// Member: the subject is named by the rule (by group or by user).
	Member
	// NotMember: the subject is not named by the rule.
	NotMember
	// TruncatedMiss: the subject is not a member, but its group list was cut
	// (Subject.GroupsTruncated), the rule has groups, and no user entry matched,
	// so the miss may be an artifact of the cut.
	TruncatedMiss
)

// Principals is a rule's compiled groups/users list. The zero value matches no
// subject. It is immutable after CompilePrincipals and safe for concurrent use.
type Principals struct {
	groups map[string]struct{}
	emails map[string]struct{} // lower-cased
	subs   map[string]struct{}
}

// CompilePrincipals compiles a rule's groups and users. A user containing "@"
// is an email (matched against a verified Subject.Email); any other user is an
// exact IdP sub. Groups are exact and case-sensitive.
func CompilePrincipals(groups, users []string) Principals {
	var p Principals
	if len(groups) > 0 {
		p.groups = make(map[string]struct{}, len(groups))
		for _, g := range groups {
			p.groups[g] = struct{}{}
		}
	}
	for _, u := range users {
		if strings.Contains(u, "@") {
			if p.emails == nil {
				p.emails = make(map[string]struct{})
			}
			p.emails[strings.ToLower(u)] = struct{}{}
			continue
		}
		if p.subs == nil {
			p.subs = make(map[string]struct{})
		}
		p.subs[u] = struct{}{}
	}
	return p
}

// Match reports whether s is named by the principals. An entry with both lists
// matches when either does. A member found in a truncated group list is still
// a member; only a miss in a truncated list is reported as TruncatedMiss, and
// only for a rule that has groups (users-only rules are unaffected).
func (p Principals) Match(s *Subject) MatchResult {
	if s == nil {
		return NoIdentity
	}
	if _, ok := p.subs[s.Sub]; ok && s.Sub != "" {
		return Member
	}
	if s.EmailVerified && s.Email != "" {
		if _, ok := p.emails[strings.ToLower(s.Email)]; ok {
			return Member
		}
	}
	for _, g := range s.Groups {
		if _, ok := p.groups[g]; ok {
			return Member
		}
	}
	if s.GroupsTruncated && len(p.groups) > 0 {
		return TruncatedMiss
	}
	return NotMember
}
