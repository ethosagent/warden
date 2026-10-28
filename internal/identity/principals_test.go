package identity_test

import (
	"testing"

	"github.com/ethosagent/warden/internal/identity"
)

func TestPrincipals(t *testing.T) {
	sub := func(mod func(*identity.Subject)) *identity.Subject {
		s := &identity.Subject{Sub: "u-1", Email: "alice@corp.example", EmailVerified: true, Groups: []string{"eng"}}
		if mod != nil {
			mod(s)
		}
		return s
	}
	cases := []struct {
		name          string
		groups, users []string
		s             *identity.Subject
		want          identity.MatchResult
	}{
		{"nil subject", []string{"eng"}, nil, nil, identity.NoIdentity},
		{"group member", []string{"eng"}, nil, sub(nil), identity.Member},
		{"group case-sensitive", []string{"ENG"}, nil, sub(nil), identity.NotMember},
		{"group non-member", []string{"sales"}, nil, sub(nil), identity.NotMember},
		{"email verified", nil, []string{"alice@corp.example"}, sub(nil), identity.Member},
		{"email unverified", nil, []string{"alice@corp.example"}, sub(func(s *identity.Subject) { s.EmailVerified = false }), identity.NotMember},
		{"email never matches sub", nil, []string{"alice@corp.example"}, sub(func(s *identity.Subject) { s.Sub = "alice@corp.example"; s.Email = "" }), identity.NotMember},
		{"sub exact", nil, []string{"u-1"}, sub(nil), identity.Member},
		{"sub never matches email", nil, []string{"u-1"}, sub(func(s *identity.Subject) { s.Sub = "x"; s.Email = "u-1" }), identity.NotMember},
		{"sub case-sensitive", nil, []string{"U-1"}, sub(nil), identity.NotMember},
		{"both lists, user hits", []string{"sales"}, []string{"u-1"}, sub(nil), identity.Member},
		{"both lists, group hits", []string{"eng"}, []string{"u-9"}, sub(nil), identity.Member},
		{"truncated member", []string{"eng"}, nil, sub(func(s *identity.Subject) { s.GroupsTruncated = true }), identity.Member},
		{"truncated miss", []string{"sales"}, nil, sub(func(s *identity.Subject) { s.GroupsTruncated = true }), identity.TruncatedMiss},
		{"truncated, user hits", []string{"sales"}, []string{"u-1"}, sub(func(s *identity.Subject) { s.GroupsTruncated = true }), identity.Member},
		{"truncated users-only is plain miss", nil, []string{"u-9"}, sub(func(s *identity.Subject) { s.GroupsTruncated = true }), identity.NotMember},
		{"empty principals", nil, nil, sub(nil), identity.NotMember},
		{"empty sub never matches", nil, []string{"u-1"}, &identity.Subject{}, identity.NotMember},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := identity.CompilePrincipals(c.groups, c.users).Match(c.s); got != c.want {
				t.Fatalf("Match = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSubjectFromCopiesGroupsTruncated(t *testing.T) {
	s := identity.SubjectFrom(identity.Claims{Sub: "u", Groups: []string{"a"}, GroupsTruncated: true}, identity.StatusValid)
	if s == nil || !s.GroupsTruncated {
		t.Fatalf("GroupsTruncated not copied: %+v", s)
	}
	if s := identity.SubjectFrom(identity.Claims{Sub: "u"}, identity.StatusValid); s.GroupsTruncated {
		t.Fatal("GroupsTruncated set without the claim")
	}
}
