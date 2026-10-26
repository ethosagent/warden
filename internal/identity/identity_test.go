package identity_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/identity"
)

func TestSubjectFrom(t *testing.T) {
	c := identity.Claims{Sub: "u1", Email: "u@x.io", EmailVerified: true, Groups: []string{"a", "b"}, GroupsTruncated: true}
	for _, st := range []identity.Status{
		identity.StatusOff, identity.StatusNone, identity.StatusInvalid,
		identity.StatusExpired, identity.StatusUnverified, identity.StatusConflict,
	} {
		if identity.SubjectFrom(c, st) != nil {
			t.Errorf("status %s yielded a subject", st)
		}
	}
	s := identity.SubjectFrom(c, identity.StatusValid)
	if s == nil || s.Sub != "u1" || s.Email != "u@x.io" || !s.EmailVerified || !s.GroupsTruncated || s.AgentID != "" {
		t.Fatalf("subject = %+v", s)
	}
	s.Groups[0] = "mutated"
	if c.Groups[0] != "a" {
		t.Error("subject groups alias the claims slice")
	}
}

func TestGroupsNormalize(t *testing.T) {
	long := strings.Repeat("x", 300)
	many := make([]string, 100)
	for i := range many {
		many[i] = fmt.Sprintf("g%03d", i)
	}
	tests := []struct {
		name      string
		in        []string
		wantLen   int
		wantTrunc bool
	}{
		{"dn intact", []string{"cn=eng,ou=groups,dc=corp"}, 1, false},
		{"100 capped", many, 64, true},
		{"oversize dropped", []string{"a", "b", "c", long}, 3, true},
		{"normal", []string{"a", "b", "c"}, 3, false},
		{"dups", []string{"b", "a", "b", ""}, 2, false},
		{"nil", nil, 0, false},
	}
	for _, tc := range tests {
		got, trunc := identity.NormalizeGroups(tc.in)
		if len(got) != tc.wantLen || trunc != tc.wantTrunc {
			t.Errorf("%s: len=%d trunc=%v", tc.name, len(got), trunc)
		}
		if !slices.IsSorted(got) {
			t.Errorf("%s: not sorted", tc.name)
		}
	}
	got, _ := identity.NormalizeGroups([]string{"cn=eng,ou=groups,dc=corp"})
	if got[0] != "cn=eng,ou=groups,dc=corp" {
		t.Errorf("dn changed: %q", got[0])
	}
}

func TestReasonsBounded(t *testing.T) {
	rs := identity.Reasons()
	if len(rs) != 11 {
		t.Fatalf("len = %d", len(rs))
	}
	seen := map[identity.Reason]bool{}
	for _, r := range rs {
		if r == "" || seen[r] {
			t.Errorf("bad or duplicate reason %q", r)
		}
		seen[r] = true
	}
}

func TestApplyOptions(t *testing.T) {
	if identity.ApplyOptions().Nonce != "" {
		t.Error("default nonce set")
	}
	if identity.ApplyOptions(nil, identity.WithNonce("n")).Nonce != "n" {
		t.Error("nonce not applied")
	}
}

func TestNormalizeGroupsMax(t *testing.T) {
	var in []string
	for i := 0; i < 300; i++ {
		in = append(in, fmt.Sprintf("g%03d", i))
	}
	got, trunc := identity.NormalizeGroupsMax(in, identity.MaxConsoleGroups)
	if len(got) != identity.MaxConsoleGroups || !trunc {
		t.Fatalf("kept %d truncated=%v, want %d true", len(got), trunc, identity.MaxConsoleGroups)
	}
	if got, trunc := identity.NormalizeGroupsMax(in[:256], identity.MaxConsoleGroups); len(got) != 256 || trunc {
		t.Fatalf("exactly the cap: kept %d truncated=%v", len(got), trunc)
	}
	if got, _ := identity.NormalizeGroups(in); len(got) != identity.MaxGroups {
		t.Fatalf("default cap kept %d, want %d", len(got), identity.MaxGroups)
	}
}
