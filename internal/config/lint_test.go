package config

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLintScoped(t *testing.T) {
	g := []string{"eng"}
	cases := []struct {
		name string
		list []AllowlistEntry
		want []string
	}{
		{"no scoped entries", []AllowlistEntry{{Domain: "a.com"}, {Domain: "*.a.com"}}, nil},
		{"empty", nil, nil},
		{"wildcard shadows exact", []AllowlistEntry{
			{Domain: "*.github.com"}, {Domain: "x.com"},
			{Domain: "api.github.com", Groups: g},
		}, []string{"allowlist[2] (api.github.com, groups) is shadowed by allowlist[0] (*.github.com), which admits everyone"}},
		{"reversed order same warning", []AllowlistEntry{
			{Domain: "api.github.com", Users: []string{"a@x.com"}}, {Domain: "*.github.com"},
		}, []string{"allowlist[0] (api.github.com, users) is shadowed by allowlist[1] (*.github.com), which admits everyone"}},
		{"same domain, groups and users", []AllowlistEntry{
			{Domain: "a.com", Groups: g, Users: []string{"u"}}, {Domain: "A.com."},
		}, []string{"allowlist[0] (a.com, groups+users) is shadowed by allowlist[1] (A.com.), which admits everyone"}},
		{"narrower unscoped methods", []AllowlistEntry{
			{Domain: "*.github.com", Methods: []string{"GET"}}, {Domain: "api.github.com", Groups: g},
		}, nil},
		{"narrower unscoped methods vs wider scoped", []AllowlistEntry{
			{Domain: "*.github.com", Methods: []string{"GET"}},
			{Domain: "api.github.com", Groups: g, Methods: []string{"GET", "POST"}},
		}, nil},
		{"unscoped methods superset", []AllowlistEntry{
			{Domain: "*.github.com", Methods: []string{"GET", "POST"}},
			{Domain: "api.github.com", Groups: g, Methods: []string{"GET"}},
		}, []string{"allowlist[1] (api.github.com, groups) is shadowed by allowlist[0] (*.github.com), which admits everyone"}},
		{"narrower unscoped paths", []AllowlistEntry{
			{Domain: "a.com", Paths: []string{"/v1/*"}}, {Domain: "a.com", Groups: g},
		}, nil},
		{"unscoped path prefix covers scoped", []AllowlistEntry{
			{Domain: "a.com", Paths: []string{"/v1/*"}}, {Domain: "a.com", Groups: g, Paths: []string{"/v1/x", "/v1/y/*"}},
		}, []string{"allowlist[1] (a.com, groups) is shadowed by allowlist[0] (a.com), which admits everyone"}},
		{"unscoped with rate limit is not shadowing", []AllowlistEntry{
			{Domain: "a.com", RateLimit: "10/second"}, {Domain: "a.com", Groups: g},
		}, nil},
		{"different port", []AllowlistEntry{
			{Domain: "a.com", Port: 8443}, {Domain: "a.com", Groups: g},
		}, nil},
		{"default port covers 443", []AllowlistEntry{
			{Domain: "a.com"}, {Domain: "a.com", Port: 443, Groups: g},
		}, []string{"allowlist[1] (a.com, groups) is shadowed by allowlist[0] (a.com), which admits everyone"}},
		{"explicit port does not cover default", []AllowlistEntry{
			{Domain: "a.com", Port: 443}, {Domain: "a.com", Groups: g},
		}, nil},
		{"scoped not shadowed by another scoped", []AllowlistEntry{
			{Domain: "*.a.com", Groups: g}, {Domain: "b.a.com", Groups: g},
		}, nil},
		{"wildcard does not cover apex", []AllowlistEntry{
			{Domain: "*.a.com"}, {Domain: "a.com", Groups: g},
		}, nil},
		{"wildcard covers narrower wildcard", []AllowlistEntry{
			{Domain: "*.a.com"}, {Domain: "*.b.a.com", Groups: g},
		}, []string{"allowlist[1] (*.b.a.com, groups) is shadowed by allowlist[0] (*.a.com), which admits everyone"}},
		{"narrower wildcard does not cover wider", []AllowlistEntry{
			{Domain: "*.b.a.com"}, {Domain: "*.a.com", Groups: g},
		}, nil},
		{"regex covers exact", []AllowlistEntry{
			{Domain: `~^api\..*\.com$`}, {Domain: "api.x.com", Groups: g},
		}, []string{`allowlist[1] (api.x.com, groups) is shadowed by allowlist[0] (~^api\..*\.com$), which admits everyone`}},
		{"regex not matching exact", []AllowlistEntry{
			{Domain: `~^api\.`}, {Domain: "web.x.com", Groups: g},
		}, nil},
		{"regex vs wildcard undecidable", []AllowlistEntry{
			{Domain: `~.*`}, {Domain: "*.x.com", Groups: g},
		}, nil},
		{"unscoped with time window is not shadowing", []AllowlistEntry{
			{Domain: "a.com", TimeWindow: "9-17"}, {Domain: "a.com", Groups: g},
		}, nil},
		{"deterministic: first shadowing entry, entry order", []AllowlistEntry{
			{Domain: "b.com", Groups: g}, {Domain: "a.com", Groups: g},
			{Domain: "*.com"}, {Domain: "a.com"}, {Domain: "b.com"},
		}, []string{
			"allowlist[0] (b.com, groups) is shadowed by allowlist[2] (*.com), which admits everyone",
			"allowlist[1] (a.com, groups) is shadowed by allowlist[2] (*.com), which admits everyone",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LintScoped(Policy{Allowlist: tc.list})
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestLintScoped_NoPrincipalValues(t *testing.T) {
	p := Policy{Allowlist: []AllowlistEntry{
		{Domain: "*.a.com"},
		{Domain: "x.a.com", Groups: []string{"SECRET-GROUP"}, Users: []string{"victim@corp.example"}},
	}}
	got := strings.Join(LintScoped(p), "\n")
	if got == "" {
		t.Fatal("expected a warning")
	}
	for _, leak := range []string{"SECRET-GROUP", "victim@corp.example", "corp.example"} {
		if strings.Contains(got, leak) {
			t.Fatalf("warning leaks %q: %s", leak, got)
		}
	}
}

func TestLintScoped_BoundsLongPattern(t *testing.T) {
	long := "~" + strings.Repeat("a", 500)
	got := LintScoped(Policy{Allowlist: []AllowlistEntry{
		{Domain: long}, {Domain: strings.Repeat("a", 500), Groups: []string{"g"}},
	}})
	if len(got) != 1 || len(got[0]) > 300 {
		t.Fatalf("warning not bounded: %d %q", len(got), got)
	}
}

func TestLintScoped_TruncationKeepsValidUTF8(t *testing.T) {
	long := strings.Repeat("é", 100)
	got := LintScoped(Policy{Allowlist: []AllowlistEntry{
		{Domain: long}, {Domain: long, Groups: []string{"g"}},
	}})
	if len(got) != 1 || !utf8.ValidString(got[0]) {
		t.Fatalf("invalid UTF-8 in warning: %q", got)
	}
}
