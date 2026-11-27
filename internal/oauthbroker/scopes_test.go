package oauthbroker

import (
	"reflect"
	"testing"
)

func TestParseScopes(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a b c", []string{"a", "b", "c"}},
		{"repo,read:org", []string{"read:org", "repo"}},
		{"b, a  ,b\ta\n", []string{"a", "b"}},
		{"https://www.googleapis.com/auth/drive openid", []string{"https://www.googleapis.com/auth/drive", "openid"}},
		{",,", nil},
		{"Repo repo", []string{"Repo", "repo"}}, // case-sensitive
	}
	for _, tc := range cases {
		if got := ParseScopes(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseScopes(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func TestCapScopes(t *testing.T) {
	cases := []struct {
		name                  string
		req, allowed          []string
		wantCapped, wantRejec []string
	}{
		{"all inside", []string{"b", "a"}, []string{"a", "b", "c"}, []string{"a", "b"}, nil},
		{"some outside", []string{"a", "x"}, []string{"a", "b"}, []string{"a"}, []string{"x"}},
		{"all outside", []string{"x"}, []string{"a"}, nil, []string{"x"}},
		{"empty allowed rejects everything", []string{"a"}, nil, nil, []string{"a"}},
		{"empty request", nil, []string{"a"}, nil, nil},
		{"duplicates and empties", []string{"a", "a", "", "x", "x"}, []string{"a"}, []string{"a"}, []string{"x"}},
		{"case sensitive", []string{"Repo"}, []string{"repo"}, nil, []string{"Repo"}},
		{"prefix is not inside", []string{"repo:admin"}, []string{"repo"}, nil, []string{"repo:admin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, r := CapScopes(tc.req, tc.allowed)
			if !reflect.DeepEqual(c, tc.wantCapped) || !reflect.DeepEqual(r, tc.wantRejec) {
				t.Errorf("CapScopes = %#v, %#v; want %#v, %#v", c, r, tc.wantCapped, tc.wantRejec)
			}
		})
	}
	// The inputs are not mutated.
	req := []string{"b", "a"}
	CapScopes(req, []string{"a", "b"})
	if req[0] != "b" {
		t.Error("CapScopes mutated its input")
	}
}

func TestScopeHelpers(t *testing.T) {
	if got := JoinScopes([]string{"b", "a", "a"}); got != "a b" {
		t.Errorf("JoinScopes = %q", got)
	}
	if got := UnionScopes([]string{"b"}, []string{"a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("UnionScopes = %v", got)
	}
}
