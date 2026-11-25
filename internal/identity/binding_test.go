package identity_test

import (
	"testing"

	"github.com/ethosagent/warden/internal/identity"
)

func bindSnap(t *testing.T, agents map[string]identity.WardenAgent) *identity.WardenSnapshot {
	t.Helper()
	s, err := identity.NewWardenSnapshot(identity.WardenBundle{Generation: 1, Agents: agents})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBindingCheck(t *testing.T) {
	jkt := func(v ...string) map[string]struct{} {
		m := map[string]struct{}{}
		for _, x := range v {
			m[x] = struct{}{}
		}
		return m
	}
	snap := bindSnap(t, map[string]identity.WardenAgent{
		"a": {Active: true, JKT: jkt("T1", "T2")},
		"b": {Active: true, JKT: jkt("T3")},
		"d": {Active: false, JKT: jkt("T4")},
	})
	tok := func(act, k string) identity.Claims {
		return identity.Claims{TokenType: identity.TokenWarden, Act: act, CnfJKT: k}
	}
	for _, tc := range []struct {
		name   string
		snap   *identity.WardenSnapshot
		agent  string
		c      identity.Claims
		reason identity.Reason
	}{
		{"match", snap, "a", tok("a", "T1"), ""},
		{"second key", snap, "a", tok("a", "T2"), ""},
		{"mismatch", snap, "b", tok("a", "T1"), identity.ReasonAgentMismatch},
		{"cnf mismatch", snap, "a", tok("a", "T9"), identity.ReasonCnfMismatch},
		{"other agents key", snap, "a", tok("a", "T3"), identity.ReasonCnfMismatch},
		{"empty cnf", snap, "a", tok("a", ""), identity.ReasonCnfMismatch},
		{"empty act", snap, "a", tok("", "T1"), identity.ReasonAgentMismatch},
		{"disabled", snap, "d", tok("d", "T4"), identity.ReasonAgentDisabled},
		{"disabled wins over mismatch", snap, "d", tok("a", "T1"), identity.ReasonAgentDisabled},
		{"unregistered", snap, "agent:8080", tok("agent:8080", "T1"), identity.ReasonAgentUnregistered},
		{"unregistered wins over mismatch", snap, "zz", tok("a", "T1"), identity.ReasonAgentUnregistered},
		{"empty bound agent", snap, "", tok("", "T1"), identity.ReasonAgentUnregistered},
		{"nil snapshot", nil, "a", tok("a", "T1"), identity.ReasonAgentUnregistered},
		{"idp token", snap, "a", identity.Claims{TokenType: identity.TokenIdP, Act: "a", CnfJKT: "T1"}, identity.ReasonUnboundToken},
		{"untyped token", snap, "a", identity.Claims{Act: "a", CnfJKT: "T1"}, identity.ReasonUnboundToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := identity.BindingCheck(tc.snap, tc.agent, tc.c)
			if r != tc.reason || ok != (tc.reason == "") {
				t.Fatalf("BindingCheck = (%q, %v), want reason %q", r, ok, tc.reason)
			}
		})
	}
}

func TestBindingCheckNoAllocs(t *testing.T) {
	snap := bindSnap(t, map[string]identity.WardenAgent{"a": {Active: true, JKT: map[string]struct{}{"T1": {}}}})
	c := identity.Claims{TokenType: identity.TokenWarden, Act: "a", CnfJKT: "T1"}
	if n := testing.AllocsPerRun(100, func() { identity.BindingCheck(snap, "a", c) }); n != 0 {
		t.Fatalf("allocs = %v", n)
	}
}
