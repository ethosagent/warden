package apikeys

import (
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func TestP2ScopesRegistered(t *testing.T) {
	reg := NewP2Registry()
	want := map[Scope]config.Role{
		"policy:read": config.RoleViewer, "settings:read": config.RoleViewer,
		"traffic:read": config.RoleViewer, "audit:read": config.RoleViewer,
		"policy:draft": config.RoleEditor, "policy:write": config.RoleEditor,
		"adminaudit:read": config.RoleAdmin, "agents:read": config.RoleAdmin,
		"agents:write": config.RoleAdmin, "workers:admin": config.RoleAdmin,
	}
	for s, role := range want {
		if got, ok := reg.Lookup(s); !ok || got != role {
			t.Errorf("Lookup(%s) = %v, %v; want %v", s, got, ok, role)
		}
	}
	if len(reg.Registered()) != len(want) {
		t.Errorf("Registered() = %v, want exactly the P2 scopes", reg.Registered())
	}
}

func TestParseScopes(t *testing.T) {
	reg := NewP2Registry()
	got, err := reg.ParseScopes([]string{"policy:read", "audit:read"})
	if err != nil || len(got) != 2 || got[0] != "policy:read" {
		t.Fatalf("ParseScopes valid = %v, %v", got, err)
	}
	for _, tc := range []struct {
		in   []string
		want error
	}{
		{[]string{"foo:bar"}, ErrUnknownScope},
		{[]string{"policy:read", "policy:read"}, ErrDuplicateScope},
		{nil, ErrNoScopes},
		{[]string{string(ScopeNone)}, ErrUnknownScope},
		{[]string{string(ScopeSelf)}, ErrUnknownScope},
		{[]string{"mcp:read"}, ErrUnknownScope},     // reserved, not registered
		{[]string{"grants:write"}, ErrUnknownScope}, // reserved, not registered
		{[]string{"Policy:Read"}, ErrUnknownScope},
	} {
		if _, err := reg.ParseScopes(tc.in); !errors.Is(err, tc.want) {
			t.Errorf("ParseScopes(%v) = %v, want %v", tc.in, err, tc.want)
		}
	}
}

func TestRegister(t *testing.T) {
	reg := NewP2Registry()
	for _, bad := range []Scope{"", "nocolon", "a:b:c", "UP:per", "policy:", ":read", ScopeNone, ScopeSelf} {
		if err := reg.Register(bad, config.RoleViewer); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("Register(%q) = %v, want ErrInvalidScope", bad, err)
		}
	}
	if err := reg.Register("zz:test", config.Role(0)); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("Register with no role = %v", err)
	}
	if err := reg.Register("policy:read", config.RoleAdmin); !errors.Is(err, ErrDuplicateScope) {
		t.Errorf("duplicate Register = %v", err)
	}
	if r, _ := reg.Lookup("policy:read"); r != config.RoleViewer {
		t.Error("a rejected duplicate changed the registered role")
	}
}

func TestReservedAndMaxRole(t *testing.T) {
	reg := NewP2Registry()
	for _, s := range []Scope{"mcp:read", "mcp:write", "grants:read", "grants:write"} {
		if !Reserved(s) {
			t.Errorf("%s not reserved", s)
		}
		if _, ok := reg.Lookup(s); ok {
			t.Errorf("%s is reserved but already registered", s)
		}
	}
	if Reserved("policy:read") {
		t.Error("a registered scope reported as reserved")
	}
	if got := reg.MaxRole([]Scope{"policy:read", "policy:write"}); got != config.RoleEditor {
		t.Errorf("MaxRole = %v, want editor", got)
	}
	if got := reg.MaxRole([]Scope{"policy:read", "workers:admin"}); got != config.RoleAdmin {
		t.Errorf("MaxRole = %v, want admin", got)
	}
	if got := reg.MaxRole(nil); got != 0 {
		t.Errorf("reg.MaxRole(nil) = %v", got)
	}
}
