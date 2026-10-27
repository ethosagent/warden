package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNormalizePrincipals(t *testing.T) {
	g, u, err := normalizePrincipals("policy.allowlist[0]",
		[]string{" eng ", "eng"}, []string{"Alice@Corp.Example", "u-123", "alice@corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, []string{"eng"}) || !reflect.DeepEqual(u, []string{"alice@corp.example", "u-123"}) {
		t.Fatalf("got groups=%v users=%v", g, u)
	}
	// Groups are case-sensitive; a non-email user keeps its case.
	g, u, _ = normalizePrincipals("p", []string{"Eng", "eng"}, []string{"U-ABC"})
	if !reflect.DeepEqual(g, []string{"Eng", "eng"}) || !reflect.DeepEqual(u, []string{"U-ABC"}) {
		t.Fatalf("case handling: groups=%v users=%v", g, u)
	}
	if g, u, err = normalizePrincipals("p", nil, nil); err != nil || g != nil || u != nil {
		t.Fatalf("empty: %v %v %v", g, u, err)
	}

	many := make([]string, 257)
	for i := range many {
		many[i] = strings.Repeat("a", 5) + string(rune('A'+i%26)) + strings.Repeat("b", i/26)
	}
	cases := []struct {
		name   string
		groups []string
		users  []string
		want   string
	}{
		{"empty group", []string{"ok", "  "}, nil, "policy.allowlist[2].groups[1]"},
		{"empty user", nil, []string{""}, "policy.allowlist[2].users[0]"},
		{"257 values", many, nil, "policy.allowlist[2].groups"},
		{"257 users", nil, many, "policy.allowlist[2].users"},
		{"257 bytes", []string{strings.Repeat("x", 257)}, nil, "policy.allowlist[2].groups[0]"},
		{"257 byte user", nil, []string{"a", strings.Repeat("x", 257)}, "policy.allowlist[2].users[1]"},
	}
	for _, c := range cases {
		_, _, err := normalizePrincipals("policy.allowlist[2]", c.groups, c.users)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want path %q", c.name, err, c.want)
		}
	}
	// Exactly at the limits is fine.
	ok := make([]string, 256)
	for i := range ok {
		ok[i] = strings.Repeat("x", 250) + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	if _, _, err := normalizePrincipals("p", ok, nil); err != nil {
		t.Errorf("256 values of 252 bytes rejected: %v", err)
	}
}

func loadErr(t *testing.T, y string) error {
	t.Helper()
	_, err := NewLocalYAMLProvider(writeTemp(t, y))
	return err
}

func TestAllowlistGroupsRejectedUntilEnforced(t *testing.T) {
	for _, field := range []string{"groups: [eng]", "users: [alice@corp.example]"} {
		y := "policy:\n  allowlist:\n    - domain: a.com\n    - domain: b.com\n      " + field + "\n"
		err := loadErr(t, y)
		if err == nil || !strings.Contains(err.Error(), "policy.allowlist[1]") || !strings.Contains(err.Error(), "not yet enforced") {
			t.Errorf("%s: err = %v", field, err)
		}
	}
	// Bad values report their own path before the guard.
	err := loadErr(t, "policy:\n  allowlist:\n    - domain: a.com\n      groups: [ok, '']\n")
	if err == nil || !strings.Contains(err.Error(), "policy.allowlist[0].groups[1]") {
		t.Errorf("empty group: %v", err)
	}
}

const mcpHead = "policy: { allowlist: [ { domain: a.com } ] }\nmcp:\n  enabled: true\n  mode: enforce\n"

func TestMCPAllowWhenGroupsRejectedUntilEnforced(t *testing.T) {
	for _, field := range []string{"groups: [eng]", "users: [u-1]"} {
		y := mcpHead + "  tools:\n    allow: [deploy]\n    constraints:\n      deploy:\n        allowWhen:\n          " + field + "\n"
		err := loadErr(t, y)
		if err == nil || !strings.Contains(err.Error(), `mcp.tools.constraints["deploy"].allowWhen`) || !strings.Contains(err.Error(), "not yet enforced") {
			t.Errorf("%s: err = %v", field, err)
		}
	}
}

func TestDenylistGroupsRejected(t *testing.T) {
	err := loadErr(t, "policy:\n  allowlist:\n    - domain: a.com\n  denylist:\n    - domain: b.com\n      groups: [eng]\n")
	if err == nil {
		t.Fatal("denylist groups must fail to load")
	}
}

func TestScopeConstraintGroupsRejected(t *testing.T) {
	for _, field := range []string{"groups: [eng]", "users: [u-1]"} {
		y := mcpHead + "  scopes:\n    list:\n      - id: s\n        tools: [x]\n        constraints:\n          x:\n            allowWhen:\n              " + field + "\n"
		err := loadErr(t, y)
		if err == nil || !strings.Contains(err.Error(), `mcp.scopes.list["s"].constraints["x"].allowWhen`) || !strings.Contains(err.Error(), "task-scope") {
			t.Errorf("%s: err = %v", field, err)
		}
	}
}

func TestReservedScopedSentinelRejected(t *testing.T) {
	for _, where := range []string{
		"  tools:\n    allow: [x]\n    constraints:\n      x:\n        allowWhen:\n          agentId: '!identity-scoped'\n",
		"  scopes:\n    list:\n      - id: s\n        tools: [x]\n        constraints:\n          x:\n            allowWhen:\n              agentId: '!identity-scoped'\n",
	} {
		err := loadErr(t, mcpHead+where)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("sentinel accepted: %v", err)
		}
	}
	// An ordinary agent id still loads.
	if err := loadErr(t, mcpHead+"  tools:\n    allow: [x]\n    constraints:\n      x:\n        allowWhen:\n          agentId: ci-agent\n"); err != nil {
		t.Errorf("ordinary agent id rejected: %v", err)
	}
}

func TestDeepCopy_GroupsNotAliased(t *testing.T) {
	orig := Policy{
		Allowlist: []AllowlistEntry{{Domain: "a.com", Groups: []string{"eng"}, Users: []string{"u-1"}}},
		MCP: MCPConfig{Enabled: true, Tools: MCPToolsConfig{Constraints: map[string]MCPToolConstraints{
			"deploy": {AllowWhen: &MCPToolCondition{Groups: []string{"eng"}, Users: []string{"u-1"}}},
		}}},
	}
	cp := orig.DeepCopy()
	cp.Allowlist[0].Groups[0], cp.Allowlist[0].Users[0] = "X", "X"
	aw := cp.MCP.Tools.Constraints["deploy"].AllowWhen
	aw.Groups[0], aw.Users[0] = "X", "X"
	if orig.Allowlist[0].Groups[0] != "eng" || orig.Allowlist[0].Users[0] != "u-1" {
		t.Errorf("allow entry aliased: %+v", orig.Allowlist[0])
	}
	oaw := orig.MCP.Tools.Constraints["deploy"].AllowWhen
	if oaw.Groups[0] != "eng" || oaw.Users[0] != "u-1" {
		t.Errorf("MCP condition aliased: %+v", oaw)
	}

	// The settings-wire copy and the raw-to-typed conversion do not alias either.
	in := map[string]MCPToolConstraints{"d": {AllowWhen: &MCPToolCondition{Groups: []string{"eng"}, Users: []string{"u"}}}}
	for name, out := range map[string]map[string]MCPToolConstraints{
		"copyToolConstraints":  copyToolConstraints(in),
		"cloneToolConstraints": cloneToolConstraints(in),
	} {
		out["d"].AllowWhen.Groups[0], out["d"].AllowWhen.Users[0] = "X", "X"
		if in["d"].AllowWhen.Groups[0] != "eng" || in["d"].AllowWhen.Users[0] != "u" {
			t.Errorf("%s aliased", name)
		}
	}
	raw := map[string]rawMCPToolConstraint{"d": {AllowWhen: &rawMCPToolCondition{Groups: []string{"eng"}, Users: []string{"u"}}}}
	conv := parseToolConstraints(raw)
	if !reflect.DeepEqual(conv["d"].AllowWhen.Groups, []string{"eng"}) || !reflect.DeepEqual(conv["d"].AllowWhen.Users, []string{"u"}) {
		t.Errorf("raw conversion lost fields: %+v", conv["d"].AllowWhen)
	}
	raw["d"].AllowWhen.Groups[0] = "X"
	if conv["d"].AllowWhen.Groups[0] != "eng" {
		t.Error("raw conversion aliased")
	}
}

// Unscoped entries must serialize exactly as before (omitempty), so existing
// ETags do not change.
func TestUnscopedPolicyMarshalUnchanged(t *testing.T) {
	e := AllowlistEntry{Domain: "api.example.com", Port: 443, Methods: []string{"GET"}, Paths: []string{"/v1/*"}, RateLimit: "10/hour", TimeWindow: "9-17"}
	j, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	const wantJSON = `{"domain":"api.example.com","port":443,"methods":["GET"],"paths":["/v1/*"],"rateLimit":"10/hour","timeWindow":"9-17"}`
	if string(j) != wantJSON {
		t.Errorf("json:\n got %s\nwant %s", j, wantJSON)
	}
	y, err := yaml.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	const wantYAML = "domain: api.example.com\nport: 443\nmethods:\n    - GET\npaths:\n    - /v1/*\nrateLimit: 10/hour\ntimeWindow: 9-17\n"
	if string(y) != wantYAML {
		t.Errorf("yaml:\n got %q\nwant %q", y, wantYAML)
	}
	c, _ := json.Marshal(MCPToolCondition{AgentID: "a", TimeWindow: "09-17"})
	if string(c) != `{"AgentID":"a","TimeWindow":"09-17"}` {
		t.Errorf("condition json: %s", c)
	}
}

func TestDiffKeyScoped(t *testing.T) {
	base := AllowlistEntry{Domain: "a.com", Port: 443}
	if base.DiffKey() != "a.com|443" {
		t.Fatalf("unscoped key changed: %q", base.DiffKey())
	}
	a := AllowlistEntry{Domain: "a.com", Port: 443, Groups: []string{"b", "a"}}
	b := AllowlistEntry{Domain: "a.com", Port: 443, Groups: []string{"a", "b"}}
	if a.DiffKey() != b.DiffKey() || a.DiffKey() == base.DiffKey() {
		t.Errorf("keys: %q %q %q", a.DiffKey(), b.DiffKey(), base.DiffKey())
	}
	if a.Groups[0] != "b" {
		t.Error("DiffKey reordered the receiver's slice")
	}
	u := AllowlistEntry{Domain: "a.com", Port: 443, Users: []string{"a"}}
	g := AllowlistEntry{Domain: "a.com", Port: 443, Groups: []string{"a"}}
	if u.DiffKey() == g.DiffKey() {
		t.Error("users and groups collide")
	}
}
