package gateway

import (
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// scopeCfg builds a config whose base Tools policy allows a broad set and whose
// active scope narrows to a purpose-bound subset. outOfScope selects the
// out-of-scope fallback ("" -> deny). The base allow list is a superset of the
// scope so scoping (not the base policy) is what denies out-of-scope tools.
func scopeCfg(mode, outOfScope string) config.MCPConfig {
	cfg := baseCfg(mode)
	cfg.Tools.Allow = []string{"get_user", "read_file", "send_email", "search"}
	cfg.Scopes = &config.MCPScopesConfig{
		ActiveScope: "triage-readonly",
		OutOfScope:  outOfScope,
		List: []config.MCPScope{
			{
				ID:      "triage-readonly",
				Purpose: "Read-only triage: look up users and read files; never send.",
				Tools:   []string{"get_user", "read_file"},
				Constraints: map[string]config.MCPToolConstraints{
					"get_user": {
						Fields: map[string]config.MCPFieldConstraint{
							"id": {Match: `^[0-9]+$`, Required: true},
						},
					},
				},
			},
		},
	}
	return cfg
}

// TestScopeInScopeAllows: a tool in the active scope with conforming args passes.
func TestScopeInScopeAllows(t *testing.T) {
	gw := newGW(t, scopeCfg(modeEnforce, "deny"))
	v := gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "get_user", `{"id":"42"}`))
	if v.Action != Pass {
		t.Fatalf("in-scope call must Pass, got %v (%q)", v.Action, v.Reason)
	}
	if _, ok := hasFinding(v.Findings, "mcp_out_of_scope"); ok {
		t.Fatalf("in-scope call must not produce an out-of-scope finding: %v", v.Findings)
	}
}

// TestScopeOutOfScopeDenies: a tool NOT in the active scope (but allowed by the
// base policy) is denied in enforce with a bounded mcp_out_of_scope reason.
func TestScopeOutOfScopeDenies(t *testing.T) {
	gw := newGW(t, scopeCfg(modeEnforce, "deny"))
	v := gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "send_email", `{"to":"x@y.com"}`))
	if v.Action != Deny || v.Reason != "mcp_out_of_scope" {
		t.Fatalf("want Deny/mcp_out_of_scope, got action=%v reason=%q", v.Action, v.Reason)
	}
	f, ok := hasFinding(v.Findings, "mcp_out_of_scope")
	if !ok {
		t.Fatalf("missing mcp_out_of_scope finding: %v", v.Findings)
	}
	if f.Severity != "high" || f.Tool != "send_email" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	// The detail is bounded metadata — it must not leak the argument value.
	if got := f.Detail; got == "" || strings.Contains(got, "x@y.com") {
		t.Fatalf("detail must be bounded and value-free, got %q", got)
	}
}

// TestScopeMonitorLogsButAllows: monitor mode records the scope violation but
// never blocks.
func TestScopeMonitorLogsButAllows(t *testing.T) {
	gw := newGW(t, scopeCfg(modeMonitor, "deny"))
	v := gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "send_email", `{"to":"x@y.com"}`))
	if v.Action != Pass {
		t.Fatalf("monitor must Pass, got %v", v.Action)
	}
	if _, ok := hasFinding(v.Findings, "mcp_out_of_scope"); !ok {
		t.Fatalf("monitor: missing mcp_out_of_scope finding: %v", v.Findings)
	}
}

// TestScopeRestrictionOverridesScope: a tool on the base deny list (Tier-1
// restriction) is denied even if it appears in the active scope's tool-set.
func TestScopeRestrictionOverridesScope(t *testing.T) {
	cfg := scopeCfg(modeEnforce, "deny")
	cfg.Tools.Deny = []string{"read_file"} // read_file is IN the scope, but restricted
	gw := newGW(t, cfg)
	v := gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "read_file", `{"path":"/a"}`))
	if v.Action != Deny || v.Reason != "mcp_tool_denied" {
		t.Fatalf("restriction must win: want Deny/mcp_tool_denied, got action=%v reason=%q", v.Action, v.Reason)
	}
	if _, ok := hasFinding(v.Findings, "mcp_out_of_scope"); ok {
		t.Fatalf("a restricted tool must not reach scope evaluation: %v", v.Findings)
	}
}

// TestScopeConstraintsEnforced: an in-scope call whose args violate the scope's
// bundled constraints is denied via the SAME constraint engine (mcp_args_constraint).
func TestScopeConstraintsEnforced(t *testing.T) {
	gw := newGW(t, scopeCfg(modeEnforce, "deny"))
	// get_user is in scope, but its id must match ^[0-9]+$; "abc" violates it.
	v := gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "get_user", `{"id":"abc"}`))
	if v.Action != Deny || v.Reason != "mcp_args_constraint" {
		t.Fatalf("want Deny/mcp_args_constraint, got action=%v reason=%q", v.Action, v.Reason)
	}
	f, ok := hasFinding(v.Findings, "mcp_args_constraint")
	if !ok || f.Path != "id" {
		t.Fatalf("expected id constraint finding, got %v", v.Findings)
	}
	if strings.Contains(f.Detail, "abc") {
		t.Fatalf("constraint detail must not leak the value, got %q", f.Detail)
	}
}

// TestScopeEscalateDegradesToDeny: with outOfScope=escalate and no approval
// channel configured, an out-of-scope call still denies (never silently allowed).
func TestScopeEscalateDegradesToDeny(t *testing.T) {
	gw := newGW(t, scopeCfg(modeEnforce, "escalate"))
	v := gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "send_email", `{"to":"x@y.com"}`))
	if v.Action != Deny || v.Reason != "mcp_out_of_scope" {
		t.Fatalf("escalate w/o channel must degrade to Deny, got action=%v reason=%q", v.Action, v.Reason)
	}
}

// TestScopePerAgentOverride: PerAgent selects the active scope for a specific
// agent id, overriding ActiveScope.
func TestScopePerAgentOverride(t *testing.T) {
	cfg := scopeCfg(modeEnforce, "deny")
	cfg.Scopes.ActiveScope = "" // no global scope
	cfg.Scopes.PerAgent = map[string]string{"triage-bot": "triage-readonly"}
	cfg.Scopes.List = append(cfg.Scopes.List, config.MCPScope{
		ID:    "sender",
		Tools: []string{"send_email"},
	})

	// triage-bot -> triage-readonly: send_email is out of scope.
	gwTriage := newGWAgent(t, cfg, "triage-bot")
	if v := gwTriage.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "send_email", `{}`)); v.Action != Deny {
		t.Fatalf("triage-bot: send_email must be out-of-scope Deny, got %v", v.Action)
	}
	// An agent with no PerAgent entry and no global ActiveScope is unscoped.
	gwOther := newGWAgent(t, cfg, "other")
	if v := gwOther.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "send_email", `{}`)); v.Action != Pass {
		t.Fatalf("unscoped agent: send_email must Pass, got %v (%q)", v.Action, v.Reason)
	}
}

// TestScopeAbsentUnchanged: with no scopes configured, behavior is unchanged —
// any base-allowed tool passes.
func TestScopeAbsentUnchanged(t *testing.T) {
	gw := newGW(t, baseCfg(modeEnforce))
	if v := gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "send_email", `{}`)); v.Action != Pass {
		t.Fatalf("no scoping: base-allowed tool must Pass, got %v", v.Action)
	}
}
