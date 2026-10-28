package gateway

import (
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// W-P1-GPOL-11: a groups/users allowWhen on an MCP tool is matched against the
// request's verified subject with the shared identity matcher.

func payCfg(mode string, cond *config.MCPToolCondition) config.MCPConfig {
	cfg := baseCfg(mode)
	cfg.Tools.Allow = append(cfg.Tools.Allow, "pay")
	cfg.Tools.Constraints = map[string]config.MCPToolConstraints{"pay": {AllowWhen: cond}}
	return cfg
}

func callPay(gw *Gateway, s *identity.Subject) Verdict {
	return gw.OnRequest("s1", "tools/call", "", nil, toolCall(`"1"`, "pay", `{}`), RequestMeta{Subject: s})
}

func subj(sub string, groups ...string) *identity.Subject {
	return &identity.Subject{Sub: sub, Groups: groups}
}

func TestConditionGroups(t *testing.T) {
	cond := &config.MCPToolCondition{Groups: []string{"finance"}, Users: []string{"carol", "Dave@Corp.Test"}}
	gw := newGW(t, payCfg(modeEnforce, cond))

	v := callPay(gw, subj("erin", "eng"))
	f, ok := hasFinding(v.Findings, "mcp_tool_condition")
	if v.Action != Deny || v.Reason != "mcp_tool_condition" || !ok {
		t.Fatalf("eng must be denied with mcp_tool_condition: %+v", v)
	}
	if f.Severity != "high" || f.Tool != "pay" {
		t.Errorf("finding = %+v", f)
	}
	if v := callPay(gw, subj("frank", "finance")); v.Action != Pass {
		t.Errorf("finance member denied: %+v", v)
	}
	if v := callPay(gw, subj("carol", "eng")); v.Action != Pass {
		t.Errorf("listed user denied: %+v", v)
	}
	verified := &identity.Subject{Sub: "x", Email: "dave@corp.test", EmailVerified: true}
	if v := callPay(gw, verified); v.Action != Pass {
		t.Errorf("verified email denied: %+v", v)
	}
	unverified := &identity.Subject{Sub: "x", Email: "dave@corp.test"}
	if v := callPay(gw, unverified); v.Action != Deny {
		t.Errorf("unverified email passed: %+v", v)
	}
}

func TestConditionGroups_NoIdentityAndNonMember(t *testing.T) {
	gw := newGW(t, payCfg(modeEnforce, &config.MCPToolCondition{Groups: []string{"finance"}}))

	v := callPay(gw, nil)
	f, _ := hasFinding(v.Findings, "mcp_tool_condition")
	if v.Action != Deny || f.Detail != "no verified identity" {
		t.Fatalf("nil subject: %+v", v)
	}
	v = callPay(gw, subj("erin", "eng"))
	f, _ = hasFinding(v.Findings, "mcp_tool_condition")
	if v.Action != Deny || f.Detail != "user not permitted" {
		t.Fatalf("non-member: %+v", v)
	}
	// Details never carry a group, email or user id.
	for _, s := range []*identity.Subject{nil, subj("erin-sub", "eng")} {
		for _, f := range callPay(gw, s).Findings {
			for _, bad := range []string{"finance", "erin", "eng"} {
				if strings.Contains(f.Detail, bad) {
					t.Errorf("detail %q leaks %q", f.Detail, bad)
				}
			}
		}
	}
}

func TestConditionGroups_Truncated(t *testing.T) {
	gw := newGW(t, payCfg(modeEnforce, &config.MCPToolCondition{Groups: []string{"finance"}}))

	member := &identity.Subject{Sub: "a", Groups: []string{"finance"}, GroupsTruncated: true}
	if v := callPay(gw, member); v.Action != Pass {
		t.Errorf("member in a truncated list denied: %+v", v)
	}
	miss := &identity.Subject{Sub: "b", Groups: []string{"eng"}, GroupsTruncated: true}
	v := callPay(gw, miss)
	f, _ := hasFinding(v.Findings, "mcp_tool_condition")
	if v.Action != Deny || v.Reason != string(denyreason.IdentityGroupsTruncated) || f.Detail != "groups truncated" {
		t.Fatalf("truncated miss: %+v", v)
	}
	// A users-only condition is unaffected by truncation.
	gw = newGW(t, payCfg(modeEnforce, &config.MCPToolCondition{Users: []string{"carol"}}))
	v = callPay(gw, miss)
	if f, _ := hasFinding(v.Findings, "mcp_tool_condition"); v.Reason != "mcp_tool_condition" || f.Detail != "user not permitted" {
		t.Errorf("users-only truncated miss: %+v", v)
	}
}

func TestConditionGroups_MonitorMode(t *testing.T) {
	gw := newGW(t, payCfg(modeMonitor, &config.MCPToolCondition{Groups: []string{"finance"}}))
	v := callPay(gw, subj("erin", "eng"))
	if v.Action != Pass {
		t.Fatalf("monitor must pass: %+v", v)
	}
	if _, ok := hasFinding(v.Findings, "mcp_tool_condition"); !ok {
		t.Errorf("monitor: finding not recorded: %+v", v.Findings)
	}
}

func TestConditionGroups_OnlyNarrow(t *testing.T) {
	// Not on the allow list: a satisfied condition does not re-permit it.
	cfg := payCfg(modeEnforce, &config.MCPToolCondition{Groups: []string{"finance"}})
	cfg.Tools.Allow = []string{"read_file"}
	gw := newGW(t, cfg)
	v := callPay(gw, subj("frank", "finance"))
	if v.Action != Deny || v.Reason != "mcp_tool_denied" {
		t.Errorf("unlisted tool re-permitted: %+v", v)
	}

	// Out of the active task scope: same.
	cfg = payCfg(modeEnforce, &config.MCPToolCondition{Groups: []string{"finance"}})
	cfg.Scopes = &config.MCPScopesConfig{
		ActiveScope: "s",
		OutOfScope:  "deny",
		List:        []config.MCPScope{{ID: "s", Tools: []string{"read_file"}}},
	}
	gw = newGW(t, cfg)
	v = callPay(gw, subj("frank", "finance"))
	if v.Action != Deny || v.Reason != "mcp_out_of_scope" {
		t.Errorf("out-of-scope tool re-permitted: %+v", v)
	}
}

// Time/agent clauses still apply with a satisfied principal (AND).
func TestConditionGroups_CombinesWithAgent(t *testing.T) {
	cond := &config.MCPToolCondition{AgentID: "ci", Groups: []string{"finance"}}
	gw := newGWAgent(t, payCfg(modeEnforce, cond), "other")
	if v := callPay(gw, subj("frank", "finance")); v.Action != Deny {
		t.Errorf("wrong agent passed: %+v", v)
	}
	gw = newGWAgent(t, payCfg(modeEnforce, cond), "ci")
	if v := callPay(gw, subj("frank", "finance")); v.Action != Pass {
		t.Errorf("right agent and group denied: %+v", v)
	}
}
