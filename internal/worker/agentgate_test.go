package worker

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func registered(id, status string) config.RegisteredAgent {
	return config.RegisteredAgent{ID: id, Status: status, JKT: []string{strings.Repeat("a", 43)}}
}

// TestResolveAgentID: --agent-id wins over central.agentID, which wins over the
// derived id; with neither set the result is exactly defaultAgentID's; a
// malformed explicit value is an error that never carries the value.
func TestResolveAgentID(t *testing.T) {
	one := config.Policy{Agents: []config.AgentPolicy{{ID: "solo"}}}
	none := config.Policy{}
	for _, c := range []struct {
		name          string
		flag, central string
		pol           config.Policy
		listen, want  string
		wantErr       bool
	}{
		{"flag beats central", "claude-code", "other", none, "127.0.0.1:8080", "claude-code", false},
		{"central when no flag", "", "other", none, "127.0.0.1:8080", "other", false},
		{"neither: port-derived", "", "", none, "127.0.0.1:8080", defaultAgentID(none, "127.0.0.1:8080"), false},
		{"neither: single configured agent", "", "", one, "127.0.0.1:8080", "solo", false},
		{"explicit wins over a single configured agent", "claude-code", "", one, "127.0.0.1:8080", "claude-code", false},
		{"bad flag", "bad id!", "other", none, "127.0.0.1:8080", "", true},
		{"bad central", "", "!identity-scoped", none, "127.0.0.1:8080", "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveAgentID(c.flag, c.central, c.pol, c.listen)
			if c.wantErr {
				if err == nil {
					t.Fatalf("resolveAgentID = %q, want an error", got)
				}
				if bad := c.flag + c.central; strings.Contains(err.Error(), bad) {
					t.Errorf("error %q carries the value", err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("resolveAgentID = %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

// TestAgentDisabledGate: the gate selects the bound agent's entry, sets the
// proxy's switch from it, closes sessions once on the active-to-disabled
// change, never touches the switch for another agent's entry, and restores
// traffic when the entry is active again.
func TestAgentDisabledGate(t *testing.T) {
	a, _, _ := newTestApplier(t)
	var buf bytes.Buffer
	g := newAgentGate(a.p, "claude-code", slog.New(slog.NewTextHandler(&buf, nil)))

	pol := func(agents ...config.RegisteredAgent) config.Policy { return config.Policy{RegisteredAgents: agents} }
	steps := []struct {
		name string
		pol  config.Policy
		want bool
	}{
		{"no registry", pol(), false},
		{"other agent disabled", pol(registered("other", config.RegisteredAgentDisabled)), false},
		{"bound agent active", pol(registered("claude-code", config.RegisteredAgentActive)), false},
		{"bound agent disabled", pol(registered("claude-code", config.RegisteredAgentDisabled), registered("other", config.RegisteredAgentActive)), true},
		{"still disabled", pol(registered("claude-code", config.RegisteredAgentDisabled)), true},
		{"re-enabled", pol(registered("claude-code", config.RegisteredAgentActive)), false},
	}
	for _, s := range steps {
		g.apply(s.pol)
		if got := a.p.AgentDisabled(); got != s.want {
			t.Fatalf("%s: AgentDisabled = %v, want %v", s.name, got, s.want)
		}
	}
	if n := strings.Count(buf.String(), "bound agent is disabled"); n != 1 {
		t.Errorf("disabled warning logged %d times, want once:\n%s", n, buf.String())
	}
	if strings.Contains(buf.String(), strings.Repeat("a", 43)) {
		t.Error("a thumbprint reached the logs")
	}
}
