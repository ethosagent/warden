package worker

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/proxy"
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

// TestAgentGateFirstApplyDisabled: a fresh gate whose first apply is a disabled
// entry (the first pull after a fail-closed boot) disables the proxy and the
// registry refuses a session opened afterwards.
func TestAgentGateFirstApplyDisabled(t *testing.T) {
	a, _, _ := newTestApplier(t)
	g := newAgentGate(a.p, "claude-code", slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.apply(config.Policy{RegisteredAgents: []config.RegisteredAgent{registered("claude-code", config.RegisteredAgentDisabled)}})
	if !a.p.AgentDisabled() {
		t.Fatal("AgentDisabled = false after a first apply with a disabled entry")
	}
}

// spyEvaluator records whether the agent switch was already on when the policy
// swap happened.
type spyEvaluator struct {
	proxy.PolicyEvaluator
	p              *proxy.Proxy
	disabledAtSwap bool
	swapped        bool
}

func (s *spyEvaluator) Replace(config.Policy) {
	s.disabledAtSwap, s.swapped = s.p.AgentDisabled(), true
}

// TestGatedEvaluatorAppliesGateBeforeSwap: a pull that both allows traffic and
// disables the bound agent flips the switch before the new policy is live, so
// there is no moment where the destination is reachable.
func TestGatedEvaluatorAppliesGateBeforeSwap(t *testing.T) {
	a, _, _ := newTestApplier(t)
	g := newAgentGate(a.p, "claude-code", slog.New(slog.NewTextHandler(io.Discard, nil)))
	spy := &spyEvaluator{p: a.p}
	ev := gatedEvaluator{PolicyEvaluator: spy, gate: g}
	ev.Replace(config.Policy{
		Allowlist:        []config.AllowlistEntry{{Domain: "api.example.com"}},
		RegisteredAgents: []config.RegisteredAgent{registered("claude-code", config.RegisteredAgentDisabled)},
	})
	if !spy.swapped || !spy.disabledAtSwap {
		t.Fatalf("swapped=%v, switch on at swap=%v; want the switch on before the swap", spy.swapped, spy.disabledAtSwap)
	}
}
