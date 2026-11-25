package worker

import (
	"log/slog"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/proxy"
)

// agentGate is the worker's side of the agent kill switch (W-P2-AREG-05). On
// every applied policy it selects the bound agent's registeredAgents entry and
// hands the proxy one bit: disabled or not. An agent with no entry is not
// disabled (an unregistered or port-derived id is not a registry agent), and a
// policy that lacks the list never reaches here with a different answer than
// the last applied one without the control plane having served it: a wire the
// worker cannot validate is rejected whole by parseRemotePolicy, so the
// last-known-good list stays and a disabled agent stays disabled. The worker
// never clears the flag on its own.
//
// apply runs from the boot path and the single apply goroutine, never
// concurrently.
type agentGate struct {
	p        *proxy.Proxy
	agentID  string
	logger   *slog.Logger
	disabled bool
}

func newAgentGate(p *proxy.Proxy, agentID string, logger *slog.Logger) *agentGate {
	return &agentGate{p: p, agentID: agentID, logger: logger}
}

// agentDisabled reports whether pol's registry lists id as disabled.
func agentDisabled(pol config.Policy, id string) bool {
	for _, a := range pol.RegisteredAgents {
		if a.ID == id {
			return a.Status == config.RegisteredAgentDisabled
		}
	}
	return false
}

// apply moves the proxy to pol's view of the bound agent. On an active to
// disabled change it also closes every open session; disabled to disabled does
// not repeat the cut, because new sessions are refused while the flag is set.
func (g *agentGate) apply(pol config.Policy) {
	now := agentDisabled(pol, g.agentID)
	was := g.disabled
	g.disabled = now
	g.p.SetAgentDisabled(now)
	switch {
	case now && !was:
		g.logger.Warn("bound agent is disabled in the registry; denying all traffic", "agent", g.agentID)
		g.p.CloseAgentSessions()
	case !now && was:
		g.logger.Info("bound agent is enabled in the registry; traffic resumes", "agent", g.agentID)
	}
}

// gatedEvaluator orders the agent gate around every policy swap. A pull that
// disables the bound agent flips the switch BEFORE the new allow policy is live
// (the first pull after a fail-closed boot included), so no destination is
// reachable in between. A pull that leaves the agent enabled or re-enables it
// swaps first and gates after, so a re-enable that also narrows the allowlist
// never runs on the old, wider policy.
type gatedEvaluator struct {
	proxy.PolicyEvaluator
	gate *agentGate
}

func (g gatedEvaluator) Replace(p config.Policy) {
	if agentDisabled(p, g.gate.agentID) {
		g.gate.apply(p)
		g.PolicyEvaluator.Replace(p)
		return
	}
	g.PolicyEvaluator.Replace(p)
	g.gate.apply(p)
}
