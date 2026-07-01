package worker

import (
	"fmt"
	"os"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/llm"
	"github.com/ethosagent/warden/internal/llmpolicy"
	"github.com/ethosagent/warden/internal/proxy"
)

// buildJudge constructs the inline judge when judge.enabled, returning the
// judge and the agent id derived from the listen port. When the judge is
// disabled it returns (nil, "", nil) and the proxy default-denies NoMatch as
// before. Config has already validated cross-field requirements; here we only
// resolve the API key from its env var.
func buildJudge(pol config.Policy, listenAddr string) (proxy.Judge, string, error) {
	// Resolve the agent id from the listen port (one proxy per agent).
	agentID := defaultAgentID(pol, listenAddr)
	judge, err := buildJudgeFrom(pol.Judge, pol.Agents, agentID)
	if err != nil {
		return nil, "", err
	}
	return judge, agentID, nil
}

// buildJudgeFrom constructs the inline judge from a JudgeConfig + agent policies,
// shared by the boot path (buildJudge) and the control-plane runtime rebuild (the
// apply loop). It returns a nil judge when jc.Enabled is false (the proxy then
// default-denies NoMatch as before). agentID is the worker's LOCAL identity and
// is passed in unchanged across rebuilds — it is never distributed.
//
// SECRET-LOCAL INVARIANT: the API key is resolved here from the worker's OWN
// environment via os.Getenv(jc.APIKeyEnv). Distributed settings carry only the
// env NAME (jc.APIKeyEnv), never a key value, so a control plane can point the
// judge at a different env var but can never inject a credential.
func buildJudgeFrom(jc config.JudgeConfig, agents []config.AgentPolicy, agentID string) (proxy.Judge, error) {
	if !jc.Enabled {
		return nil, nil
	}

	apiKey := os.Getenv(jc.APIKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("judge.enabled but env var %s is empty (it holds the LLM API key)", jc.APIKeyEnv)
	}
	client, err := llm.NewClient(llm.Config{
		BaseURL: jc.BaseURL,
		Model:   jc.Model,
		APIKey:  apiKey,
		Timeout: jc.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("build LLM client: %w", err)
	}

	policies := make(map[string]string, len(agents))
	for _, a := range agents {
		policies[a.ID] = a.Policy
	}

	judge := llmpolicy.NewJudge(client, policies, llmpolicy.JudgeOptions{
		CacheTTL:    jc.CacheTTL,
		Timeout:     jc.Timeout,
		MaxFailures: jc.CircuitBreaker.MaxFailures,
		Cooldown:    jc.CircuitBreaker.Cooldown,
	})
	return judgeAdapter{judge}, nil
}

// judgeAdapter bridges *llmpolicy.Judge to the proxy.Judge interface. The proxy
// deliberately does not import llmpolicy (its Judge/Verdict are consumer-side);
// this thin wiring adapter lives in the worker, where both packages are already
// in scope.
type judgeAdapter struct{ j *llmpolicy.Judge }

func (a judgeAdapter) Evaluate(agentID, method, url, host, contentType string, hasAuth bool) proxy.Verdict {
	v := a.j.Evaluate(agentID, method, url, host, contentType, hasAuth)
	return proxy.Verdict{Decision: v.Decision, Reason: v.Reason}
}

// defaultAgentID derives the agent identity. When exactly one agent policy is
// configured, its id is used directly so it matches the configured policy key;
// otherwise the port-binding identifier labels the agent by listen port.
func defaultAgentID(pol config.Policy, listenAddr string) string {
	if len(pol.Agents) == 1 {
		return pol.Agents[0].ID
	}
	port := 0
	if _, p, err := proxy.SplitHostPort(listenAddr); err == nil {
		port = p
	}
	return agentid.NewPortBindingIdentifier("agent").Identify(port)
}
