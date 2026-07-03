package worker

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/llm"
	"github.com/ethosagent/warden/internal/llmpolicy"
	"github.com/ethosagent/warden/internal/proxy"
)

// buildJudge constructs the inline judge when judge.enabled, returning the
// judge and the agent id derived from the listen port. When the judge is
// disabled it returns (nil, "", nil) and the proxy default-denies NoMatch as
// before. Config has already validated cross-field requirements; here we only
// resolve the API key from its env var.
func buildJudge(pol config.Policy, listenAddr string, logger *slog.Logger) (proxy.Judge, string, error) {
	// Resolve the agent id from the listen port (one proxy per agent).
	agentID := defaultAgentID(pol, listenAddr)

	// Build the named-provider client map ONCE from THIS node's env. Per-name
	// errors (empty key env, bad client) are logged (metadata only, never a key)
	// and the provider is simply absent from the map — fail-soft, never fatal.
	clients, errs := BuildLLMClients(pol.LLMProviders)
	logLLMClientErrs(logger, errs)

	judge, err := buildJudgeFrom(pol.Judge, pol.Agents, agentID, clients)
	if err != nil {
		// Fail-soft ONLY for a named-provider selection: a judge pointed at a
		// registry provider whose key env is empty (or client failed to build) on
		// THIS node disables the judge with a logged reason rather than aborting
		// worker start — the proxy still default-denies NoMatch, exactly as when the
		// judge is off. The INLINE path keeps today's hard boot error (byte-identical),
		// so an inline misconfiguration still fails fast at startup.
		if pol.Judge.LLMProvider != "" {
			if logger != nil {
				logger.Warn("judge disabled: named LLM provider unresolved on this node",
					"provider", pol.Judge.LLMProvider, "error", err.Error())
			}
			return nil, agentID, nil
		}
		return nil, "", err
	}
	return judge, agentID, nil
}

// logLLMClientErrs logs each per-provider build error as metadata only (provider
// name + reason), never a key value. nil-safe so non-logging callers (tests) can
// pass a nil logger.
func logLLMClientErrs(logger *slog.Logger, errs map[string]error) {
	if logger == nil {
		return
	}
	for name, e := range errs {
		logger.Warn("llm provider unavailable on this node", "provider", name, "error", e.Error())
	}
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
func buildJudgeFrom(jc config.JudgeConfig, agents []config.AgentPolicy, agentID string, clients map[string]*llm.Client) (proxy.Judge, error) {
	if !jc.Enabled {
		return nil, nil
	}

	// Select the LLM: a named provider resolves from the prebuilt client map; an
	// empty jc.LLMProvider keeps the inline BuildLLMClient(jc) path (byte-identical
	// to before).
	client, err := resolveJudgeLLM(jc, jc.LLMProvider, clients)
	if err != nil {
		return nil, err
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

// BuildLLMClient constructs the OpenAI-compatible LLM client from a judge config,
// resolving the API key from this node's OWN environment (the SECRET-LOCAL
// invariant: distributed settings carry only the env NAME, never a key value).
// It is the single source of key-resolution + client construction, shared by the
// inline judge (buildJudgeFrom) and the dashboard NL→SQL wiring so both use the
// exact same provider/model/baseURL/key.
//
// Return contract:
//   - jc.Enabled == false            → (nil, nil): the judge/feature is simply off.
//   - enabled but APIKeyEnv is empty → (nil, error): a misconfiguration the judge
//     boot path surfaces as before. The dashboard wiring treats any error as
//     fail-soft "no generator" (it never blocks node start).
//   - enabled + key present          → (client, nil).
func BuildLLMClient(jc config.JudgeConfig) (*llm.Client, error) {
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
	return client, nil
}

// BuildLLMClients builds one *llm.Client per named provider, resolving each
// APIKeyEnv from THIS node's OWN env (the SECRET-LOCAL rule: the registry carries
// only env NAMES, never key values). It returns the usable clients keyed by name,
// plus a per-name error for any provider whose key env is empty or whose client
// fails to build (for the status view / logging).
//
// It NEVER returns a top-level error and NEVER logs a key value: a bad provider is
// recorded in errs and skipped, not fatal (fail-soft). The same per-provider
// construction as BuildLLMClient — os.Getenv(APIKeyEnv) then llm.NewClient with
// BaseURL/Model/APIKey/Timeout — so both share identical key-resolution semantics.
func BuildLLMClients(providers []config.LLMProvider) (clients map[string]*llm.Client, errs map[string]error) {
	clients = make(map[string]*llm.Client, len(providers))
	errs = make(map[string]error, len(providers))
	for _, p := range providers {
		apiKey := os.Getenv(p.APIKeyEnv)
		if apiKey == "" {
			errs[p.Name] = fmt.Errorf("env var %s is empty (it holds the LLM API key for provider %q)", p.APIKeyEnv, p.Name)
			continue
		}
		client, err := llm.NewClient(llm.Config{
			BaseURL: p.BaseURL,
			Model:   p.Model,
			APIKey:  apiKey,
			Timeout: p.Timeout,
		})
		if err != nil {
			errs[p.Name] = fmt.Errorf("build LLM client for provider %q: %w", p.Name, err)
			continue
		}
		clients[p.Name] = client
	}
	return clients, errs
}

// resolveJudgeLLM returns the LLM client the judge should use:
//   - judge disabled                    → (nil, nil): the judge is off, unchanged.
//   - providerName != "" and present    → the named registry client.
//   - providerName != "" and absent     → (nil, error): named but unresolved (its
//     key env was empty or the client failed to build) — the caller disables the
//     judge and logs the reason (fail-soft), never crashes.
//   - providerName == ""                → BuildLLMClient(jc): today's inline path,
//     byte-identical to before.
func resolveJudgeLLM(jc config.JudgeConfig, providerName string, clients map[string]*llm.Client) (*llm.Client, error) {
	if !jc.Enabled {
		return nil, nil
	}
	if providerName != "" {
		client, ok := clients[providerName]
		if !ok {
			return nil, fmt.Errorf("judge.llmProvider %q is not a resolved provider (its key env is empty on this node or its client failed to build)", providerName)
		}
		return client, nil
	}
	return BuildLLMClient(jc)
}

// PickExploreLLM returns the *llm.Client the Explore / NL→SQL generator should
// use, or nil. It is the Explore analogue of resolveJudgeLLM but returns a
// CONCRETE *llm.Client (never an interface), so the caller MUST guard the
// typed-nil interface trap: only call dashSrv.SetSQLGenerator(c) when c != nil —
// boxing a nil *llm.Client into the SQLGenerator interface would defeat the
// dashboard's `sqlGen == nil` 409 check. Exported so the control plane can select
// the Explore client from wire-distributed settings, exactly as the worker does.
//
//	name == ""                     → judgeClient (today's fallback: reuse the judge's client)
//	name set & present in clients  → clients[name]
//	name set & absent/unresolved   → nil (→ the existing 409 llm_not_configured path)
func PickExploreLLM(name string, clients map[string]*llm.Client, judgeClient *llm.Client) *llm.Client {
	if name == "" {
		return judgeClient
	}
	// A missing key returns the zero *llm.Client (nil) — the unresolved-name case.
	return clients[name]
}

// BuildLLMProviderViews builds the dashboard status view for each registry provider,
// resolving Resolved/Reason against THIS node's OWN env via BuildLLMClients (the
// single key-resolution seam). It is shared by the control plane and worker dashboard
// wiring so the config→view projection lives in ONE place. SECRET-LOCAL: it NEVER
// emits a key value — Reason is the bounded, value-free error BuildLLMClients records
// (e.g. "env var OPENAI_API_KEY is empty …"), and a resolved provider has no reason.
func BuildLLMProviderViews(providers []config.LLMProvider) []dashboard.LLMProviderView {
	_, errs := BuildLLMClients(providers)
	out := make([]dashboard.LLMProviderView, 0, len(providers))
	for _, p := range providers {
		v := dashboard.LLMProviderView{
			Name:           p.Name,
			BaseURL:        p.BaseURL,
			Model:          p.Model,
			APIKeyEnv:      p.APIKeyEnv,
			TimeoutSeconds: int(p.Timeout.Seconds()),
		}
		if e, bad := errs[p.Name]; bad {
			v.Reason = e.Error()
		} else {
			v.Resolved = true
		}
		out = append(out, v)
	}
	return out
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
