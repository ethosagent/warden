package worker

import (
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/proxy"
)

func TestBuildJudge_DisabledReturnsNil(t *testing.T) {
	pol := config.Policy{
		Judge:  config.JudgeConfig{Enabled: false},
		Agents: []config.AgentPolicy{{ID: "default", Policy: "x"}},
	}
	judge, agentID, err := buildJudge(pol, "127.0.0.1:8080", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if judge != nil {
		t.Error("disabled judge must be nil")
	}
	if agentID != "default" {
		t.Errorf("agentID = %q, want default (single agent)", agentID)
	}
}

func TestBuildJudge_EnabledMissingKeyErrors(t *testing.T) {
	pol := config.Policy{
		Judge: config.JudgeConfig{
			Enabled:   true,
			Model:     "m",
			BaseURL:   "https://x/v1",
			APIKeyEnv: "WARDEN_JUDGE_KEY_UNSET",
		},
		Agents: []config.AgentPolicy{{ID: "default", Policy: "x"}},
	}
	if _, _, err := buildJudge(pol, "127.0.0.1:8080", nil); err == nil {
		t.Fatal("expected error when API key env is empty")
	}
}

func TestBuildJudge_EnabledConstructs(t *testing.T) {
	t.Setenv("WARDEN_JUDGE_KEY_SET", "sk-x")
	pol := config.Policy{
		Judge: config.JudgeConfig{
			Enabled:   true,
			Model:     "gpt-4o-mini",
			BaseURL:   "https://api.openai.com/v1",
			APIKeyEnv: "WARDEN_JUDGE_KEY_SET",
		},
		Agents: []config.AgentPolicy{{ID: "default", Policy: "allow reads"}},
	}
	judge, agentID, err := buildJudge(pol, "127.0.0.1:8080", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if judge == nil {
		t.Fatal("expected a judge")
	}
	if agentID != "default" {
		t.Errorf("agentID = %q, want default", agentID)
	}
	// The adapter returns a proxy.Verdict; a no-policy agent denies (fail-closed),
	// but here the single agent exists, so it will attempt an LLM call. We only
	// assert the adapter type is wired (deny on unknown agent stays deny).
	v := judge.Evaluate("nonexistent", "GET", "https://h/x", "h", "application/json", false)
	if v.Decision != "deny" {
		t.Errorf("unknown agent should deny, got %q", v.Decision)
	}
}

// TestBuildJudgeFrom_DisabledReturnsNil verifies the shared builder returns a nil
// judge (no error) when the config is disabled, so a control-plane apply with the
// judge off disables it cleanly.
func TestBuildJudgeFrom_DisabledReturnsNil(t *testing.T) {
	j, err := buildJudgeFrom(config.JudgeConfig{Enabled: false}, nil, "default", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if j != nil {
		t.Error("disabled judge must be nil")
	}
}

// TestBuildJudgeFrom_ResolvesAPIKeyFromLocalEnv verifies the API key is read from
// the worker's LOCAL environment via the env NAME — the value never travels in
// settings. It builds from a JudgeConfig produced by JudgeConfigFromSettings (the
// distribution path), confirming the rebuilt judge succeeds only because the key
// is present in the local env under the distributed env NAME.
func TestBuildJudgeFrom_ResolvesAPIKeyFromLocalEnv(t *testing.T) {
	const envName = "WARDEN_JUDGE_LOCAL_KEY"

	// The wire settings carry only the env NAME, never a key value.
	wire := &config.JudgeSettings{
		Enabled:   true,
		Model:     "gpt-4o-mini",
		BaseURL:   "https://api.openai.com/v1",
		APIKeyEnv: envName,
	}
	jc := config.JudgeConfigFromSettings(wire)
	agents := config.AgentsFromSettings([]config.AgentSettings{{ID: "default", Policy: "allow reads"}})

	// With the env var UNSET locally, the build must fail (no key resolved).
	if _, err := buildJudgeFrom(jc, agents, "default", nil); err == nil {
		t.Fatal("expected error when local env key is unset")
	}

	// Set the key in the LOCAL env under the distributed name; build now succeeds.
	t.Setenv(envName, "sk-local-value")
	j, err := buildJudgeFrom(jc, agents, "default", nil)
	if err != nil {
		t.Fatalf("unexpected error after setting local env key: %v", err)
	}
	if j == nil {
		t.Fatal("expected a judge once the local key resolves")
	}
}

// TestBuildLLMClient_GatesOnEnabledAndKey verifies the shared helper the dashboard
// NL→SQL wiring uses: it yields a client only when the judge is enabled AND the key
// env resolves locally, mirroring "SetSQLGenerator is wired when the judge is
// configured with a key in env, and NOT when the key env is empty".
func TestBuildLLMClient_GatesOnEnabledAndKey(t *testing.T) {
	const envName = "WARDEN_NL2SQL_KEY"
	jc := config.JudgeConfig{
		Enabled:   true,
		Model:     "gpt-4o-mini",
		BaseURL:   "https://api.openai.com/v1",
		APIKeyEnv: envName,
	}

	// Disabled → (nil, nil): the feature is simply off, not an error.
	if c, err := BuildLLMClient(config.JudgeConfig{Enabled: false}); err != nil || c != nil {
		t.Fatalf("disabled: want (nil,nil), got (%v,%v)", c, err)
	}

	// Enabled but the key env is empty → (nil, error): the dashboard treats this as
	// fail-soft "no generator", so no SetSQLGenerator call happens.
	if c, err := BuildLLMClient(jc); err == nil || c != nil {
		t.Fatalf("empty key: want (nil,error), got (%v,%v)", c, err)
	}

	// Enabled + key present in the local env → a usable client.
	t.Setenv(envName, "sk-local")
	c, err := BuildLLMClient(jc)
	if err != nil {
		t.Fatalf("unexpected error with key set: %v", err)
	}
	if c == nil {
		t.Fatal("expected a client when enabled and key present")
	}
}

// TestBuildLLMClients_KeyPresentAbsentAndMultiple verifies the shared map builder:
// a provider whose key env is set yields a usable client; one whose key env is
// empty is absent from clients and present in errs; and multiple providers resolve
// independently. It never returns a top-level error (fail-soft).
func TestBuildLLMClients_KeyPresentAbsentAndMultiple(t *testing.T) {
	t.Setenv("WARDEN_PROV_A_KEY", "sk-a")
	// WARDEN_PROV_B_KEY intentionally left unset.
	providers := []config.LLMProvider{
		{Name: "prov-a", BaseURL: "https://a/v1", Model: "m-a", APIKeyEnv: "WARDEN_PROV_A_KEY"},
		{Name: "prov-b", BaseURL: "https://b/v1", Model: "m-b", APIKeyEnv: "WARDEN_PROV_B_KEY_UNSET"},
	}
	clients, errs := BuildLLMClients(providers)

	if clients["prov-a"] == nil {
		t.Error("prov-a: want a client when its key env is set")
	}
	if _, ok := errs["prov-a"]; ok {
		t.Error("prov-a: want no error when its key env is set")
	}
	if clients["prov-b"] != nil {
		t.Error("prov-b: want no client when its key env is empty")
	}
	if errs["prov-b"] == nil {
		t.Error("prov-b: want a recorded error when its key env is empty")
	}
}

// TestBuildLLMClients_EmptyInput verifies an empty registry yields empty (non-nil)
// maps and no error — the back-compat "no providers" case.
func TestBuildLLMClients_EmptyInput(t *testing.T) {
	clients, errs := BuildLLMClients(nil)
	if len(clients) != 0 || len(errs) != 0 {
		t.Fatalf("empty registry: want empty maps, got clients=%v errs=%v", clients, errs)
	}
}

// TestResolveJudgeLLM covers the four selection branches: disabled → (nil,nil);
// inline (no name) → BuildLLMClient path; named+present → that client; named+absent
// → error (named but unresolved).
func TestResolveJudgeLLM(t *testing.T) {
	t.Setenv("WARDEN_RESOLVE_INLINE_KEY", "sk-inline")
	t.Setenv("WARDEN_RESOLVE_NAMED_KEY", "sk-named")

	inline := config.JudgeConfig{
		Enabled:   true,
		Model:     "m",
		BaseURL:   "https://x/v1",
		APIKeyEnv: "WARDEN_RESOLVE_INLINE_KEY",
	}
	clients, _ := BuildLLMClients([]config.LLMProvider{
		{Name: "named", BaseURL: "https://n/v1", Model: "m-n", APIKeyEnv: "WARDEN_RESOLVE_NAMED_KEY"},
	})

	// Disabled → (nil, nil).
	if c, err := resolveJudgeLLM(config.JudgeConfig{Enabled: false}, "", clients); c != nil || err != nil {
		t.Fatalf("disabled: want (nil,nil), got (%v,%v)", c, err)
	}

	// Inline (no provider name) → BuildLLMClient path yields a client.
	if c, err := resolveJudgeLLM(inline, "", clients); err != nil || c == nil {
		t.Fatalf("inline: want a client, got (%v,%v)", c, err)
	}

	// Named + present → the map client.
	if c, err := resolveJudgeLLM(inline, "named", clients); err != nil || c == nil {
		t.Fatalf("named present: want the named client, got (%v,%v)", c, err)
	}
	if c, _ := resolveJudgeLLM(inline, "named", clients); c != clients["named"] {
		t.Error("named present: want the exact map client")
	}

	// Named + absent → error (named but unresolved).
	if c, err := resolveJudgeLLM(inline, "missing", clients); err == nil || c != nil {
		t.Fatalf("named absent: want (nil,error), got (%v,%v)", c, err)
	}
}

// TestBuildJudgeFrom_NamedProviderResolves verifies the judge selects a named
// registry client from the prebuilt map (the managed-worker path where the
// registry is reconstructed from the wire and the key resolves from local env).
func TestBuildJudgeFrom_NamedProviderResolves(t *testing.T) {
	t.Setenv("WARDEN_NAMED_JUDGE_KEY", "sk-named-judge")
	clients, _ := BuildLLMClients([]config.LLMProvider{
		{Name: "judge-prov", BaseURL: "https://j/v1", Model: "m-j", APIKeyEnv: "WARDEN_NAMED_JUDGE_KEY"},
	})
	jc := config.JudgeConfig{Enabled: true, LLMProvider: "judge-prov"}
	agents := []config.AgentPolicy{{ID: "default", Policy: "allow reads"}}

	j, err := buildJudgeFrom(jc, agents, "default", clients)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if j == nil {
		t.Fatal("expected a judge built from the named provider")
	}
}

// TestBuildJudge_NamedProviderUnresolvedFailsSoft verifies that at boot a judge
// pointed at a registry provider whose key env is empty on THIS node disables the
// judge (nil, no error) rather than aborting worker start — fail-soft. The inline
// path (no name) still errors, proven by TestBuildJudge_EnabledMissingKeyErrors.
func TestBuildJudge_NamedProviderUnresolvedFailsSoft(t *testing.T) {
	// Provider exists in the registry (so config would validate), but its key env
	// is unset locally → absent from the client map → named-but-unresolved.
	pol := config.Policy{
		Judge: config.JudgeConfig{Enabled: true, LLMProvider: "unresolved-prov"},
		LLMProviders: []config.LLMProvider{
			{Name: "unresolved-prov", BaseURL: "https://u/v1", Model: "m-u", APIKeyEnv: "WARDEN_UNRESOLVED_KEY_UNSET"},
		},
		Agents: []config.AgentPolicy{{ID: "default", Policy: "x"}},
	}
	judge, agentID, err := buildJudge(pol, "127.0.0.1:8080", nil)
	if err != nil {
		t.Fatalf("named-unresolved judge must fail SOFT (no boot error), got %v", err)
	}
	if judge != nil {
		t.Error("named-unresolved judge must be disabled (nil)")
	}
	if agentID != "default" {
		t.Errorf("agentID = %q, want default (identity preserved on fail-soft)", agentID)
	}
}

// TestManagedWorkerApply_ResolvesNamedProviderFromWire mirrors the applier's judge
// path: a managed worker receives llmProviders + judge.llmProvider over the wire,
// reconstructs the registry via config.LLMProvidersFromSettings, builds the client
// map from its OWN env, and resolves the judge's named client. It proves the wire
// selection resolves end-to-end (the live consumer M1 deferred).
func TestManagedWorkerApply_ResolvesNamedProviderFromWire(t *testing.T) {
	const keyEnv = "WARDEN_WIRE_JUDGE_KEY"

	wire := &config.SettingsWire{
		Judge:  &config.JudgeSettings{Enabled: true, LLMProvider: "wire-prov"},
		Agents: []config.AgentSettings{{ID: "default", Policy: "allow reads"}},
		LLMProviders: []config.LLMProviderSettings{
			{Name: "wire-prov", BaseURL: "https://w/v1", Model: "m-w", APIKeyEnv: keyEnv},
		},
	}

	// Reconstruct exactly as the applier does.
	rebuild := func() (proxy.Judge, error) {
		clients, _ := BuildLLMClients(config.LLMProvidersFromSettings(wire.LLMProviders))
		return buildJudgeFrom(
			config.JudgeConfigFromSettings(wire.Judge),
			config.AgentsFromSettings(wire.Agents),
			"default",
			clients,
		)
	}

	// Key env UNSET locally → named provider unresolved → judge build errors
	// (the applier treats this fail-soft: keeps the current judge).
	if _, err := rebuild(); err == nil {
		t.Fatal("expected error when the wire provider's key env is unset locally")
	}

	// Key present in THIS node's env under the wire-delivered NAME → judge builds.
	t.Setenv(keyEnv, "sk-wire-local")
	j, err := rebuild()
	if err != nil {
		t.Fatalf("unexpected error once local key resolves: %v", err)
	}
	if j == nil {
		t.Fatal("expected a judge resolved from the wire-delivered named provider")
	}
}

func TestDefaultAgentID_PortBindingWhenMultiple(t *testing.T) {
	pol := config.Policy{Agents: []config.AgentPolicy{
		{ID: "a", Policy: "x"},
		{ID: "b", Policy: "y"},
	}}
	got := defaultAgentID(pol, "127.0.0.1:9000")
	if got != "agent:9000" {
		t.Errorf("agentID = %q, want agent:9000", got)
	}
}
