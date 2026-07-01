package worker

import (
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func TestBuildJudge_DisabledReturnsNil(t *testing.T) {
	pol := config.Policy{
		Judge:  config.JudgeConfig{Enabled: false},
		Agents: []config.AgentPolicy{{ID: "default", Policy: "x"}},
	}
	judge, agentID, err := buildJudge(pol, "127.0.0.1:8080")
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
	if _, _, err := buildJudge(pol, "127.0.0.1:8080"); err == nil {
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
	judge, agentID, err := buildJudge(pol, "127.0.0.1:8080")
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
	j, err := buildJudgeFrom(config.JudgeConfig{Enabled: false}, nil, "default")
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
	if _, err := buildJudgeFrom(jc, agents, "default"); err == nil {
		t.Fatal("expected error when local env key is unset")
	}

	// Set the key in the LOCAL env under the distributed name; build now succeeds.
	t.Setenv(envName, "sk-local-value")
	j, err := buildJudgeFrom(jc, agents, "default")
	if err != nil {
		t.Fatalf("unexpected error after setting local env key: %v", err)
	}
	if j == nil {
		t.Fatal("expected a judge once the local key resolves")
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
