package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/llmpolicy"
)

// newTestCmd returns a cobra command whose stdout is captured in the returned
// buffer.
func newTestCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	return cmd, buf
}

func TestPrintRecommendations_Text(t *testing.T) {
	cmd, buf := newTestCmd()
	recs := []llmpolicy.Recommendation{
		{Type: "add_deny", Domain: "evil.com", Reason: "spike of blocked attempts", Severity: "high"},
	}
	if err := printRecommendations(cmd, recs, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"add_deny", "evil.com", "high", "review only"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q; got:\n%s", want, out)
		}
	}
}

func TestPrintRecommendations_Empty(t *testing.T) {
	cmd, buf := newTestCmd()
	if err := printRecommendations(cmd, nil, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No recommendations") {
		t.Errorf("expected empty message, got %q", buf.String())
	}
}

func TestPrintRecommendations_JSON(t *testing.T) {
	cmd, buf := newTestCmd()
	recs := []llmpolicy.Recommendation{
		{Type: "investigate", Domain: "x.com", Reason: "off-hours", Severity: "low"},
	}
	if err := printRecommendations(cmd, recs, true); err != nil {
		t.Fatal(err)
	}
	var got []llmpolicy.Recommendation
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(got) != 1 || got[0].Domain != "x.com" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestPrintRecommendations_JSON_EmptyIsArray(t *testing.T) {
	cmd, buf := newTestCmd()
	if err := printRecommendations(cmd, nil, true); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("expected empty JSON array, got %q", buf.String())
	}
}

func TestAdviseClient_RequiresJudgeConfig(t *testing.T) {
	// No judge config -> cannot build a client.
	if _, err := adviseClient(config.Policy{}); err == nil {
		t.Fatal("expected error when judge config absent")
	}
}

func TestAdviseClient_RequiresAPIKeyEnv(t *testing.T) {
	pol := config.Policy{Judge: config.JudgeConfig{
		Model:     "gpt-4o-mini",
		BaseURL:   "https://api.openai.com/v1",
		APIKeyEnv: "WARDEN_TEST_KEY_DEFINITELY_UNSET",
	}}
	if _, err := adviseClient(pol); err == nil {
		t.Fatal("expected error when API key env var is empty")
	}
}

func TestAdviseClient_Success(t *testing.T) {
	t.Setenv("WARDEN_TEST_ADVISE_KEY", "sk-test")
	pol := config.Policy{Judge: config.JudgeConfig{
		Model:     "gpt-4o-mini",
		BaseURL:   "https://api.openai.com/v1",
		APIKeyEnv: "WARDEN_TEST_ADVISE_KEY",
	}}
	c, err := adviseClient(pol)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected a client")
	}
}

func TestRootHasAdviseCommand(t *testing.T) {
	root := newRootCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "advise" {
			found = true
		}
	}
	if !found {
		t.Error("root command missing 'advise' subcommand")
	}
}

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
