package worker

import (
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// TestPickExploreLLM covers the three selection branches, including the back-compat
// fallback that keeps today's behavior when no explore.llmProvider is set:
//   - name == ""            → the judge's client (fallback / no explore block)
//   - name set & present    → the exact named registry client (distinct from judge)
//   - name set & absent      → nil (→ dashboard's existing 409 llm_not_configured)
func TestPickExploreLLM(t *testing.T) {
	t.Setenv("WARDEN_EXPLORE_JUDGE_KEY", "sk-judge")
	t.Setenv("WARDEN_EXPLORE_NAMED_KEY", "sk-explore")

	judgeClient, err := BuildLLMClient(config.JudgeConfig{
		Enabled:   true,
		Model:     "m-j",
		BaseURL:   "https://j/v1",
		APIKeyEnv: "WARDEN_EXPLORE_JUDGE_KEY",
	})
	if err != nil || judgeClient == nil {
		t.Fatalf("build judge client: (%v,%v)", judgeClient, err)
	}
	clients, _ := BuildLLMClients([]config.LLMProvider{
		{Name: "explore-prov", BaseURL: "https://e/v1", Model: "m-e", APIKeyEnv: "WARDEN_EXPLORE_NAMED_KEY"},
	})

	// Unset name → fall back to the judge's client (back-compat: no behavior change).
	if got := PickExploreLLM("", clients, judgeClient); got != judgeClient {
		t.Fatalf("unset name: want the judge client, got %v", got)
	}

	// Named + present → that exact client, and it must be DISTINCT from the judge's
	// (Explore honors explore.llmProvider independent of the judge).
	got := PickExploreLLM("explore-prov", clients, judgeClient)
	if got != clients["explore-prov"] {
		t.Fatalf("named present: want the exact named client, got %v", got)
	}
	if got == judgeClient {
		t.Fatal("named present: Explore must pick a client distinct from the judge's")
	}

	// Named + absent/unresolved → nil, so the CALLER never boxes a typed-nil into
	// the SQLGenerator interface and the dashboard reports 409 (llm_not_configured).
	if got := PickExploreLLM("missing", clients, judgeClient); got != nil {
		t.Fatalf("named absent: want nil, got %v", got)
	}
}

// TestPickExploreLLM_UnsetWithNoJudge proves the fully-unconfigured path: no
// explore selection and no judge client → nil, which the caller's `if gen != nil`
// guard turns into "SetSQLGenerator never called" → the dashboard's 409 path.
func TestPickExploreLLM_UnsetWithNoJudge(t *testing.T) {
	if got := PickExploreLLM("", nil, nil); got != nil {
		t.Fatalf("unset name + nil judge: want nil, got %v", got)
	}
}
