package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// TestWriteLLMProviders_RoundTripPreservesBlocks asserts the registry writer adds the
// `llmProviders:` block while preserving every other block byte-for-value, and that an
// EMPTY list DELETES the key (like WriteDetection/WriteIntegrations) — the round-trip
// discipline the whole config-writer family shares.
func TestWriteLLMProviders_RoundTripPreservesBlocks(t *testing.T) {
	cfg := Config{PolicyPath: writePolicyFileWithSettings(t, "api.openai.com")}
	srv := New(cfg)

	providers := []config.LLMProvider{
		{Name: "openai-main", BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini", APIKeyEnv: "OPENAI_API_KEY"},
		{Name: "anthropic-judge", BaseURL: "https://api.anthropic.com/v1", Model: "claude-haiku-4-5", APIKeyEnv: "ANTHROPIC_API_KEY"},
	}
	if err := srv.WriteLLMProviders(providers); err != nil {
		t.Fatalf("WriteLLMProviders: %v", err)
	}

	got := readFile(t, cfg.PolicyPath)
	// The registry block was written…
	for _, must := range []string{"llmProviders:", "openai-main", "anthropic-judge", "ANTHROPIC_API_KEY"} {
		if !strings.Contains(got, must) {
			t.Errorf("served config missing %q after llmProviders write; file:\n%s", must, got)
		}
	}
	// …and every pre-existing block survived (policy, judge, mcp, agents, logging).
	for _, must := range []string{"api.openai.com", "judge:", "mcp:", "agents:", "logging:"} {
		if !strings.Contains(got, must) {
			t.Errorf("llmProviders write clobbered pre-existing block %q; file:\n%s", must, got)
		}
	}
	// A fresh loader must still accept the written file (validation + default-deny).
	if _, err := config.NewLocalYAMLProvider(cfg.PolicyPath); err != nil {
		t.Fatalf("written config no longer loads: %v", err)
	}

	// Empty list DELETES the key rather than writing an empty sequence.
	if err := srv.WriteLLMProviders(nil); err != nil {
		t.Fatalf("WriteLLMProviders(nil): %v", err)
	}
	got = readFile(t, cfg.PolicyPath)
	if strings.Contains(got, "llmProviders:") {
		t.Errorf("empty list should DELETE the llmProviders key; file:\n%s", got)
	}
	if !strings.Contains(got, "judge:") {
		t.Errorf("deleting llmProviders must not clobber other blocks; file:\n%s", got)
	}
}

// TestWriteLLMProviders_RejectsDanglingReference proves the full-loader validation in
// atomicWriteConfig catches a cross-block error: removing a provider that judge.
// llmProvider still names is rejected HERE (never silently written).
func TestWriteLLMProviders_RejectsDanglingReference(t *testing.T) {
	path := writePolicyFileWithProviderJudge(t)
	srv := New(Config{PolicyPath: path})

	// Removing every provider while judge.llmProvider still points at "p1" must fail.
	if err := srv.WriteLLMProviders(nil); err == nil {
		t.Fatal("removing a referenced provider should be rejected by the full loader")
	}
	// The good file survived (the referenced provider is still there).
	if !strings.Contains(readFile(t, path), "p1") {
		t.Error("a rejected write must not have altered the served file")
	}
}

// fakeQuery is a minimal analytics.AnalyticsQuery so the Explore /query/generate
// endpoint is available (past its 404 guard); its Query is never exercised (the test
// only reaches the LLM-generator stage).
type fakeQuery struct{}

func (fakeQuery) Query(context.Context, string, int) (analytics.QueryResult, error) {
	return analytics.QueryResult{}, nil
}
func (fakeQuery) Schema() analytics.SchemaInfo { return analytics.SchemaInfo{Dialect: "sqlite"} }

// TestWriteLLMProviders_ReloadReinjectsSQLGenerator is the money test for the reload
// seam: after selecting a RESOLVABLE Explore provider, the CP dashboard's NL→SQL
// generator is RE-INJECTED live — the /query/generate endpoint stops returning the
// 409 llm_not_configured it returned while nothing resolved.
func TestWriteLLMProviders_ReloadReinjectsSQLGenerator(t *testing.T) {
	cfg := Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: "gen-token"}
	srv := New(cfg)
	mux := srv.Handler() // sets s.dash + runs the initial (nil) inject
	// Attach a query engine so the endpoint clears its 404 guard; the in-memory store
	// does not implement AnalyticsQuery, so we wire a fake onto the SAME dashboard.
	srv.dash.SetQueryEngine(fakeQuery{})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Precondition: no provider resolves yet → 409 llm_not_configured.
	if code := postGenerate(t, ts.URL); code != http.StatusConflict {
		t.Fatalf("precondition generate = %d, want 409 (no generator)", code)
	}

	// Make a provider resolvable on THIS (control-plane) node, register it, then select
	// it for Explore. WriteSettings' re-inject must install the generator.
	t.Setenv("TEST_LLM_KEY", "present")
	if err := srv.WriteLLMProviders([]config.LLMProvider{
		{Name: "p1", BaseURL: "https://example.invalid/v1", Model: "m", APIKeyEnv: "TEST_LLM_KEY"},
	}); err != nil {
		t.Fatalf("WriteLLMProviders: %v", err)
	}
	if err := srv.WriteSettings(config.SettingsWire{Explore: &config.ExploreSettings{LLMProvider: "p1"}}); err != nil {
		t.Fatalf("WriteSettings(explore): %v", err)
	}

	// The generator is now injected: the endpoint no longer 409s (it reaches the LLM,
	// which fails against the dummy host — a 502, NOT the 409 "not configured").
	if code := postGenerate(t, ts.URL); code == http.StatusConflict {
		t.Fatalf("after selecting a resolvable Explore provider, generate still 409s — generator was not re-injected")
	}
}

func postGenerate(t *testing.T, base string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/dashboard/api/query/generate", strings.NewReader(`{"question":"count events"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer gen-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// writePolicyFileWithProviderJudge writes a config whose judge selects a registry
// provider "p1" by name, so a write that removes p1 must be rejected as a dangling
// reference by the loader.
func writePolicyFileWithProviderJudge(t *testing.T) string {
	t.Helper()
	path := writePolicyFile(t, "api.openai.com")
	body := readFile(t, path) +
		"llmProviders:\n  - name: p1\n    baseURL: https://api.openai.com/v1\n    model: gpt-4o-mini\n    apiKeyEnv: OPENAI_API_KEY\n" +
		"judge:\n  enabled: true\n  llmProvider: p1\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
