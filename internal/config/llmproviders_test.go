package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestParse_LLMProvidersBlock parses a valid llmProviders block (including a
// timeout duration) and asserts it lands as a typed slice with fields intact.
func TestParse_LLMProvidersBlock(t *testing.T) {
	y := baseAllow + `
llmProviders:
  - name: openai-main
    baseURL: https://api.openai.com/v1
    model: gpt-4o-mini
    apiKeyEnv: OPENAI_API_KEY
    timeout: 30s
  - name: anthropic-judge
    baseURL: https://api.anthropic.com/v1
    model: claude-haiku-4-5
    apiKeyEnv: ANTHROPIC_API_KEY
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, err := p.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.LLMProviders) != 2 {
		t.Fatalf("LLMProviders len = %d, want 2", len(pol.LLMProviders))
	}
	first := pol.LLMProviders[0]
	if first.Name != "openai-main" || first.BaseURL != "https://api.openai.com/v1" ||
		first.Model != "gpt-4o-mini" || first.APIKeyEnv != "OPENAI_API_KEY" {
		t.Fatalf("first provider not round-tripped: %+v", first)
	}
	if first.Timeout != 30*time.Second {
		t.Fatalf("first provider timeout = %v, want 30s", first.Timeout)
	}
	// An omitted timeout stays 0 (⇒ client default).
	if pol.LLMProviders[1].Timeout != 0 {
		t.Fatalf("second provider timeout = %v, want 0 (default)", pol.LLMProviders[1].Timeout)
	}
}

// TestParse_LLMProvidersAbsent asserts an absent block yields a nil slice and no
// error — byte-identical to a config that never declared providers.
func TestParse_LLMProvidersAbsent(t *testing.T) {
	p, err := NewLocalYAMLProvider(writeTemp(t, baseAllow))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := p.GetPolicy()
	if pol.LLMProviders != nil {
		t.Fatalf("LLMProviders = %+v, want nil when absent", pol.LLMProviders)
	}
}

// TestValidate_LLMProvidersErrors covers uniqueness + per-field-required rules.
func TestValidate_LLMProvidersErrors(t *testing.T) {
	const full = "  - name: a\n    baseURL: https://x/v1\n    model: m\n    apiKeyEnv: KEY\n"
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing name",
			yaml: baseAllow + "llmProviders:\n  - baseURL: https://x/v1\n    model: m\n    apiKeyEnv: KEY\n",
			want: "name is required",
		},
		{
			name: "missing baseURL",
			yaml: baseAllow + "llmProviders:\n  - name: a\n    model: m\n    apiKeyEnv: KEY\n",
			want: "baseURL is required",
		},
		{
			name: "missing model",
			yaml: baseAllow + "llmProviders:\n  - name: a\n    baseURL: https://x/v1\n    apiKeyEnv: KEY\n",
			want: "model is required",
		},
		{
			name: "missing apiKeyEnv",
			yaml: baseAllow + "llmProviders:\n  - name: a\n    baseURL: https://x/v1\n    model: m\n",
			want: "apiKeyEnv is required",
		},
		{
			name: "duplicate name",
			yaml: baseAllow + "llmProviders:\n" + full + full,
			want: "duplicate name",
		},
		{
			name: "invalid timeout duration",
			yaml: baseAllow + "llmProviders:\n  - name: a\n    baseURL: https://x/v1\n    model: m\n    apiKeyEnv: KEY\n    timeout: notaduration\n",
			want: "not a valid duration",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewLocalYAMLProvider(writeTemp(t, tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestLLMProviders_WireRoundTrip asserts Policy → SettingsWire → Policy preserves
// providers, and that the wire carries ONLY the apiKeyEnv NAME — never a key value
// (the SECRET-FREE invariant). There is no value field to carry, so the guarantee
// is structural; the JSON assertion makes the "name only" contract explicit.
func TestLLMProviders_WireRoundTrip(t *testing.T) {
	orig := []LLMProvider{
		{Name: "openai-main", BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini", APIKeyEnv: "OPENAI_API_KEY", Timeout: 30 * time.Second},
		{Name: "anthropic-judge", BaseURL: "https://api.anthropic.com/v1", Model: "claude-haiku-4-5", APIKeyEnv: "ANTHROPIC_API_KEY"},
	}
	// The wire is only emitted for a policy with meaningful behavioral config, and
	// llmProviders alone must make it emit (any = true).
	wire := SettingsWireFromPolicy(Policy{LLMProviders: orig})
	if wire == nil {
		t.Fatal("SettingsWireFromPolicy returned nil; llmProviders should make the wire non-nil")
	}
	if len(wire.LLMProviders) != 2 {
		t.Fatalf("wire.LLMProviders len = %d, want 2", len(wire.LLMProviders))
	}
	if wire.LLMProviders[0].TimeoutSeconds != 30 {
		t.Fatalf("wire timeoutSeconds = %d, want 30", wire.LLMProviders[0].TimeoutSeconds)
	}

	// Secret-free: the marshaled wire carries the env NAME, and nothing resembling
	// a resolved key value (there is no field that could hold one).
	blob, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	if !strings.Contains(string(blob), "OPENAI_API_KEY") {
		t.Fatalf("wire should carry the apiKeyEnv NAME: %s", blob)
	}
	if strings.Contains(string(blob), "\"apiKey\"") {
		t.Fatalf("wire must not carry a key value field: %s", blob)
	}

	got := LLMProvidersFromSettings(wire.LLMProviders)
	if len(got) != len(orig) {
		t.Fatalf("round-trip len = %d, want %d", len(got), len(orig))
	}
	for i := range orig {
		if got[i] != orig[i] {
			t.Fatalf("provider[%d] round-trip mismatch:\n got %+v\nwant %+v", i, got[i], orig[i])
		}
	}
}

// TestLLMProvidersFromSettings_Nil asserts the reverse mapper maps the empty case
// to nil (matching "no providers distributed").
func TestLLMProvidersFromSettings_Nil(t *testing.T) {
	if got := LLMProvidersFromSettings(nil); got != nil {
		t.Fatalf("LLMProvidersFromSettings(nil) = %+v, want nil", got)
	}
}

// TestEncodeLLMProvidersNode_RoundTrips encodes providers, marshals under an
// `llmProviders:` key, and parses back through the full loader — asserting the
// write direction is the faithful inverse of the read direction, timeout included.
func TestEncodeLLMProvidersNode_RoundTrips(t *testing.T) {
	orig := []LLMProvider{
		{Name: "openai-main", BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini", APIKeyEnv: "OPENAI_API_KEY", Timeout: 30 * time.Second},
		{Name: "anthropic-judge", BaseURL: "https://api.anthropic.com/v1", Model: "claude-haiku-4-5", APIKeyEnv: "ANTHROPIC_API_KEY"},
	}
	node, err := EncodeLLMProvidersNode(orig)
	if err != nil {
		t.Fatalf("EncodeLLMProvidersNode: %v", err)
	}
	blk, err := yaml.Marshal(map[string]yaml.Node{"llmProviders": node})
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	p, err := parse([]byte(baseAllow + "\n" + string(blk)))
	if err != nil {
		t.Fatalf("parse round-tripped config: %v\n%s", err, blk)
	}
	got := p.policy.LLMProviders
	if len(got) != len(orig) {
		t.Fatalf("round-trip len = %d, want %d\n%s", len(got), len(orig), blk)
	}
	for i := range orig {
		if got[i] != orig[i] {
			t.Fatalf("provider[%d] mismatch:\n got %+v\nwant %+v\n%s", i, got[i], orig[i], blk)
		}
	}
	// An omitted (zero) timeout must NOT be written (omitempty keeps it minimal).
	if strings.Contains(string(blk), "timeout: 0") {
		t.Errorf("zero timeout should be omitted from encoded block:\n%s", blk)
	}
}

// TestLLMProviders_DeepCopyIndependent asserts both DeepCopy paths (Policy and
// SettingsWire) allocate an independent backing array, so mutating the copy never
// touches the original — the shared-slice aliasing hazard for distributed config.
func TestLLMProviders_DeepCopyIndependent(t *testing.T) {
	orig := []LLMProvider{
		{Name: "openai-main", BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini", APIKeyEnv: "OPENAI_API_KEY", Timeout: 30 * time.Second},
	}

	pol := Policy{Allowlist: []AllowlistEntry{{Domain: "api.openai.com"}}, LLMProviders: orig}
	cp := pol.DeepCopy()
	cp.LLMProviders[0].Name = "mutated"
	if pol.LLMProviders[0].Name != "openai-main" {
		t.Fatalf("Policy.DeepCopy aliased LLMProviders: original mutated to %q", pol.LLMProviders[0].Name)
	}

	wire := &SettingsWire{LLMProviders: []LLMProviderSettings{{Name: "openai-main", APIKeyEnv: "OPENAI_API_KEY", TimeoutSeconds: 30}}}
	wcp := wire.DeepCopy()
	wcp.LLMProviders[0].Name = "mutated"
	if wire.LLMProviders[0].Name != "openai-main" {
		t.Fatalf("SettingsWire.DeepCopy aliased LLMProviders: original mutated to %q", wire.LLMProviders[0].Name)
	}
}

// TestParse_JudgeLLMProviderSelectsRegistry parses a judge that NAMES a registry
// entry via judge.llmProvider and asserts the name lands on JudgeConfig. The
// inline model/baseURL/apiKeyEnv are still present (all-or-nothing selection is a
// runtime concern; the fields parse regardless).
func TestParse_JudgeLLMProviderSelectsRegistry(t *testing.T) {
	y := baseAllow + `
llmProviders:
  - name: anthropic-judge
    baseURL: https://api.anthropic.com/v1
    model: claude-haiku-4-5
    apiKeyEnv: ANTHROPIC_API_KEY
judge:
  enabled: true
  llmProvider: anthropic-judge
  model: m
  baseURL: https://x/v1
  apiKeyEnv: K
agents:
  - {id: default, policy: allow reads}
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.Judge.LLMProvider != "anthropic-judge" {
		t.Fatalf("judge.LLMProvider = %q, want anthropic-judge", pol.Judge.LLMProvider)
	}
}

// TestValidate_JudgeLLMProviderDanglingName asserts that a judge.llmProvider naming
// a provider ABSENT from llmProviders fails at config LOAD (a typo is an operator
// error worth surfacing early), while a name that DOES match loads cleanly.
func TestValidate_JudgeLLMProviderDanglingName(t *testing.T) {
	dangling := baseAllow + `
llmProviders:
  - {name: openai-main, baseURL: https://api.openai.com/v1, model: gpt-4o-mini, apiKeyEnv: OPENAI_API_KEY}
judge:
  enabled: true
  llmProvider: does-not-exist
  model: m
  baseURL: https://x/v1
  apiKeyEnv: K
agents:
  - {id: default, policy: x}
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, dangling)); err == nil {
		t.Fatal("expected a load error for a dangling judge.llmProvider name")
	} else if !strings.Contains(err.Error(), "does-not-exist") {
		t.Fatalf("error should name the dangling provider, got: %v", err)
	}

	valid := baseAllow + `
llmProviders:
  - {name: openai-main, baseURL: https://api.openai.com/v1, model: gpt-4o-mini, apiKeyEnv: OPENAI_API_KEY}
judge:
  enabled: true
  llmProvider: openai-main
  model: m
  baseURL: https://x/v1
  apiKeyEnv: K
agents:
  - {id: default, policy: x}
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, valid)); err != nil {
		t.Fatalf("a matching judge.llmProvider must load cleanly, got: %v", err)
	}
}

// TestParse_InlineJudgeNoProvidersBackCompat proves the back-compat guarantee: a
// config with an inline judge and NO llmProviders / NO judge.llmProvider loads
// exactly as before — empty LLMProvider selection, nil registry.
func TestParse_InlineJudgeNoProvidersBackCompat(t *testing.T) {
	y := baseAllow + `
judge:
  enabled: true
  model: m
  baseURL: https://x/v1
  apiKeyEnv: K
agents:
  - {id: default, policy: x}
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("inline judge must load unchanged, got: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.Judge.LLMProvider != "" {
		t.Errorf("inline judge.LLMProvider = %q, want empty", pol.Judge.LLMProvider)
	}
	if pol.LLMProviders != nil {
		t.Errorf("LLMProviders = %+v, want nil when absent", pol.LLMProviders)
	}
}
