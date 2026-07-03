package config

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// LLMProvider is one named entry in the shared `llmProviders:` registry. Each
// feature that needs an LLM (the inline judge, Explore NL→SQL) can later select
// a provider BY NAME; a config that names none keeps today's inline behavior.
//
// SECRET-LOCAL: APIKeyEnv is an env-var NAME only (e.g. "OPENAI_API_KEY"), never
// a key value. The value is resolved from the hosting node's OWN environment at
// client-build time, so the whole block is wire-safe and rides SettingsWire.
type LLMProvider struct {
	// Name identifies the provider; unique across the list (validated at load).
	Name string
	// BaseURL is the provider's API base (required).
	BaseURL string
	// Model is the model identifier passed to the provider (required).
	Model string
	// APIKeyEnv is the env-var NAME the key resolves from — never a value (required).
	APIKeyEnv string
	// Timeout is the per-provider client timeout; 0 => client default.
	Timeout time.Duration
}

// rawLLMProvider mirrors one on-disk `llmProviders:` list item. KnownFields(true)
// is strict, so this MUST be registered in rawConfig or configs carrying the
// block fail to parse. Timeout is a Go-duration string ("30s", "1m"), parsed via
// the shared parseDurationField; `omitempty` keeps the write path minimal.
type rawLLMProvider struct {
	Name      string `yaml:"name"`
	BaseURL   string `yaml:"baseURL"`
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"apiKeyEnv"`
	Timeout   string `yaml:"timeout,omitempty"`
}

// parseLLMProviders converts the raw llmProviders list into typed config. An
// absent/empty block yields a nil slice (byte-identical to today). Duration
// strings are parsed here (non-negative enforced by parseDurationField);
// structural validation happens in validateLLMProviders.
func parseLLMProviders(raw []rawLLMProvider) ([]LLMProvider, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]LLMProvider, 0, len(raw))
	for i, r := range raw {
		p := LLMProvider{
			Name:      r.Name,
			BaseURL:   r.BaseURL,
			Model:     r.Model,
			APIKeyEnv: r.APIKeyEnv,
		}
		if err := parseDurationField(fmt.Sprintf("llmProviders[%d].timeout", i), r.Timeout, &p.Timeout); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// EncodeLLMProvidersNode encodes typed providers into a yaml.Node matching the
// on-disk `llmProviders:` sequence — the write-direction counterpart of
// parseLLMProviders and the analogue of EncodeIntegrationsNode/EncodeDetectionNode
// for the future config-writer (M4). It round-trips through rawLLMProvider so the
// YAML tags stay in lockstep with the read path, and emits Timeout as the same
// Go-duration string the parser accepts (omitted when 0 ⇒ client default). Callers
// decide whether an empty list deletes the key vs writes an empty sequence.
func EncodeLLMProvidersNode(ps []LLMProvider) (yaml.Node, error) {
	raw := make([]rawLLMProvider, 0, len(ps))
	for _, p := range ps {
		raw = append(raw, rawLLMProvider{
			Name:      p.Name,
			BaseURL:   p.BaseURL,
			Model:     p.Model,
			APIKeyEnv: p.APIKeyEnv,
			Timeout:   llmProviderDurString(p.Timeout),
		})
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return yaml.Node{}, fmt.Errorf("config: encode llmProviders: %w", err)
	}
	return node, nil
}

// llmProviderDurString renders a provider timeout as a Go-duration string, or ""
// when 0 (⇒ omitted by omitempty / client default) — the non-pointer analogue of
// detection.go's durOverride.
func llmProviderDurString(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

// validateLLMProviders checks each provider structurally: name/baseURL/model/
// apiKeyEnv are required, and names are unique across the list (mirroring the
// integrations duplicate-name check). apiKeyEnv is the env NAME only — never a
// value. A provider timeout, when set, is already guaranteed non-negative by
// parseDurationField (0 means client default), so no further timeout check is
// needed here. Error style matches validateIntegrations.
func validateLLMProviders(ps []LLMProvider) error {
	seen := make(map[string]struct{}, len(ps))
	for i, p := range ps {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("config: llmProviders[%d]: name is required", i)
		}
		if _, dup := seen[p.Name]; dup {
			return fmt.Errorf("config: llmProviders[%d]: duplicate name %q", i, p.Name)
		}
		seen[p.Name] = struct{}{}
		if strings.TrimSpace(p.BaseURL) == "" {
			return fmt.Errorf("config: llmProviders[%d]: baseURL is required", i)
		}
		if strings.TrimSpace(p.Model) == "" {
			return fmt.Errorf("config: llmProviders[%d]: model is required", i)
		}
		if strings.TrimSpace(p.APIKeyEnv) == "" {
			return fmt.Errorf("config: llmProviders[%d]: apiKeyEnv is required", i)
		}
	}
	return nil
}
