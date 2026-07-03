package config

import (
	"fmt"
	"strings"
)

// ExploreConfig configures the Explore / NL→SQL feature's LLM selection. It is
// CP-LOCAL (json:"-" on Policy, and it is NOT projected onto the settings wire):
// the query engine Explore runs against is set only on the control plane
// (SetQueryEngine is CP-only), so distributing this to workers would be dead
// config — exactly the reasoning that keeps Detection/Integrations CP-local. An
// absent/empty block yields the zero value, and Explore reuses the judge's
// resolved client exactly as before (no behavior change).
type ExploreConfig struct {
	// LLMProvider optionally names an entry in the shared llmProviders registry the
	// Explore NL→SQL feature should use for its LLM client, INDEPENDENT of the
	// judge. Empty (the default) keeps today's behavior: Explore falls back to the
	// judge's resolved client. A NAME only — never a key value; the selected
	// provider's apiKeyEnv resolves from the CP's own env at client-build time.
	LLMProvider string
}

// rawExplore mirrors the on-disk `explore:` block. Pointer so absence is distinct
// from an empty block; both map to the zero ExploreConfig (no behavior change).
type rawExplore struct {
	LLMProvider string `yaml:"llmProvider"`
}

// parseExplore converts the raw explore block into a typed ExploreConfig. An
// absent block (nil) yields the zero value, so Explore reuses the judge's client.
func parseExplore(r *rawExplore) ExploreConfig {
	if r == nil {
		return ExploreConfig{}
	}
	return ExploreConfig{LLMProvider: r.LLMProvider}
}

// validateExploreProviderRef enforces that an explore.llmProvider selection names
// an EXISTING entry in the shared llmProviders registry. A DANGLING name is an
// operator typo worth surfacing strictly at config LOAD — the same discipline as
// validateJudgeProviderRef. It is deliberately distinct from a provider that
// EXISTS yet has an empty key env on the hosting node: that is an environment gap
// resolved fail-soft at runtime (Explore leaves SetSQLGenerator unset → the
// existing 409 llm_not_configured path), never a load failure. This is a
// cross-block check, so it runs from validate() after both the explore and
// llmProviders blocks are parsed.
func validateExploreProviderRef(e ExploreConfig, providers []LLMProvider) error {
	name := strings.TrimSpace(e.LLMProvider)
	if name == "" {
		return nil
	}
	for _, p := range providers {
		if p.Name == name {
			return nil
		}
	}
	return fmt.Errorf("config: explore.llmProvider %q does not name any llmProviders entry", e.LLMProvider)
}
