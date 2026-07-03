package config

import (
	"fmt"
	"strings"
	"time"
)

// JudgeConfig configures the inline LLM judge. The LLM is never authoritative:
// it is consulted only for requests that match neither the allowlist nor the
// denylist, and it fails closed (deny) on any error.
type JudgeConfig struct {
	Enabled  bool
	Provider string
	// LLMProvider optionally names an entry in the shared llmProviders registry
	// the judge should use for its LLM client. Empty (the default) keeps today's
	// INLINE behavior (Model/BaseURL/APIKeyEnv build the client directly). A NAME
	// only — never a key value; the selected provider's apiKeyEnv still resolves
	// from THIS node's own env at client-build time.
	LLMProvider    string
	Model          string
	BaseURL        string
	APIKeyEnv      string
	Timeout        time.Duration
	CircuitBreaker CircuitBreakerConfig
	CacheTTL       time.Duration
	// RateLimit caps judge invocations, e.g. "100/minute".
	RateLimit string
}

// CircuitBreakerConfig bounds consecutive LLM failures before the judge trips
// open and fails closed for the cooldown.
type CircuitBreakerConfig struct {
	MaxFailures int
	Cooldown    time.Duration
}

// rawJudge mirrors the on-disk `judge:` block. Pointer so absence is distinct
// from an all-zero (disabled) block.
type rawJudge struct {
	Enabled        bool   `yaml:"enabled"`
	Provider       string `yaml:"provider"`
	LLMProvider    string `yaml:"llmProvider"`
	Model          string `yaml:"model"`
	BaseURL        string `yaml:"baseURL"`
	APIKeyEnv      string `yaml:"apiKeyEnv"`
	Timeout        string `yaml:"timeout"`
	CircuitBreaker struct {
		MaxFailures int    `yaml:"maxFailures"`
		Cooldown    string `yaml:"cooldown"`
	} `yaml:"circuitBreaker"`
	Cache struct {
		TTL string `yaml:"ttl"`
	} `yaml:"cache"`
	RateLimit string `yaml:"rateLimit"`
}

// judge defaults applied when the corresponding field is omitted.
const (
	defaultJudgeTimeout     = 5 * time.Second
	defaultJudgeMaxFailures = 5
	defaultJudgeCooldown    = 30 * time.Second
	defaultJudgeCacheTTL    = 5 * time.Minute
)

// parseJudge converts the raw judge block into a typed JudgeConfig, parsing
// durations and applying defaults. Validation of cross-field requirements (e.g.
// model + apiKeyEnv when enabled) happens in validate.
func parseJudge(r *rawJudge) (JudgeConfig, error) {
	jc := JudgeConfig{
		Enabled:     r.Enabled,
		Provider:    r.Provider,
		LLMProvider: r.LLMProvider,
		Model:       r.Model,
		BaseURL:     r.BaseURL,
		APIKeyEnv:   r.APIKeyEnv,
		RateLimit:   r.RateLimit,
		Timeout:     defaultJudgeTimeout,
		CacheTTL:    defaultJudgeCacheTTL,
		CircuitBreaker: CircuitBreakerConfig{
			MaxFailures: defaultJudgeMaxFailures,
			Cooldown:    defaultJudgeCooldown,
		},
	}
	if r.Provider == "" {
		jc.Provider = "openai"
	}
	if err := parseDurationField("judge.timeout", r.Timeout, &jc.Timeout); err != nil {
		return JudgeConfig{}, err
	}
	if err := parseDurationField("judge.cache.ttl", r.Cache.TTL, &jc.CacheTTL); err != nil {
		return JudgeConfig{}, err
	}
	if err := parseDurationField("judge.circuitBreaker.cooldown", r.CircuitBreaker.Cooldown, &jc.CircuitBreaker.Cooldown); err != nil {
		return JudgeConfig{}, err
	}
	if r.CircuitBreaker.MaxFailures != 0 {
		jc.CircuitBreaker.MaxFailures = r.CircuitBreaker.MaxFailures
	}
	return jc, nil
}

// validateJudge enforces the judge's runtime requirements only when it is
// enabled, so a disabled judge with zero-valued config is always valid.
func validateJudge(j JudgeConfig, agents []AgentPolicy) error {
	if !j.Enabled {
		return nil
	}
	// A named llmProvider supplies the LLM connection (its BaseURL/Model/APIKeyEnv
	// build the client via BuildLLMClients; resolveJudgeLLM never reads the inline
	// trio in that case), so the inline model/baseURL/apiKeyEnv are optional then.
	// They are only required on the inline path (llmProvider empty). Existence of a
	// named provider is enforced separately by validateJudgeProviderRef.
	if strings.TrimSpace(j.LLMProvider) == "" {
		if strings.TrimSpace(j.Model) == "" {
			return fmt.Errorf("config: judge.model is required when judge.enabled")
		}
		if strings.TrimSpace(j.APIKeyEnv) == "" {
			return fmt.Errorf("config: judge.apiKeyEnv is required when judge.enabled")
		}
		if strings.TrimSpace(j.BaseURL) == "" {
			return fmt.Errorf("config: judge.baseURL is required when judge.enabled")
		}
	}
	if len(agents) == 0 {
		return fmt.Errorf("config: at least one agents[] policy is required when judge.enabled")
	}
	if j.RateLimit != "" {
		if err := validateRateLimit("judge.rateLimit", j.RateLimit); err != nil {
			return err
		}
	}
	return nil
}

// validateJudgeProviderRef enforces that a judge.llmProvider selection names an
// EXISTING entry in the shared llmProviders registry. A DANGLING name is an
// operator typo worth surfacing strictly at config LOAD. It is deliberately
// distinct from a provider that EXISTS yet has an empty key env on the hosting
// node — that is an environment gap resolved fail-soft at runtime (resolveJudgeLLM
// disables the judge, logged), never a load failure. This is a cross-block check,
// so it runs from validate() after both the judge and llmProviders are parsed. It
// applies regardless of judge.enabled: a typo in a currently-disabled block is
// still worth catching before it is toggled on.
func validateJudgeProviderRef(j JudgeConfig, providers []LLMProvider) error {
	name := strings.TrimSpace(j.LLMProvider)
	if name == "" {
		return nil
	}
	for _, p := range providers {
		if p.Name == name {
			return nil
		}
	}
	return fmt.Errorf("config: judge.llmProvider %q does not name any llmProviders entry", j.LLMProvider)
}
