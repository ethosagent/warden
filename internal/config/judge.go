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
	Enabled        bool
	Provider       string
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
		Enabled:   r.Enabled,
		Provider:  r.Provider,
		Model:     r.Model,
		BaseURL:   r.BaseURL,
		APIKeyEnv: r.APIKeyEnv,
		RateLimit: r.RateLimit,
		Timeout:   defaultJudgeTimeout,
		CacheTTL:  defaultJudgeCacheTTL,
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
	if strings.TrimSpace(j.Model) == "" {
		return fmt.Errorf("config: judge.model is required when judge.enabled")
	}
	if strings.TrimSpace(j.APIKeyEnv) == "" {
		return fmt.Errorf("config: judge.apiKeyEnv is required when judge.enabled")
	}
	if strings.TrimSpace(j.BaseURL) == "" {
		return fmt.Errorf("config: judge.baseURL is required when judge.enabled")
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
