// Package config defines the ConfigProvider interface and the policy/config
// types loaded from a local YAML file (phase 1). The same schema is reused
// when configuration later comes from a control-plane pull, so callers depend
// only on the interface, never on the concrete provider.
package config

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigProvider supplies the active policy. The interface is deliberately
// tiny: phase 1 is a local YAML file; later phases add a control-plane pull
// behind the same method. Watch/refresh methods are added only when a remote
// implementation lands.
type ConfigProvider interface {
	GetPolicy() (Policy, error)
}

// Policy is the resolved configuration the proxy enforces.
type Policy struct {
	// Allowlist is the set of permitted destinations. Anything not present is
	// denied (default-deny).
	Allowlist []AllowlistEntry `json:"allowlist"`
	// Denylist is checked before the allowlist; deny wins on conflict.
	Denylist []DenylistEntry `json:"denylist"`
	// Secrets maps placeholder tokens to their source env var (phase 1).
	Secrets []SecretMapping `json:"-"`
	// CacheTTLSeconds is the secret cache time-to-live in seconds.
	CacheTTLSeconds int `json:"-"`
	// LogLevel and LogFormat configure observability output.
	LogLevel  string `json:"-"`
	LogFormat string `json:"-"`

	// Judge configures the optional inline LLM judge. Disabled by default; when
	// disabled every field is zero-valued and harmless.
	Judge JudgeConfig `json:"-"`
	// Agents holds per-agent natural-language policies consulted by the judge.
	Agents []AgentPolicy `json:"-"`
	// Advisory configures the optional offline advisory mode (CLI-only).
	Advisory AdvisoryConfig `json:"-"`
	// Observability configures OTel metrics + structured logging. Off by default.
	Observability ObservabilityConfig `json:"-"`
}

// ObservabilityConfig configures the OTel emission seam (Phase 1: metrics +
// structured logging). Everything is off by default; a zero value is harmless.
// Traces (Phase 2) and collector recipes (Phase 3) are deferred.
type ObservabilityConfig struct {
	// Enabled gates the entire subsystem.
	Enabled bool
	// ServiceName populates the OTel resource (defaults to "warden").
	ServiceName string
	// MetricsEnabled gates the Prometheus /metrics exporter on the admin
	// listener. Defaults to true when the block is present.
	MetricsEnabled bool
	// OTLPEndpoint, when non-empty, enables an outbound OTLP/grpc metric push to
	// a collector (e.g. "otel-collector:4317").
	OTLPEndpoint string
	// ResourceAttributes are extra bounded resource key/value pairs. Never put
	// secrets here.
	ResourceAttributes map[string]string
}

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

// AgentPolicy is one agent's natural-language policy text.
type AgentPolicy struct {
	ID     string
	Policy string
}

// AdvisoryConfig configures offline advisory mode.
type AdvisoryConfig struct {
	Enabled bool
}

// DeepCopy returns a deep copy of the policy, with all slices independently
// allocated so mutations to the copy cannot affect the original.
func (p Policy) DeepCopy() Policy {
	cp := p
	cp.Allowlist = append([]AllowlistEntry(nil), p.Allowlist...)
	cp.Denylist = append([]DenylistEntry(nil), p.Denylist...)
	cp.Secrets = append([]SecretMapping(nil), p.Secrets...)
	cp.Agents = append([]AgentPolicy(nil), p.Agents...)
	if p.Observability.ResourceAttributes != nil {
		ra := make(map[string]string, len(p.Observability.ResourceAttributes))
		for k, v := range p.Observability.ResourceAttributes {
			ra[k] = v
		}
		cp.Observability.ResourceAttributes = ra
	}
	return cp
}

// AllowlistEntry is a single permitted destination. Port is optional; when
// zero the policy engine infers 443 (HTTPS) or 80 (HTTP). RateLimit and
// TimeWindow are reserved for milestone 2: they parse from config but are
// unused in phase 1.
type AllowlistEntry struct {
	Domain string `yaml:"domain" json:"domain"`
	Port   int    `yaml:"port,omitempty" json:"port"`

	// Reserved (M2): parsed but not enforced in phase 1.
	RateLimit  string `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	TimeWindow string `yaml:"timeWindow,omitempty" json:"timeWindow,omitempty"`
}

// SecretMapping ties a placeholder the agent holds to the env var that carries
// the real value (phase 1 ENV provider).
type SecretMapping struct {
	Placeholder string `yaml:"placeholder"`
	EnvVar      string `yaml:"envVar"`
}

// DenylistEntry is a single explicitly-blocked destination. The denylist is
// checked before the allowlist — deny wins on conflict.
type DenylistEntry struct {
	Domain string `yaml:"domain" json:"domain"`
	Port   int    `yaml:"port,omitempty" json:"port"`
}

// rawConfig mirrors the on-disk YAML shape (see configs/config.example.yaml).
type rawConfig struct {
	Policy struct {
		Allowlist []AllowlistEntry `yaml:"allowlist"`
		Denylist  []DenylistEntry  `yaml:"denylist"`
	} `yaml:"policy"`
	Secrets []SecretMapping `yaml:"secrets"`
	Cache   struct {
		TTL int `yaml:"ttl"`
	} `yaml:"cache"`
	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
	Judge         *rawJudge         `yaml:"judge"`
	Agents        []rawAgent        `yaml:"agents"`
	Advisory      *rawAdvisory      `yaml:"advisory"`
	Observability *rawObservability `yaml:"observability"`
}

// rawObservability mirrors the on-disk `observability:` block. Pointer so an
// absent block is distinct from an explicit (disabled) block. KnownFields(true)
// is strict, so this MUST be registered or configs with the block fail to parse.
type rawObservability struct {
	Enabled     bool   `yaml:"enabled"`
	ServiceName string `yaml:"serviceName"`
	Metrics     *struct {
		Enabled      *bool  `yaml:"enabled"`
		OTLPEndpoint string `yaml:"otlpEndpoint"`
	} `yaml:"metrics"`
	ResourceAttributes map[string]string `yaml:"resourceAttributes"`
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

type rawAgent struct {
	ID     string `yaml:"id"`
	Policy string `yaml:"policy"`
}

type rawAdvisory struct {
	Enabled bool `yaml:"enabled"`
}

// defaultCacheTTLSeconds is used when the config omits cache.ttl.
const defaultCacheTTLSeconds = 3600

// LocalYAMLProvider loads policy from a YAML file on disk. It implements
// ConfigProvider.
type LocalYAMLProvider struct {
	policy Policy
}

var _ ConfigProvider = (*LocalYAMLProvider)(nil)

// NewLocalYAMLProvider reads and validates the YAML config at path, returning a
// provider that serves the parsed policy. It errors on a missing file or
// malformed/invalid config.
func NewLocalYAMLProvider(path string) (*LocalYAMLProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	return parse(data)
}

// parse decodes and validates raw YAML bytes into a provider.
func parse(data []byte) (*LocalYAMLProvider, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}

	policy := Policy{
		Allowlist:       raw.Policy.Allowlist,
		Denylist:        raw.Policy.Denylist,
		Secrets:         raw.Secrets,
		CacheTTLSeconds: raw.Cache.TTL,
		LogLevel:        raw.Logging.Level,
		LogFormat:       raw.Logging.Format,
	}
	policy.LogLevel = strings.ToLower(policy.LogLevel)
	if policy.LogLevel == "" {
		policy.LogLevel = "info"
	}
	policy.LogFormat = strings.ToLower(policy.LogFormat)
	if policy.LogFormat == "" {
		policy.LogFormat = "json"
	}
	for i := range policy.Allowlist {
		policy.Allowlist[i].Domain = strings.ToLower(policy.Allowlist[i].Domain)
	}
	for i := range policy.Denylist {
		policy.Denylist[i].Domain = strings.ToLower(policy.Denylist[i].Domain)
	}
	if policy.CacheTTLSeconds == 0 {
		policy.CacheTTLSeconds = defaultCacheTTLSeconds
	}

	for _, a := range raw.Agents {
		policy.Agents = append(policy.Agents, AgentPolicy{ID: a.ID, Policy: a.Policy})
	}
	if raw.Advisory != nil {
		policy.Advisory.Enabled = raw.Advisory.Enabled
	}
	if raw.Judge != nil {
		jc, err := parseJudge(raw.Judge)
		if err != nil {
			return nil, err
		}
		policy.Judge = jc
	}
	policy.Observability = parseObservability(raw.Observability)

	if err := validate(policy); err != nil {
		return nil, err
	}
	return &LocalYAMLProvider{policy: policy}, nil
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

// parseObservability converts the raw observability block into a typed config,
// applying defaults and honoring standard OTEL_* env vars (which override the
// file). An absent block yields a disabled, harmless zero value.
func parseObservability(r *rawObservability) ObservabilityConfig {
	var oc ObservabilityConfig
	if r != nil {
		oc.Enabled = r.Enabled
		oc.ServiceName = r.ServiceName
		// Metrics default ON when the block is present (served at /metrics).
		oc.MetricsEnabled = true
		if r.Metrics != nil {
			if r.Metrics.Enabled != nil {
				oc.MetricsEnabled = *r.Metrics.Enabled
			}
			oc.OTLPEndpoint = r.Metrics.OTLPEndpoint
		}
		oc.ResourceAttributes = r.ResourceAttributes
	}
	if oc.ServiceName == "" {
		oc.ServiceName = "warden"
	}
	// Env wins over config (standard OTel precedence).
	if v := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); v != "" {
		oc.ServiceName = v
	}
	if v := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); v != "" {
		oc.OTLPEndpoint = v
	}
	return oc
}

// parseDurationField parses a Go duration string into *dst when non-empty.
func parseDurationField(name, raw string, dst *time.Duration) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("config: %s %q is not a valid duration: %w", name, raw, err)
	}
	if d < 0 {
		return fmt.Errorf("config: %s must not be negative", name)
	}
	*dst = d
	return nil
}

// validate enforces the invariants the proxy relies on at runtime.
func validate(p Policy) error {
	if len(p.Allowlist) == 0 {
		return fmt.Errorf("config: policy.allowlist must have at least one entry")
	}
	for i, e := range p.Allowlist {
		if strings.TrimSpace(e.Domain) == "" {
			return fmt.Errorf("config: policy.allowlist[%d]: domain is required", i)
		}
		if strings.ContainsRune(e.Domain, ' ') {
			return fmt.Errorf("config: policy.allowlist[%d]: domain %q contains spaces", i, e.Domain)
		}
		if e.Port < 0 || e.Port > 65535 {
			return fmt.Errorf("config: policy.allowlist[%d]: port %d out of range", i, e.Port)
		}
		if e.RateLimit != "" {
			parts := strings.SplitN(e.RateLimit, "/", 2)
			if len(parts) != 2 {
				return fmt.Errorf("config: policy.allowlist[%d]: invalid rateLimit format %q", i, e.RateLimit)
			}
			n, err := strconv.Atoi(parts[0])
			if err != nil || n <= 0 {
				return fmt.Errorf("config: policy.allowlist[%d]: invalid rateLimit count %q", i, e.RateLimit)
			}
			switch parts[1] {
			case "second", "minute", "hour":
			default:
				return fmt.Errorf("config: policy.allowlist[%d]: invalid rateLimit period %q; must be second, minute, or hour", i, e.RateLimit)
			}
		}
		if e.TimeWindow != "" {
			parts := strings.SplitN(e.TimeWindow, "-", 2)
			if len(parts) != 2 {
				return fmt.Errorf("config: policy.allowlist[%d]: invalid timeWindow format %q", i, e.TimeWindow)
			}
			for _, p := range parts {
				h, err := strconv.Atoi(p)
				if err != nil || h < 0 || h > 23 {
					return fmt.Errorf("config: policy.allowlist[%d]: invalid timeWindow hour %q", i, e.TimeWindow)
				}
			}
		}
		// Regex domain: ~<pattern>
		if strings.HasPrefix(e.Domain, "~") {
			if _, err := regexp.Compile(e.Domain[1:]); err != nil {
				return fmt.Errorf("config: policy.allowlist[%d]: domain %q has invalid regex: %v", i, e.Domain, err)
			}
			continue
		}
		if strings.Contains(e.Domain, "*") {
			if !strings.HasPrefix(e.Domain, "*.") || strings.Count(e.Domain, "*") != 1 {
				return fmt.Errorf("config: policy.allowlist[%d]: domain %q has invalid wildcard; only \"*.suffix\" form is supported", i, e.Domain)
			}
			suffix := e.Domain[2:]
			if suffix == "" || strings.HasPrefix(suffix, ".") {
				return fmt.Errorf("config: policy.allowlist[%d]: domain %q has invalid wildcard; only \"*.suffix\" form is supported", i, e.Domain)
			}
		}
	}
	for i, e := range p.Denylist {
		if strings.TrimSpace(e.Domain) == "" {
			return fmt.Errorf("config: policy.denylist[%d]: domain is required", i)
		}
		if strings.ContainsRune(e.Domain, ' ') {
			return fmt.Errorf("config: policy.denylist[%d]: domain %q contains spaces", i, e.Domain)
		}
		if e.Port < 0 || e.Port > 65535 {
			return fmt.Errorf("config: policy.denylist[%d]: port %d out of range", i, e.Port)
		}
		// Regex domain: ~<pattern>
		if strings.HasPrefix(e.Domain, "~") {
			if _, err := regexp.Compile(e.Domain[1:]); err != nil {
				return fmt.Errorf("config: policy.denylist[%d]: domain %q has invalid regex: %v", i, e.Domain, err)
			}
			continue
		}
		if strings.Contains(e.Domain, "*") {
			if !strings.HasPrefix(e.Domain, "*.") || strings.Count(e.Domain, "*") != 1 {
				return fmt.Errorf("config: policy.denylist[%d]: domain %q has invalid wildcard; only \"*.suffix\" form is supported", i, e.Domain)
			}
			suffix := e.Domain[2:]
			if suffix == "" || strings.HasPrefix(suffix, ".") {
				return fmt.Errorf("config: policy.denylist[%d]: domain %q has invalid wildcard; only \"*.suffix\" form is supported", i, e.Domain)
			}
		}
	}
	for i, s := range p.Secrets {
		if s.Placeholder == "" {
			return fmt.Errorf("config: secrets[%d]: placeholder is required", i)
		}
		if s.EnvVar == "" {
			return fmt.Errorf("config: secrets[%d]: envVar is required", i)
		}
	}
	seen := make(map[string]struct{}, len(p.Secrets))
	for _, s := range p.Secrets {
		if _, dup := seen[s.Placeholder]; dup {
			return fmt.Errorf("config: secrets: duplicate placeholder %q", s.Placeholder)
		}
		seen[s.Placeholder] = struct{}{}
	}
	if p.CacheTTLSeconds < 0 {
		return fmt.Errorf("config: cache.ttl must not be negative")
	}
	switch p.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: logging.level %q is invalid; must be one of: debug, info, warn, error", p.LogLevel)
	}
	switch p.LogFormat {
	case "json", "text":
	default:
		return fmt.Errorf("config: logging.format %q is invalid; must be one of: json, text", p.LogFormat)
	}
	if err := validateAgents(p.Agents); err != nil {
		return err
	}
	if err := validateJudge(p.Judge, p.Agents); err != nil {
		return err
	}
	return nil
}

// validateAgents enforces that agent ids are present and unique. Agent policies
// may be configured even when the judge is disabled (they are simply unused).
func validateAgents(agents []AgentPolicy) error {
	seen := make(map[string]struct{}, len(agents))
	for i, a := range agents {
		if strings.TrimSpace(a.ID) == "" {
			return fmt.Errorf("config: agents[%d]: id is required", i)
		}
		if _, dup := seen[a.ID]; dup {
			return fmt.Errorf("config: agents: duplicate id %q", a.ID)
		}
		seen[a.ID] = struct{}{}
	}
	return nil
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
		parts := strings.SplitN(j.RateLimit, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("config: judge.rateLimit %q is invalid; want N/period", j.RateLimit)
		}
		n, err := strconv.Atoi(parts[0])
		if err != nil || n <= 0 {
			return fmt.Errorf("config: judge.rateLimit count %q is invalid", j.RateLimit)
		}
		switch parts[1] {
		case "second", "minute", "hour":
		default:
			return fmt.Errorf("config: judge.rateLimit period %q is invalid; must be second, minute, or hour", j.RateLimit)
		}
	}
	return nil
}

// GetPolicy returns the loaded policy.
func (p *LocalYAMLProvider) GetPolicy() (Policy, error) {
	return p.policy, nil
}
