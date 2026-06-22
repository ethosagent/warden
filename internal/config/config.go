// Package config defines the ConfigProvider interface and the policy/config
// types loaded from a local YAML file (phase 1). The same schema is reused
// when configuration later comes from a control-plane pull, so callers depend
// only on the interface, never on the concrete provider.
package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

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
	Allowlist []AllowlistEntry
	// Secrets maps placeholder tokens to their source env var (phase 1).
	Secrets []SecretMapping
	// CacheTTLSeconds is the secret cache time-to-live in seconds.
	CacheTTLSeconds int
	// LogLevel and LogFormat configure observability output.
	LogLevel  string
	LogFormat string
}

// AllowlistEntry is a single permitted destination. Port is optional; when
// zero the policy engine infers 443 (HTTPS) or 80 (HTTP). RateLimit and
// TimeWindow are reserved for milestone 2: they parse from config but are
// unused in phase 1.
type AllowlistEntry struct {
	Domain string `yaml:"domain"`
	Port   int    `yaml:"port,omitempty"`

	// Reserved (M2): parsed but not enforced in phase 1.
	RateLimit  string `yaml:"rateLimit,omitempty"`
	TimeWindow string `yaml:"timeWindow,omitempty"`
}

// SecretMapping ties a placeholder the agent holds to the env var that carries
// the real value (phase 1 ENV provider).
type SecretMapping struct {
	Placeholder string `yaml:"placeholder"`
	EnvVar      string `yaml:"envVar"`
}

// rawConfig mirrors the on-disk YAML shape (see configs/config.example.yaml).
type rawConfig struct {
	Policy struct {
		Allowlist []AllowlistEntry `yaml:"allowlist"`
	} `yaml:"policy"`
	Secrets []SecretMapping `yaml:"secrets"`
	Cache   struct {
		TTL int `yaml:"ttl"`
	} `yaml:"cache"`
	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
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
	if policy.CacheTTLSeconds == 0 {
		policy.CacheTTLSeconds = defaultCacheTTLSeconds
	}

	if err := validate(policy); err != nil {
		return nil, err
	}
	return &LocalYAMLProvider{policy: policy}, nil
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
	return nil
}

// GetPolicy returns the loaded policy.
func (p *LocalYAMLProvider) GetPolicy() (Policy, error) {
	return p.policy, nil
}
