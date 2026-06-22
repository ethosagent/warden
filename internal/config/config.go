// Package config defines the ConfigProvider interface and the policy/config
// types loaded from a local YAML file (phase 1). The same schema is reused
// when configuration later comes from a control-plane pull, so callers depend
// only on the interface, never on the concrete provider.
package config

import (
	"bytes"
	"fmt"
	"os"

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
		if e.Domain == "" {
			return fmt.Errorf("config: policy.allowlist[%d]: domain is required", i)
		}
		if e.Port < 0 || e.Port > 65535 {
			return fmt.Errorf("config: policy.allowlist[%d]: port %d out of range", i, e.Port)
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
	if p.CacheTTLSeconds < 0 {
		return fmt.Errorf("config: cache.ttl must not be negative")
	}
	return nil
}

// GetPolicy returns the loaded policy.
func (p *LocalYAMLProvider) GetPolicy() (Policy, error) {
	return p.policy, nil
}
