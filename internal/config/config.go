// Package config defines the ConfigProvider interface and the policy/config
// types loaded from a local YAML file (phase 1). The same schema is reused
// when configuration later comes from a control-plane pull, so callers depend
// only on the interface, never on the concrete provider.
//
// The schema is large: each feature domain (judge, mcp, observability, auth,
// controlPlane, central, audit, integrations, …) lives in its own file within
// this package, carrying its public config type(s), its on-disk `raw*` mirror,
// and its parse/validate helpers. This file holds only the aggregate `Policy`,
// the `rawConfig` that stitches the domains together, the `parse`/`validate`
// orchestration, the local YAML provider, and the cross-domain shared helpers.
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
	// MCP configures the optional MCP egress wedge (deep MCP analysis). Disabled
	// by default; when disabled every field is zero-valued and harmless.
	MCP MCPConfig `json:"-"`
	// ResponseScan configures scanning of ordinary (non-MCP) HTTP/HTTPS response
	// bodies. Off by default; when disabled every field is zero-valued and harmless.
	ResponseScan ResponseScanConfig `json:"-"`
	// DLP configures outbound REQUEST-body data-loss-prevention scanning. Off by
	// default; when off the dlpScan stage is a no-op (no body read) and behavior
	// is byte-identical to before.
	DLP DLPConfig `json:"-"`
	// Auth holds per-destination request-authentication transforms (OAuth2,
	// SigV4, HMAC, API-key). Empty by default. Credentials are referenced from
	// env (${VAR}) and held by the proxy only — never seen by the agent.
	Auth []AuthEntry `json:"-"`
	// ControlPlane configures pulling allow/deny policy from a remote control
	// plane. Disabled when Endpoint is empty.
	ControlPlane ControlPlaneConfig `json:"-"`
	// Central configures fleet analytics aggregation (worker forward / aggregator
	// ingest). Disabled when Mode is "" or "off".
	Central CentralConfig `json:"-"`
	// Audit configures signed receipts and compliance tagging of events. Both
	// off by default.
	Audit AuditConfig `json:"-"`
	// Integrations holds CP-local outbound alert-delivery integrations (webhook,
	// Slack, …). It is consumed by the control plane ONLY and is never projected
	// onto the worker-served policyWire (which carries allow/deny + settings only).
	// Empty by default.
	Integrations []IntegrationInstance `json:"-"`
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
	cp.MCP.Tools.Allow = append([]string(nil), p.MCP.Tools.Allow...)
	cp.MCP.Tools.Deny = append([]string(nil), p.MCP.Tools.Deny...)
	if p.MCP.Tools.RateLimit != nil {
		rl := make(map[string]string, len(p.MCP.Tools.RateLimit))
		for k, v := range p.MCP.Tools.RateLimit {
			rl[k] = v
		}
		cp.MCP.Tools.RateLimit = rl
	}
	cp.MCP.Tools.Constraints = cloneToolConstraints(p.MCP.Tools.Constraints)
	cp.MCP.Chain.Patterns = append([]string(nil), p.MCP.Chain.Patterns...)
	if p.MCP.Scopes != nil {
		sc := &MCPScopesConfig{
			ActiveScope: p.MCP.Scopes.ActiveScope,
			OutOfScope:  p.MCP.Scopes.OutOfScope,
		}
		if p.MCP.Scopes.PerAgent != nil {
			sc.PerAgent = make(map[string]string, len(p.MCP.Scopes.PerAgent))
			for k, v := range p.MCP.Scopes.PerAgent {
				sc.PerAgent[k] = v
			}
		}
		for _, s := range p.MCP.Scopes.List {
			sc.List = append(sc.List, MCPScope{
				ID:          s.ID,
				Purpose:     s.Purpose,
				Tools:       append([]string(nil), s.Tools...),
				Constraints: cloneToolConstraints(s.Constraints),
			})
		}
		cp.MCP.Scopes = sc
	}
	cp.MCP.Servers = append([]MCPServerConfig(nil), p.MCP.Servers...)
	cp.Auth = append([]AuthEntry(nil), p.Auth...)
	for i := range cp.Auth {
		cp.Auth[i].Scopes = append([]string(nil), p.Auth[i].Scopes...)
	}
	if len(p.Integrations) > 0 {
		ints := make([]IntegrationInstance, len(p.Integrations))
		for i, in := range p.Integrations {
			ints[i] = in
			ints[i].Match = append([]IntegrationMatch(nil), in.Match...)
			// Config is an opaque, read-only pass-through map (mapped to the
			// integration package once at CP startup, never mutated after load), so
			// it is shared by reference — consistent with how opaque config is
			// treated elsewhere in the loader.
		}
		cp.Integrations = ints
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
	MCP           *rawMCP           `yaml:"mcp"`
	ResponseScan  *rawResponseScan  `yaml:"responseScan"`
	DLP           *rawDLP           `yaml:"dlp"`
	Auth          []rawAuthEntry    `yaml:"auth"`
	ControlPlane  *rawControlPlane  `yaml:"controlPlane"`
	Central       *rawCentral       `yaml:"central"`
	Audit         *rawAudit         `yaml:"audit"`
	Integrations  []rawIntegration  `yaml:"integrations"`
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
		policy.Agents = append(policy.Agents, AgentPolicy(a))
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
	policy.MCP = parseMCP(raw.MCP)
	policy.ResponseScan = parseResponseScan(raw.ResponseScan)
	policy.DLP = parseDLP(raw.DLP)
	policy.Auth = parseAuth(raw.Auth)
	cp, err := parseControlPlane(raw.ControlPlane)
	if err != nil {
		return nil, err
	}
	policy.ControlPlane = cp
	central, err := parseCentral(raw.Central)
	if err != nil {
		return nil, err
	}
	policy.Central = central
	policy.Audit = parseAudit(raw.Audit)
	policy.Integrations = parseIntegrations(raw.Integrations)

	if err := validate(policy); err != nil {
		return nil, err
	}
	return &LocalYAMLProvider{policy: policy}, nil
}

// GetPolicy returns the loaded policy.
func (p *LocalYAMLProvider) GetPolicy() (Policy, error) {
	return p.policy, nil
}

// parseDurationField parses a Go duration string into *dst when non-empty.
// Shared by the judge, control-plane, and central domains so duration parsing
// (and the non-negative check) is identical everywhere.
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

// validate enforces the invariants the proxy relies on at runtime. It validates
// the core allow/deny policy inline and delegates each feature domain to its own
// validate helper (defined alongside that domain's types).
func validate(p Policy) error {
	// A control-plane-managed worker (controlPlane configured, not local-only)
	// gets its policy from the CP and boots fail-closed, so it needs no local
	// allowlist. Every other mode must declare at least one allow entry.
	managed := p.ControlPlane.Endpoint != "" && !p.ControlPlane.LocalOnly
	if len(p.Allowlist) == 0 && !managed {
		return fmt.Errorf("config: policy.allowlist must have at least one entry (or set controlPlane.endpoint for CP-managed mode)")
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
			if err := validateTimeWindow(fmt.Sprintf("policy.allowlist[%d].timeWindow", i), e.TimeWindow); err != nil {
				return err
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
	if err := validateMCP(p.MCP); err != nil {
		return err
	}
	if err := validateResponseScan(p.ResponseScan); err != nil {
		return err
	}
	if err := validateDLP(p.DLP); err != nil {
		return err
	}
	if err := validateAuth(p.Auth); err != nil {
		return err
	}
	if err := validateControlPlane(p.ControlPlane); err != nil {
		return err
	}
	if err := validateCentral(p.Central); err != nil {
		return err
	}
	if err := validateAudit(p.Audit); err != nil {
		return err
	}
	if err := validateIntegrations(p.Integrations); err != nil {
		return err
	}
	return nil
}

// validateDomainPattern validates a destination pattern in the ONE dialect the
// policy evaluator matches (exact / "*.suffix" wildcard / "~regex"): non-empty,
// space-free, compilable regex, and only the "*.suffix" wildcard form. It is the
// shared check the dlp `to` lists reuse so DLP destinations never fork a second
// dialect. context is the caller's field path for a precise error.
func validateDomainPattern(context, domain string) error {
	if strings.TrimSpace(domain) == "" {
		return fmt.Errorf("config: %s: domain is required", context)
	}
	if strings.ContainsRune(domain, ' ') {
		return fmt.Errorf("config: %s: domain %q contains spaces", context, domain)
	}
	if strings.HasPrefix(domain, "~") {
		if _, err := regexp.Compile(domain[1:]); err != nil {
			return fmt.Errorf("config: %s: domain %q has invalid regex: %v", context, domain, err)
		}
		return nil
	}
	if strings.Contains(domain, "*") {
		if !strings.HasPrefix(domain, "*.") || strings.Count(domain, "*") != 1 {
			return fmt.Errorf("config: %s: domain %q has invalid wildcard; only \"*.suffix\" form is supported", context, domain)
		}
		suffix := domain[2:]
		if suffix == "" || strings.HasPrefix(suffix, ".") {
			return fmt.Errorf("config: %s: domain %q has invalid wildcard; only \"*.suffix\" form is supported", context, domain)
		}
	}
	return nil
}

// validateRateLimit checks the shared "N/second|minute|hour" rate-limit format,
// returning a descriptive error keyed by name. Reused by the allowlist, judge,
// and MCP tool policies so the format stays in one place.
func validateRateLimit(name, raw string) error {
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("config: %s %q is invalid; want N/period", name, raw)
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n <= 0 {
		return fmt.Errorf("config: %s count %q is invalid", name, raw)
	}
	switch parts[1] {
	case "second", "minute", "hour":
	default:
		return fmt.Errorf("config: %s period %q is invalid; must be second, minute, or hour", name, raw)
	}
	return nil
}

// validateTimeWindow checks the shared "HH-HH" time-window format (two hours in
// 0-23, server local time), returning a descriptive error keyed by name. Reused
// by the allowlist and the MCP per-tool conditions so the format stays in one
// place.
func validateTimeWindow(name, raw string) error {
	parts := strings.SplitN(raw, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("config: %s: invalid timeWindow format %q", name, raw)
	}
	for _, p := range parts {
		h, err := strconv.Atoi(p)
		if err != nil || h < 0 || h > 23 {
			return fmt.Errorf("config: %s: invalid timeWindow hour %q", name, raw)
		}
	}
	return nil
}
