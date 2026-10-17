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
	// Listen, AdminListen and TLS are the optional config-file values for the
	// listeners and CA paths; CLI flags override them (see ResolveListen).
	Listen      string    `json:"-"`
	AdminListen string    `json:"-"`
	TLS         TLSConfig `json:"-"`

	// Allowlist is the set of permitted destinations. Anything not present is
	// denied (default-deny).
	Allowlist []AllowlistEntry `json:"allowlist"`
	// Denylist is checked before the allowlist; deny wins on conflict.
	Denylist []DenylistEntry `json:"denylist"`
	// Secrets maps placeholder tokens to their source env var (phase 1).
	Secrets []SecretMapping `json:"-"`
	// SecretStore selects the backend the worker resolves placeholders through
	// (env|echo|aws). Optional sibling of Secrets; omitted => env (byte-identical
	// to today). LOCAL only this phase (never on the wire).
	SecretStore SecretStoreConfig `json:"-"`
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
	// EchoGuard configures the check for swapped secrets echoed back in a response.
	// ON by default (zero value = enabled, block), independent of ResponseScan.
	EchoGuard EchoGuardConfig `json:"-"`
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
	// Detection configures the control-plane temporal-detection engine. It is
	// CP-local (never on the worker wire). An absent block = detection ON with
	// engine defaults; see DetectionConfig.
	Detection DetectionConfig `json:"-"`
	// LLMProviders is the shared, named LLM-provider registry (name + baseURL +
	// model + apiKeyEnv NAME + optional timeout). It carries no secret VALUE, so
	// it RIDES the secret-free settings wire (unlike the CP-local blocks above):
	// the judge runs on workers, so a managed worker must receive it. Projection
	// is via llmProvidersSettingsFromPolicy → SettingsWire, exactly as Judge
	// projects — so, like every behavioral block, this stays json:"-" (the wire
	// carries it through SettingsWire, never through Policy's own JSON). Empty by
	// default. No feature consumes it yet (M1 is pure plumbing).
	LLMProviders []LLMProvider `json:"-"`
	// Explore selects which named llmProviders entry the Explore / NL→SQL feature
	// uses, independently of the judge. It is CP-LOCAL (json:"-", never on the
	// worker wire): the query engine Explore runs against is CP-only, so
	// distributing this to workers would be dead config — like Detection and
	// Integrations above. Empty by default; then Explore reuses the judge's client
	// exactly as before.
	Explore ExploreConfig `json:"-"`
	// DNS configures the resolver for warden's OWN upstream dials
	// (dns.upstreamResolver). Boot-time LOCAL config (never on the settings
	// wire): it is consumed once at worker assembly, like the flag-derived
	// listen addresses. Zero value = Go's default resolver (no behavior change).
	DNS DNSConfig `json:"-"`
	// Upstream holds LOCAL-ONLY exceptions to the upstream SSRF private-IP
	// blocklist (upstream.allowPrivateCIDRs) for lab/test networks where an
	// allowlisted upstream legitimately sits on a private range. It is a
	// security exception, so it never travels: json:"-" keeps a CP-served
	// policy from setting or widening it (a CP that could push it could switch
	// a worker's SSRF guard off remotely), exactly like the listen/CA paths.
	// Zero value = no exceptions (default-deny blocklist unchanged).
	Upstream UpstreamConfig `json:"-"`
	// Proxy configures the interception mode (#376): the explicit CONNECT
	// forward proxy (the default, unchanged), transparent interception on
	// dedicated listeners, or both. Boot-time LOCAL config consumed at worker
	// assembly like the listen addresses — json:"-" keeps it off the CP wire,
	// so a control plane can never change how a worker is reachable.
	Proxy ProxyConfig `json:"-"`
}

// DeepCopy returns a deep copy of the policy, with all slices independently
// allocated so mutations to the copy cannot affect the original.
func (p Policy) DeepCopy() Policy {
	cp := p
	cp.Allowlist = append([]AllowlistEntry(nil), p.Allowlist...)
	for i := range cp.Allowlist {
		// #371: constraint slices are independently allocated like every other
		// slice, so mutating a copy cannot retarget the live policy.
		cp.Allowlist[i].Methods = append([]string(nil), p.Allowlist[i].Methods...)
		cp.Allowlist[i].Paths = append([]string(nil), p.Allowlist[i].Paths...)
	}
	cp.Denylist = append([]DenylistEntry(nil), p.Denylist...)
	cp.Secrets = append([]SecretMapping(nil), p.Secrets...)
	for i := range cp.Secrets {
		cp.Secrets[i].MatchHosts = append([]string(nil), p.Secrets[i].MatchHosts...)
	}
	if p.SecretStore.AWS != nil {
		aws := *p.SecretStore.AWS
		cp.SecretStore.AWS = &aws
	}
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
	// LLMProvider is a flat value struct (no nested slices/maps), so an
	// independent backing array is a full deep copy.
	cp.LLMProviders = append([]LLMProvider(nil), p.LLMProviders...)
	cp.Upstream.AllowPrivateCIDRs = append([]string(nil), p.Upstream.AllowPrivateCIDRs...)
	return cp
}

// AllowlistEntry is a single permitted destination. Port is optional; when
// zero the policy engine infers 443 (HTTPS) or 80 (HTTP). RateLimit and
// TimeWindow are reserved for milestone 2: they parse from config but are
// unused in phase 1.
//
// Methods and Paths (#371) optionally narrow what the entry permits. Both are
// allow-lists: a non-empty Methods admits only those HTTP methods, a non-empty
// Paths admits only request paths matching at least one pattern (raw,
// percent-encoded byte comparison — see internal/policy). Nil/empty = any
// method/path. An entry with constraints still matches its domain+port for
// CONNECT admission; the per-request evaluation enforces the constraints.
type AllowlistEntry struct {
	Domain string `yaml:"domain" json:"domain"`
	Port   int    `yaml:"port,omitempty" json:"port"`

	// #371 request constraints: uppercased HTTP method names and path patterns
	// (validated dialect: absolute path, "*" wildcards). Empty = unrestricted.
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`

	// Reserved (M2): parsed but not enforced in phase 1.
	RateLimit  string `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`
	TimeWindow string `yaml:"timeWindow,omitempty" json:"timeWindow,omitempty"`
}

// SecretMapping ties a placeholder the agent holds to the env var that carries
// the real value (phase 1 ENV provider).
//
// MatchHosts scopes the placeholder to destinations (exact host, "*.suffix", or
// "~regex" — the policy dialect): it is swapped only on requests whose
// destination host matches. Empty = unscoped (swap on every allowed host); the
// worker logs a startup warning for such entries.
type SecretMapping struct {
	Placeholder string   `yaml:"placeholder"`
	EnvVar      string   `yaml:"envVar"`
	MatchHosts  []string `yaml:"matchHosts,omitempty"`
}

// DenylistEntry is a single explicitly-blocked destination. The denylist is
// checked before the allowlist — deny wins on conflict.
type DenylistEntry struct {
	Domain string `yaml:"domain" json:"domain"`
	Port   int    `yaml:"port,omitempty" json:"port"`
}

// rawConfig mirrors the on-disk YAML shape (see configs/config.example.yaml).
type rawConfig struct {
	Listen      string  `yaml:"listen"`
	AdminListen string  `yaml:"adminListen"`
	TLS         *rawTLS `yaml:"tls"`
	Policy      struct {
		Allowlist []AllowlistEntry `yaml:"allowlist"`
		Denylist  []DenylistEntry  `yaml:"denylist"`
	} `yaml:"policy"`
	Secrets     []SecretMapping `yaml:"secrets"`
	SecretStore *rawSecretStore `yaml:"secretStore"`
	Cache       struct {
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
	EchoGuard     *rawEchoGuard     `yaml:"echoGuard"`
	DLP           *rawDLP           `yaml:"dlp"`
	Auth          []rawAuthEntry    `yaml:"auth"`
	ControlPlane  *rawControlPlane  `yaml:"controlPlane"`
	Central       *rawCentral       `yaml:"central"`
	Audit         *rawAudit         `yaml:"audit"`
	Integrations  []rawIntegration  `yaml:"integrations"`
	Detection     *rawDetection     `yaml:"detection"`
	LLMProviders  []rawLLMProvider  `yaml:"llmProviders"`
	Explore       *rawExplore       `yaml:"explore"`
	DNS           *rawDNS           `yaml:"dns"`
	Upstream      *rawUpstream      `yaml:"upstream"`
	Proxy         *rawProxy         `yaml:"proxy"`
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
		SecretStore:     parseSecretStore(raw.SecretStore),
		CacheTTLSeconds: raw.Cache.TTL,
		LogLevel:        raw.Logging.Level,
		LogFormat:       raw.Logging.Format,
	}
	policy.Listen = raw.Listen
	policy.AdminListen = raw.AdminListen
	if raw.TLS != nil {
		policy.TLS = TLSConfig(*raw.TLS)
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
		// Methods normalize to upper at load (#371) so runtime matching is a
		// case-sensitive comparison against the method exactly as sent.
		for j, m := range policy.Allowlist[i].Methods {
			policy.Allowlist[i].Methods[j] = strings.ToUpper(m)
		}
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
	policy.EchoGuard = parseEchoGuard(raw.EchoGuard)
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
	detection, err := parseDetection(raw.Detection)
	if err != nil {
		return nil, err
	}
	policy.Detection = detection
	llmProviders, err := parseLLMProviders(raw.LLMProviders)
	if err != nil {
		return nil, err
	}
	policy.LLMProviders = llmProviders
	policy.Explore = parseExplore(raw.Explore)
	policy.DNS = parseDNS(raw.DNS)
	policy.Upstream = parseUpstream(raw.Upstream)
	policy.Proxy = parseProxy(raw.Proxy)

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
		// #371 request constraints: an unknown method must fail at load (the
		// agent already holds no secret, but a typo silently broadening or
		// narrowing what an entry admits is a policy bug — fail closed).
		for _, m := range e.Methods {
			if !knownHTTPMethods[m] {
				return fmt.Errorf("config: policy.allowlist[%d]: unknown method %q; methods are uppercased and must be standard HTTP methods", i, m)
			}
		}
		for _, pat := range e.Paths {
			if err := validatePathPattern(fmt.Sprintf("policy.allowlist[%d].paths", i), pat); err != nil {
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
	if err := validateSecretStore(p.SecretStore); err != nil {
		return err
	}
	// envVar is REQUIRED only for the env backend (the placeholder→envVar mapping
	// is how env resolves a value — today's implicit rule, made explicit here).
	// For echo/aws the placeholder IS the store key, so envVar is optional and
	// ignored. Placeholders stay required + unique for every backend.
	envBackend := p.SecretStore.ResolvedBackend() == SecretBackendEnv
	for i, s := range p.Secrets {
		if s.Placeholder == "" {
			return fmt.Errorf("config: secrets[%d]: placeholder is required", i)
		}
		if envBackend && s.EnvVar == "" {
			return fmt.Errorf("config: secrets[%d]: envVar is required for the env secret backend", i)
		}
		for j, h := range s.MatchHosts {
			if strings.TrimSpace(h) == "" {
				return fmt.Errorf("config: secrets[%d].matchHosts[%d]: host pattern must not be empty (omit matchHosts to leave the secret unscoped)", i, j)
			}
			if err := validateMatchPattern(fmt.Sprintf("secrets[%d].matchHosts[%d]", i, j), h); err != nil {
				return err
			}
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
	if err := validateEchoGuard(p.EchoGuard); err != nil {
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
	if err := validateDetection(p.Detection); err != nil {
		return err
	}
	if err := validateLLMProviders(p.LLMProviders); err != nil {
		return err
	}
	// Cross-block: a judge.llmProvider selection must name an existing registry
	// entry. Checked here (not in validateJudge) because it needs BOTH the judge
	// block and the llmProviders list, which are parsed independently above.
	if err := validateJudgeProviderRef(p.Judge, p.LLMProviders); err != nil {
		return err
	}
	// Cross-block twin of the judge check: an explore.llmProvider selection must
	// name an existing registry entry. Placed here (not in an explore-only
	// validator) because it needs BOTH the explore block and the llmProviders list.
	if err := validateExploreProviderRef(p.Explore, p.LLMProviders); err != nil {
		return err
	}
	if err := validateDNS(p.DNS); err != nil {
		return err
	}
	if err := validateUpstream(p.Upstream); err != nil {
		return err
	}
	if err := validateProxyMode(p.Proxy); err != nil {
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

// knownHTTPMethods is the closed set of methods an allowlist entry may constrain
// by (#371): the core RFC methods plus the WebDAV verbs HTTP backends commonly
// expose. Anything outside the set is rejected at load.
var knownHTTPMethods = map[string]bool{
	"CONNECT":   true,
	"DELETE":    true,
	"GET":       true,
	"HEAD":      true,
	"OPTIONS":   true,
	"PATCH":     true,
	"POST":      true,
	"PUT":       true,
	"TRACE":     true,
	"PROPFIND":  true,
	"PROPPATCH": true,
	"MKCOL":     true,
	"COPY":      true,
	"MOVE":      true,
	"LOCK":      true,
	"UNLOCK":    true,
	"REPORT":    true,
}

// validatePathPattern checks one allowlist `paths` pattern (#371). Patterns are
// absolute paths matched byte-for-byte against the RAW request path (wildcards
// aside), so anything that cannot appear in a raw path component — query,
// fragment, backslash, empty segments — is rejected at load rather than silently
// never matching. context is the caller's field path for a precise error.
func validatePathPattern(context, pat string) error {
	switch {
	case pat == "":
		return fmt.Errorf("config: %s: path pattern must not be empty", context)
	case !strings.HasPrefix(pat, "/"):
		return fmt.Errorf("config: %s: path pattern %q must start with /", context, pat)
	case strings.ContainsAny(pat, "?#"):
		return fmt.Errorf("config: %s: path pattern %q must not contain ? or # (matching covers the path component only)", context, pat)
	case strings.ContainsRune(pat, '\\'):
		return fmt.Errorf("config: %s: path pattern %q must not contain backslash", context, pat)
	case strings.Contains(pat, "//"):
		return fmt.Errorf("config: %s: path pattern %q must not contain empty path segments", context, pat)
	}
	return nil
}
