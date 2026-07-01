package config

import "time"

// SettingsWire is the behavioral worker-config document the control plane
// distributes alongside allow/deny over the policy long-poll. It centralizes
// the operator-tunable blocks (MCP, judge+agents, observability, advisory,
// compliance, cache TTL, logging) so the fleet can be configured from one place.
//
// SECRET-FREE INVARIANT (structural, not policy): every field here carries only
// non-secret configuration or an env-NAME reference (e.g. Judge.APIKeyEnv =
// "OPENAI_API_KEY"). No field carries a resolved secret VALUE. A worker resolves
// the actual credential from its OWN environment after applying settings, so a
// compromised control plane can change behavior but can never leak a credential.
// Because the wire type has no value-carrying field, this guarantee is enforced
// by the type itself rather than by careful marshaling — adding a value field
// here would be the only way to break it, which review must reject.
//
// Out of scope for this wire type (local by necessity, never distributed):
// secret VALUES, the controlPlane bootstrap block, worker identity, audit
// signing paths, deployment flags, and auth transforms / secret mappings (the
// latter deferred to a later phase). Those stay in each worker's local config.
type SettingsWire struct {
	MCP           *MCPSettings           `json:"mcp,omitempty"`
	Judge         *JudgeSettings         `json:"judge,omitempty"`
	Agents        []AgentSettings        `json:"agents,omitempty"`
	Observability *ObservabilitySettings `json:"observability,omitempty"`
	Advisory      *ToggleSetting         `json:"advisory,omitempty"`
	Compliance    *ToggleSetting         `json:"compliance,omitempty"`
	// CacheTTLSeconds is the secret cache TTL. Pointer so "unset" (nil) is
	// distinct from an explicit 0.
	CacheTTLSeconds *int             `json:"cacheTTLSeconds,omitempty"`
	Logging         *LoggingSettings `json:"logging,omitempty"`
}

// ToggleSetting is a simple on/off block (advisory, compliance).
type ToggleSetting struct {
	Enabled bool `json:"enabled"`
}

// LoggingSettings carries the distributable logging knobs (level/format).
type LoggingSettings struct {
	Level  string `json:"level,omitempty"`
	Format string `json:"format,omitempty"`
}

// JudgeSettings carries the judge's distributable config. APIKeyEnv is an env
// NAME only — never an API key value (the worker resolves the key from its own
// environment).
type JudgeSettings struct {
	Enabled   bool   `json:"enabled"`
	Provider  string `json:"provider,omitempty"`
	Model     string `json:"model,omitempty"`
	BaseURL   string `json:"baseURL,omitempty"`
	APIKeyEnv string `json:"apiKeyEnv,omitempty"`
	// TimeoutSeconds / cache / circuit-breaker tuning travel as plain numbers.
	TimeoutSeconds  int                          `json:"timeoutSeconds,omitempty"`
	CacheTTLSeconds int                          `json:"cacheTTLSeconds,omitempty"`
	RateLimit       string                       `json:"rateLimit,omitempty"`
	CircuitBreaker  *JudgeCircuitBreakerSettings `json:"circuitBreaker,omitempty"`
}

// JudgeCircuitBreakerSettings carries the judge circuit-breaker tuning.
type JudgeCircuitBreakerSettings struct {
	MaxFailures     int `json:"maxFailures,omitempty"`
	CooldownSeconds int `json:"cooldownSeconds,omitempty"`
}

// AgentSettings is one agent's natural-language policy (id + policy text).
type AgentSettings struct {
	ID     string `json:"id"`
	Policy string `json:"policy,omitempty"`
}

// ObservabilitySettings carries the distributable observability knobs. Resource
// attributes are bounded operator labels — never secrets (same rule as the
// local config block).
type ObservabilitySettings struct {
	Enabled            bool              `json:"enabled"`
	ServiceName        string            `json:"serviceName,omitempty"`
	MetricsEnabled     bool              `json:"metricsEnabled"`
	OTLPEndpoint       string            `json:"otlpEndpoint,omitempty"`
	ResourceAttributes map[string]string `json:"resourceAttributes,omitempty"`
}

// MCPSettings carries the distributable MCP wedge config. It mirrors the
// operator-relevant fields of MCPConfig (none of which are secrets).
type MCPSettings struct {
	Enabled              bool               `json:"enabled"`
	Mode                 string             `json:"mode,omitempty"`
	FailClosedOnError    bool               `json:"failClosedOnError,omitempty"`
	MaxResponseScanBytes int                `json:"maxResponseScanBytes,omitempty"`
	Tools                *MCPToolsSettings  `json:"tools,omitempty"`
	Schema               *MCPSchemaSettings `json:"schema,omitempty"`
	Scan                 *MCPScanSettings   `json:"scan,omitempty"`
	Chain                *MCPChainSettings  `json:"chain,omitempty"`
}

// MCPToolsSettings mirrors MCPToolsConfig: tool allow/deny + per-tool rate +
// argument constraints. None of these carry secrets.
type MCPToolsSettings struct {
	Allow       []string                      `json:"allow,omitempty"`
	Deny        []string                      `json:"deny,omitempty"`
	RateLimit   map[string]string             `json:"rateLimit,omitempty"`
	Constraints map[string]MCPToolConstraints `json:"constraints,omitempty"`
}

// MCPSchemaSettings mirrors MCPSchemaConfig.
type MCPSchemaSettings struct {
	Pin bool `json:"pin"`
}

// MCPScanSettings mirrors MCPScanConfig (with PII opt-ins).
type MCPScanSettings struct {
	ToolArgs      bool `json:"toolArgs"`
	ToolResults   bool `json:"toolResults"`
	ProfileSchema bool `json:"profileSchema"`
	PIIPhone      bool `json:"piiPhone,omitempty"`
}

// MCPChainSettings mirrors MCPChainConfig.
type MCPChainSettings struct {
	Enabled    bool     `json:"enabled"`
	WindowSize int      `json:"windowSize,omitempty"`
	Patterns   []string `json:"patterns,omitempty"`
}

// SettingsWireFromPolicy projects a loaded Policy's behavioral blocks onto the
// secret-free wire type. It returns nil when the policy carries no meaningful
// behavioral config (pure allow/deny), so a control plane with only allow/deny
// emits no "settings" key and stays byte-for-byte back-compatible.
//
// Only operator-tunable, non-secret fields are copied. Secret VALUES, the
// controlPlane/central blocks, audit signing paths, and auth transforms are
// intentionally NOT projected (local by necessity / deferred).
func SettingsWireFromPolicy(p Policy) *SettingsWire {
	var s SettingsWire
	any := false

	if mcp := mcpSettingsFromPolicy(p.MCP); mcp != nil {
		s.MCP = mcp
		any = true
	}
	if j := judgeSettingsFromPolicy(p.Judge); j != nil {
		s.Judge = j
		any = true
	}
	if len(p.Agents) > 0 {
		s.Agents = make([]AgentSettings, 0, len(p.Agents))
		for _, a := range p.Agents {
			s.Agents = append(s.Agents, AgentSettings(a))
		}
		any = true
	}
	if obs := observabilitySettingsFromPolicy(p.Observability); obs != nil {
		s.Observability = obs
		any = true
	}
	if p.Advisory.Enabled {
		s.Advisory = &ToggleSetting{Enabled: true}
		any = true
	}
	if p.Audit.Compliance.Enabled {
		s.Compliance = &ToggleSetting{Enabled: true}
		any = true
	}
	// A non-default cache TTL is operator config worth distributing. The
	// default (defaultCacheTTLSeconds) is implied, so skip it to keep the
	// payload minimal and back-compat-friendly.
	if p.CacheTTLSeconds != 0 && p.CacheTTLSeconds != defaultCacheTTLSeconds {
		ttl := p.CacheTTLSeconds
		s.CacheTTLSeconds = &ttl
		any = true
	}
	if log := loggingSettingsFromPolicy(p); log != nil {
		s.Logging = log
		any = true
	}

	if !any {
		return nil
	}
	return &s
}

// mcpSettingsFromPolicy projects MCPConfig onto MCPSettings, or nil if the MCP
// wedge is disabled (the default), so a worker that never configured MCP emits
// nothing for it.
func mcpSettingsFromPolicy(m MCPConfig) *MCPSettings {
	if !m.Enabled {
		return nil
	}
	out := &MCPSettings{
		Enabled:              m.Enabled,
		Mode:                 m.Mode,
		FailClosedOnError:    m.FailClosedOnError,
		MaxResponseScanBytes: m.MaxResponseScanBytes,
		Schema:               &MCPSchemaSettings{Pin: m.Schema.Pin},
		Scan: &MCPScanSettings{
			ToolArgs:      m.Scan.ToolArgs,
			ToolResults:   m.Scan.ToolResults,
			ProfileSchema: m.Scan.ProfileSchema,
			PIIPhone:      m.Scan.PII.Phone,
		},
		Chain: &MCPChainSettings{
			Enabled:    m.Chain.Enabled,
			WindowSize: m.Chain.WindowSize,
			Patterns:   append([]string(nil), m.Chain.Patterns...),
		},
	}
	if len(m.Tools.Allow) > 0 || len(m.Tools.Deny) > 0 ||
		len(m.Tools.RateLimit) > 0 || len(m.Tools.Constraints) > 0 {
		out.Tools = &MCPToolsSettings{
			Allow:       append([]string(nil), m.Tools.Allow...),
			Deny:        append([]string(nil), m.Tools.Deny...),
			RateLimit:   copyStringMap(m.Tools.RateLimit),
			Constraints: copyToolConstraints(m.Tools.Constraints),
		}
	}
	return out
}

// MCPConfigFromSettings is the reverse of mcpSettingsFromPolicy: it maps the
// secret-free wire MCP block back to a full MCPConfig so a worker can REBUILD
// its MCP gateway from control-plane-distributed settings. It is field-for-field
// symmetric with mcpSettingsFromPolicy (Enabled, Mode, FailClosedOnError,
// MaxResponseScanBytes, Tools{Allow,Deny,RateLimit,Constraints}, Schema.Pin,
// Scan{ToolArgs,ToolResults,ProfileSchema,PII.Phone}, Chain{Enabled,WindowSize,
// Patterns}). A nil input returns a zero MCPConfig (Enabled=false → the gateway
// is disabled), matching the "no MCP distributed" case.
func MCPConfigFromSettings(s *MCPSettings) MCPConfig {
	if s == nil {
		return MCPConfig{}
	}
	out := MCPConfig{
		Enabled:              s.Enabled,
		Mode:                 s.Mode,
		FailClosedOnError:    s.FailClosedOnError,
		MaxResponseScanBytes: s.MaxResponseScanBytes,
	}
	if s.Schema != nil {
		out.Schema = MCPSchemaConfig{Pin: s.Schema.Pin}
	}
	if s.Scan != nil {
		out.Scan = MCPScanConfig{
			ToolArgs:      s.Scan.ToolArgs,
			ToolResults:   s.Scan.ToolResults,
			ProfileSchema: s.Scan.ProfileSchema,
			PII:           MCPPIIConfig{Phone: s.Scan.PIIPhone},
		}
	}
	if s.Chain != nil {
		// A wire windowSize of <=0 means "not set" (omitempty drops it), so apply
		// the loader's default rather than rebuild a gateway with windowSize==0,
		// which validateMCP rejects.
		windowSize := s.Chain.WindowSize
		if windowSize <= 0 {
			windowSize = defaultMCPChainWindowSize
		}
		out.Chain = MCPChainConfig{
			Enabled:    s.Chain.Enabled,
			WindowSize: windowSize,
			Patterns:   append([]string(nil), s.Chain.Patterns...),
		}
	}
	if s.Tools != nil {
		out.Tools = MCPToolsConfig{
			Allow:       append([]string(nil), s.Tools.Allow...),
			Deny:        append([]string(nil), s.Tools.Deny...),
			RateLimit:   copyStringMap(s.Tools.RateLimit),
			Constraints: copyToolConstraints(s.Tools.Constraints),
		}
	}
	return out
}

// JudgeConfigFromSettings is the reverse of judgeSettingsFromPolicy: it maps the
// secret-free wire judge block back to a full JudgeConfig so a managed worker can
// REBUILD its inline judge from control-plane-distributed settings. It is
// field-for-field symmetric with judgeSettingsFromPolicy (Enabled, Provider,
// Model, BaseURL, APIKeyEnv, Timeout, CacheTTL, RateLimit, CircuitBreaker
// {MaxFailures,Cooldown}), converting the seconds-valued ints back to
// time.Duration. A nil input returns a zero JudgeConfig (Enabled=false → the
// judge is disabled), matching the "no judge distributed" case. APIKeyEnv carries
// only an env NAME; the worker resolves the actual key from its OWN environment.
func JudgeConfigFromSettings(s *JudgeSettings) JudgeConfig {
	if s == nil {
		return JudgeConfig{}
	}
	out := JudgeConfig{
		Enabled:   s.Enabled,
		Provider:  s.Provider,
		Model:     s.Model,
		BaseURL:   s.BaseURL,
		APIKeyEnv: s.APIKeyEnv,
		Timeout:   time.Duration(s.TimeoutSeconds) * time.Second,
		CacheTTL:  time.Duration(s.CacheTTLSeconds) * time.Second,
		RateLimit: s.RateLimit,
	}
	if s.CircuitBreaker != nil {
		out.CircuitBreaker = CircuitBreakerConfig{
			MaxFailures: s.CircuitBreaker.MaxFailures,
			Cooldown:    time.Duration(s.CircuitBreaker.CooldownSeconds) * time.Second,
		}
	}
	return out
}

// AgentsFromSettings is the reverse of the agents projection in
// SettingsWireFromPolicy: it maps the wire AgentSettings list (id + policy text)
// back to []AgentPolicy so the rebuilt judge gets the same per-agent policies. A
// nil/empty input returns nil.
func AgentsFromSettings(in []AgentSettings) []AgentPolicy {
	if len(in) == 0 {
		return nil
	}
	out := make([]AgentPolicy, 0, len(in))
	for _, a := range in {
		out = append(out, AgentPolicy(a))
	}
	return out
}

// judgeSettingsFromPolicy projects JudgeConfig onto JudgeSettings, or nil if the
// judge is disabled (the default). APIKeyEnv is an env NAME only.
func judgeSettingsFromPolicy(j JudgeConfig) *JudgeSettings {
	if !j.Enabled {
		return nil
	}
	out := &JudgeSettings{
		Enabled:         j.Enabled,
		Provider:        j.Provider,
		Model:           j.Model,
		BaseURL:         j.BaseURL,
		APIKeyEnv:       j.APIKeyEnv,
		TimeoutSeconds:  int(j.Timeout.Seconds()),
		CacheTTLSeconds: int(j.CacheTTL.Seconds()),
		RateLimit:       j.RateLimit,
	}
	if j.CircuitBreaker.MaxFailures != 0 || j.CircuitBreaker.Cooldown != 0 {
		out.CircuitBreaker = &JudgeCircuitBreakerSettings{
			MaxFailures:     j.CircuitBreaker.MaxFailures,
			CooldownSeconds: int(j.CircuitBreaker.Cooldown.Seconds()),
		}
	}
	return out
}

// observabilitySettingsFromPolicy projects ObservabilityConfig onto
// ObservabilitySettings, or nil if observability is disabled (the default).
func observabilitySettingsFromPolicy(o ObservabilityConfig) *ObservabilitySettings {
	if !o.Enabled {
		return nil
	}
	return &ObservabilitySettings{
		Enabled:            o.Enabled,
		ServiceName:        o.ServiceName,
		MetricsEnabled:     o.MetricsEnabled,
		OTLPEndpoint:       o.OTLPEndpoint,
		ResourceAttributes: copyStringMap(o.ResourceAttributes),
	}
}

// ObservabilityConfigFromSettings is the reverse of observabilitySettingsFromPolicy:
// it maps the secret-free wire observability block back to a full
// ObservabilityConfig so a managed worker can INITIALIZE its OTel providers from
// control-plane-distributed settings at boot. It is field-for-field symmetric
// with observabilitySettingsFromPolicy (Enabled, ServiceName, MetricsEnabled,
// OTLPEndpoint, ResourceAttributes). A nil input returns a zero
// ObservabilityConfig (Enabled=false → observability is disabled), matching the
// "no observability distributed" case. ResourceAttributes are bounded operator
// labels only — never secrets. Note: OTel providers initialize ONCE per process,
// so this resolved config takes effect at (re)start, not on a live long-poll.
func ObservabilityConfigFromSettings(s *ObservabilitySettings) ObservabilityConfig {
	if s == nil {
		return ObservabilityConfig{}
	}
	return ObservabilityConfig{
		Enabled:            s.Enabled,
		ServiceName:        s.ServiceName,
		MetricsEnabled:     s.MetricsEnabled,
		OTLPEndpoint:       s.OTLPEndpoint,
		ResourceAttributes: copyStringMap(s.ResourceAttributes),
	}
}

// loggingSettingsFromPolicy projects the logging knobs, or nil if both are the
// loader defaults (info/json), so a worker that never customized logging emits
// nothing for it.
func loggingSettingsFromPolicy(p Policy) *LoggingSettings {
	level, format := p.LogLevel, p.LogFormat
	defaulted := (level == "" || level == "info") && (format == "" || format == "json")
	if defaulted {
		return nil
	}
	return &LoggingSettings{Level: level, Format: format}
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyToolConstraints(in map[string]MCPToolConstraints) map[string]MCPToolConstraints {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]MCPToolConstraints, len(in))
	for tool, tc := range in {
		ctc := MCPToolConstraints{MaxArgsBytes: tc.MaxArgsBytes}
		if tc.Fields != nil {
			fields := make(map[string]MCPFieldConstraint, len(tc.Fields))
			for f, fc := range tc.Fields {
				fields[f] = fc
			}
			ctc.Fields = fields
		}
		if tc.AllowWhen != nil {
			aw := *tc.AllowWhen
			ctc.AllowWhen = &aw
		}
		out[tool] = ctc
	}
	return out
}

// DeepCopy returns an independent copy of the settings wire (nil-safe), so an
// accessor can hand callers a value they may freely retain without aliasing the
// provider's stored copy.
func (s *SettingsWire) DeepCopy() *SettingsWire {
	if s == nil {
		return nil
	}
	cp := *s
	if s.MCP != nil {
		m := *s.MCP
		if s.MCP.Schema != nil {
			sc := *s.MCP.Schema
			m.Schema = &sc
		}
		if s.MCP.Scan != nil {
			sc := *s.MCP.Scan
			m.Scan = &sc
		}
		if s.MCP.Chain != nil {
			ch := *s.MCP.Chain
			ch.Patterns = append([]string(nil), s.MCP.Chain.Patterns...)
			m.Chain = &ch
		}
		if s.MCP.Tools != nil {
			t := *s.MCP.Tools
			t.Allow = append([]string(nil), s.MCP.Tools.Allow...)
			t.Deny = append([]string(nil), s.MCP.Tools.Deny...)
			t.RateLimit = copyStringMap(s.MCP.Tools.RateLimit)
			t.Constraints = copyToolConstraints(s.MCP.Tools.Constraints)
			m.Tools = &t
		}
		cp.MCP = &m
	}
	if s.Judge != nil {
		j := *s.Judge
		if s.Judge.CircuitBreaker != nil {
			cb := *s.Judge.CircuitBreaker
			j.CircuitBreaker = &cb
		}
		cp.Judge = &j
	}
	if s.Agents != nil {
		cp.Agents = append([]AgentSettings(nil), s.Agents...)
	}
	if s.Observability != nil {
		o := *s.Observability
		o.ResourceAttributes = copyStringMap(s.Observability.ResourceAttributes)
		cp.Observability = &o
	}
	if s.Advisory != nil {
		a := *s.Advisory
		cp.Advisory = &a
	}
	if s.Compliance != nil {
		c := *s.Compliance
		cp.Compliance = &c
	}
	if s.CacheTTLSeconds != nil {
		ttl := *s.CacheTTLSeconds
		cp.CacheTTLSeconds = &ttl
	}
	if s.Logging != nil {
		l := *s.Logging
		cp.Logging = &l
	}
	return &cp
}
