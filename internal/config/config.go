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
	// MCP configures the optional MCP egress wedge (deep MCP analysis). Disabled
	// by default; when disabled every field is zero-valued and harmless.
	MCP MCPConfig `json:"-"`
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
}

// Auth transform type identifiers. Each corresponds to a concrete
// auth.RequestTransformer implementation.
const (
	AuthOAuth2ClientCredentials = "oauth2_client_credentials"
	AuthAWSSigV4                = "aws_sigv4"
	AuthHMAC                    = "hmac"
	AuthAPIKey                  = "api_key"
)

// AuthEntry maps a destination pattern to a request-authentication transform.
// Match uses the same syntax as the policy engine (exact / *.wildcard / ~regex).
// Credential-bearing fields support ${ENV_VAR} expansion, resolved at build time
// so secrets live in the environment, never in the config file or in logs.
type AuthEntry struct {
	Match string
	Type  string

	// oauth2_client_credentials
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string

	// aws_sigv4
	Region          string
	Service         string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// hmac
	Algorithm string // sha256 | sha512 | sha1
	Secret    string
	Header    string

	// api_key
	Location string // header | basic_auth
	Name     string
	Value    string
}

// ControlPlaneConfig configures the remote ConfigProvider. When Endpoint is set,
// the proxy pulls allow/deny policy from it at startup and re-pulls every
// PollInterval, hot-swapping the live evaluator. A pull failure preserves the
// last-known-good policy so a worker keeps running if the control plane is down.
type ControlPlaneConfig struct {
	Endpoint     string        // https control-plane URL ("" disables)
	TokenEnv     string        // env var holding the bearer token
	PollInterval time.Duration // re-pull interval (default 30s) — legacy/fallback
	// CACert is an optional CA certificate (PEM) added to this worker's trust
	// pool ONLY for the control-plane connection, so a control plane serving a
	// privately-signed cert is trusted without altering upstream TLS trust.
	CACert string
	// LongPollWait is how long the worker asks the CP to hold a /policy request
	// open before returning 304 (default 30s).
	LongPollWait time.Duration
	// HeartbeatInterval is how often the worker pings /control/heartbeat so the CP
	// lists it as online even when idle (default 10s).
	HeartbeatInterval time.Duration
	// LocalOnly, when true, makes the worker ignore the control plane and enforce
	// its LOCAL policy (standalone). Default false = CP-managed: policy comes only
	// from the control plane and the worker fails closed until the first pull.
	LocalOnly bool
}

// CentralConfig configures fleet analytics aggregation.
//   - mode: aggregator — run an ingest endpoint that receives event batches into
//     an in-memory central store the dashboard reads from.
//   - mode: worker — forward this proxy's local events to a remote aggregator.
//   - mode: off (default) — single-node, no aggregation.
type CentralConfig struct {
	Mode string // off | aggregator | worker

	// aggregator
	TokenEnv  string // env var holding the bearer token ingest requests must present
	MaxEvents int    // central store retention cap (0 = default)

	// worker
	Endpoint  string        // aggregator ingest URL
	ProxyID   string        // label this worker's events with
	BatchSize int           // events per forward batch (default 100)
	BufferCap int           // local buffer cap before dropping oldest (default 10000)
	Interval  time.Duration // forward interval (default 10s)
	// CACert is an optional CA certificate (PEM) added to the forwarding client's
	// trust pool ONLY for the aggregator connection (same rationale as
	// ControlPlaneConfig.CACert).
	CACert string
	// MCPPushInterval is how often a worker forwards its MCP inventory + observed
	// schema to the aggregator (push-on-change is automatic; default 30s).
	MCPPushInterval time.Duration
	// ForwardSecretInventory, when true, forwards the worker's configured secrets
	// BY REFERENCE (sha256/last4/length, never values) so the CP can show them.
	// Default false.
	ForwardSecretInventory bool
}

// AuditConfig groups the signed-receipt and compliance-tagging features.
type AuditConfig struct {
	SignedReceipts SignedReceiptsConfig
	Compliance     ComplianceConfig
}

// SignedReceiptsConfig configures Ed25519-signed, independently-verifiable
// receipts for every mediated event.
type SignedReceiptsConfig struct {
	Enabled bool
	// KeyFile is the Ed25519 private-key path (PKCS#8 PEM). It is generated and
	// persisted on first run if absent, and its public key is logged at startup.
	KeyFile string
	// Log is the JSONL receipts output path (one signed receipt per line).
	Log string
}

// ComplianceConfig toggles tagging events with OWASP/MITRE control IDs.
type ComplianceConfig struct {
	Enabled bool
}

// MCPConfig configures the MCP wedge: routing live MCP traffic through the deep
// MCP analyzers (tool policy, schema drift, poisoning, chain, scan). Everything
// is off by default; a zero value means "no MCP processing" and is harmless.
type MCPConfig struct {
	// Enabled gates the entire MCP subsystem. Default false.
	Enabled bool
	// Mode is one of off|monitor|enforce. monitor detects+logs but never blocks;
	// enforce additionally blocks. Empty normalizes to monitor.
	Mode string
	// FailClosedOnError flips analysis errors from fail-open (allow) to
	// fail-closed (deny). Default false (fail-open: an analyzer bug never takes
	// down egress).
	FailClosedOnError bool
	// MaxResponseScanBytes caps the buffered response body scanned inline.
	// Default 1 MiB (1048576).
	MaxResponseScanBytes int
	// Tools is the default-deny tool policy (name allow/deny + per-tool rate).
	Tools MCPToolsConfig
	// Schema configures declared-schema (tools/list) drift handling.
	Schema MCPSchemaConfig
	// Scan configures which payloads are scanned and which PII detectors run.
	Scan MCPScanConfig
	// Chain configures the per-session call-chain analyzer.
	Chain MCPChainConfig
}

// MCPToolsConfig is the Phase-1 tool policy: name allow/deny plus per-tool rate
// limits. Deny wins over allow; an empty allow under enforce denies all tools.
type MCPToolsConfig struct {
	// Allow lists permitted tool names.
	Allow []string
	// Deny lists blocked tool names; deny wins over allow.
	Deny []string
	// RateLimit maps a tool name to a rate string ("N/second|minute|hour"),
	// validated by the shared rate-limit validator.
	RateLimit map[string]string
	// Constraints holds optional per-tool argument constraints, keyed by tool
	// name. Additive over the allow/deny policy: a tool may be permitted yet
	// still fail a per-field constraint. Absent = no extra constraint.
	Constraints map[string]MCPToolConstraints
}

// MCPToolConstraints bounds one tool's call arguments: an overall size cap on
// the raw params plus per-top-level-field constraints. A zero value imposes no
// constraint.
type MCPToolConstraints struct {
	// MaxArgsBytes caps the raw params JSON size in bytes (0 = unlimited).
	MaxArgsBytes int
	// Fields holds per-top-level-param-field constraints, keyed by field name.
	Fields map[string]MCPFieldConstraint
	// AllowWhen, when non-nil, further gates an already-allowed tool to a
	// specific agent id and/or server-local time window. nil = no extra condition.
	AllowWhen *MCPToolCondition
}

// MCPToolCondition further restricts an allowed tool. It only narrows: a tool
// must already pass the allow/deny policy before the condition is consulted.
type MCPToolCondition struct {
	// AgentID, if set, permits the tool only for this agent id.
	AgentID string
	// TimeWindow, if set ("HH-HH", server local, 0-23), permits the tool only
	// within the window.
	TimeWindow string
}

// MCPFieldConstraint constrains one top-level param field. All checks are
// transient: the field value is matched against Match/MaxLen but never stored.
type MCPFieldConstraint struct {
	// Match is an optional Go regexp the field's string value must match
	// (empty = no match check).
	Match string
	// MaxLen caps the field's string length (0 = unlimited).
	MaxLen int
	// Required means the field must be present.
	Required bool
	// Forbidden means the field must NOT be present.
	Forbidden bool
}

// MCPSchemaConfig configures declared-schema drift handling.
type MCPSchemaConfig struct {
	// Pin blocks on any tools/list drift (enforce mode). Default false.
	Pin bool
}

// MCPScanConfig configures which payloads are scanned and PII opt-ins.
type MCPScanConfig struct {
	// ToolArgs scans outbound tool arguments. Default true.
	ToolArgs bool
	// ToolResults scans inbound tool results. Default true.
	ToolResults bool
	// ProfileSchema learns + merges observed in/out schema per tool. Default true.
	ProfileSchema bool
	// PII configures the minimal PII detectors.
	PII MCPPIIConfig
}

// MCPPIIConfig opts in to the noisier PII detectors. email/card/SSN are always
// on; phone is opt-in because bare digit runs over-match.
type MCPPIIConfig struct {
	// Phone enables the opt-in phone-number detector. Default false.
	Phone bool
}

// MCPChainConfig configures the per-session call-chain analyzer.
type MCPChainConfig struct {
	// Enabled gates chain analysis. Default true.
	Enabled bool
	// WindowSize bounds the per-session sliding window. Default 50; must be > 0.
	WindowSize int
	// Patterns selects which built-in chain patterns are active. Default = all
	// three (read_then_send, permission_probing, rapid_repeat).
	Patterns []string
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
	cp.MCP.Tools.Allow = append([]string(nil), p.MCP.Tools.Allow...)
	cp.MCP.Tools.Deny = append([]string(nil), p.MCP.Tools.Deny...)
	if p.MCP.Tools.RateLimit != nil {
		rl := make(map[string]string, len(p.MCP.Tools.RateLimit))
		for k, v := range p.MCP.Tools.RateLimit {
			rl[k] = v
		}
		cp.MCP.Tools.RateLimit = rl
	}
	if p.MCP.Tools.Constraints != nil {
		cs := make(map[string]MCPToolConstraints, len(p.MCP.Tools.Constraints))
		for tool, tc := range p.MCP.Tools.Constraints {
			ctc := MCPToolConstraints{MaxArgsBytes: tc.MaxArgsBytes}
			if tc.Fields != nil {
				fields := make(map[string]MCPFieldConstraint, len(tc.Fields))
				for field, fc := range tc.Fields {
					fields[field] = fc
				}
				ctc.Fields = fields
			}
			if tc.AllowWhen != nil {
				aw := *tc.AllowWhen
				ctc.AllowWhen = &aw
			}
			cs[tool] = ctc
		}
		cp.MCP.Tools.Constraints = cs
	}
	cp.MCP.Chain.Patterns = append([]string(nil), p.MCP.Chain.Patterns...)
	cp.Auth = append([]AuthEntry(nil), p.Auth...)
	for i := range cp.Auth {
		cp.Auth[i].Scopes = append([]string(nil), p.Auth[i].Scopes...)
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
	Auth          []rawAuthEntry    `yaml:"auth"`
	ControlPlane  *rawControlPlane  `yaml:"controlPlane"`
	Central       *rawCentral       `yaml:"central"`
	Audit         *rawAudit         `yaml:"audit"`
}

// rawAuthEntry mirrors one on-disk `auth:` list item. All credential fields are
// strings so ${ENV} placeholders survive parsing and are expanded at build time.
type rawAuthEntry struct {
	Match           string   `yaml:"match"`
	Type            string   `yaml:"type"`
	TokenURL        string   `yaml:"tokenURL"`
	ClientID        string   `yaml:"clientID"`
	ClientSecret    string   `yaml:"clientSecret"`
	Scopes          []string `yaml:"scopes"`
	Region          string   `yaml:"region"`
	Service         string   `yaml:"service"`
	AccessKeyID     string   `yaml:"accessKeyID"`
	SecretAccessKey string   `yaml:"secretAccessKey"`
	SessionToken    string   `yaml:"sessionToken"`
	Algorithm       string   `yaml:"algorithm"`
	Secret          string   `yaml:"secret"`
	Header          string   `yaml:"header"`
	Location        string   `yaml:"location"`
	Name            string   `yaml:"name"`
	Value           string   `yaml:"value"`
}

// rawControlPlane mirrors the on-disk `controlPlane:` block.
type rawControlPlane struct {
	Endpoint          string `yaml:"endpoint"`
	TokenEnv          string `yaml:"tokenEnv"`
	PollInterval      string `yaml:"pollInterval"`
	CACert            string `yaml:"caCert"`
	LongPollWait      string `yaml:"longPollWait"`
	HeartbeatInterval string `yaml:"heartbeatInterval"`
	LocalOnly         bool   `yaml:"localOnly"`
}

// rawCentral mirrors the on-disk `central:` block.
type rawCentral struct {
	Mode                   string `yaml:"mode"`
	TokenEnv               string `yaml:"tokenEnv"`
	MaxEvents              int    `yaml:"maxEvents"`
	Endpoint               string `yaml:"endpoint"`
	ProxyID                string `yaml:"proxyID"`
	BatchSize              int    `yaml:"batchSize"`
	BufferCap              int    `yaml:"bufferCap"`
	Interval               string `yaml:"interval"`
	CACert                 string `yaml:"caCert"`
	MCPPushInterval        string `yaml:"mcpPushInterval"`
	ForwardSecretInventory bool   `yaml:"forwardSecretInventory"`
}

// rawAudit mirrors the on-disk `audit:` block.
type rawAudit struct {
	SignedReceipts *struct {
		Enabled bool   `yaml:"enabled"`
		KeyFile string `yaml:"keyFile"`
		Log     string `yaml:"log"`
	} `yaml:"signedReceipts"`
	Compliance *struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"compliance"`
}

// rawMCP mirrors the on-disk `mcp:` block. Pointer so an absent block is
// distinct from an explicit (disabled) one. Sub-blocks are pointers where
// "absent vs zero" matters for default application (mirrors rawJudge/rawObservability).
// KnownFields(true) is strict, so this MUST be registered or configs with the
// block fail to parse.
type rawMCP struct {
	Enabled              bool          `yaml:"enabled"`
	Mode                 string        `yaml:"mode"`
	FailClosedOnError    bool          `yaml:"failClosedOnError"`
	MaxResponseScanBytes *int          `yaml:"maxResponseScanBytes"`
	Tools                *rawMCPTools  `yaml:"tools"`
	Schema               *rawMCPSchema `yaml:"schema"`
	Scan                 *rawMCPScan   `yaml:"scan"`
	Chain                *rawMCPChain  `yaml:"chain"`
}

type rawMCPTools struct {
	Allow       []string                        `yaml:"allow"`
	Deny        []string                        `yaml:"deny"`
	RateLimit   map[string]string               `yaml:"rateLimit"`
	Constraints map[string]rawMCPToolConstraint `yaml:"constraints"`
}

type rawMCPToolConstraint struct {
	MaxArgsBytes int                              `yaml:"maxArgsBytes"`
	Fields       map[string]rawMCPFieldConstraint `yaml:"fields"`
	AllowWhen    *rawMCPToolCondition             `yaml:"allowWhen"`
}

type rawMCPToolCondition struct {
	AgentID    string `yaml:"agentId"`
	TimeWindow string `yaml:"timeWindow"`
}

type rawMCPFieldConstraint struct {
	Match     string `yaml:"match"`
	MaxLen    int    `yaml:"maxLen"`
	Required  bool   `yaml:"required"`
	Forbidden bool   `yaml:"forbidden"`
}

type rawMCPSchema struct {
	Pin bool `yaml:"pin"`
}

type rawMCPScan struct {
	ToolArgs      *bool          `yaml:"toolArgs"`
	ToolResults   *bool          `yaml:"toolResults"`
	ProfileSchema *bool          `yaml:"profileSchema"`
	PII           *rawMCPScanPII `yaml:"pii"`
}

type rawMCPScanPII struct {
	Phone bool `yaml:"phone"`
}

type rawMCPChain struct {
	Enabled    *bool    `yaml:"enabled"`
	WindowSize *int     `yaml:"windowSize"`
	Patterns   []string `yaml:"patterns"`
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

	if err := validate(policy); err != nil {
		return nil, err
	}
	return &LocalYAMLProvider{policy: policy}, nil
}

// parseAuth converts the raw auth list into typed AuthEntry values. Defaults are
// applied at build time (run.go); here we only normalize the type string.
func parseAuth(raw []rawAuthEntry) []AuthEntry {
	if len(raw) == 0 {
		return nil
	}
	out := make([]AuthEntry, 0, len(raw))
	for _, r := range raw {
		out = append(out, AuthEntry{
			Match:           r.Match,
			Type:            strings.ToLower(strings.TrimSpace(r.Type)),
			TokenURL:        r.TokenURL,
			ClientID:        r.ClientID,
			ClientSecret:    r.ClientSecret,
			Scopes:          append([]string(nil), r.Scopes...),
			Region:          r.Region,
			Service:         r.Service,
			AccessKeyID:     r.AccessKeyID,
			SecretAccessKey: r.SecretAccessKey,
			SessionToken:    r.SessionToken,
			Algorithm:       strings.ToLower(strings.TrimSpace(r.Algorithm)),
			Secret:          r.Secret,
			Header:          r.Header,
			Location:        strings.ToLower(strings.TrimSpace(r.Location)),
			Name:            r.Name,
			Value:           r.Value,
		})
	}
	return out
}

// control-plane defaults applied when the corresponding field is omitted.
const (
	defaultControlPlanePollInterval = 30 * time.Second
	defaultLongPollWait             = 30 * time.Second
	defaultHeartbeatInterval        = 10 * time.Second
)

// parseControlPlane converts the raw controlPlane block into typed config,
// applying defaults. An absent block yields a disabled value.
func parseControlPlane(r *rawControlPlane) (ControlPlaneConfig, error) {
	var c ControlPlaneConfig
	if r == nil {
		return c, nil
	}
	c.Endpoint = strings.TrimSpace(r.Endpoint)
	c.TokenEnv = r.TokenEnv
	c.CACert = strings.TrimSpace(r.CACert)
	c.LocalOnly = r.LocalOnly
	c.PollInterval = defaultControlPlanePollInterval
	c.LongPollWait = defaultLongPollWait
	c.HeartbeatInterval = defaultHeartbeatInterval
	if err := parseDurationField("controlPlane.pollInterval", r.PollInterval, &c.PollInterval); err != nil {
		return ControlPlaneConfig{}, err
	}
	if err := parseDurationField("controlPlane.longPollWait", r.LongPollWait, &c.LongPollWait); err != nil {
		return ControlPlaneConfig{}, err
	}
	if err := parseDurationField("controlPlane.heartbeatInterval", r.HeartbeatInterval, &c.HeartbeatInterval); err != nil {
		return ControlPlaneConfig{}, err
	}
	return c, nil
}

// central defaults applied when the corresponding field is omitted (worker mode).
const (
	defaultCentralBatchSize       = 100
	defaultCentralBufferCap       = 10000
	defaultCentralInterval        = 10 * time.Second
	defaultCentralMCPPushInterval = 30 * time.Second
)

// parseCentral converts the raw central block into typed config, normalizing the
// mode and applying worker-side defaults. An absent block yields mode "off".
func parseCentral(r *rawCentral) (CentralConfig, error) {
	c := CentralConfig{Mode: "off"}
	if r == nil {
		return c, nil
	}
	if m := strings.ToLower(strings.TrimSpace(r.Mode)); m != "" {
		c.Mode = m
	}
	c.TokenEnv = r.TokenEnv
	c.MaxEvents = r.MaxEvents
	c.Endpoint = strings.TrimSpace(r.Endpoint)
	c.ProxyID = r.ProxyID
	c.CACert = strings.TrimSpace(r.CACert)
	c.BatchSize = defaultCentralBatchSize
	if r.BatchSize > 0 {
		c.BatchSize = r.BatchSize
	}
	c.BufferCap = defaultCentralBufferCap
	if r.BufferCap > 0 {
		c.BufferCap = r.BufferCap
	}
	c.Interval = defaultCentralInterval
	if err := parseDurationField("central.interval", r.Interval, &c.Interval); err != nil {
		return CentralConfig{}, err
	}
	c.MCPPushInterval = defaultCentralMCPPushInterval
	if err := parseDurationField("central.mcpPushInterval", r.MCPPushInterval, &c.MCPPushInterval); err != nil {
		return CentralConfig{}, err
	}
	c.ForwardSecretInventory = r.ForwardSecretInventory
	return c, nil
}

// parseAudit converts the raw audit block into typed config. An absent block
// yields both features disabled.
func parseAudit(r *rawAudit) AuditConfig {
	var a AuditConfig
	if r == nil {
		return a
	}
	if r.SignedReceipts != nil {
		a.SignedReceipts.Enabled = r.SignedReceipts.Enabled
		a.SignedReceipts.KeyFile = strings.TrimSpace(r.SignedReceipts.KeyFile)
		a.SignedReceipts.Log = strings.TrimSpace(r.SignedReceipts.Log)
	}
	if r.Compliance != nil {
		a.Compliance.Enabled = r.Compliance.Enabled
	}
	return a
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

// MCP defaults applied when the corresponding field is omitted.
const (
	defaultMCPMode                 = "monitor"
	defaultMCPMaxResponseScanBytes = 1048576 // 1 MiB
	defaultMCPChainWindowSize      = 50
)

// mcpChainPatterns is the default (and only valid) set of built-in chain
// patterns. The default config enables all three.
var mcpChainPatterns = []string{"read_then_send", "permission_probing", "rapid_repeat"}

// parseMCP converts the raw mcp block into a typed MCPConfig, applying the
// documented defaults. An absent block yields a disabled, harmless value with
// the documented zero-ish defaults. Cross-field validation (mode enum, window
// size, patterns, per-tool rate limits) happens in validate, only when enabled.
func parseMCP(r *rawMCP) MCPConfig {
	mc := MCPConfig{
		Mode:                 defaultMCPMode,
		MaxResponseScanBytes: defaultMCPMaxResponseScanBytes,
		Scan: MCPScanConfig{
			ToolArgs:      true,
			ToolResults:   true,
			ProfileSchema: true,
		},
		Chain: MCPChainConfig{
			Enabled:    true,
			WindowSize: defaultMCPChainWindowSize,
			Patterns:   append([]string(nil), mcpChainPatterns...),
		},
	}
	if r == nil {
		return mc
	}
	mc.Enabled = r.Enabled
	mc.FailClosedOnError = r.FailClosedOnError
	if strings.TrimSpace(r.Mode) != "" {
		mc.Mode = strings.ToLower(strings.TrimSpace(r.Mode))
	}
	if r.MaxResponseScanBytes != nil {
		mc.MaxResponseScanBytes = *r.MaxResponseScanBytes
	}
	if r.Tools != nil {
		mc.Tools.Allow = append([]string(nil), r.Tools.Allow...)
		mc.Tools.Deny = append([]string(nil), r.Tools.Deny...)
		if r.Tools.RateLimit != nil {
			mc.Tools.RateLimit = make(map[string]string, len(r.Tools.RateLimit))
			for k, v := range r.Tools.RateLimit {
				mc.Tools.RateLimit[k] = v
			}
		}
		if r.Tools.Constraints != nil {
			mc.Tools.Constraints = make(map[string]MCPToolConstraints, len(r.Tools.Constraints))
			for tool, rc := range r.Tools.Constraints {
				tc := MCPToolConstraints{MaxArgsBytes: rc.MaxArgsBytes}
				if rc.Fields != nil {
					tc.Fields = make(map[string]MCPFieldConstraint, len(rc.Fields))
					for field, rf := range rc.Fields {
						tc.Fields[field] = MCPFieldConstraint(rf)
					}
				}
				if rc.AllowWhen != nil {
					tc.AllowWhen = &MCPToolCondition{
						AgentID:    rc.AllowWhen.AgentID,
						TimeWindow: rc.AllowWhen.TimeWindow,
					}
				}
				mc.Tools.Constraints[tool] = tc
			}
		}
	}
	if r.Schema != nil {
		mc.Schema.Pin = r.Schema.Pin
	}
	if r.Scan != nil {
		if r.Scan.ToolArgs != nil {
			mc.Scan.ToolArgs = *r.Scan.ToolArgs
		}
		if r.Scan.ToolResults != nil {
			mc.Scan.ToolResults = *r.Scan.ToolResults
		}
		if r.Scan.ProfileSchema != nil {
			mc.Scan.ProfileSchema = *r.Scan.ProfileSchema
		}
		if r.Scan.PII != nil {
			mc.Scan.PII.Phone = r.Scan.PII.Phone
		}
	}
	if r.Chain != nil {
		if r.Chain.Enabled != nil {
			mc.Chain.Enabled = *r.Chain.Enabled
		}
		if r.Chain.WindowSize != nil {
			mc.Chain.WindowSize = *r.Chain.WindowSize
		}
		if r.Chain.Patterns != nil {
			mc.Chain.Patterns = append([]string(nil), r.Chain.Patterns...)
		}
	}
	return mc
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
	return nil
}

// validateMatchPattern checks an auth `match` uses the same syntax the policy
// engine accepts: exact host, "*.suffix" wildcard, or "~regex".
func validateMatchPattern(ctx, pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("config: %s: match is required", ctx)
	}
	if strings.HasPrefix(pattern, "~") {
		if _, err := regexp.Compile(pattern[1:]); err != nil {
			return fmt.Errorf("config: %s: match %q has invalid regex: %v", ctx, pattern, err)
		}
		return nil
	}
	if strings.Contains(pattern, "*") {
		if !strings.HasPrefix(pattern, "*.") || strings.Count(pattern, "*") != 1 {
			return fmt.Errorf("config: %s: match %q has invalid wildcard; only \"*.suffix\" is supported", ctx, pattern)
		}
	}
	return nil
}

// validateAuth enforces structural requirements per transform type. Credential
// values may be ${ENV} placeholders (resolved at build time), so presence — not
// the resolved secret — is what is checked here.
func validateAuth(entries []AuthEntry) error {
	for i, e := range entries {
		ctx := fmt.Sprintf("auth[%d]", i)
		if err := validateMatchPattern(ctx, e.Match); err != nil {
			return err
		}
		switch e.Type {
		case AuthOAuth2ClientCredentials:
			if e.TokenURL == "" || e.ClientID == "" || e.ClientSecret == "" {
				return fmt.Errorf("config: %s: type %s requires tokenURL, clientID, and clientSecret", ctx, e.Type)
			}
		case AuthAWSSigV4:
			if e.Region == "" || e.AccessKeyID == "" || e.SecretAccessKey == "" {
				return fmt.Errorf("config: %s: type %s requires region, accessKeyID, and secretAccessKey", ctx, e.Type)
			}
		case AuthHMAC:
			switch e.Algorithm {
			case "sha256", "sha512", "sha1":
			default:
				return fmt.Errorf("config: %s: hmac algorithm %q is invalid; must be sha256, sha512, or sha1", ctx, e.Algorithm)
			}
			if e.Secret == "" || e.Header == "" {
				return fmt.Errorf("config: %s: type %s requires secret and header", ctx, e.Type)
			}
		case AuthAPIKey:
			switch e.Location {
			case "header", "basic_auth":
			default:
				return fmt.Errorf("config: %s: api_key location %q is invalid; must be header or basic_auth", ctx, e.Location)
			}
			if e.Name == "" || e.Value == "" {
				return fmt.Errorf("config: %s: type %s requires name and value", ctx, e.Type)
			}
		case "":
			return fmt.Errorf("config: %s: type is required", ctx)
		default:
			return fmt.Errorf("config: %s: unknown type %q; must be one of: %s, %s, %s, %s", ctx, e.Type,
				AuthOAuth2ClientCredentials, AuthAWSSigV4, AuthHMAC, AuthAPIKey)
		}
	}
	return nil
}

// validateControlPlane enforces the control-plane block's requirements only when
// it is enabled (Endpoint set), so an absent/empty block is always valid.
func validateControlPlane(c ControlPlaneConfig) error {
	if c.Endpoint == "" {
		return nil
	}
	if !strings.HasPrefix(c.Endpoint, "https://") {
		return fmt.Errorf("config: controlPlane.endpoint must use https, got %q", c.Endpoint)
	}
	if c.PollInterval <= 0 {
		return fmt.Errorf("config: controlPlane.pollInterval must be greater than 0")
	}
	return nil
}

// validateCentral enforces the central block's requirements per mode.
func validateCentral(c CentralConfig) error {
	switch c.Mode {
	case "", "off":
		return nil
	case "aggregator":
		return nil
	case "worker":
		if c.Endpoint == "" {
			return fmt.Errorf("config: central.endpoint is required when central.mode is worker")
		}
		return nil
	default:
		return fmt.Errorf("config: central.mode %q is invalid; must be one of: off, aggregator, worker", c.Mode)
	}
}

// validateAudit enforces the audit block's requirements only for enabled features.
func validateAudit(a AuditConfig) error {
	if a.SignedReceipts.Enabled && a.SignedReceipts.Log == "" {
		return fmt.Errorf("config: audit.signedReceipts.log is required when signed receipts are enabled")
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

// validateMCP enforces the MCP block's requirements only when it is enabled, so
// a disabled block with default-valued config is always valid (back-compat:
// configs that omit mcp never fail here).
func validateMCP(m MCPConfig) error {
	if !m.Enabled {
		return nil
	}
	switch m.Mode {
	case "off", "monitor", "enforce":
	default:
		return fmt.Errorf("config: mcp.mode %q is invalid; must be one of: off, monitor, enforce", m.Mode)
	}
	if m.MaxResponseScanBytes < 0 {
		return fmt.Errorf("config: mcp.maxResponseScanBytes must not be negative")
	}
	if m.Chain.WindowSize <= 0 {
		return fmt.Errorf("config: mcp.chain.windowSize must be greater than 0")
	}
	for _, p := range m.Chain.Patterns {
		switch p {
		case "read_then_send", "permission_probing", "rapid_repeat":
		default:
			return fmt.Errorf("config: mcp.chain.patterns: unknown pattern %q; must be one of: read_then_send, permission_probing, rapid_repeat", p)
		}
	}
	for name, rl := range m.Tools.RateLimit {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("config: mcp.tools.rateLimit: tool name is required")
		}
		if err := validateRateLimit(fmt.Sprintf("mcp.tools.rateLimit[%q]", name), rl); err != nil {
			return err
		}
	}
	for i, t := range m.Tools.Allow {
		if strings.TrimSpace(t) == "" {
			return fmt.Errorf("config: mcp.tools.allow[%d]: tool name must not be empty", i)
		}
	}
	for i, t := range m.Tools.Deny {
		if strings.TrimSpace(t) == "" {
			return fmt.Errorf("config: mcp.tools.deny[%d]: tool name must not be empty", i)
		}
	}
	for tool, tc := range m.Tools.Constraints {
		if strings.TrimSpace(tool) == "" {
			return fmt.Errorf("config: mcp.tools.constraints: tool name is required")
		}
		if tc.MaxArgsBytes < 0 {
			return fmt.Errorf("config: mcp.tools.constraints[%q].maxArgsBytes must not be negative", tool)
		}
		if tc.AllowWhen != nil && tc.AllowWhen.TimeWindow != "" {
			if err := validateTimeWindow(fmt.Sprintf("mcp.tools.constraints[%q].allowWhen", tool), tc.AllowWhen.TimeWindow); err != nil {
				return err
			}
		}
		for field, fc := range tc.Fields {
			if strings.TrimSpace(field) == "" {
				return fmt.Errorf("config: mcp.tools.constraints[%q].fields: field name is required", tool)
			}
			if fc.MaxLen < 0 {
				return fmt.Errorf("config: mcp.tools.constraints[%q].fields[%q].maxLen must not be negative", tool, field)
			}
			if fc.Required && fc.Forbidden {
				return fmt.Errorf("config: mcp.tools.constraints[%q].fields[%q]: cannot be both required and forbidden", tool, field)
			}
			if fc.Match != "" {
				if _, err := regexp.Compile(fc.Match); err != nil {
					return fmt.Errorf("config: mcp.tools.constraints[%q].fields[%q].match has invalid regex: %v", tool, field, err)
				}
			}
		}
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
		if err := validateRateLimit("judge.rateLimit", j.RateLimit); err != nil {
			return err
		}
	}
	return nil
}

// GetPolicy returns the loaded policy.
func (p *LocalYAMLProvider) GetPolicy() (Policy, error) {
	return p.policy, nil
}
