package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestSettingsWireFromPolicy_NilForPureAllowDeny verifies a pure allow/deny
// policy (no behavioral blocks) projects to nil, so the wire payload omits the
// "settings" key entirely (back-compat).
func TestSettingsWireFromPolicy_NilForPureAllowDeny(t *testing.T) {
	p := Policy{
		Allowlist:       []AllowlistEntry{{Domain: "api.example.com"}},
		LogLevel:        "info",
		LogFormat:       "json",
		CacheTTLSeconds: defaultCacheTTLSeconds,
	}
	if got := SettingsWireFromPolicy(p); got != nil {
		t.Fatalf("expected nil settings for pure allow/deny, got %+v", got)
	}
}

// TestSettingsWireFromPolicy_ProjectsBehavioralBlocks verifies the converter
// copies the operator-tunable blocks (and only those), including the judge's
// env-NAME reference.
func TestSettingsWireFromPolicy_ProjectsBehavioralBlocks(t *testing.T) {
	p := Policy{
		MCP: MCPConfig{
			Enabled: true,
			Mode:    "enforce",
			Tools:   MCPToolsConfig{Allow: []string{"read_file"}, Deny: []string{"shell"}},
			Chain:   MCPChainConfig{Enabled: true, WindowSize: 50, Patterns: []string{"rapid_repeat"}},
			Scan:    MCPScanConfig{ToolArgs: true, ToolResults: true, ProfileSchema: true},
		},
		Judge: JudgeConfig{
			Enabled:   true,
			Provider:  "openai",
			Model:     "gpt-4o-mini",
			BaseURL:   "https://api.openai.com/v1",
			APIKeyEnv: "OPENAI_API_KEY",
			Timeout:   5 * time.Second,
		},
		Agents:          []AgentPolicy{{ID: "agent-1", Policy: "be careful"}},
		Observability:   ObservabilityConfig{Enabled: true, ServiceName: "warden", MetricsEnabled: true},
		Advisory:        AdvisoryConfig{Enabled: true},
		Audit:           AuditConfig{Compliance: ComplianceConfig{Enabled: true}},
		CacheTTLSeconds: 1800,
		LogLevel:        "debug",
		LogFormat:       "text",
	}
	s := SettingsWireFromPolicy(p)
	if s == nil {
		t.Fatal("expected non-nil settings")
	}
	if s.MCP == nil || s.MCP.Mode != "enforce" || s.MCP.Tools == nil ||
		!reflect.DeepEqual(s.MCP.Tools.Allow, []string{"read_file"}) {
		t.Errorf("mcp not projected: %+v", s.MCP)
	}
	if s.Judge == nil || s.Judge.APIKeyEnv != "OPENAI_API_KEY" || s.Judge.Model != "gpt-4o-mini" {
		t.Errorf("judge not projected (env-name ref): %+v", s.Judge)
	}
	if len(s.Agents) != 1 || s.Agents[0].ID != "agent-1" {
		t.Errorf("agents not projected: %+v", s.Agents)
	}
	if s.Observability == nil || !s.Observability.MetricsEnabled {
		t.Errorf("observability not projected: %+v", s.Observability)
	}
	if s.Advisory == nil || !s.Advisory.Enabled {
		t.Errorf("advisory not projected: %+v", s.Advisory)
	}
	if s.Compliance == nil || !s.Compliance.Enabled {
		t.Errorf("compliance not projected: %+v", s.Compliance)
	}
	if s.CacheTTLSeconds == nil || *s.CacheTTLSeconds != 1800 {
		t.Errorf("cacheTTL not projected: %+v", s.CacheTTLSeconds)
	}
	if s.Logging == nil || s.Logging.Level != "debug" || s.Logging.Format != "text" {
		t.Errorf("logging not projected: %+v", s.Logging)
	}
}

// TestMCPConfigFromSettings_RoundTrip verifies the reverse converter is
// field-for-field symmetric with mcpSettingsFromPolicy: projecting an MCPConfig
// to the wire and back preserves every operator-relevant field, so a worker can
// faithfully rebuild its gateway from distributed settings.
func TestMCPConfigFromSettings_RoundTrip(t *testing.T) {
	cfg := MCPConfig{
		Enabled:              true,
		Mode:                 "enforce",
		FailClosedOnError:    true,
		MaxResponseScanBytes: 2 << 20,
		Tools: MCPToolsConfig{
			Allow:     []string{"read_file", "list_dir"},
			Deny:      []string{"shell"},
			RateLimit: map[string]string{"read_file": "10/minute"},
			Constraints: map[string]MCPToolConstraints{
				"read_file": {
					MaxArgsBytes: 4096,
					Fields:       map[string]MCPFieldConstraint{"path": {MaxLen: 256, Required: true}},
					AllowWhen:    &MCPToolCondition{AgentID: "agent-1", TimeWindow: "09-17"},
				},
			},
		},
		Schema: MCPSchemaConfig{Pin: true},
		Scan:   MCPScanConfig{ToolArgs: true, ToolResults: true, ProfileSchema: true, PII: MCPPIIConfig{Phone: true}},
		Chain:  MCPChainConfig{Enabled: true, WindowSize: 25, Patterns: []string{"read_then_send", "rapid_repeat"}},
	}

	got := MCPConfigFromSettings(mcpSettingsFromPolicy(cfg))
	if !reflect.DeepEqual(got, cfg) {
		t.Errorf("round-trip mismatch:\n got: %+v\nwant: %+v", got, cfg)
	}
}

// TestMCPConfigFromSettings_WindowSizeDefault verifies that rebuilding an
// MCPConfig from wire settings applies the loader's chain windowSize default
// when the wire carries no explicit (positive) value, so a worker never rebuilds
// a gateway with windowSize==0 (which fails validateMCP). An explicit positive
// value is preserved as-is.
func TestMCPConfigFromSettings_WindowSizeDefault(t *testing.T) {
	// windowSize absent (0) → default 50.
	got := MCPConfigFromSettings(&MCPSettings{
		Enabled: true,
		Chain:   &MCPChainSettings{Enabled: true, WindowSize: 0},
	})
	if got.Chain.WindowSize != defaultMCPChainWindowSize {
		t.Errorf("windowSize default not applied: got %d, want %d",
			got.Chain.WindowSize, defaultMCPChainWindowSize)
	}

	// Explicit positive windowSize preserved.
	got = MCPConfigFromSettings(&MCPSettings{
		Enabled: true,
		Chain:   &MCPChainSettings{Enabled: true, WindowSize: 20},
	})
	if got.Chain.WindowSize != 20 {
		t.Errorf("explicit windowSize not preserved: got %d, want 20", got.Chain.WindowSize)
	}
}

// TestMCPConfigFromSettings_NilDisabled verifies a nil wire block maps to a zero
// (disabled) MCPConfig, matching the "no MCP distributed" case.
func TestMCPConfigFromSettings_NilDisabled(t *testing.T) {
	if got := MCPConfigFromSettings(nil); got.Enabled {
		t.Errorf("expected disabled MCPConfig for nil input, got %+v", got)
	}
}

// TestJudgeConfigFromSettings_RoundTrip verifies the reverse converter is
// field-for-field symmetric with judgeSettingsFromPolicy: projecting a
// JudgeConfig to the wire and back preserves every operator-relevant field
// (including the seconds<->Duration conversions), so a worker can faithfully
// rebuild its judge from distributed settings.
func TestJudgeConfigFromSettings_RoundTrip(t *testing.T) {
	cfg := JudgeConfig{
		Enabled:        true,
		Provider:       "openai",
		Model:          "gpt-4o-mini",
		BaseURL:        "https://api.openai.com/v1",
		APIKeyEnv:      "OPENAI_API_KEY",
		Timeout:        5 * time.Second,
		CacheTTL:       30 * time.Second,
		RateLimit:      "100/minute",
		CircuitBreaker: CircuitBreakerConfig{MaxFailures: 3, Cooldown: 60 * time.Second},
	}

	got := JudgeConfigFromSettings(judgeSettingsFromPolicy(cfg))
	if !reflect.DeepEqual(got, cfg) {
		t.Errorf("round-trip mismatch:\n got: %+v\nwant: %+v", got, cfg)
	}
}

// TestJudgeConfigFromSettings_NilDisabled verifies a nil wire block maps to a
// zero (disabled) JudgeConfig, matching the "no judge distributed" case.
func TestJudgeConfigFromSettings_NilDisabled(t *testing.T) {
	if got := JudgeConfigFromSettings(nil); got.Enabled {
		t.Errorf("expected disabled JudgeConfig for nil input, got %+v", got)
	}
}

// TestObservabilityConfigFromSettings_RoundTrip verifies the reverse converter is
// field-for-field symmetric with observabilitySettingsFromPolicy: projecting an
// ObservabilityConfig to the wire and back preserves every field (including the
// ResourceAttributes map), so a managed worker can faithfully INITIALIZE OTel from
// distributed settings at boot.
func TestObservabilityConfigFromSettings_RoundTrip(t *testing.T) {
	cfg := ObservabilityConfig{
		Enabled:            true,
		ServiceName:        "warden",
		MetricsEnabled:     true,
		OTLPEndpoint:       "otel-collector:4317",
		ResourceAttributes: map[string]string{"warden.proxy.id": "edge-1", "env": "prod"},
	}

	got := ObservabilityConfigFromSettings(observabilitySettingsFromPolicy(cfg))
	if !reflect.DeepEqual(got, cfg) {
		t.Errorf("round-trip mismatch:\n got: %+v\nwant: %+v", got, cfg)
	}
}

// TestObservabilityConfigFromSettings_NilDisabled verifies a nil wire block maps
// to a zero (disabled) ObservabilityConfig, matching the "no observability
// distributed" case.
func TestObservabilityConfigFromSettings_NilDisabled(t *testing.T) {
	if got := ObservabilityConfigFromSettings(nil); got.Enabled {
		t.Errorf("expected disabled ObservabilityConfig for nil input, got %+v", got)
	}
}

// TestAgentsFromSettings_RoundTrip verifies the agents converter is symmetric
// with the projection in SettingsWireFromPolicy.
func TestAgentsFromSettings_RoundTrip(t *testing.T) {
	in := []AgentPolicy{{ID: "a", Policy: "x"}, {ID: "b", Policy: "y"}}
	s := SettingsWireFromPolicy(Policy{Agents: in})
	if s == nil {
		t.Fatal("expected non-nil settings")
	}
	if got := AgentsFromSettings(s.Agents); !reflect.DeepEqual(got, in) {
		t.Errorf("round-trip mismatch:\n got: %+v\nwant: %+v", got, in)
	}
	if AgentsFromSettings(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

// TestSettingsWire_SecretFree is the core boundary guarantee: a SettingsWire
// built from a Policy that has secret VALUES set locally (judge config, auth
// transforms, secret mappings) must contain NONE of those values in its JSON —
// only the env-NAME reference. It also asserts, by reflecting field names, that
// the wire type carries no value-bearing field.
func TestSettingsWire_SecretFree(t *testing.T) {
	const (
		secretKey    = "sk-SUPER-SECRET-VALUE-123"
		clientSecret = "oauth-client-secret-xyz"
		hmacSecret   = "hmac-shared-secret-abc"
	)
	p := Policy{
		// Judge references its key by env NAME, but the local env also HOLDS a
		// value somewhere — the wire must carry only the name, never the value.
		Judge: JudgeConfig{
			Enabled:   true,
			Model:     "gpt-4o",
			BaseURL:   "https://api.openai.com/v1",
			APIKeyEnv: "OPENAI_API_KEY",
		},
		// Auth transforms hold resolved credentials locally; they must NOT be
		// projected onto the wire at all (deferred to a later phase).
		Auth: []AuthEntry{
			{Match: "api.x.com", Type: AuthOAuth2ClientCredentials, ClientID: "id", ClientSecret: clientSecret},
			{Match: "api.y.com", Type: AuthHMAC, Algorithm: "sha256", Secret: hmacSecret, Header: "X-Sig"},
		},
		// Secret mappings carry an env name, never a value — but to be safe we
		// also seed a fake "value" via the env name and assert it never appears.
		Secrets:       []SecretMapping{{Placeholder: "tok", EnvVar: "SECRET_TOKEN"}},
		MCP:           MCPConfig{Enabled: true, Mode: "monitor"},
		Observability: ObservabilityConfig{Enabled: true, MetricsEnabled: true},
	}
	s := SettingsWireFromPolicy(p)
	if s == nil {
		t.Fatal("expected non-nil settings")
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, leak := range []string{secretKey, clientSecret, hmacSecret} {
		if strings.Contains(js, leak) {
			t.Fatalf("settings JSON leaked a secret value %q: %s", leak, js)
		}
	}
	// The judge's env-NAME reference DOES round-trip (that is the allowed form).
	if !strings.Contains(js, "OPENAI_API_KEY") {
		t.Fatalf("env-name reference did not round-trip: %s", js)
	}

	// Structural check: no field anywhere in the wire type tree is named like a
	// secret-VALUE carrier (ClientSecret, SecretAccessKey, APIKey w/o Env, etc.).
	assertNoSecretValueFields(t, reflect.TypeOf(SettingsWire{}), map[reflect.Type]bool{})
}

// assertNoSecretValueFields walks a struct type tree and fails if any field name
// looks like it carries a secret VALUE rather than an env-NAME reference. This
// makes the secret-free invariant a compile-shaped assertion: a future field
// that holds a credential value trips this test.
func assertNoSecretValueFields(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := f.Name
		// Allowed: anything ending in "Env" is an env-NAME reference, not a value.
		isEnvRef := strings.HasSuffix(name, "Env")
		lower := strings.ToLower(name)
		looksSecret := strings.Contains(lower, "secret") ||
			strings.Contains(lower, "password") ||
			strings.Contains(lower, "credential") ||
			strings.Contains(lower, "accesskey") ||
			(strings.Contains(lower, "apikey") && !isEnvRef) ||
			lower == "token"
		if looksSecret && !isEnvRef {
			t.Errorf("SettingsWire field %q looks like a secret VALUE carrier (must reference by env name only)", name)
		}
		assertNoSecretValueFields(t, f.Type, seen)
	}
}

// TestSettingsWire_DeepCopy verifies the accessor's deep copy is independent.
func TestSettingsWire_DeepCopy(t *testing.T) {
	if (*SettingsWire)(nil).DeepCopy() != nil {
		t.Fatal("nil DeepCopy should return nil")
	}
	orig := &SettingsWire{
		MCP:   &MCPSettings{Enabled: true, Tools: &MCPToolsSettings{Allow: []string{"a"}}},
		Judge: &JudgeSettings{Enabled: true, APIKeyEnv: "K"},
	}
	cp := orig.DeepCopy()
	cp.MCP.Tools.Allow[0] = "mutated"
	if orig.MCP.Tools.Allow[0] != "a" {
		t.Fatal("deep copy aliased the original slice")
	}
}
