package config

import (
	"fmt"
	"regexp"
	"strings"
)

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
	// Scopes, when non-nil, layers purpose-bound (task-scoped) authorization on top
	// of the Tools policy: an active scope narrows the permitted tool-set + bundles
	// per-tool arg constraints. nil = no scoping (unchanged behavior). LOCAL config.
	Scopes *MCPScopesConfig
	// Servers declares per-server binary-integrity material for the `warden mcp`
	// wedge: an operator pins the expected SHA-256 and/or Ed25519 signature of each
	// MCP server binary, and the wedge refuses to launch a mismatched binary.
	// Empty = no server-integrity pinning (unchanged behavior). LOCAL config.
	Servers []MCPServerConfig
}

// MCPServerConfig pins the integrity of one named MCP server binary for the
// `warden mcp` wedge. Name identifies the server (matched against the resolved
// server command / --server flag). The integrity fields are all hex-encoded and
// optional; when set the wedge verifies them before launch and refuses to start
// on any mismatch. A signature requires a public key (checked in validation).
type MCPServerConfig struct {
	// Name is the server identifier, matched against the wedge's --server flag.
	Name string
	// SHA256 pins the server binary's SHA-256 (hex, case-insensitive). Empty skips.
	SHA256 string
	// Ed25519PublicKey is the 32-byte Ed25519 public key (hex) used to verify the
	// binary's signature. Empty skips the signature check.
	Ed25519PublicKey string
	// Ed25519Signature is the 64-byte detached signature (hex) over the binary's
	// raw bytes. Requires Ed25519PublicKey. Empty skips the signature check.
	Ed25519Signature string
}

// MCPScopesConfig configures task-scoped authorization: approve a purpose once,
// then the gateway enforces its allowed tool-set (and bundled constraints) on
// every tools/call with no re-prompting. Scopes only NARROW the Tools policy —
// a tool must already be allowed before its scope membership is consulted, and
// scoping can never re-permit a tool the base policy or a restriction denied.
type MCPScopesConfig struct {
	// ActiveScope is the scope id enforced fleet-wide unless a PerAgent entry
	// overrides it. Empty = no global scope (only PerAgent-selected agents scoped).
	ActiveScope string
	// OutOfScope is the fallback for a call whose tool is not in the active scope:
	// "deny" (default, fail-closed) or "escalate". Escalate routes to a human
	// approval channel — DEFERRED; with none configured it degrades to deny, so the
	// absence of an approval mechanism can never widen access.
	OutOfScope string
	// PerAgent optionally selects the active scope id per agent id, overriding
	// ActiveScope for that agent. Keyed by agent id.
	PerAgent map[string]string
	// List holds every defined scope. Referenced by ActiveScope / PerAgent by id.
	List []MCPScope
}

// MCPScope is one approve-once purpose: a natural-language intent bound to an
// allowed tool-set and (optionally) per-tool argument constraints reusing the
// exact Phase-3a constraint shape.
type MCPScope struct {
	// ID is the unique scope identifier referenced by ActiveScope / PerAgent.
	ID string
	// Purpose is the human-readable intent this scope authorizes (documentation +
	// future LLM intent verification; not evaluated by the deterministic tiers).
	Purpose string
	// Tools is the set of tool names permitted while this scope is active.
	Tools []string
	// Constraints optionally bounds in-scope tool arguments, keyed by tool name,
	// reusing the Tools.Constraints shape (fed to the same evaluator).
	Constraints map[string]MCPToolConstraints
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
	// Evidence captures a MASKED sample (last-4 + length, never the raw value)
	// per sensitivity detection, so an operator can judge a real leak from a
	// false positive. Default false. This is LOCAL config (not distributed).
	Evidence bool
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

// rawMCP mirrors the on-disk `mcp:` block. Pointer so an absent block is
// distinct from an explicit (disabled) one. Sub-blocks are pointers where
// "absent vs zero" matters for default application (mirrors rawJudge/rawObservability).
// KnownFields(true) is strict, so this MUST be registered or configs with the
// block fail to parse.
type rawMCP struct {
	Enabled              bool           `yaml:"enabled"`
	Mode                 string         `yaml:"mode"`
	FailClosedOnError    bool           `yaml:"failClosedOnError"`
	MaxResponseScanBytes *int           `yaml:"maxResponseScanBytes"`
	Tools                *rawMCPTools   `yaml:"tools"`
	Schema               *rawMCPSchema  `yaml:"schema"`
	Scan                 *rawMCPScan    `yaml:"scan"`
	Chain                *rawMCPChain   `yaml:"chain"`
	Scopes               *rawMCPScopes  `yaml:"scopes"`
	Servers              []rawMCPServer `yaml:"servers"`
}

type rawMCPServer struct {
	Name             string `yaml:"name"`
	SHA256           string `yaml:"sha256"`
	Ed25519PublicKey string `yaml:"ed25519PublicKey"`
	Ed25519Signature string `yaml:"ed25519Signature"`
}

type rawMCPTools struct {
	Allow       []string                        `yaml:"allow"`
	Deny        []string                        `yaml:"deny"`
	RateLimit   map[string]string               `yaml:"rateLimit"`
	Constraints map[string]rawMCPToolConstraint `yaml:"constraints"`
}

type rawMCPScopes struct {
	ActiveScope string            `yaml:"activeScope"`
	OutOfScope  string            `yaml:"outOfScope"`
	PerAgent    map[string]string `yaml:"perAgent"`
	List        []rawMCPScope     `yaml:"list"`
}

type rawMCPScope struct {
	ID          string                          `yaml:"id"`
	Purpose     string                          `yaml:"purpose"`
	Tools       []string                        `yaml:"tools"`
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
	Evidence      bool           `yaml:"evidence"`
}

type rawMCPScanPII struct {
	Phone bool `yaml:"phone"`
}

type rawMCPChain struct {
	Enabled    *bool    `yaml:"enabled"`
	WindowSize *int     `yaml:"windowSize"`
	Patterns   []string `yaml:"patterns"`
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
		mc.Tools.Constraints = parseToolConstraints(r.Tools.Constraints)
	}
	if r.Scopes != nil {
		sc := &MCPScopesConfig{
			ActiveScope: r.Scopes.ActiveScope,
			OutOfScope:  strings.ToLower(strings.TrimSpace(r.Scopes.OutOfScope)),
		}
		if r.Scopes.PerAgent != nil {
			sc.PerAgent = make(map[string]string, len(r.Scopes.PerAgent))
			for k, v := range r.Scopes.PerAgent {
				sc.PerAgent[k] = v
			}
		}
		for _, rs := range r.Scopes.List {
			sc.List = append(sc.List, MCPScope{
				ID:          rs.ID,
				Purpose:     rs.Purpose,
				Tools:       append([]string(nil), rs.Tools...),
				Constraints: parseToolConstraints(rs.Constraints),
			})
		}
		mc.Scopes = sc
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
		mc.Scan.Evidence = r.Scan.Evidence
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
	for _, rs := range r.Servers {
		mc.Servers = append(mc.Servers, MCPServerConfig{
			Name:             strings.TrimSpace(rs.Name),
			SHA256:           strings.TrimSpace(rs.SHA256),
			Ed25519PublicKey: strings.TrimSpace(rs.Ed25519PublicKey),
			Ed25519Signature: strings.TrimSpace(rs.Ed25519Signature),
		})
	}
	return mc
}

// parseToolConstraints converts the raw per-tool constraint map into the typed
// form. Shared by the Tools policy and each task scope so the constraint shape is
// parsed identically in both places. Returns nil for an empty/absent map.
func parseToolConstraints(raw map[string]rawMCPToolConstraint) map[string]MCPToolConstraints {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]MCPToolConstraints, len(raw))
	for tool, rc := range raw {
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
		out[tool] = tc
	}
	return out
}

// cloneToolConstraints deep-copies a per-tool constraint map (maps + the
// AllowWhen pointer). Shared by Policy.Clone for the Tools policy and each task
// scope. Returns nil for an empty/absent map.
func cloneToolConstraints(in map[string]MCPToolConstraints) map[string]MCPToolConstraints {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]MCPToolConstraints, len(in))
	for tool, tc := range in {
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
		out[tool] = ctc
	}
	return out
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
	if err := validateToolConstraints("mcp.tools.constraints", m.Tools.Constraints); err != nil {
		return err
	}
	if err := validateScopes(m.Scopes); err != nil {
		return err
	}
	if err := validateMCPServers(m.Servers); err != nil {
		return err
	}
	return nil
}

// validateMCPServers checks the per-server integrity block: each entry needs a
// unique non-empty name, and an Ed25519 signature requires a matching public key
// (a signature without a key can never verify, so it is rejected up front rather
// than failing closed only at launch).
func validateMCPServers(servers []MCPServerConfig) error {
	seen := make(map[string]struct{}, len(servers))
	for i, s := range servers {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("config: mcp.servers[%d]: name must not be empty", i)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("config: mcp.servers[%d]: duplicate server name %q", i, s.Name)
		}
		seen[s.Name] = struct{}{}
		if s.Ed25519Signature != "" && s.Ed25519PublicKey == "" {
			return fmt.Errorf("config: mcp.servers[%q]: ed25519Signature is set but ed25519PublicKey is missing", s.Name)
		}
	}
	return nil
}

// validateToolConstraints validates a per-tool constraint map (size caps,
// field constraints, AllowWhen windows, regexp compilation). Shared by the Tools
// policy and every task scope so the rules are identical. prefix names the config
// path for error messages (e.g. "mcp.tools.constraints" or
// "mcp.scopes.list[\"triage\"].constraints").
func validateToolConstraints(prefix string, cs map[string]MCPToolConstraints) error {
	for tool, tc := range cs {
		if strings.TrimSpace(tool) == "" {
			return fmt.Errorf("config: %s: tool name is required", prefix)
		}
		if tc.MaxArgsBytes < 0 {
			return fmt.Errorf("config: %s[%q].maxArgsBytes must not be negative", prefix, tool)
		}
		if tc.AllowWhen != nil && tc.AllowWhen.TimeWindow != "" {
			if err := validateTimeWindow(fmt.Sprintf("%s[%q].allowWhen", prefix, tool), tc.AllowWhen.TimeWindow); err != nil {
				return err
			}
		}
		for field, fc := range tc.Fields {
			if strings.TrimSpace(field) == "" {
				return fmt.Errorf("config: %s[%q].fields: field name is required", prefix, tool)
			}
			if fc.MaxLen < 0 {
				return fmt.Errorf("config: %s[%q].fields[%q].maxLen must not be negative", prefix, tool, field)
			}
			if fc.Required && fc.Forbidden {
				return fmt.Errorf("config: %s[%q].fields[%q]: cannot be both required and forbidden", prefix, tool, field)
			}
			if fc.Match != "" {
				if _, err := regexp.Compile(fc.Match); err != nil {
					return fmt.Errorf("config: %s[%q].fields[%q].match has invalid regex: %v", prefix, tool, field, err)
				}
			}
		}
	}
	return nil
}

// validateScopes validates the task-scope block: unique non-empty ids, a valid
// outOfScope mode, non-empty tool sets, that ActiveScope / PerAgent reference a
// defined scope, and that each scope's constraints are well-formed. A scope may
// only reference tools by name (membership is checked against the base policy at
// runtime); it does not need to list them in mcp.tools.allow here.
func validateScopes(s *MCPScopesConfig) error {
	if s == nil {
		return nil
	}
	switch s.OutOfScope {
	case "", "deny", "escalate":
	default:
		return fmt.Errorf("config: mcp.scopes.outOfScope %q is invalid; must be one of: deny, escalate", s.OutOfScope)
	}
	ids := make(map[string]struct{}, len(s.List))
	for i, sc := range s.List {
		if strings.TrimSpace(sc.ID) == "" {
			return fmt.Errorf("config: mcp.scopes.list[%d]: id is required", i)
		}
		if _, dup := ids[sc.ID]; dup {
			return fmt.Errorf("config: mcp.scopes.list: duplicate scope id %q", sc.ID)
		}
		ids[sc.ID] = struct{}{}
		if len(sc.Tools) == 0 {
			return fmt.Errorf("config: mcp.scopes.list[%q]: at least one tool is required", sc.ID)
		}
		for j, t := range sc.Tools {
			if strings.TrimSpace(t) == "" {
				return fmt.Errorf("config: mcp.scopes.list[%q].tools[%d]: tool name must not be empty", sc.ID, j)
			}
		}
		if err := validateToolConstraints(fmt.Sprintf("mcp.scopes.list[%q].constraints", sc.ID), sc.Constraints); err != nil {
			return err
		}
	}
	if s.ActiveScope != "" {
		if _, ok := ids[s.ActiveScope]; !ok {
			return fmt.Errorf("config: mcp.scopes.activeScope %q references an undefined scope", s.ActiveScope)
		}
	}
	for agent, id := range s.PerAgent {
		if _, ok := ids[id]; !ok {
			return fmt.Errorf("config: mcp.scopes.perAgent[%q] references an undefined scope %q", agent, id)
		}
	}
	return nil
}
