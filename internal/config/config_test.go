package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const goodYAML = `
policy:
  allowlist:
    - domain: api.openai.com
    - domain: "*.internal.company.com"
      port: 8443
      rateLimit: "100/hour"
      timeWindow: "9-17"

secrets:
  - placeholder: openai_secret_001
    envVar: OPENAI_API_KEY

cache:
  ttl: 1800

logging:
  level: info
  format: json
`

const denylistYAML = `
policy:
  allowlist:
    - domain: api.openai.com
  denylist:
    - domain: evil.example.com
    - domain: "*.malware.net"
      port: 443

logging:
  level: info
  format: json
`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestNewLocalYAMLProvider_Good(t *testing.T) {
	p, err := NewLocalYAMLProvider(writeTemp(t, goodYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, err := p.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(pol.Allowlist) != 2 {
		t.Fatalf("allowlist len = %d, want 2", len(pol.Allowlist))
	}
	if pol.Allowlist[0].Domain != "api.openai.com" {
		t.Errorf("entry0 domain = %q", pol.Allowlist[0].Domain)
	}
	if pol.Allowlist[0].Port != 0 {
		t.Errorf("entry0 port = %d, want 0 (inferred later)", pol.Allowlist[0].Port)
	}
	if pol.Allowlist[1].Port != 8443 {
		t.Errorf("entry1 port = %d, want 8443", pol.Allowlist[1].Port)
	}
	// Reserved M2 fields parse but are not enforced.
	if pol.Allowlist[1].RateLimit != "100/hour" {
		t.Errorf("rateLimit = %q", pol.Allowlist[1].RateLimit)
	}
	if pol.Allowlist[1].TimeWindow != "9-17" {
		t.Errorf("timeWindow = %q", pol.Allowlist[1].TimeWindow)
	}
	if pol.CacheTTLSeconds != 1800 {
		t.Errorf("cache ttl = %d, want 1800", pol.CacheTTLSeconds)
	}
	if len(pol.Secrets) != 1 || pol.Secrets[0].Placeholder != "openai_secret_001" || pol.Secrets[0].EnvVar != "OPENAI_API_KEY" {
		t.Errorf("secrets = %+v", pol.Secrets)
	}
	if pol.LogLevel != "info" || pol.LogFormat != "json" {
		t.Errorf("logging = %q/%q", pol.LogLevel, pol.LogFormat)
	}
}

func TestNewLocalYAMLProvider_DefaultTTL(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.CacheTTLSeconds != defaultCacheTTLSeconds {
		t.Errorf("default ttl = %d, want %d", pol.CacheTTLSeconds, defaultCacheTTLSeconds)
	}
}

func TestNewLocalYAMLProvider_MissingFile(t *testing.T) {
	if _, err := NewLocalYAMLProvider(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestNewLocalYAMLProvider_Malformed(t *testing.T) {
	if _, err := NewLocalYAMLProvider(writeTemp(t, "policy: [this is: not valid")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNewLocalYAMLProvider_UnknownField(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
bogusTopLevel: true
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestValidate_Errors(t *testing.T) {
	cases := map[string]Policy{
		"empty allowlist":           {Allowlist: nil, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"missing domain":            {Allowlist: []AllowlistEntry{{Domain: ""}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"port too high":             {Allowlist: []AllowlistEntry{{Domain: "x", Port: 70000}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"port negative":             {Allowlist: []AllowlistEntry{{Domain: "x", Port: -1}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"secret no holder":          {Allowlist: []AllowlistEntry{{Domain: "x"}}, Secrets: []SecretMapping{{EnvVar: "E"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"secret no env":             {Allowlist: []AllowlistEntry{{Domain: "x"}}, Secrets: []SecretMapping{{Placeholder: "p"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"negative ttl":              {Allowlist: []AllowlistEntry{{Domain: "x"}}, CacheTTLSeconds: -5, LogLevel: "info", LogFormat: "json"},
		"domain with spaces":        {Allowlist: []AllowlistEntry{{Domain: "foo bar.com"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"domain empty after trim":   {Allowlist: []AllowlistEntry{{Domain: "  "}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard no dot prefix":    {Allowlist: []AllowlistEntry{{Domain: "*foo.com"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard mid domain":       {Allowlist: []AllowlistEntry{{Domain: "foo*.com"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard bare star":        {Allowlist: []AllowlistEntry{{Domain: "*"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard double star":      {Allowlist: []AllowlistEntry{{Domain: "**"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard dot only":         {Allowlist: []AllowlistEntry{{Domain: "*."}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"bad log level":             {Allowlist: []AllowlistEntry{{Domain: "x"}}, CacheTTLSeconds: 1, LogLevel: "verbose", LogFormat: "json"},
		"bad log format":            {Allowlist: []AllowlistEntry{{Domain: "x"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "yaml"},
		"duplicate placeholder":     {Allowlist: []AllowlistEntry{{Domain: "x"}}, Secrets: []SecretMapping{{Placeholder: "p", EnvVar: "A"}, {Placeholder: "p", EnvVar: "B"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"denylist empty domain":     {Allowlist: []AllowlistEntry{{Domain: "x"}}, Denylist: []DenylistEntry{{Domain: ""}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"denylist bad port":         {Allowlist: []AllowlistEntry{{Domain: "x"}}, Denylist: []DenylistEntry{{Domain: "evil.com", Port: 70000}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"denylist invalid wildcard": {Allowlist: []AllowlistEntry{{Domain: "x"}}, Denylist: []DenylistEntry{{Domain: "*foo.com"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"allowlist invalid regex":   {Allowlist: []AllowlistEntry{{Domain: "~([invalid"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"denylist invalid regex":    {Allowlist: []AllowlistEntry{{Domain: "x"}}, Denylist: []DenylistEntry{{Domain: "~([invalid"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"bad rate limit":            {Allowlist: []AllowlistEntry{{Domain: "x", RateLimit: "notvalid"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"bad time window":           {Allowlist: []AllowlistEntry{{Domain: "x", TimeWindow: "notvalid"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
	}
	for name, p := range cases {
		if err := validate(p); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestExampleConfigLoads(t *testing.T) {
	// The shipped example config must always be valid.
	p, err := NewLocalYAMLProvider(filepath.Join("..", "..", "configs", "config.example.yaml"))
	if err != nil {
		t.Fatalf("example config failed to load: %v", err)
	}
	pol, _ := p.GetPolicy()
	if len(pol.Allowlist) == 0 {
		t.Fatal("example config has empty allowlist")
	}
}

func TestParse_Defaults(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
`
	p, err := parse([]byte(y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.LogLevel != "info" {
		t.Errorf("default log level = %q, want %q", pol.LogLevel, "info")
	}
	if pol.LogFormat != "json" {
		t.Errorf("default log format = %q, want %q", pol.LogFormat, "json")
	}
}

func TestParse_NormalizesCase(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: API.OpenAI.COM
logging:
  level: WARN
  format: TEXT
`
	p, err := parse([]byte(y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.Allowlist[0].Domain != "api.openai.com" {
		t.Errorf("domain = %q, want lowercase", pol.Allowlist[0].Domain)
	}
	if pol.LogLevel != "warn" {
		t.Errorf("log level = %q, want %q", pol.LogLevel, "warn")
	}
	if pol.LogFormat != "text" {
		t.Errorf("log format = %q, want %q", pol.LogFormat, "text")
	}
}

func TestParse_Denylist(t *testing.T) {
	p, err := parse([]byte(denylistYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, _ := p.GetPolicy()
	if len(pol.Denylist) != 2 {
		t.Fatalf("denylist len = %d, want 2", len(pol.Denylist))
	}
	if pol.Denylist[0].Domain != "evil.example.com" {
		t.Errorf("denylist[0] domain = %q", pol.Denylist[0].Domain)
	}
	if pol.Denylist[1].Domain != "*.malware.net" {
		t.Errorf("denylist[1] domain = %q", pol.Denylist[1].Domain)
	}
	if pol.Denylist[1].Port != 443 {
		t.Errorf("denylist[1] port = %d, want 443", pol.Denylist[1].Port)
	}
}

const judgeYAML = `
policy:
  allowlist:
    - domain: api.openai.com

judge:
  enabled: true
  provider: openai
  model: gpt-4o-mini
  baseURL: https://api.openai.com/v1
  apiKeyEnv: OPENAI_API_KEY
  timeout: 7s
  circuitBreaker:
    maxFailures: 3
    cooldown: 45s
  cache:
    ttl: 2m
  rateLimit: 50/minute

agents:
  - id: default
    policy: |
      Allow reads from approved APIs only.

advisory:
  enabled: true

logging:
  level: info
  format: json
`

func TestNewLocalYAMLProvider_JudgeParsed(t *testing.T) {
	p, err := NewLocalYAMLProvider(writeTemp(t, judgeYAML))
	if err != nil {
		t.Fatalf("parse judge config: %v", err)
	}
	pol, _ := p.GetPolicy()
	j := pol.Judge
	if !j.Enabled {
		t.Fatal("judge should be enabled")
	}
	if j.Model != "gpt-4o-mini" || j.BaseURL != "https://api.openai.com/v1" || j.APIKeyEnv != "OPENAI_API_KEY" {
		t.Fatalf("judge fields mis-parsed: %+v", j)
	}
	if j.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want 7s", j.Timeout)
	}
	if j.CircuitBreaker.MaxFailures != 3 || j.CircuitBreaker.Cooldown != 45*time.Second {
		t.Errorf("circuit breaker = %+v", j.CircuitBreaker)
	}
	if j.CacheTTL != 2*time.Minute {
		t.Errorf("cache ttl = %v, want 2m", j.CacheTTL)
	}
	if j.RateLimit != "50/minute" {
		t.Errorf("rateLimit = %q", j.RateLimit)
	}
	if len(pol.Agents) != 1 || pol.Agents[0].ID != "default" {
		t.Fatalf("agents mis-parsed: %+v", pol.Agents)
	}
	if !pol.Advisory.Enabled {
		t.Error("advisory should be enabled")
	}
}

func TestNewLocalYAMLProvider_JudgeDisabledDefaults(t *testing.T) {
	// No judge block at all: zero-valued and harmless, config still valid.
	p, err := NewLocalYAMLProvider(writeTemp(t, goodYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.Judge.Enabled {
		t.Fatal("judge should default to disabled")
	}
}

func TestNewLocalYAMLProvider_JudgeAppliesDefaults(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
judge:
  enabled: true
  model: gpt-4o-mini
  baseURL: https://api.openai.com/v1
  apiKeyEnv: OPENAI_API_KEY
agents:
  - id: default
    policy: "allow reads"
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, _ := p.GetPolicy()
	j := pol.Judge
	if j.Provider != "openai" {
		t.Errorf("provider default = %q, want openai", j.Provider)
	}
	if j.Timeout != 5*time.Second || j.CacheTTL != 5*time.Minute {
		t.Errorf("defaults not applied: %+v", j)
	}
	if j.CircuitBreaker.MaxFailures != 5 || j.CircuitBreaker.Cooldown != 30*time.Second {
		t.Errorf("breaker defaults not applied: %+v", j.CircuitBreaker)
	}
}

func TestValidate_JudgeRequiresFields(t *testing.T) {
	cases := map[string]string{
		"missing model": `
policy: {allowlist: [{domain: a.com}]}
judge: {enabled: true, baseURL: https://x/v1, apiKeyEnv: K}
agents: [{id: default, policy: x}]
`,
		"missing apiKeyEnv": `
policy: {allowlist: [{domain: a.com}]}
judge: {enabled: true, model: m, baseURL: https://x/v1}
agents: [{id: default, policy: x}]
`,
		"missing baseURL": `
policy: {allowlist: [{domain: a.com}]}
judge: {enabled: true, model: m, apiKeyEnv: K}
agents: [{id: default, policy: x}]
`,
		"no agents": `
policy: {allowlist: [{domain: a.com}]}
judge: {enabled: true, model: m, baseURL: https://x/v1, apiKeyEnv: K}
`,
		"bad rateLimit": `
policy: {allowlist: [{domain: a.com}]}
judge: {enabled: true, model: m, baseURL: https://x/v1, apiKeyEnv: K, rateLimit: "abc"}
agents: [{id: default, policy: x}]
`,
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

func TestValidate_DuplicateAgentID(t *testing.T) {
	const y = `
policy: {allowlist: [{domain: a.com}]}
agents:
  - {id: dup, policy: x}
  - {id: dup, policy: y}
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err == nil {
		t.Fatal("expected duplicate agent id error")
	}
}

func TestValidate_BadJudgeDuration(t *testing.T) {
	const y = `
policy: {allowlist: [{domain: a.com}]}
judge: {enabled: false, timeout: "notaduration"}
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err == nil {
		t.Fatal("expected duration parse error")
	}
}

const mcpYAML = `
policy:
  allowlist:
    - domain: api.openai.com

mcp:
  enabled: true
  mode: enforce
  failClosedOnError: true
  maxResponseScanBytes: 2048
  tools:
    allow: [read_file, list_dir]
    deny: [delete_file]
    rateLimit:
      read_file: "10/minute"
    constraints:
      read_file:
        maxArgsBytes: 65536
        fields:
          path: { match: "^/workspace/.*", maxLen: 4096, required: true }
          recursive: { forbidden: true }
  schema:
    pin: true
  scan:
    toolArgs: false
    toolResults: false
    profileSchema: false
    pii:
      phone: true
  chain:
    enabled: false
    windowSize: 25
    patterns: [read_then_send, rapid_repeat]

logging:
  level: info
  format: json
`

func TestNewLocalYAMLProvider_MCPParsed(t *testing.T) {
	p, err := NewLocalYAMLProvider(writeTemp(t, mcpYAML))
	if err != nil {
		t.Fatalf("parse mcp config: %v", err)
	}
	pol, _ := p.GetPolicy()
	m := pol.MCP
	if !m.Enabled {
		t.Fatal("mcp should be enabled")
	}
	if m.Mode != "enforce" {
		t.Errorf("mode = %q, want enforce", m.Mode)
	}
	if !m.FailClosedOnError {
		t.Error("failClosedOnError should be true")
	}
	if m.MaxResponseScanBytes != 2048 {
		t.Errorf("maxResponseScanBytes = %d, want 2048", m.MaxResponseScanBytes)
	}
	if len(m.Tools.Allow) != 2 || m.Tools.Allow[0] != "read_file" || m.Tools.Allow[1] != "list_dir" {
		t.Errorf("tools.allow = %v", m.Tools.Allow)
	}
	if len(m.Tools.Deny) != 1 || m.Tools.Deny[0] != "delete_file" {
		t.Errorf("tools.deny = %v", m.Tools.Deny)
	}
	if m.Tools.RateLimit["read_file"] != "10/minute" {
		t.Errorf("tools.rateLimit = %v", m.Tools.RateLimit)
	}
	rfc, ok := m.Tools.Constraints["read_file"]
	if !ok {
		t.Fatalf("tools.constraints missing read_file: %v", m.Tools.Constraints)
	}
	if rfc.MaxArgsBytes != 65536 {
		t.Errorf("constraints.read_file.maxArgsBytes = %d, want 65536", rfc.MaxArgsBytes)
	}
	pathC, ok := rfc.Fields["path"]
	if !ok {
		t.Fatalf("constraints.read_file.fields missing path: %v", rfc.Fields)
	}
	if pathC.Match != "^/workspace/.*" || pathC.MaxLen != 4096 || !pathC.Required || pathC.Forbidden {
		t.Errorf("constraints path = %+v", pathC)
	}
	recC, ok := rfc.Fields["recursive"]
	if !ok {
		t.Fatalf("constraints.read_file.fields missing recursive: %v", rfc.Fields)
	}
	if !recC.Forbidden || recC.Required {
		t.Errorf("constraints recursive = %+v", recC)
	}
	if !m.Schema.Pin {
		t.Error("schema.pin should be true")
	}
	if m.Scan.ToolArgs || m.Scan.ToolResults || m.Scan.ProfileSchema {
		t.Errorf("scan flags should all be false: %+v", m.Scan)
	}
	if !m.Scan.PII.Phone {
		t.Error("scan.pii.phone should be true")
	}
	if m.Chain.Enabled {
		t.Error("chain.enabled should be false")
	}
	if m.Chain.WindowSize != 25 {
		t.Errorf("chain.windowSize = %d, want 25", m.Chain.WindowSize)
	}
	if len(m.Chain.Patterns) != 2 || m.Chain.Patterns[0] != "read_then_send" || m.Chain.Patterns[1] != "rapid_repeat" {
		t.Errorf("chain.patterns = %v", m.Chain.Patterns)
	}
}

func TestNewLocalYAMLProvider_MCPAllowWhenParsed(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: a.com
mcp:
  enabled: true
  mode: enforce
  tools:
    allow: [deploy]
    constraints:
      deploy:
        allowWhen:
          agentId: "ci-agent"
          timeWindow: "09-17"
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("parse allowWhen config: %v", err)
	}
	pol, _ := p.GetPolicy()
	tc, ok := pol.MCP.Tools.Constraints["deploy"]
	if !ok {
		t.Fatalf("constraints missing deploy: %v", pol.MCP.Tools.Constraints)
	}
	if tc.AllowWhen == nil {
		t.Fatal("deploy.allowWhen should be non-nil")
	}
	if tc.AllowWhen.AgentID != "ci-agent" {
		t.Errorf("allowWhen.agentId = %q, want ci-agent", tc.AllowWhen.AgentID)
	}
	if tc.AllowWhen.TimeWindow != "09-17" {
		t.Errorf("allowWhen.timeWindow = %q, want 09-17", tc.AllowWhen.TimeWindow)
	}
}

func TestNewLocalYAMLProvider_MCPScopesParsed(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: a.com
mcp:
  enabled: true
  mode: enforce
  tools:
    allow: [get_user, read_ticket, send_email]
  scopes:
    activeScope: triage-readonly
    outOfScope: deny
    perAgent:
      reporting-bot: triage-readonly
    list:
      - id: triage-readonly
        purpose: Read-only triage.
        tools: [get_user, read_ticket]
        constraints:
          get_user:
            fields:
              id: { match: '^[0-9]+$', required: true }
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("parse scopes config: %v", err)
	}
	pol, _ := p.GetPolicy()
	sc := pol.MCP.Scopes
	if sc == nil {
		t.Fatal("mcp.scopes should be non-nil")
	}
	if sc.ActiveScope != "triage-readonly" || sc.OutOfScope != "deny" {
		t.Fatalf("unexpected scope header: %+v", sc)
	}
	if sc.PerAgent["reporting-bot"] != "triage-readonly" {
		t.Fatalf("perAgent not parsed: %v", sc.PerAgent)
	}
	if len(sc.List) != 1 || sc.List[0].ID != "triage-readonly" {
		t.Fatalf("scope list not parsed: %+v", sc.List)
	}
	if got := sc.List[0].Tools; len(got) != 2 || got[0] != "get_user" {
		t.Fatalf("scope tools not parsed: %v", got)
	}
	if _, ok := sc.List[0].Constraints["get_user"]; !ok {
		t.Fatalf("scope constraints not parsed: %v", sc.List[0].Constraints)
	}
}

func TestValidate_MCPScopesErrors(t *testing.T) {
	cases := map[string]string{
		"unknown activeScope": `
policy: { allowlist: [ { domain: a.com } ] }
mcp:
  enabled: true
  scopes:
    activeScope: nope
    list:
      - id: real
        tools: [x]
`,
		"duplicate id": `
policy: { allowlist: [ { domain: a.com } ] }
mcp:
  enabled: true
  scopes:
    list:
      - id: dup
        tools: [x]
      - id: dup
        tools: [y]
`,
		"empty tools": `
policy: { allowlist: [ { domain: a.com } ] }
mcp:
  enabled: true
  scopes:
    list:
      - id: s
        tools: []
`,
		"bad outOfScope": `
policy: { allowlist: [ { domain: a.com } ] }
mcp:
  enabled: true
  scopes:
    outOfScope: maybe
    list:
      - id: s
        tools: [x]
`,
		"unknown perAgent scope": `
policy: { allowlist: [ { domain: a.com } ] }
mcp:
  enabled: true
  scopes:
    perAgent: { bot: ghost }
    list:
      - id: s
        tools: [x]
`,
		"bad scope constraint regex": `
policy: { allowlist: [ { domain: a.com } ] }
mcp:
  enabled: true
  scopes:
    list:
      - id: s
        tools: [x]
        constraints:
          x:
            fields:
              f: { match: '([' }
`,
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err == nil {
				t.Fatalf("expected validation error for %q", name)
			}
		})
	}
}

func TestValidate_MCPScopesDisabledSkips(t *testing.T) {
	// An invalid scope block is tolerated when mcp is disabled (enabled-only validation).
	const y = `
policy: { allowlist: [ { domain: a.com } ] }
mcp:
  enabled: false
  scopes:
    activeScope: nope
    list:
      - id: real
        tools: [x]
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err != nil {
		t.Fatalf("disabled mcp should skip scope validation: %v", err)
	}
}

func TestDeepCopy_MCPScopesIndependence(t *testing.T) {
	orig := Policy{
		MCP: MCPConfig{
			Enabled: true,
			Scopes: &MCPScopesConfig{
				ActiveScope: "s",
				PerAgent:    map[string]string{"a": "s"},
				List: []MCPScope{{
					ID:    "s",
					Tools: []string{"t1"},
					Constraints: map[string]MCPToolConstraints{
						"t1": {Fields: map[string]MCPFieldConstraint{"f": {Match: "x"}}},
					},
				}},
			},
		},
	}
	cp := orig.DeepCopy()
	// Mutate the copy; the original must not change.
	cp.MCP.Scopes.PerAgent["a"] = "other"
	cp.MCP.Scopes.List[0].Tools[0] = "mutated"
	cp.MCP.Scopes.List[0].Constraints["t1"] = MCPToolConstraints{}
	if orig.MCP.Scopes.PerAgent["a"] != "s" {
		t.Fatal("perAgent map is shared, not deep-copied")
	}
	if orig.MCP.Scopes.List[0].Tools[0] != "t1" {
		t.Fatal("scope tools slice is shared, not deep-copied")
	}
	if f := orig.MCP.Scopes.List[0].Constraints["t1"].Fields; f == nil || f["f"].Match != "x" {
		t.Fatal("scope constraints map is shared, not deep-copied")
	}
}

func TestValidate_MCPAllowWhenBadWindow(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: a.com
mcp:
  enabled: true
  tools:
    constraints:
      deploy:
        allowWhen:
          timeWindow: "9-99"
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err == nil {
		t.Fatal("expected validation error for bad allowWhen timeWindow")
	}
}

func TestValidate_MCPAllowWhenBadWindowDisabledOK(t *testing.T) {
	// Bad window is tolerated when mcp is disabled (validation is enabled-only).
	const y = `
policy:
  allowlist:
    - domain: a.com
mcp:
  enabled: false
  tools:
    constraints:
      deploy:
        allowWhen:
          timeWindow: "9-99"
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err != nil {
		t.Fatalf("disabled mcp should skip allowWhen validation: %v", err)
	}
}

func TestDeepCopy_MCPAllowWhenIndependence(t *testing.T) {
	orig := Policy{
		Allowlist: []AllowlistEntry{{Domain: "a.com"}},
		MCP: MCPConfig{
			Enabled: true,
			Tools: MCPToolsConfig{
				Constraints: map[string]MCPToolConstraints{
					"deploy": {
						AllowWhen: &MCPToolCondition{AgentID: "ci-agent", TimeWindow: "09-17"},
					},
				},
			},
		},
	}
	cp := orig.DeepCopy()
	// Mutating the copy's pointed-to condition must not touch the original.
	cp.MCP.Tools.Constraints["deploy"].AllowWhen.AgentID = "MUTATED"
	cp.MCP.Tools.Constraints["deploy"].AllowWhen.TimeWindow = "00-01"

	origAW := orig.MCP.Tools.Constraints["deploy"].AllowWhen
	if origAW == nil {
		t.Fatal("orig allowWhen became nil")
	}
	if origAW.AgentID != "ci-agent" || origAW.TimeWindow != "09-17" {
		t.Errorf("orig allowWhen mutated via copy: %+v", origAW)
	}
	if origAW == cp.MCP.Tools.Constraints["deploy"].AllowWhen {
		t.Error("orig and copy share the same allowWhen pointer")
	}
}

func TestNewLocalYAMLProvider_MCPOmittedDisabled(t *testing.T) {
	// No mcp block at all: disabled, harmless, config still valid (back-compat).
	p, err := NewLocalYAMLProvider(writeTemp(t, goodYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.MCP.Enabled {
		t.Fatal("mcp should default to disabled when omitted")
	}
}

func TestNewLocalYAMLProvider_MCPAppliesDefaults(t *testing.T) {
	// Block present but every sub-field omitted: documented defaults apply.
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
mcp:
  enabled: true
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, _ := p.GetPolicy()
	mc := m.MCP
	if mc.Mode != "monitor" {
		t.Errorf("mode default = %q, want monitor", mc.Mode)
	}
	if mc.FailClosedOnError {
		t.Error("failClosedOnError default should be false")
	}
	if mc.MaxResponseScanBytes != 1048576 {
		t.Errorf("maxResponseScanBytes default = %d, want 1048576", mc.MaxResponseScanBytes)
	}
	if !mc.Scan.ToolArgs || !mc.Scan.ToolResults || !mc.Scan.ProfileSchema {
		t.Errorf("scan defaults should all be true: %+v", mc.Scan)
	}
	if mc.Scan.PII.Phone {
		t.Error("scan.pii.phone default should be false")
	}
	if !mc.Chain.Enabled {
		t.Error("chain.enabled default should be true")
	}
	if mc.Chain.WindowSize != 50 {
		t.Errorf("chain.windowSize default = %d, want 50", mc.Chain.WindowSize)
	}
	wantPatterns := []string{"read_then_send", "permission_probing", "rapid_repeat"}
	if len(mc.Chain.Patterns) != len(wantPatterns) {
		t.Fatalf("chain.patterns default = %v, want %v", mc.Chain.Patterns, wantPatterns)
	}
	for i, p := range wantPatterns {
		if mc.Chain.Patterns[i] != p {
			t.Errorf("chain.patterns[%d] = %q, want %q", i, mc.Chain.Patterns[i], p)
		}
	}
}

func TestValidate_MCPErrors(t *testing.T) {
	base := func(block string) string {
		return "policy:\n  allowlist:\n    - domain: a.com\n" + block
	}
	cases := map[string]string{
		"bad mode": base(`mcp:
  enabled: true
  mode: bogus
`),
		"zero window": base(`mcp:
  enabled: true
  chain:
    windowSize: 0
`),
		"unknown pattern": base(`mcp:
  enabled: true
  chain:
    patterns: [nope]
`),
		"bad rateLimit": base(`mcp:
  enabled: true
  tools:
    rateLimit:
      read_file: "abc"
`),
		"negative maxBytes": base(`mcp:
  enabled: true
  maxResponseScanBytes: -1
`),
		"empty allow name": base(`mcp:
  enabled: true
  tools:
    allow: [""]
`),
		"empty deny name": base(`mcp:
  enabled: true
  tools:
    deny: ["  "]
`),
		"bad constraint regex": base(`mcp:
  enabled: true
  tools:
    constraints:
      read_file:
        fields:
          path: { match: "[unclosed" }
`),
		"negative maxArgsBytes": base(`mcp:
  enabled: true
  tools:
    constraints:
      read_file:
        maxArgsBytes: -1
`),
		"negative field maxLen": base(`mcp:
  enabled: true
  tools:
    constraints:
      read_file:
        fields:
          path: { maxLen: -1 }
`),
		"required and forbidden": base(`mcp:
  enabled: true
  tools:
    constraints:
      read_file:
        fields:
          path: { required: true, forbidden: true }
`),
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

func TestValidate_MCPDisabledSkipsValidation(t *testing.T) {
	// An invalid mode is tolerated when mcp is disabled (validation only fires
	// when enabled), so configs that omit/disable mcp never break.
	const y = `
policy:
  allowlist:
    - domain: a.com
mcp:
  enabled: false
  mode: bogus
  chain:
    windowSize: 0
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err != nil {
		t.Fatalf("disabled mcp should skip validation: %v", err)
	}
}

func TestDeepCopy_MCPIndependence(t *testing.T) {
	orig := Policy{
		Allowlist: []AllowlistEntry{{Domain: "a.com"}},
		MCP: MCPConfig{
			Enabled: true,
			Tools: MCPToolsConfig{
				Allow:     []string{"read_file"},
				Deny:      []string{"delete_file"},
				RateLimit: map[string]string{"read_file": "10/minute"},
				Constraints: map[string]MCPToolConstraints{
					"read_file": {
						MaxArgsBytes: 100,
						Fields: map[string]MCPFieldConstraint{
							"path": {Match: "^/workspace/", Required: true},
						},
					},
				},
			},
			Chain: MCPChainConfig{Patterns: []string{"rapid_repeat"}},
		},
	}
	cp := orig.DeepCopy()
	cp.MCP.Tools.Allow[0] = "MUTATED"
	cp.MCP.Tools.Deny[0] = "MUTATED"
	cp.MCP.Tools.RateLimit["read_file"] = "999/hour"
	cp.MCP.Tools.RateLimit["new"] = "1/second"
	cp.MCP.Chain.Patterns[0] = "MUTATED"
	cp.MCP.Tools.Constraints["read_file"].Fields["path"] = MCPFieldConstraint{Match: "MUTATED"}
	cp.MCP.Tools.Constraints["new_tool"] = MCPToolConstraints{}

	if orig.MCP.Tools.Allow[0] != "read_file" {
		t.Errorf("orig allow mutated: %v", orig.MCP.Tools.Allow)
	}
	if orig.MCP.Tools.Deny[0] != "delete_file" {
		t.Errorf("orig deny mutated: %v", orig.MCP.Tools.Deny)
	}
	if orig.MCP.Tools.RateLimit["read_file"] != "10/minute" {
		t.Errorf("orig rateLimit value mutated: %v", orig.MCP.Tools.RateLimit)
	}
	if _, exists := orig.MCP.Tools.RateLimit["new"]; exists {
		t.Errorf("orig rateLimit gained key from copy: %v", orig.MCP.Tools.RateLimit)
	}
	if orig.MCP.Chain.Patterns[0] != "rapid_repeat" {
		t.Errorf("orig chain.patterns mutated: %v", orig.MCP.Chain.Patterns)
	}
	if origPath := orig.MCP.Tools.Constraints["read_file"].Fields["path"]; origPath.Match != "^/workspace/" || !origPath.Required {
		t.Errorf("orig constraints field mutated: %+v", origPath)
	}
	if _, exists := orig.MCP.Tools.Constraints["new_tool"]; exists {
		t.Errorf("orig constraints gained key from copy: %v", orig.MCP.Tools.Constraints)
	}
}
