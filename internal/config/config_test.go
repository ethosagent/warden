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
