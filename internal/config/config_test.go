package config

import (
	"os"
	"path/filepath"
	"testing"
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
		"empty allowlist":         {Allowlist: nil, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"missing domain":          {Allowlist: []AllowlistEntry{{Domain: ""}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"port too high":           {Allowlist: []AllowlistEntry{{Domain: "x", Port: 70000}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"port negative":           {Allowlist: []AllowlistEntry{{Domain: "x", Port: -1}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"secret no holder":        {Allowlist: []AllowlistEntry{{Domain: "x"}}, Secrets: []SecretMapping{{EnvVar: "E"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"secret no env":           {Allowlist: []AllowlistEntry{{Domain: "x"}}, Secrets: []SecretMapping{{Placeholder: "p"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"negative ttl":            {Allowlist: []AllowlistEntry{{Domain: "x"}}, CacheTTLSeconds: -5, LogLevel: "info", LogFormat: "json"},
		"domain with spaces":      {Allowlist: []AllowlistEntry{{Domain: "foo bar.com"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"domain empty after trim": {Allowlist: []AllowlistEntry{{Domain: "  "}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard no dot prefix":  {Allowlist: []AllowlistEntry{{Domain: "*foo.com"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard mid domain":     {Allowlist: []AllowlistEntry{{Domain: "foo*.com"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard bare star":      {Allowlist: []AllowlistEntry{{Domain: "*"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard double star":    {Allowlist: []AllowlistEntry{{Domain: "**"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"wildcard dot only":       {Allowlist: []AllowlistEntry{{Domain: "*."}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
		"bad log level":           {Allowlist: []AllowlistEntry{{Domain: "x"}}, CacheTTLSeconds: 1, LogLevel: "verbose", LogFormat: "json"},
		"bad log format":          {Allowlist: []AllowlistEntry{{Domain: "x"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "yaml"},
		"duplicate placeholder":   {Allowlist: []AllowlistEntry{{Domain: "x"}}, Secrets: []SecretMapping{{Placeholder: "p", EnvVar: "A"}, {Placeholder: "p", EnvVar: "B"}}, CacheTTLSeconds: 1, LogLevel: "info", LogFormat: "json"},
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
