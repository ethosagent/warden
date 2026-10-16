package config

import (
	"strings"
	"testing"
)

func secretScopeYAML(hosts string) string {
	return `
policy:
  allowlist:
    - domain: api.github.com
secrets:
  - placeholder: github_secret_001
    envVar: GITHUB_TOKEN
    matchHosts: ` + hosts + `
`
}

func TestSecrets_MatchHostsParsed(t *testing.T) {
	prov, err := NewLocalYAMLProvider(writeTemp(t, secretScopeYAML(`["github.com", "*.githubusercontent.com", "~^api\\d+\\.x\\.com$"]`)))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := prov.GetPolicy()
	got := pol.Secrets[0].MatchHosts
	if len(got) != 3 || got[0] != "github.com" || got[1] != "*.githubusercontent.com" {
		t.Fatalf("MatchHosts = %v", got)
	}
	cp := pol.DeepCopy()
	cp.Secrets[0].MatchHosts[0] = "mutated"
	if pol.Secrets[0].MatchHosts[0] != "github.com" {
		t.Fatal("DeepCopy shares MatchHosts backing array")
	}
}

func TestSecrets_MatchHostsInvalidFailsLoad(t *testing.T) {
	for name, hosts := range map[string]string{
		"bad regex":    `["~("]`,
		"bad wildcard": `["a.*.com"]`,
		"empty":        `[""]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewLocalYAMLProvider(writeTemp(t, secretScopeYAML(hosts)))
			if err == nil || !strings.Contains(err.Error(), "secrets[0].matchHosts[0]") {
				t.Fatalf("want matchHosts validation error, got %v", err)
			}
			if name == "empty" && strings.Contains(err.Error(), "match is required") {
				t.Fatalf("empty matchHosts entry reuses the auth wording: %v", err)
			}
		})
	}
}

func TestSecrets_NoMatchHostsStillValid(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.github.com
secrets:
  - placeholder: github_secret_001
    envVar: GITHUB_TOKEN
`
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err != nil {
		t.Fatal(err)
	}
}
