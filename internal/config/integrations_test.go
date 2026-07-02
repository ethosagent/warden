package config

import (
	"strings"
	"testing"
)

// baseAllow (a minimal valid policy block) is declared in wiring_blocks_test.go
// and reused here.

func TestParse_IntegrationsBlock(t *testing.T) {
	y := baseAllow + `
integrations:
  - type: webhook
    name: sec-alerts
    config:
      url: "${WARDEN_WEBHOOK_URL}"
      nested:
        keep: true
    match:
      - severity: high
      - category: security
`
	p, err := NewLocalYAMLProvider(writeTemp(t, y))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pol, err := p.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.Integrations) != 1 {
		t.Fatalf("Integrations len = %d, want 1", len(pol.Integrations))
	}
	got := pol.Integrations[0]
	if got.Type != "webhook" || got.Name != "sec-alerts" {
		t.Fatalf("type/name = %q/%q, want webhook/sec-alerts", got.Type, got.Name)
	}
	// config is opaque and passes through untouched, including the ${ENV} string
	// (secrets are expanded later by the integration, not at parse time).
	if u, _ := got.Config["url"].(string); u != "${WARDEN_WEBHOOK_URL}" {
		t.Fatalf("config.url = %q, want the unexpanded ${ENV} string", u)
	}
	if _, ok := got.Config["nested"]; !ok {
		t.Fatal("config lost the nested opaque sub-map")
	}
	if len(got.Match) != 2 || got.Match[0].Severity != "high" || got.Match[1].Category != "security" {
		t.Fatalf("match not round-tripped: %+v", got.Match)
	}
}

func TestParse_IntegrationsAbsent(t *testing.T) {
	p, err := NewLocalYAMLProvider(writeTemp(t, baseAllow))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := p.GetPolicy()
	if pol.Integrations != nil {
		t.Fatalf("Integrations = %+v, want nil when absent", pol.Integrations)
	}
}

func TestValidate_IntegrationsErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing type",
			yaml: baseAllow + "integrations:\n  - name: a\n",
			want: "type is required",
		},
		{
			name: "missing name",
			yaml: baseAllow + "integrations:\n  - type: webhook\n",
			want: "name is required",
		},
		{
			name: "duplicate names",
			yaml: baseAllow + "integrations:\n  - type: webhook\n    name: dup\n  - type: webhook\n    name: dup\n",
			want: "duplicate name",
		},
		{
			name: "invalid match severity",
			yaml: baseAllow + "integrations:\n  - type: webhook\n    name: a\n    match:\n      - severity: catastrophic\n",
			want: "invalid severity",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewLocalYAMLProvider(writeTemp(t, tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestValidate_IntegrationsUnknownTypeAccepted asserts an unregistered type is
// NOT a parse-time failure: registration lives in the binary (a blank import),
// not in config, so the manager (not the parser) is where unknown types surface.
func TestValidate_IntegrationsUnknownTypeAccepted(t *testing.T) {
	y := baseAllow + "integrations:\n  - type: not_registered_anywhere\n    name: x\n"
	if _, err := NewLocalYAMLProvider(writeTemp(t, y)); err != nil {
		t.Fatalf("unregistered type should parse, got: %v", err)
	}
}
