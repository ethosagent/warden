package config

import "testing"

const obsBaseYAML = `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: info
  format: json
`

func parsePolicy(t *testing.T, yaml string) Policy {
	t.Helper()
	p, err := parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, err := p.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return pol
}

func TestObservabilityAbsentIsDisabled(t *testing.T) {
	pol := parsePolicy(t, obsBaseYAML)
	o := pol.Observability
	if o.Enabled {
		t.Error("expected Enabled=false when block absent")
	}
	// Harmless zero values, but ServiceName is always normalized to "warden".
	if o.ServiceName != "warden" {
		t.Errorf("ServiceName = %q, want warden", o.ServiceName)
	}
	if o.OTLPEndpoint != "" || o.MetricsEnabled {
		t.Errorf("expected zero-valued metrics fields when absent, got %+v", o)
	}
}

func TestObservabilityEnabledDefaults(t *testing.T) {
	yaml := obsBaseYAML + `
observability:
  enabled: true
`
	o := parsePolicy(t, yaml).Observability
	if !o.Enabled {
		t.Fatal("expected Enabled=true")
	}
	if o.ServiceName != "warden" {
		t.Errorf("ServiceName = %q, want warden", o.ServiceName)
	}
	if !o.MetricsEnabled {
		t.Error("expected MetricsEnabled to default true when block present")
	}
}

func TestObservabilityExplicit(t *testing.T) {
	yaml := obsBaseYAML + `
observability:
  enabled: true
  serviceName: warden-prod
  metrics:
    enabled: false
    otlpEndpoint: otel-collector:4317
  resourceAttributes:
    warden.proxy.id: p1
`
	o := parsePolicy(t, yaml).Observability
	if o.ServiceName != "warden-prod" {
		t.Errorf("ServiceName = %q", o.ServiceName)
	}
	if o.MetricsEnabled {
		t.Error("expected MetricsEnabled=false from explicit config")
	}
	if o.OTLPEndpoint != "otel-collector:4317" {
		t.Errorf("OTLPEndpoint = %q", o.OTLPEndpoint)
	}
	if o.ResourceAttributes["warden.proxy.id"] != "p1" {
		t.Errorf("resourceAttributes = %v", o.ResourceAttributes)
	}
}

func TestObservabilityEnvOverride(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "env-svc")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "env-collector:4317")
	yaml := obsBaseYAML + `
observability:
  enabled: true
  serviceName: file-svc
  metrics:
    otlpEndpoint: file-collector:4317
`
	o := parsePolicy(t, yaml).Observability
	if o.ServiceName != "env-svc" {
		t.Errorf("env OTEL_SERVICE_NAME should win: got %q", o.ServiceName)
	}
	if o.OTLPEndpoint != "env-collector:4317" {
		t.Errorf("env OTEL_EXPORTER_OTLP_ENDPOINT should win: got %q", o.OTLPEndpoint)
	}
}

func TestObservabilityDeepCopyNoAlias(t *testing.T) {
	yaml := obsBaseYAML + `
observability:
  enabled: true
  resourceAttributes:
    k: v
`
	pol := parsePolicy(t, yaml)
	cp := pol.DeepCopy()
	cp.Observability.ResourceAttributes["k"] = "mutated"
	if pol.Observability.ResourceAttributes["k"] != "v" {
		t.Fatalf("DeepCopy aliased the map: original mutated to %q",
			pol.Observability.ResourceAttributes["k"])
	}
}

func TestObservabilityUnknownKeyRejected(t *testing.T) {
	yaml := obsBaseYAML + `
observability:
  enabled: true
  bogusKey: true
`
	if _, err := parse([]byte(yaml)); err == nil {
		t.Fatal("expected strict KnownFields to reject unknown observability key")
	}
}
