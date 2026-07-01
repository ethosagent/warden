package worker

import (
	"reflect"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// TestResolveObservability_PrefersDistributed verifies a managed worker boots OTel
// from the control-plane-distributed settings.Observability when present, so
// central observability config actually takes effect on (re)start.
func TestResolveObservability_PrefersDistributed(t *testing.T) {
	local := config.Policy{Observability: config.ObservabilityConfig{
		Enabled:      true,
		ServiceName:  "local",
		OTLPEndpoint: "local:4317",
	}}
	distributed := &config.SettingsWire{Observability: &config.ObservabilitySettings{
		Enabled:        true,
		ServiceName:    "central",
		MetricsEnabled: true,
		OTLPEndpoint:   "central:4317",
	}}

	got := resolveObservability(distributed, local)
	want := config.ObservabilityConfig{
		Enabled:        true,
		ServiceName:    "central",
		MetricsEnabled: true,
		OTLPEndpoint:   "central:4317",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expected distributed observability to win:\n got: %+v\nwant: %+v", got, want)
	}
}

// TestResolveObservability_FallsBackToLocal verifies that when the distributed
// settings carry no observability block (or the wire is nil — e.g. the CP was
// unreachable at boot), the worker falls back to its LOCAL pol.Observability.
func TestResolveObservability_FallsBackToLocal(t *testing.T) {
	local := config.Policy{Observability: config.ObservabilityConfig{
		Enabled:      true,
		ServiceName:  "local",
		OTLPEndpoint: "local:4317",
	}}

	// Wire present but no observability block.
	if got := resolveObservability(&config.SettingsWire{}, local); !reflect.DeepEqual(got, local.Observability) {
		t.Errorf("settings without observability should fall back to local:\n got: %+v\nwant: %+v", got, local.Observability)
	}
	// Nil wire (no settings distributed at all / CP unreachable).
	if got := resolveObservability(nil, local); !reflect.DeepEqual(got, local.Observability) {
		t.Errorf("nil settings should fall back to local:\n got: %+v\nwant: %+v", got, local.Observability)
	}
}

// TestObservabilityConfigsEqual verifies the comparison used by the long-poll to
// detect a pending-restart observability change, including the ResourceAttributes
// map.
func TestObservabilityConfigsEqual(t *testing.T) {
	base := config.ObservabilityConfig{
		Enabled:            true,
		ServiceName:        "warden",
		MetricsEnabled:     true,
		OTLPEndpoint:       "c:4317",
		ResourceAttributes: map[string]string{"k": "v"},
	}
	same := base
	same.ResourceAttributes = map[string]string{"k": "v"}
	if !observabilityConfigsEqual(base, same) {
		t.Error("expected equal configs to compare equal")
	}

	cases := []config.ObservabilityConfig{
		func() config.ObservabilityConfig { c := base; c.Enabled = false; return c }(),
		func() config.ObservabilityConfig { c := base; c.ServiceName = "other"; return c }(),
		func() config.ObservabilityConfig { c := base; c.MetricsEnabled = false; return c }(),
		func() config.ObservabilityConfig { c := base; c.OTLPEndpoint = "d:4317"; return c }(),
		func() config.ObservabilityConfig {
			c := base
			c.ResourceAttributes = map[string]string{"k": "w"}
			return c
		}(),
		func() config.ObservabilityConfig {
			c := base
			c.ResourceAttributes = map[string]string{"k": "v", "x": "y"}
			return c
		}(),
	}
	for i, c := range cases {
		if observabilityConfigsEqual(base, c) {
			t.Errorf("case %d: expected differing configs to compare unequal: %+v", i, c)
		}
	}
}
