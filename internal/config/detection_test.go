package config

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestEncodeDetectionNode_RoundTrips encodes a DetectionConfig with overrides,
// marshals it under a `detection:` key, and parses it back through the full loader —
// asserting the write direction (EncodeDetectionNode) is the faithful inverse of
// the read direction (parseDetection), including durations and per-detector toggles.
func TestEncodeDetectionNode_RoundTrips(t *testing.T) {
	tick := 30 * time.Second
	win := 10 * time.Minute
	minSamples := 42
	orig := DetectionConfig{Enabled: true, MaxKeys: 256, TickInterval: &tick}
	orig.ErrorRate.Enabled = boolp(false)
	orig.ResponseTime.Window = &win
	orig.ResponseTime.MinSamples = &minSamples

	node, err := EncodeDetectionNode(orig)
	if err != nil {
		t.Fatalf("EncodeDetectionNode: %v", err)
	}
	blk, err := yaml.Marshal(map[string]yaml.Node{"detection": node})
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	p, err := parse([]byte(baseAllow + "\n" + string(blk)))
	if err != nil {
		t.Fatalf("parse round-tripped config: %v\n%s", err, blk)
	}
	got := p.policy.Detection
	if !got.Enabled || got.MaxKeys != 256 {
		t.Errorf("scalars lost: enabled=%v maxKeys=%d", got.Enabled, got.MaxKeys)
	}
	if got.TickInterval == nil || *got.TickInterval != tick {
		t.Errorf("tickInterval lost: %v", got.TickInterval)
	}
	if got.ErrorRate.Enabled == nil || *got.ErrorRate.Enabled {
		t.Errorf("errorRate.enabled override lost: %v", got.ErrorRate.Enabled)
	}
	if got.ResponseTime.Window == nil || *got.ResponseTime.Window != win {
		t.Errorf("responseTime.window lost: %v", got.ResponseTime.Window)
	}
	if got.ResponseTime.MinSamples == nil || *got.ResponseTime.MinSamples != minSamples {
		t.Errorf("responseTime.minSamples lost: %v", got.ResponseTime.MinSamples)
	}
	// A detector with NO overrides must be omitted from the encoded block (minimal).
	if strings.Contains(string(blk), "costAnomaly") {
		t.Errorf("unset costAnomaly should be omitted from encoded block:\n%s", blk)
	}
}

func boolp(b bool) *bool { return &b }

// TestParseDetection_DefaultsOn asserts that a config with NO detection block
// leaves detection ON with all overrides unset (⇒ the engine keeps its own
// defaults). This is the back-compat default: omitting the block = detection on.
func TestParseDetection_DefaultsOn(t *testing.T) {
	p, err := parse([]byte(baseAllow))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := p.policy.Detection
	if !d.Enabled {
		t.Fatal("detection should default ON when the block is omitted")
	}
	if d.TickInterval != nil {
		t.Errorf("TickInterval override should be nil by default, got %v", *d.TickInterval)
	}
	if d.ErrorRate.Enabled != nil || d.AuthFailBurst.CountThreshold != nil {
		t.Error("per-detector overrides should be nil (engine defaults) by default")
	}
}

// TestParseDetection_Full asserts a fully-specified detection block parses into
// the expected typed overrides (enabled, tick, and per-detector thresholds).
func TestParseDetection_Full(t *testing.T) {
	yaml := baseAllow + `
detection:
  enabled: true
  tickInterval: 10s
  maxKeys: 512
  errorRate:
    enabled: true
    window: 2m
    minSamples: 30
    rateThreshold: 0.2
  authFailBurst:
    window: 3m
    countThreshold: 15
  costAnomaly:
    budgetUSD: 100
  responseTime:
    enabled: false
    floorMs: 500
    degradeFactor: 4
`
	p, err := parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := p.policy.Detection
	if !d.Enabled {
		t.Fatal("detection.enabled should be true")
	}
	if d.TickInterval == nil || *d.TickInterval != 10*time.Second {
		t.Errorf("TickInterval = %v, want 10s", d.TickInterval)
	}
	if d.MaxKeys != 512 {
		t.Errorf("MaxKeys = %d, want 512", d.MaxKeys)
	}
	if d.ErrorRate.Window == nil || *d.ErrorRate.Window != 2*time.Minute {
		t.Errorf("errorRate.window = %v, want 2m", d.ErrorRate.Window)
	}
	if d.ErrorRate.MinSamples == nil || *d.ErrorRate.MinSamples != 30 {
		t.Errorf("errorRate.minSamples = %v, want 30", d.ErrorRate.MinSamples)
	}
	if d.ErrorRate.RateThreshold == nil || *d.ErrorRate.RateThreshold != 0.2 {
		t.Errorf("errorRate.rateThreshold = %v, want 0.2", d.ErrorRate.RateThreshold)
	}
	if d.AuthFailBurst.CountThreshold == nil || *d.AuthFailBurst.CountThreshold != 15 {
		t.Errorf("authFailBurst.countThreshold = %v, want 15", d.AuthFailBurst.CountThreshold)
	}
	if d.CostAnomaly.BudgetUSD == nil || *d.CostAnomaly.BudgetUSD != 100 {
		t.Errorf("costAnomaly.budgetUSD = %v, want 100", d.CostAnomaly.BudgetUSD)
	}
	if d.ResponseTime.Enabled == nil || *d.ResponseTime.Enabled {
		t.Errorf("responseTime.enabled = %v, want explicit false", d.ResponseTime.Enabled)
	}
}

// TestParseDetection_Disabled asserts an explicit enabled:false disables the
// engine (the converter later returns enabled=false).
func TestParseDetection_Disabled(t *testing.T) {
	p, err := parse([]byte(baseAllow + "\ndetection:\n  enabled: false\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.policy.Detection.Enabled {
		t.Fatal("detection.enabled:false should disable detection")
	}
}

// TestValidateDetection_Invalid asserts the range checks reject a negative
// threshold, a zero/negative window, a non-positive tick, and a negative maxKeys.
func TestValidateDetection_Invalid(t *testing.T) {
	cases := map[string]string{
		"negative rateThreshold":  "\ndetection:\n  errorRate:\n    rateThreshold: -0.1\n",
		"zero window":             "\ndetection:\n  authFailBurst:\n    window: 0s\n",
		"negative window":         "\ndetection:\n  errorRate:\n    window: -1m\n",
		"zero tick":               "\ndetection:\n  tickInterval: 0s\n",
		"negative maxKeys":        "\ndetection:\n  maxKeys: -5\n",
		"negative countThreshold": "\ndetection:\n  authFailBurst:\n    countThreshold: -1\n",
		"negative budget":         "\ndetection:\n  costAnomaly:\n    budgetUSD: -10\n",
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(baseAllow + block)); err == nil {
				t.Fatalf("expected a validation error for %s", name)
			}
		})
	}
}

// TestParseDetection_BadDuration asserts a malformed duration string is a parse
// error (surfaced with the field name).
func TestParseDetection_BadDuration(t *testing.T) {
	_, err := parse([]byte(baseAllow + "\ndetection:\n  tickInterval: notaduration\n"))
	if err == nil || !strings.Contains(err.Error(), "tickInterval") {
		t.Fatalf("expected a tickInterval duration error, got %v", err)
	}
}
