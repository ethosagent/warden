package alertpipeline

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/detect"
)

func hasName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// TestReloadDetection_SwapsLiveEngine covers the M3 engine hot-reload directly at
// the pipeline layer: it can DISABLE detection (nil engine), ENABLE it from off,
// and REPLACE the config so a detector drops — all observable via Detectors().
func TestReloadDetection_SwapsLiveEngine(t *testing.T) {
	store := newStore(t)
	// Start with detection OFF: no engine, but a manager (so the pipeline is live).
	p := New(Config{Store: store, Detect: false, ResolveTTL: time.Minute})
	if p.CurrentManager() == nil {
		t.Fatal("manager should build even with detection off")
	}
	if len(p.Detectors()) != 0 {
		t.Fatalf("detection off should have no detectors, got %v", p.Detectors())
	}

	// ENABLE detection from off: all four detectors come up.
	if err := p.ReloadDetection(detect.DefaultConfig(), true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if len(p.Detectors()) != 4 {
		t.Fatalf("enable should build 4 detectors, got %v", p.Detectors())
	}

	// REPLACE with a config that disables error_rate: it drops from the live engine.
	cfg := detect.DefaultConfig()
	cfg.ErrorRate.Enabled = false
	if err := p.ReloadDetection(cfg, true); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if hasName(p.Detectors(), "error_rate") {
		t.Errorf("error_rate should be dropped after reload; got %v", p.Detectors())
	}
	if !hasName(p.Detectors(), "auth_fail_burst") {
		t.Errorf("other detectors should remain; got %v", p.Detectors())
	}

	// DISABLE again: engine goes nil, Evictions degrades to 0.
	if err := p.ReloadDetection(detect.Config{}, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if len(p.Detectors()) != 0 || p.Evictions() != 0 {
		t.Errorf("disable should clear detectors + evictions; got %v / %d", p.Detectors(), p.Evictions())
	}
}

// TestPipeline_NilSafeReload proves ReloadDetection/Evictions/Detectors are safe on
// a no-store (no-manager) pipeline — the fail-open no-op path.
func TestPipeline_NilSafeReload(t *testing.T) {
	p := New(Config{Store: nil})
	if err := p.ReloadDetection(detect.DefaultConfig(), true); err != nil {
		t.Fatalf("reload on nil-store pipeline should be a safe no-op: %v", err)
	}
	if p.Evictions() != 0 || len(p.Detectors()) != 0 {
		t.Errorf("nil-store pipeline should report no detectors/evictions")
	}
}
