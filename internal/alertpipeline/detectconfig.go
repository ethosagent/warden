package alertpipeline

import (
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/detect"
)

// DetectConfigFrom converts the CP-local (or, in local-only, the worker-local)
// detection config into the detect engine config, the enabled flag, and the tick
// interval. It starts from detect.DefaultConfig() and applies ONLY the operator's
// set overrides, so the numeric defaults live in exactly one place
// (internal/detect) and internal/config stays free of a detect import. It is the
// single shared converter both the control-plane cmd wiring and the worker's
// local-only pipeline use — mirroring how the pipeline itself is one embeddable
// unit both hosts construct. Returns enabled=false (and a zero config) when the
// operator disabled detection, so the host reverts to its pre-detection behavior.
func DetectConfigFrom(dc config.DetectionConfig) (detect.Config, bool, time.Duration) {
	if !dc.Enabled {
		return detect.Config{}, false, 0
	}
	cfg := detect.DefaultConfig()
	if dc.MaxKeys > 0 {
		cfg.MaxKeys = dc.MaxKeys
	}

	if v := dc.ErrorRate.Enabled; v != nil {
		cfg.ErrorRate.Enabled = *v
	}
	if v := dc.ErrorRate.Window; v != nil {
		cfg.ErrorRate.Window = *v
	}
	if v := dc.ErrorRate.MinSamples; v != nil {
		cfg.ErrorRate.MinSamples = *v
	}
	if v := dc.ErrorRate.RateThreshold; v != nil {
		cfg.ErrorRate.RateThreshold = *v
	}

	if v := dc.AuthFailBurst.Enabled; v != nil {
		cfg.AuthFailBurst.Enabled = *v
	}
	if v := dc.AuthFailBurst.Window; v != nil {
		cfg.AuthFailBurst.Window = *v
	}
	if v := dc.AuthFailBurst.CountThreshold; v != nil {
		cfg.AuthFailBurst.CountThreshold = *v
	}

	if v := dc.CostAnomaly.Enabled; v != nil {
		cfg.CostAnomaly.Enabled = *v
	}
	if v := dc.CostAnomaly.Window; v != nil {
		cfg.CostAnomaly.Window = *v
	}
	if v := dc.CostAnomaly.BudgetUSD; v != nil {
		cfg.CostAnomaly.BudgetUSD = *v
	}

	if v := dc.ResponseTime.Enabled; v != nil {
		cfg.ResponseTime.Enabled = *v
	}
	if v := dc.ResponseTime.Window; v != nil {
		cfg.ResponseTime.Window = *v
	}
	if v := dc.ResponseTime.MinSamples; v != nil {
		cfg.ResponseTime.MinSamples = *v
	}
	if v := dc.ResponseTime.FloorMs; v != nil {
		cfg.ResponseTime.FloorMs = *v
	}
	if v := dc.ResponseTime.DegradeFactor; v != nil {
		cfg.ResponseTime.DegradeFactor = *v
	}
	if v := dc.ResponseTime.BaselineAlpha; v != nil {
		cfg.ResponseTime.BaselineAlpha = *v
	}

	tick := DefaultDetectionTick
	if dc.TickInterval != nil {
		tick = *dc.TickInterval
	}
	return cfg, true, tick
}
