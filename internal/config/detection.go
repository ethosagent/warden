package config

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DetectionConfig is the control-plane-local temporal-detection configuration.
// It is consumed by the control plane ONLY (Policy tags it json:"-", so it is
// never projected onto the worker-served policy wire).
//
// Cycle-avoidance (deliberate): this package does NOT import internal/detect
// (which imports internal/integration). Instead DetectionConfig carries operator
// OVERRIDES as pointers — a nil field means "use the engine default" — and the
// thin cmd layer converts it to a detect.Config by starting from
// detect.DefaultConfig() and applying only the fields the operator set. So the
// numeric defaults live in exactly ONE place (internal/detect) and never drift,
// while internal/config stays free of a detect dependency (mirroring how the
// integrations InstanceConfig mapping lives in cmd, not here).
type DetectionConfig struct {
	// Enabled turns temporal detection on. Defaults to TRUE: an absent detection
	// block = detection ON with engine defaults.
	Enabled bool
	// TickInterval is how often the engine is evaluated and findings published.
	// nil => wiring default; when set it must be > 0.
	TickInterval *time.Duration
	// MaxKeys caps the number of distinct keys each detector tracks. 0 => engine
	// default; must be >= 0.
	MaxKeys int

	ErrorRate     DetectErrorRateConfig
	AuthFailBurst DetectAuthFailBurstConfig
	CostAnomaly   DetectCostAnomalyConfig
	ResponseTime  DetectResponseTimeConfig
}

// DetectErrorRateConfig mirrors detect.ErrorRateConfig as pointer overrides.
type DetectErrorRateConfig struct {
	Enabled       *bool
	Window        *time.Duration
	MinSamples    *int
	RateThreshold *float64
}

// DetectAuthFailBurstConfig mirrors detect.AuthFailBurstConfig as overrides.
type DetectAuthFailBurstConfig struct {
	Enabled        *bool
	Window         *time.Duration
	CountThreshold *int
}

// DetectCostAnomalyConfig mirrors detect.CostAnomalyConfig as overrides.
type DetectCostAnomalyConfig struct {
	Enabled   *bool
	Window    *time.Duration
	BudgetUSD *float64
}

// DetectResponseTimeConfig mirrors detect.ResponseTimeConfig as overrides.
type DetectResponseTimeConfig struct {
	Enabled       *bool
	Window        *time.Duration
	MinSamples    *int
	FloorMs       *float64
	DegradeFactor *float64
	BaselineAlpha *float64
}

// rawDetection mirrors the on-disk `detection:` block. Pointer so an absent
// block is distinct from an explicit (disabled) block. KnownFields(true) is
// strict, so this MUST be registered in rawConfig or configs carrying the block
// fail to parse.
//
// The `omitempty` tags matter for the write direction (EncodeDetectionNode): a nil
// override / empty duration / zero maxKeys is omitted so the persisted `detection:`
// block stays minimal and unset fields keep their engine defaults. omitempty is a
// marshal-only concern; the strict KnownFields(true) read path is unaffected.
type rawDetection struct {
	Enabled      *bool  `yaml:"enabled,omitempty"`
	TickInterval string `yaml:"tickInterval,omitempty"`
	MaxKeys      int    `yaml:"maxKeys,omitempty"`

	ErrorRate     *rawDetectErrorRate     `yaml:"errorRate,omitempty"`
	AuthFailBurst *rawDetectAuthFailBurst `yaml:"authFailBurst,omitempty"`
	CostAnomaly   *rawDetectCostAnomaly   `yaml:"costAnomaly,omitempty"`
	ResponseTime  *rawDetectResponseTime  `yaml:"responseTime,omitempty"`
}

type rawDetectErrorRate struct {
	Enabled       *bool    `yaml:"enabled,omitempty"`
	Window        string   `yaml:"window,omitempty"`
	MinSamples    *int     `yaml:"minSamples,omitempty"`
	RateThreshold *float64 `yaml:"rateThreshold,omitempty"`
}

type rawDetectAuthFailBurst struct {
	Enabled        *bool  `yaml:"enabled,omitempty"`
	Window         string `yaml:"window,omitempty"`
	CountThreshold *int   `yaml:"countThreshold,omitempty"`
}

type rawDetectCostAnomaly struct {
	Enabled   *bool    `yaml:"enabled,omitempty"`
	Window    string   `yaml:"window,omitempty"`
	BudgetUSD *float64 `yaml:"budgetUSD,omitempty"`
}

type rawDetectResponseTime struct {
	Enabled       *bool    `yaml:"enabled,omitempty"`
	Window        string   `yaml:"window,omitempty"`
	MinSamples    *int     `yaml:"minSamples,omitempty"`
	FloorMs       *float64 `yaml:"floorMs,omitempty"`
	DegradeFactor *float64 `yaml:"degradeFactor,omitempty"`
	BaselineAlpha *float64 `yaml:"baselineAlpha,omitempty"`
}

// parseDetection converts the raw detection block into a typed config. An absent
// block yields detection ON with all overrides nil (⇒ engine defaults). Duration
// strings ("5m", "1h", "20s") are parsed here; numeric ranges are checked in
// validateDetection.
func parseDetection(r *rawDetection) (DetectionConfig, error) {
	if r == nil {
		return DetectionConfig{Enabled: true}, nil
	}
	dc := DetectionConfig{Enabled: true, MaxKeys: r.MaxKeys}
	if r.Enabled != nil {
		dc.Enabled = *r.Enabled
	}
	if err := parseOptionalDuration("detection.tickInterval", r.TickInterval, &dc.TickInterval); err != nil {
		return DetectionConfig{}, err
	}
	if r.ErrorRate != nil {
		dc.ErrorRate.Enabled = r.ErrorRate.Enabled
		dc.ErrorRate.MinSamples = r.ErrorRate.MinSamples
		dc.ErrorRate.RateThreshold = r.ErrorRate.RateThreshold
		if err := parseOptionalDuration("detection.errorRate.window", r.ErrorRate.Window, &dc.ErrorRate.Window); err != nil {
			return DetectionConfig{}, err
		}
	}
	if r.AuthFailBurst != nil {
		dc.AuthFailBurst.Enabled = r.AuthFailBurst.Enabled
		dc.AuthFailBurst.CountThreshold = r.AuthFailBurst.CountThreshold
		if err := parseOptionalDuration("detection.authFailBurst.window", r.AuthFailBurst.Window, &dc.AuthFailBurst.Window); err != nil {
			return DetectionConfig{}, err
		}
	}
	if r.CostAnomaly != nil {
		dc.CostAnomaly.Enabled = r.CostAnomaly.Enabled
		dc.CostAnomaly.BudgetUSD = r.CostAnomaly.BudgetUSD
		if err := parseOptionalDuration("detection.costAnomaly.window", r.CostAnomaly.Window, &dc.CostAnomaly.Window); err != nil {
			return DetectionConfig{}, err
		}
	}
	if r.ResponseTime != nil {
		dc.ResponseTime.Enabled = r.ResponseTime.Enabled
		dc.ResponseTime.MinSamples = r.ResponseTime.MinSamples
		dc.ResponseTime.FloorMs = r.ResponseTime.FloorMs
		dc.ResponseTime.DegradeFactor = r.ResponseTime.DegradeFactor
		dc.ResponseTime.BaselineAlpha = r.ResponseTime.BaselineAlpha
		if err := parseOptionalDuration("detection.responseTime.window", r.ResponseTime.Window, &dc.ResponseTime.Window); err != nil {
			return DetectionConfig{}, err
		}
	}
	return dc, nil
}

// parseOptionalDuration parses a Go duration string into *dst when non-empty,
// leaving dst nil (⇒ engine default) when the field is absent.
func parseOptionalDuration(name, raw string, dst **time.Duration) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("config: %s %q is not a valid duration: %w", name, raw, err)
	}
	*dst = &d
	return nil
}

// EncodeDetectionNode encodes a typed DetectionConfig into a yaml.Node matching
// the on-disk `detection:` block — the write-direction counterpart of
// parseDetection and the detection analogue of EncodeIntegrationsNode. It
// round-trips through rawDetection so the YAML tags stay in lockstep with the read
// path (a single source of tag truth). Durations are rendered as Go-duration
// strings; nil overrides are omitted (via the raw struct's omitempty) so the
// persisted block stays minimal and unset fields keep their engine defaults. The
// master `enabled` is ALWAYS written (false is meaningful — it disables detection).
func EncodeDetectionNode(dc DetectionConfig) (yaml.Node, error) {
	enabled := dc.Enabled
	raw := rawDetection{
		Enabled:      &enabled,
		TickInterval: durOverride(dc.TickInterval),
		MaxKeys:      dc.MaxKeys,
	}
	if er := dc.ErrorRate; er.Enabled != nil || er.Window != nil || er.MinSamples != nil || er.RateThreshold != nil {
		raw.ErrorRate = &rawDetectErrorRate{
			Enabled:       er.Enabled,
			Window:        durOverride(er.Window),
			MinSamples:    er.MinSamples,
			RateThreshold: er.RateThreshold,
		}
	}
	if afb := dc.AuthFailBurst; afb.Enabled != nil || afb.Window != nil || afb.CountThreshold != nil {
		raw.AuthFailBurst = &rawDetectAuthFailBurst{
			Enabled:        afb.Enabled,
			Window:         durOverride(afb.Window),
			CountThreshold: afb.CountThreshold,
		}
	}
	if ca := dc.CostAnomaly; ca.Enabled != nil || ca.Window != nil || ca.BudgetUSD != nil {
		raw.CostAnomaly = &rawDetectCostAnomaly{
			Enabled:   ca.Enabled,
			Window:    durOverride(ca.Window),
			BudgetUSD: ca.BudgetUSD,
		}
	}
	if rt := dc.ResponseTime; rt.Enabled != nil || rt.Window != nil || rt.MinSamples != nil || rt.FloorMs != nil || rt.DegradeFactor != nil || rt.BaselineAlpha != nil {
		raw.ResponseTime = &rawDetectResponseTime{
			Enabled:       rt.Enabled,
			Window:        durOverride(rt.Window),
			MinSamples:    rt.MinSamples,
			FloorMs:       rt.FloorMs,
			DegradeFactor: rt.DegradeFactor,
			BaselineAlpha: rt.BaselineAlpha,
		}
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return yaml.Node{}, fmt.Errorf("config: encode detection: %w", err)
	}
	return node, nil
}

// durOverride renders an optional duration override as a Go-duration string, or
// "" when unset (⇒ omitted by omitempty / engine default).
func durOverride(d *time.Duration) string {
	if d == nil {
		return ""
	}
	return d.String()
}

// validateDetection enforces the detection block's invariants: thresholds must
// be >= 0, any explicitly-set window and tick interval must be > 0, and maxKeys
// must not be negative. Unset (nil) overrides are always valid — they fall back
// to the engine's own validated defaults.
func validateDetection(dc DetectionConfig) error {
	if dc.MaxKeys < 0 {
		return fmt.Errorf("config: detection.maxKeys must not be negative")
	}
	if dc.TickInterval != nil && *dc.TickInterval <= 0 {
		return fmt.Errorf("config: detection.tickInterval must be > 0")
	}

	if err := checkPositiveWindow("detection.errorRate.window", dc.ErrorRate.Window); err != nil {
		return err
	}
	if err := checkNonNegativeInt("detection.errorRate.minSamples", dc.ErrorRate.MinSamples); err != nil {
		return err
	}
	if err := checkNonNegativeFloat("detection.errorRate.rateThreshold", dc.ErrorRate.RateThreshold); err != nil {
		return err
	}

	if err := checkPositiveWindow("detection.authFailBurst.window", dc.AuthFailBurst.Window); err != nil {
		return err
	}
	if err := checkNonNegativeInt("detection.authFailBurst.countThreshold", dc.AuthFailBurst.CountThreshold); err != nil {
		return err
	}

	if err := checkPositiveWindow("detection.costAnomaly.window", dc.CostAnomaly.Window); err != nil {
		return err
	}
	if err := checkNonNegativeFloat("detection.costAnomaly.budgetUSD", dc.CostAnomaly.BudgetUSD); err != nil {
		return err
	}

	if err := checkPositiveWindow("detection.responseTime.window", dc.ResponseTime.Window); err != nil {
		return err
	}
	if err := checkNonNegativeInt("detection.responseTime.minSamples", dc.ResponseTime.MinSamples); err != nil {
		return err
	}
	if err := checkNonNegativeFloat("detection.responseTime.floorMs", dc.ResponseTime.FloorMs); err != nil {
		return err
	}
	if err := checkNonNegativeFloat("detection.responseTime.degradeFactor", dc.ResponseTime.DegradeFactor); err != nil {
		return err
	}
	if err := checkNonNegativeFloat("detection.responseTime.baselineAlpha", dc.ResponseTime.BaselineAlpha); err != nil {
		return err
	}
	return nil
}

func checkPositiveWindow(name string, w *time.Duration) error {
	if w != nil && *w <= 0 {
		return fmt.Errorf("config: %s must be > 0", name)
	}
	return nil
}

func checkNonNegativeInt(name string, v *int) error {
	if v != nil && *v < 0 {
		return fmt.Errorf("config: %s must not be negative", name)
	}
	return nil
}

func checkNonNegativeFloat(name string, v *float64) error {
	if v != nil && *v < 0 {
		return fmt.Errorf("config: %s must not be negative", name)
	}
	return nil
}
