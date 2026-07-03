package dashboard

// dashboard_detection.go backs the Alerts → Detection panel with the CP-hosted
// (or, in local-only, worker-hosted) temporal-detection config editor. It mirrors
// the integrations editor: a GET returns the current typed config plus a read-only
// STATUS view (which detectors are actually active + the eviction counter) and an
// `editable` flag; a PUT applies a full detection document and hot-reloads the
// live engine. On a node that does not host the alert pipeline both the source and
// writer are nil, so the endpoint is read-only (GET → empty config, PUT → 405).
//
// Egress/secrecy note: detection config carries NO secrets and NO bodies — every
// field is a bounded enum/number/duration (thresholds, windows, counts). The
// status view exposes only detector NAMES and a numeric eviction count. So there is
// nothing here to redact; the endpoint is metadata-only by construction.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// --- wire types (metadata only: enums, numbers, durations — never a secret) ---

// DetectionView is the payload for GET /dashboard/api/detection: the current
// detection config, a read-only live status, and whether this dashboard can edit.
type DetectionView struct {
	Config   DetectionConfigView `json:"config"`
	Status   DetectionStatusView `json:"status"`
	Editable bool                `json:"editable"`
}

// DetectionStatusView is the read-only live engine status: the names of the
// currently-active detectors (from the engine, so it reflects what is REALLY
// running after any reload) and the total cardinality-cap eviction count.
type DetectionStatusView struct {
	Detectors []string `json:"detectors"`
	Evictions uint64   `json:"evictions"`
}

// DetectionConfigView is the JSON projection of config.DetectionConfig. It is also
// the PUT request body (the UI does read-modify-write on the config document).
// Durations are Go-duration strings ("5m", "1h", "20s"); nil overrides are omitted
// so an unset field means "engine default". Field names track config.DetectionConfig
// and the on-disk `detection:` block.
type DetectionConfigView struct {
	Enabled       bool                    `json:"enabled"`
	TickInterval  string                  `json:"tickInterval,omitempty"`
	MaxKeys       int                     `json:"maxKeys,omitempty"`
	ErrorRate     DetectErrorRateView     `json:"errorRate"`
	AuthFailBurst DetectAuthFailBurstView `json:"authFailBurst"`
	CostAnomaly   DetectCostAnomalyView   `json:"costAnomaly"`
	ResponseTime  DetectResponseTimeView  `json:"responseTime"`
}

// DetectErrorRateView projects config.DetectErrorRateConfig (pointer overrides;
// null = engine default).
type DetectErrorRateView struct {
	Enabled       *bool    `json:"enabled,omitempty"`
	Window        string   `json:"window,omitempty"`
	MinSamples    *int     `json:"minSamples,omitempty"`
	RateThreshold *float64 `json:"rateThreshold,omitempty"`
}

// DetectAuthFailBurstView projects config.DetectAuthFailBurstConfig.
type DetectAuthFailBurstView struct {
	Enabled        *bool  `json:"enabled,omitempty"`
	Window         string `json:"window,omitempty"`
	CountThreshold *int   `json:"countThreshold,omitempty"`
}

// DetectCostAnomalyView projects config.DetectCostAnomalyConfig.
type DetectCostAnomalyView struct {
	Enabled   *bool    `json:"enabled,omitempty"`
	Window    string   `json:"window,omitempty"`
	BudgetUSD *float64 `json:"budgetUSD,omitempty"`
}

// DetectResponseTimeView projects config.DetectResponseTimeConfig.
type DetectResponseTimeView struct {
	Enabled       *bool    `json:"enabled,omitempty"`
	Window        string   `json:"window,omitempty"`
	MinSamples    *int     `json:"minSamples,omitempty"`
	FloorMs       *float64 `json:"floorMs,omitempty"`
	DegradeFactor *float64 `json:"degradeFactor,omitempty"`
	BaselineAlpha *float64 `json:"baselineAlpha,omitempty"`
}

// --- setters (mirror SetIntegrationsSource/Writer) ---

// SetDetectionSource supplies the current detection config + live engine status.
// Set only where the alert pipeline is hosted; a node without it leaves this nil so
// the endpoint reports an empty, read-only config.
func (s *Server) SetDetectionSource(fn func() DetectionView) {
	s.detectionSource = fn
}

// SetDetectionWriter enables editing detection config from the dashboard. Like
// SetIntegrationsWriter it is available only where the pipeline is hosted: the
// closure persists the FULL detection document to the served/own config file and
// hot-reloads the live engine. Nodes without it leave this nil, so PUT returns 405.
func (s *Server) SetDetectionWriter(fn func(config.DetectionConfig) error) {
	s.detectionWriter = fn
}

// NewDetectionView builds a DetectionView from a typed detection config plus the
// live engine status (active detector names + eviction count). Hosts (control
// plane / worker) call it in their detection source closure so the config↔wire
// projection lives in ONE place (here) rather than being duplicated per host.
func NewDetectionView(dc config.DetectionConfig, detectors []string, evictions uint64) DetectionView {
	if detectors == nil {
		detectors = []string{}
	}
	return DetectionView{
		Config: detectionConfigView(dc),
		Status: DetectionStatusView{Detectors: detectors, Evictions: evictions},
	}
}

// --- handler ---

// handleDetection serves /dashboard/api/detection, method-routed:
//   - GET      returns the current config + live status + editable flag.
//   - PUT/POST applies a full detection document (control plane / local-only only).
//   - other    → 405.
func (s *Server) handleDetection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getDetection(w, r)
	case http.MethodPost, http.MethodPut:
		s.putDetection(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// getDetection returns the current detection config + live status. A nil source (a
// node not hosting the pipeline) yields an empty config; editable is true only
// where a detection writer is configured.
func (s *Server) getDetection(w http.ResponseWriter, _ *http.Request) {
	var v DetectionView
	if s.detectionSource != nil {
		v = s.detectionSource()
	}
	v.Editable = s.detectionWriter != nil
	if v.Status.Detectors == nil {
		v.Status.Detectors = []string{}
	}
	writeJSON(w, v)
}

// putDetection applies an edited detection document. Like putSettings it exists
// only where a writer is configured; otherwise it returns 405 so detection is never
// mutable from a read-only node. The writer validates+persists+reloads, so an
// invalid edit (bad duration here, or an out-of-range threshold in the full-loader
// validation) is rejected with the error.
func (s *Server) putDetection(w http.ResponseWriter, r *http.Request) {
	if s.detectionWriter == nil {
		writeError(w, http.StatusMethodNotAllowed, "detection editing is not available on this dashboard")
		return
	}
	var wire DetectionConfigView
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&wire); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	dc, err := wire.toConfig()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.detectionWriter(dc); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Echo back the now-current view so the UI refreshes from the authoritative
	// post-write (post-reload) state.
	s.getDetection(w, r)
}

// --- config <-> wire mapping (single home for the projection) ---

// detectionConfigView projects a typed config.DetectionConfig into its wire view.
func detectionConfigView(dc config.DetectionConfig) DetectionConfigView {
	return DetectionConfigView{
		Enabled:      dc.Enabled,
		TickInterval: durView(dc.TickInterval),
		MaxKeys:      dc.MaxKeys,
		ErrorRate: DetectErrorRateView{
			Enabled:       dc.ErrorRate.Enabled,
			Window:        durView(dc.ErrorRate.Window),
			MinSamples:    dc.ErrorRate.MinSamples,
			RateThreshold: dc.ErrorRate.RateThreshold,
		},
		AuthFailBurst: DetectAuthFailBurstView{
			Enabled:        dc.AuthFailBurst.Enabled,
			Window:         durView(dc.AuthFailBurst.Window),
			CountThreshold: dc.AuthFailBurst.CountThreshold,
		},
		CostAnomaly: DetectCostAnomalyView{
			Enabled:   dc.CostAnomaly.Enabled,
			Window:    durView(dc.CostAnomaly.Window),
			BudgetUSD: dc.CostAnomaly.BudgetUSD,
		},
		ResponseTime: DetectResponseTimeView{
			Enabled:       dc.ResponseTime.Enabled,
			Window:        durView(dc.ResponseTime.Window),
			MinSamples:    dc.ResponseTime.MinSamples,
			FloorMs:       dc.ResponseTime.FloorMs,
			DegradeFactor: dc.ResponseTime.DegradeFactor,
			BaselineAlpha: dc.ResponseTime.BaselineAlpha,
		},
	}
}

// toConfig parses a wire config document into a typed config.DetectionConfig,
// parsing every duration string. Numeric-RANGE validation is deliberately NOT done
// here — the writer persists via the full config loader (validateDetection), which
// is the single source of range truth, so a bad threshold is rejected there.
func (v DetectionConfigView) toConfig() (config.DetectionConfig, error) {
	dc := config.DetectionConfig{Enabled: v.Enabled, MaxKeys: v.MaxKeys}
	if err := parseDurView("tickInterval", v.TickInterval, &dc.TickInterval); err != nil {
		return config.DetectionConfig{}, err
	}
	dc.ErrorRate.Enabled = v.ErrorRate.Enabled
	dc.ErrorRate.MinSamples = v.ErrorRate.MinSamples
	dc.ErrorRate.RateThreshold = v.ErrorRate.RateThreshold
	if err := parseDurView("errorRate.window", v.ErrorRate.Window, &dc.ErrorRate.Window); err != nil {
		return config.DetectionConfig{}, err
	}
	dc.AuthFailBurst.Enabled = v.AuthFailBurst.Enabled
	dc.AuthFailBurst.CountThreshold = v.AuthFailBurst.CountThreshold
	if err := parseDurView("authFailBurst.window", v.AuthFailBurst.Window, &dc.AuthFailBurst.Window); err != nil {
		return config.DetectionConfig{}, err
	}
	dc.CostAnomaly.Enabled = v.CostAnomaly.Enabled
	dc.CostAnomaly.BudgetUSD = v.CostAnomaly.BudgetUSD
	if err := parseDurView("costAnomaly.window", v.CostAnomaly.Window, &dc.CostAnomaly.Window); err != nil {
		return config.DetectionConfig{}, err
	}
	dc.ResponseTime.Enabled = v.ResponseTime.Enabled
	dc.ResponseTime.MinSamples = v.ResponseTime.MinSamples
	dc.ResponseTime.FloorMs = v.ResponseTime.FloorMs
	dc.ResponseTime.DegradeFactor = v.ResponseTime.DegradeFactor
	dc.ResponseTime.BaselineAlpha = v.ResponseTime.BaselineAlpha
	if err := parseDurView("responseTime.window", v.ResponseTime.Window, &dc.ResponseTime.Window); err != nil {
		return config.DetectionConfig{}, err
	}
	return dc, nil
}

// durView renders an optional duration override as a Go-duration string, or "" when
// unset (⇒ omitted / engine default).
func durView(d *time.Duration) string {
	if d == nil {
		return ""
	}
	return d.String()
}

// parseDurView parses a Go-duration string into *dst when non-empty, leaving dst
// nil (⇒ engine default) when the field is absent.
func parseDurView(name, raw string, dst **time.Duration) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("detection.%s %q is not a valid duration", name, raw)
	}
	*dst = &d
	return nil
}
