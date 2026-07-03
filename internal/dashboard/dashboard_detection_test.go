package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// boolPtr builds a *bool override for tests.
func boolPtr(b bool) *bool { return &b }

// newDetectionServer wires a dashboard with an in-memory detection config as the
// source and (optionally) a writer that mutates it — simulating the CP/worker
// persist+reload. The status reports whichever detectors the stored config leaves
// enabled, so a PUT that disables one is observable via GET.
func newDetectionServer(t *testing.T, withWriter bool) (*Server, *config.DetectionConfig) {
	t.Helper()
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	stored := &config.DetectionConfig{Enabled: true}
	srv.SetDetectionSource(func() DetectionView {
		return NewDetectionView(*stored, activeDetectors(*stored), 7)
	})
	if withWriter {
		srv.SetDetectionWriter(func(dc config.DetectionConfig) error {
			*stored = dc
			return nil
		})
	}
	return srv, stored
}

// activeDetectors reports which detectors a config leaves on (nil override = on),
// mimicking the engine's construction gate so the test's status view is realistic.
func activeDetectors(dc config.DetectionConfig) []string {
	if !dc.Enabled {
		return nil
	}
	on := func(p *bool) bool { return p == nil || *p }
	var names []string
	if on(dc.ErrorRate.Enabled) {
		names = append(names, "error_rate")
	}
	if on(dc.AuthFailBurst.Enabled) {
		names = append(names, "auth_fail_burst")
	}
	if on(dc.CostAnomaly.Enabled) {
		names = append(names, "cost_anomaly")
	}
	if on(dc.ResponseTime.Enabled) {
		names = append(names, "response_time")
	}
	return names
}

func getDetectionJSON(t *testing.T, srv *Server) DetectionView {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/detection", nil)
	rr := httptest.NewRecorder()
	srv.handleDetection(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET detection = %d, want 200", rr.Code)
	}
	var v DetectionView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode detection response: %v", err)
	}
	return v
}

func TestDetection_GETReportsConfigStatusEditable(t *testing.T) {
	// No writer: read-only, editable=false, but config + status still present.
	roSrv, _ := newDetectionServer(t, false)
	v := getDetectionJSON(t, roSrv)
	if v.Editable {
		t.Error("no writer should be editable=false")
	}
	if len(v.Status.Detectors) != 4 {
		t.Errorf("status detectors = %v, want all 4 active", v.Status.Detectors)
	}
	if v.Status.Evictions != 7 {
		t.Errorf("status evictions = %d, want 7", v.Status.Evictions)
	}
	if !v.Config.Enabled {
		t.Error("config.enabled should be true")
	}

	// With writer: editable=true.
	rwSrv, _ := newDetectionServer(t, true)
	if v := getDetectionJSON(t, rwSrv); !v.Editable {
		t.Error("with writer should be editable=true")
	}
}

func TestDetection_PUTNoWriterIs405(t *testing.T) {
	srv, _ := newDetectionServer(t, false)
	body := `{"enabled":true,"errorRate":{"enabled":false}}`
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/detection", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleDetection(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT with no writer = %d, want 405", rr.Code)
	}
}

func TestDetection_PUTPersistsAndReloads(t *testing.T) {
	srv, stored := newDetectionServer(t, true)

	// Disable error_rate and set a custom tick — the read-modify-write M4 does.
	body := `{"enabled":true,"tickInterval":"30s","errorRate":{"enabled":false}}`
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/detection", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleDetection(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT detection = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	// The writer received the parsed config: error_rate disabled, tick 30s.
	if stored.ErrorRate.Enabled == nil || *stored.ErrorRate.Enabled {
		t.Errorf("stored error_rate.enabled = %v, want false", stored.ErrorRate.Enabled)
	}
	if stored.TickInterval == nil || stored.TickInterval.String() != "30s" {
		t.Errorf("stored tickInterval = %v, want 30s", stored.TickInterval)
	}

	// The echoed response reflects the reload: error_rate dropped from the status.
	var v DetectionView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	for _, d := range v.Status.Detectors {
		if d == "error_rate" {
			t.Errorf("error_rate should be dropped from active detectors after PUT; got %v", v.Status.Detectors)
		}
	}
	if v.Config.ErrorRate.Enabled == nil || *v.Config.ErrorRate.Enabled {
		t.Errorf("echoed config error_rate.enabled = %v, want false", v.Config.ErrorRate.Enabled)
	}
}

func TestDetection_PUTBadDurationIs400(t *testing.T) {
	srv, _ := newDetectionServer(t, true)
	body := `{"enabled":true,"tickInterval":"not-a-duration"}`
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/detection", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleDetection(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT bad duration = %d, want 400", rr.Code)
	}
}

func TestDetection_DELETEIs405(t *testing.T) {
	srv, _ := newDetectionServer(t, true)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/detection", nil)
	rr := httptest.NewRecorder()
	srv.handleDetection(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE detection = %d, want 405", rr.Code)
	}
}

// TestDetection_ConfigViewRoundTrips asserts the wire projection is faithful: a
// config with overrides projects to the view and parses back to the same config.
func TestDetection_ConfigViewRoundTrips(t *testing.T) {
	orig := config.DetectionConfig{Enabled: true, MaxKeys: 512}
	orig.AuthFailBurst.Enabled = boolPtr(false)
	view := detectionConfigView(orig)
	back, err := view.toConfig()
	if err != nil {
		t.Fatalf("toConfig: %v", err)
	}
	if back.MaxKeys != 512 || !back.Enabled {
		t.Errorf("round-trip lost scalars: %+v", back)
	}
	if back.AuthFailBurst.Enabled == nil || *back.AuthFailBurst.Enabled {
		t.Errorf("round-trip lost auth_fail_burst override: %v", back.AuthFailBurst.Enabled)
	}
}
