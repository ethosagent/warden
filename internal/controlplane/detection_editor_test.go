package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/detect"
)

// detectionEditorConfig builds a CP config whose served file carries policy +
// secrets blocks (so we can assert they survive a detection edit) with the
// detection engine ON and a typed DetectionConfig for the editor source.
func detectionEditorConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		PolicyPath:       writePolicyFile(t, "api.openai.com"),
		AlertDBPath:      filepath.Join(t.TempDir(), "warden-alerts.db"),
		DetectionEnabled: true,
		Detection:        detect.DefaultConfig(),
		DetectionTick:    50 * time.Millisecond,
		DetectionConfig:  config.DetectionConfig{Enabled: true},
	}
}

func hasDetector(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// TestDetectionEditor_PUTReloadsLiveEngineAndPreservesBlocks is the money test for
// M3's CP editor: a PUT disabling error_rate must (1) drop error_rate from the LIVE
// engine's active detectors (hot reload under the manager lock), and (2) persist to
// the served config file while preserving every other block byte-for-byte.
func TestDetectionEditor_PUTReloadsLiveEngineAndPreservesBlocks(t *testing.T) {
	cfg := detectionEditorConfig(t)
	cfg.Token = "editor-token"
	srv := New(cfg)
	if !hasDetector(srv.pipeline.Detectors(), "error_rate") {
		t.Fatal("precondition: error_rate should be active at startup")
	}

	cp := httptest.NewServer(srv.Handler())
	defer cp.Close()

	// GET: config + status + editable.
	getResp, err := http.Get(cp.URL + "/dashboard/api/detection")
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		Config map[string]any `json:"config"`
		Status struct {
			Detectors []string `json:"detectors"`
		} `json:"status"`
		Editable bool `json:"editable"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	_ = getResp.Body.Close()
	if !view.Editable {
		t.Error("control-plane detection editor should be editable")
	}
	if len(view.Status.Detectors) != 4 {
		t.Errorf("startup active detectors = %v, want 4", view.Status.Detectors)
	}

	// PUT: disable error_rate.
	body := `{"enabled":true,"errorRate":{"enabled":false}}`
	req, _ := http.NewRequest(http.MethodPut, cp.URL+"/dashboard/api/detection", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer editor-token")
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT detection = %d, want 200", putResp.StatusCode)
	}
	_ = putResp.Body.Close()

	// The LIVE engine dropped error_rate (hot reload observable via the pipeline).
	if hasDetector(srv.pipeline.Detectors(), "error_rate") {
		t.Errorf("error_rate still active after PUT disabling it: %v", srv.pipeline.Detectors())
	}
	if !hasDetector(srv.pipeline.Detectors(), "auth_fail_burst") {
		t.Errorf("other detectors should remain active: %v", srv.pipeline.Detectors())
	}

	// The served file preserved policy + secrets and gained the detection block.
	raw, err := os.ReadFile(cfg.PolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, must := range []string{"api.openai.com", "openai_secret_001", "detection:", "errorRate:"} {
		if !strings.Contains(got, must) {
			t.Errorf("served config missing %q after detection write; file:\n%s", must, got)
		}
	}

	// A fresh loader must still accept the written file (default-deny + validation).
	if _, err := config.NewLocalYAMLProvider(cfg.PolicyPath); err != nil {
		t.Fatalf("written config no longer loads: %v", err)
	}
}

// TestDetectionEditor_DisableThenEnable proves a PUT can turn detection fully OFF
// (engine dropped) and a later PUT can turn it back ON (engine rebuilt) — the tick
// loop runs whenever the manager exists, so re-enable takes effect without restart.
func TestDetectionEditor_DisableThenEnable(t *testing.T) {
	srv := New(detectionEditorConfig(t))
	if err := srv.WriteDetection(config.DetectionConfig{Enabled: false}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if len(srv.pipeline.Detectors()) != 0 {
		t.Fatalf("detection disabled should drop all detectors; got %v", srv.pipeline.Detectors())
	}
	if err := srv.WriteDetection(config.DetectionConfig{Enabled: true}); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if len(srv.pipeline.Detectors()) != 4 {
		t.Fatalf("re-enable should rebuild all detectors; got %v", srv.pipeline.Detectors())
	}
}
