package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/dashboard"
)

// fakeSecrets is a no-op SecretProvider so the worker dashboard can be built in a
// test without a real secret backend.
type fakeSecrets struct{}

func (fakeSecrets) GetSecret(string) (string, error) { return "", nil }
func (fakeSecrets) RefreshSecrets() error            { return nil }

const detectionCfg = `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: error
  format: json
detection:
  enabled: true
`

// TestWorkerDetectionEditor_PUTReloadsEmbeddedEngine proves the local-only worker
// exposes the detection editor on its OWN dashboard and that a PUT reloads the
// embedded engine (drops a detector) while preserving the worker config file's
// other blocks.
func TestWorkerDetectionEditor_PUTReloadsEmbeddedEngine(t *testing.T) {
	pol, cfgPath := loadPolicy(t, detectionCfg)
	alerts := newWorkerAlerts(pol, cfgPath, t.TempDir()+"/alerts.db", "worker-1", newTestLogger())
	if alerts == nil {
		t.Fatal("expected a pipeline for a local-only worker")
	}
	t.Cleanup(alerts.Close)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts.Start(ctx)

	if len(alerts.pipeline.Detectors()) != 4 {
		t.Fatalf("precondition: expected 4 active detectors, got %v", alerts.pipeline.Detectors())
	}

	// Build the worker's own dashboard and wire the alert surfaces (as worker.Run does).
	store, err := analytics.NewSQLiteStore(t.TempDir()+"/warden.db", 0)
	if err != nil {
		t.Fatalf("analytics store: %v", err)
	}
	defer func() { _ = store.Close() }()
	dash := dashboard.NewServer(store, pol, fakeSecrets{})
	dash.SetWriteGuard(dashboard.AllowUngatedWritesForTests) // the editor is under test, not auth
	alerts.wireDashboard(dash)

	ts := httptest.NewServer(dash.Handler())
	defer ts.Close()

	// GET: editable + 4 active detectors.
	getResp, err := http.Get(ts.URL + "/dashboard/api/detection")
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		Status struct {
			Detectors []string `json:"detectors"`
		} `json:"status"`
		Editable bool `json:"editable"`
	}
	_ = json.NewDecoder(getResp.Body).Decode(&view)
	_ = getResp.Body.Close()
	if !view.Editable {
		t.Error("local-only worker detection editor should be editable")
	}
	if len(view.Status.Detectors) != 4 {
		t.Errorf("startup detectors = %v, want 4", view.Status.Detectors)
	}

	// PUT: disable auth_fail_burst.
	body := `{"enabled":true,"authFailBurst":{"enabled":false}}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/dashboard/api/detection", strings.NewReader(body))
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT detection = %d, want 200", putResp.StatusCode)
	}
	_ = putResp.Body.Close()

	// The EMBEDDED engine reloaded: auth_fail_burst dropped.
	for _, d := range alerts.pipeline.Detectors() {
		if d == "auth_fail_burst" {
			t.Errorf("auth_fail_burst still active after PUT: %v", alerts.pipeline.Detectors())
		}
	}
	if len(alerts.pipeline.Detectors()) != 3 {
		t.Errorf("expected 3 active detectors after disabling one, got %v", alerts.pipeline.Detectors())
	}

	// The worker's own config file preserved policy/logging and gained the edit.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, must := range []string{"api.openai.com", "logging:", "authFailBurst:"} {
		if !strings.Contains(got, must) {
			t.Errorf("worker config missing %q after detection write; file:\n%s", must, got)
		}
	}
}
