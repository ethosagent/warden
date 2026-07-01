package controlplane

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/secrets"
)

// Compile-time assertions duplicated in tests document, at the seam's own file,
// which concrete type satisfies which role interface. They mirror the assertions
// in controlplane.go so a rename breaks the build here too.
var (
	_ PolicyServer  = (*policyServer)(nil)
	_ ConfigEditor  = (*Server)(nil)
	_ WorkerTracker = (*WorkerRegistry)(nil)
	_ IngestSink    = (*ingestSink)(nil)
)

// fakeConfigEditor is a package-local fake ConfigEditor: it records the last
// policy/settings it was asked to write and never touches disk. It exists to
// prove a consumer (the dashboard's write endpoints) depends only on the
// ConfigEditor seam, not on the concrete Server.
type fakeConfigEditor struct {
	gotPolicy   *config.Policy
	gotSettings *config.SettingsWire
}

func (f *fakeConfigEditor) WritePolicy(p config.Policy) error {
	f.gotPolicy = &p
	return nil
}

func (f *fakeConfigEditor) WriteSettings(s config.SettingsWire) error {
	f.gotSettings = &s
	return nil
}

// fakeWorkerTracker is a package-local fake WorkerTracker returning a fixed row,
// proving the dashboard's fleet view depends only on the WorkerTracker seam.
type fakeWorkerTracker struct {
	views []dashboard.WorkerView
}

func (f *fakeWorkerTracker) SeenPolicyPull(string)        {}
func (f *fakeWorkerTracker) SeenIngest(string, int)       {}
func (f *fakeWorkerTracker) SeenHeartbeat(string, string) {}
func (f *fakeWorkerTracker) Views() []dashboard.WorkerView {
	return f.views
}

// TestDashboardDependsOnConfigEditorSeam wires a fake ConfigEditor into the
// dashboard's policy/settings write setters and drives the dashboard's write
// endpoints, proving the consumer depends only on the ConfigEditor interface (a
// disk-free fake satisfies it). It also drives a fake WorkerTracker through the
// workers view. This asserts the seam, not control-plane write behavior — the
// byte-for-byte YAML-preservation of the real Server is covered by the existing
// controlplane tests.
func TestDashboardDependsOnConfigEditorSeam(t *testing.T) {
	editor := &fakeConfigEditor{}
	tracker := &fakeWorkerTracker{views: []dashboard.WorkerView{{ProxyID: "w-1", Online: true}}}

	// The control plane holds no secrets; the dashboard is given an empty provider.
	emptySecrets, _ := secrets.NewCache(secrets.NewEnvFetcher(map[string]string{}), 0, nil)
	dash := dashboard.NewServer(analytics.NewCentralStore(0),
		config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "example.com"}}}, emptySecrets)

	// The dashboard's write setters take function injection; sourcing them from the
	// ConfigEditor seam is exactly the control-plane wiring pattern in Handler.
	var ce ConfigEditor = editor
	dash.SetPolicyWriter(ce.WritePolicy)
	dash.SetSettingsWriter(ce.WriteSettings)

	var wt WorkerTracker = tracker
	dash.SetWorkers(wt.Views)

	h := dash.Handler()

	// POST a policy edit; the dashboard must route it to the seam.
	body := `{"allowlist":[{"domain":"edited.example.com"}],"denylist":[]}`
	req := httptest.NewRequest("POST", "/dashboard/api/policy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if editor.gotPolicy == nil {
		t.Fatalf("dashboard did not route policy write to the ConfigEditor seam (status %d)", rec.Code)
	}
	if len(editor.gotPolicy.Allowlist) != 1 || editor.gotPolicy.Allowlist[0].Domain != "edited.example.com" {
		t.Fatalf("ConfigEditor received wrong policy: %+v", editor.gotPolicy)
	}

	// The workers view must read from the WorkerTracker seam.
	wreq := httptest.NewRequest("GET", "/dashboard/api/workers", nil)
	wrec := httptest.NewRecorder()
	h.ServeHTTP(wrec, wreq)
	if wrec.Code != 200 {
		t.Fatalf("workers endpoint: got %d, want 200", wrec.Code)
	}
	if !strings.Contains(wrec.Body.String(), "w-1") {
		t.Fatalf("workers view did not surface the WorkerTracker row: %s", wrec.Body.String())
	}
}

// TestIngestSinkForwards proves the ingestSink adapter forwards to the registry
// and mcp store unchanged: an ingest tags the worker, and an MCP snapshot lands
// in the store's per-worker view.
func TestIngestSinkForwards(t *testing.T) {
	reg := NewWorkerRegistry()
	store := newMCPStore()
	var sink IngestSink = &ingestSink{registry: reg, mcp: store}

	sink.SeenIngest("w-2", 3)
	views := reg.Views()
	if len(views) != 1 || views[0].ProxyID != "w-2" || views[0].EventsForwarded != 3 {
		t.Fatalf("ingestSink.SeenIngest did not tag the worker: %+v", views)
	}

	sink.UpdateMCP("w-2", analytics.MCPSnapshot{})
	if _, ok := store.byID["w-2"]; !ok {
		t.Fatalf("ingestSink.UpdateMCP did not store the snapshot for w-2")
	}
}
