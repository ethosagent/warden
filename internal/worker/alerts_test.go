package worker

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"

	_ "github.com/ethosagent/warden/internal/integration/webhook" // register the webhook sink for the reload test
)

// newTestLogger returns a discarding logger so tests stay quiet.
func newTestLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// loadPolicy writes cfg to a temp config file, loads it through the real loader,
// and returns the resolved policy + the file path (so the integrations-writer test
// can round-trip the same file the worker owns).
func loadPolicy(t *testing.T, cfg string) (config.Policy, string) {
	t.Helper()
	path := writeConfig(t, cfg)
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	return pol, path
}

const minimalCfg = `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: error
  format: json
`

// TestNewWorkerAlerts_BuildsAndBridgesBlock proves a local-only worker with an
// alert DB builds the pipeline and that a block/deny event Observed by the pipeline
// bridges into a stored alert queryable via CurrentManager().ListAlerts.
func TestNewWorkerAlerts_BuildsAndBridgesBlock(t *testing.T) {
	pol, cfgPath := loadPolicy(t, minimalCfg)
	alertDB := filepath.Join(t.TempDir(), "warden-alerts.db")

	alerts := newWorkerAlerts(pol, cfgPath, alertDB, "worker-1", newTestLogger())
	if alerts == nil {
		t.Fatal("expected a pipeline for a local-only worker with an alert DB")
	}
	t.Cleanup(alerts.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts.Start(ctx)

	alerts.Observe([]analytics.Event{{
		Timestamp: time.Now(), Domain: "evil.example.com", Decision: "deny",
		Method: "POST",
	}})

	m := alerts.pipeline.CurrentManager()
	got := m.ListAlerts(10)
	if len(got) != 1 {
		t.Fatalf("expected 1 bridged alert, got %d", len(got))
	}
	if got[0].DedupKey != "egress_blocked:evil.example.com" {
		t.Errorf("unexpected dedupKey %q", got[0].DedupKey)
	}
	if got[0].Subject.Worker != "worker-1" {
		t.Errorf("expected Subject.Worker=worker-1, got %q", got[0].Subject.Worker)
	}
}

// TestWorkerAlerts_TeesThroughAsyncWriter proves the OFF-HOT-PATH tee: an event
// written through the async analytics writer (WithOnBatch wired to the pipeline's
// Observe, exactly as worker.Run wires it) reaches the alert store. Close drains
// the queue, firing the tee, so the block event lands as an alert.
func TestWorkerAlerts_TeesThroughAsyncWriter(t *testing.T) {
	pol, cfgPath := loadPolicy(t, minimalCfg)
	analyticsDB := filepath.Join(t.TempDir(), "warden.db")
	store, err := analytics.NewSQLiteStore(analyticsDB, 0)
	if err != nil {
		t.Fatalf("open analytics store: %v", err)
	}
	defer func() { _ = store.Close() }()

	alerts := newWorkerAlerts(pol, cfgPath, filepath.Join(t.TempDir(), "alerts.db"), "worker-1", newTestLogger())
	if alerts == nil {
		t.Fatal("expected a pipeline")
	}
	t.Cleanup(alerts.Close)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts.Start(ctx)

	async := analytics.NewAsyncWriter(store, analytics.WithOnBatch(alerts.Observe))
	if err := async.StoreEvent(analytics.Event{
		Timestamp: time.Now(), Domain: "blocked.example.com", Decision: "deny", Method: "GET",
	}); err != nil {
		t.Fatalf("StoreEvent: %v", err)
	}
	// Close drains the queue on the writer goroutine → the tee fires with the batch.
	if err := async.Close(); err != nil {
		t.Fatalf("async close: %v", err)
	}

	got := alerts.pipeline.CurrentManager().ListAlerts(10)
	if len(got) != 1 || got[0].DedupKey != "egress_blocked:blocked.example.com" {
		t.Fatalf("expected the block event teed into an alert, got %+v", got)
	}
}

// TestNewWorkerAlerts_FailOpen proves a store-open failure disables alerting
// (returns nil) WITHOUT panicking — the fail-open invariant. Pointing the alert DB
// at an existing directory makes the SQLite open fail.
func TestNewWorkerAlerts_FailOpen(t *testing.T) {
	pol, cfgPath := loadPolicy(t, minimalCfg)
	badPath := filepath.Join(t.TempDir(), "not-a-db")
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if alerts := newWorkerAlerts(pol, cfgPath, badPath, "worker-1", newTestLogger()); alerts != nil {
		alerts.Close()
		t.Fatal("expected nil (alerting disabled) on a bad alert DB path")
	}
}

// TestWorkerAlerts_WriteIntegrationsPersistsAndReloads proves the local-only
// integrations WRITER is wired: it persists the integrations block to the worker's
// own config file and hot-reloads the live manager so the instance appears in the
// integrations status source.
func TestWorkerAlerts_WriteIntegrationsPersistsAndReloads(t *testing.T) {
	t.Setenv("WARDEN_TEST_WEBHOOK_URL", "https://hooks.example.com/x")
	pol, cfgPath := loadPolicy(t, minimalCfg)
	alerts := newWorkerAlerts(pol, cfgPath, filepath.Join(t.TempDir(), "alerts.db"), "worker-1", newTestLogger())
	if alerts == nil {
		t.Fatal("expected a pipeline")
	}
	t.Cleanup(alerts.Close)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts.Start(ctx)

	err := alerts.writeIntegrations([]config.IntegrationInstance{{
		Type:   "webhook",
		Name:   "ops",
		Config: map[string]any{"url": "${WARDEN_TEST_WEBHOOK_URL}"},
		Match:  []config.IntegrationMatch{{Severity: "high"}},
	}})
	if err != nil {
		t.Fatalf("writeIntegrations: %v", err)
	}

	// (a) The worker's config file now carries the integrations block.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(raw), "integrations:") || !strings.Contains(string(raw), "name: ops") {
		t.Fatalf("config file missing persisted integrations block:\n%s", raw)
	}
	// The persisted secret stays an ${ENV} reference — never a raw value.
	if strings.Contains(string(raw), "hooks.example.com") {
		t.Fatalf("config file leaked a resolved secret value:\n%s", raw)
	}

	// (b) The live manager reloaded: the instance now shows in the status source.
	statuses := alerts.integrationStatuses()
	if len(statuses) != 1 || statuses[0].Name != "ops" {
		t.Fatalf("expected the reloaded ops instance in the status source, got %+v", statuses)
	}
}

// TestRun_LocalOnly_BuildsAlertDB and TestRun_Fleet_NoAlertDB together prove the
// gate: the embedded pipeline (and its alert DB) is built ONLY for a local-only
// worker. A fleet (not-local-only) worker builds no pipeline, so no alert DB file
// is ever created — behavior identical to before M2.
func TestRun_LocalOnly_BuildsAlertDB(t *testing.T) {
	cfgPath := writeConfig(t, minimalCfg)
	alertDB := filepath.Join(t.TempDir(), "alerts.db")
	p := Params{
		ConfigPath: cfgPath, ListenAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		DBPath: filepath.Join(t.TempDir(), "warden.db"), Version: "test",
		LocalOnly: true, AlertsDBPath: alertDB,
	}
	if err := runWorkerBriefly(t, p); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(alertDB); err != nil {
		t.Fatalf("expected the alert DB to be created for a local-only worker: %v", err)
	}
}

func TestRun_Fleet_NoAlertDB(t *testing.T) {
	cfgPath := writeConfig(t, minimalCfg)
	alertDB := filepath.Join(t.TempDir(), "alerts.db")
	p := Params{
		ConfigPath: cfgPath, ListenAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		DBPath: filepath.Join(t.TempDir(), "warden.db"), Version: "test",
		LocalOnly: false, AlertsDBPath: alertDB,
	}
	if err := runWorkerBriefly(t, p); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(alertDB); !os.IsNotExist(err) {
		t.Fatalf("a fleet worker must build no pipeline/alert DB; stat err=%v", err)
	}
}

// runWorkerBriefly runs Run under a context cancelled after a short delay so the
// synchronous assembly (incl. the alert pipeline build) completes and Serve shuts
// down cleanly. It returns Run's error (nil on a clean ctx-driven shutdown).
func runWorkerBriefly(t *testing.T, p Params) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	return Run(ctx, io.Discard, p)
}
