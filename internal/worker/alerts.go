package worker

// alerts.go embeds the alert-delivery pipeline in a LOCAL-ONLY worker. In fleet
// mode the pipeline is CP-hosted and Findings ride central ingest; a standalone
// (`--local-only`) worker has no control plane, so it runs the SAME embeddable
// alertpipeline in-process and feeds it from its OWN analytics event stream. This
// is the "logical role, not a process" placement: one pipeline package, hosted by
// the CP in fleet mode or by the worker in local-only.
//
// Ownership mirrors the control plane: the worker OPENS the alert integration.Store
// (pure-Go modernc, via integration.NewStore — no new driver) and closes it EXACTLY
// once at shutdown; the pipeline holds a non-owning reference for manager rebuilds.
// Everything here is FAIL-OPEN: a store-open or manager-build failure logs and
// disables alerting, and NEVER blocks the proxy from serving.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/alertpipeline"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
)

// workerAlerts is the local-only worker's embedded alert-delivery assembly. It
// owns the caller-open alert store and wraps the shared alertpipeline so the
// worker.go assembler stays thin: build → tee events → wire the dashboard →
// start → close. Nil-valued receivers are never used — newWorkerAlerts returns
// nil when alerting is disabled, and every call site nil-checks the pointer.
type workerAlerts struct {
	pipeline   *alertpipeline.Pipeline
	store      *integration.Store
	configPath string
	proxyID    string
	logger     *slog.Logger
	// writeMu serializes dashboard integrations + detection edits (config-file
	// round-trip + reload), mirroring the control plane's writeMu.
	writeMu sync.Mutex
	// detectionMu guards detectionConfig — the live typed detection config the
	// dashboard editor reads and writeDetection updates.
	detectionMu     sync.RWMutex
	detectionConfig config.DetectionConfig
}

// newWorkerAlerts builds the embedded alert pipeline for a local-only worker at
// alertDBPath. It is FAIL-OPEN: any store-open or manager-build failure logs and
// returns nil, so the worker runs with alerting disabled but never fails to serve.
// configPath is the worker's own live config file — the integrations dashboard
// writer persists to it and reloads the live manager. proxyID labels Subject.Worker
// on bridged Findings (the worker's local agent identity).
func newWorkerAlerts(pol config.Policy, configPath, alertDBPath, proxyID string, logger *slog.Logger) *workerAlerts {
	st, err := integration.NewStore(alertDBPath)
	if err != nil {
		logger.Error("worker: alert pipeline disabled (alert store open failed)", "error", err, "path", alertDBPath)
		return nil
	}
	detectCfg, detectionEnabled, detectionTick := alertpipeline.DetectConfigFrom(pol.Detection)
	p := alertpipeline.New(alertpipeline.Config{
		Store:     st,
		Instances: toWorkerInstances(pol.Integrations),
		Detection: detectCfg,
		Detect:    detectionEnabled,
		Tick:      detectionTick,
		Logger:    logger,
	})
	if p.CurrentManager() == nil {
		// Manager build failed (fail-open): close the store we opened; nothing
		// runnable was built. Alerting stays disabled; the worker still serves.
		logger.Error("worker: alert pipeline disabled (manager build failed)")
		_ = st.Close()
		return nil
	}
	if detectionEnabled {
		logger.Info("worker: local-only alert pipeline enabled",
			"alertsDB", alertDBPath, "detectors", p.Detectors(), "tick", detectionTick.String())
	} else {
		logger.Info("worker: local-only alert pipeline enabled (detection off)", "alertsDB", alertDBPath)
	}
	return &workerAlerts{
		pipeline: p, store: st, configPath: configPath, proxyID: proxyID, logger: logger,
		detectionConfig: pol.Detection,
	}
}

// Start launches the pipeline (manager start + detection tick) under the worker's
// run context. It does NOT close the store — Close owns that.
func (w *workerAlerts) Start(ctx context.Context) { w.pipeline.Start(ctx) }

// Observe tees a batch of the worker's own analytics events into the pipeline's
// fan-in (detector fold + immediate event→Finding bridge). It is invoked off the
// request hot path from the async analytics writer's tee (analytics.WithOnBatch).
func (w *workerAlerts) Observe(events []analytics.Event) { w.pipeline.Observe(w.proxyID, events) }

// Close stops the current manager's instances (router + sinks) and then closes the
// worker-owned alert store exactly once. The worker.go defer that calls this is
// registered BEFORE the async writer's Close defer, so under defer LIFO the async
// queue drains first (its final teed batch's Observe still reaches a live store +
// router) and only then does the store close.
func (w *workerAlerts) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.pipeline.StopInstances(ctx); err != nil {
		w.logger.Warn("worker: alert pipeline shutdown error", "error", err)
	}
	if err := w.store.Close(); err != nil {
		w.logger.Warn("worker: alert store close error", "error", err)
	}
}

// wireDashboard attaches the alert surfaces to the worker's own dashboard, the
// same way the control plane wires them: the Alerts tab lists live alerts from the
// CURRENT manager (re-pointed on reload), the integrations tab shows per-instance
// status, and the integrations writer persists to the worker's config file and
// reloads the live manager. Called only when the embedded pipeline exists.
func (w *workerAlerts) wireDashboard(dash *dashboard.Server) {
	dash.SetAlerts(func(limit int) []integration.Alert {
		m := w.pipeline.CurrentManager()
		if m == nil {
			return nil
		}
		return m.ListAlerts(limit)
	})
	dash.SetIntegrationsSource(w.integrationStatuses)
	dash.SetIntegrationsWriter(w.writeIntegrations)
	// Detection editor (local-only analogue of the CP's): the source is the live
	// typed config + the embedded engine's active-detector names + eviction count;
	// the writer persists the worker's own `detection:` block and reloads the engine.
	dash.SetDetectionSource(func() dashboard.DetectionView {
		return dashboard.NewDetectionView(w.currentDetectionConfig(), w.pipeline.Detectors(), w.pipeline.Evictions())
	})
	dash.SetDetectionWriter(w.writeDetection)
}

// currentDetectionConfig returns the worker's live typed detection config under the
// read lock (updated by writeDetection).
func (w *workerAlerts) currentDetectionConfig() config.DetectionConfig {
	w.detectionMu.RLock()
	defer w.detectionMu.RUnlock()
	return w.detectionConfig
}

// integrationStatuses adapts the live manager's per-instance runtime status into
// the dashboard's value-free view (mirrors the control plane's adapter). A nil
// manager yields nil → the tab reports no instances.
func (w *workerAlerts) integrationStatuses() []dashboard.IntegrationInstanceStatus {
	m := w.pipeline.CurrentManager()
	if m == nil {
		return nil
	}
	statuses := m.InstanceStatuses()
	out := make([]dashboard.IntegrationInstanceStatus, 0, len(statuses))
	for _, st := range statuses {
		v := dashboard.IntegrationInstanceStatus{
			Name:   st.Name,
			Type:   st.Type,
			Status: st.Status,
			Reason: st.Reason,
			Config: st.Config,
		}
		for _, mc := range st.Match {
			v.Match = append(v.Match, config.IntegrationMatch{
				Severity: mc.Severity, Category: mc.Category, Domain: mc.Domain, Rule: mc.Rule,
			})
		}
		out = append(out, v)
	}
	return out
}

// writeIntegrations persists the full desired integrations list to the worker's
// OWN config file and reloads the live manager over the SAME alert store — the
// local-only analogue of the control plane's WriteIntegrations + reloadIntegrations.
// It round-trips the config file through a top-level YAML map so every other block
// (policy, logging, mcp, judge, secrets, audit, …) survives byte-for-byte; only the
// `integrations` key is replaced (an empty list deletes it). The candidate is
// validated by the full loader before it can replace the good file. Nothing here
// surfaces a raw secret: config secret fields stay ${ENV} references, expanded only
// at Integration.Start.
func (w *workerAlerts) writeIntegrations(instances []config.IntegrationInstance) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(w.configPath); err == nil {
		// Best-effort: a malformed current file just means we rebuild the block we
		// own; the loader validation below still guards the result.
		_ = yaml.Unmarshal(cur, &root)
	}
	if len(instances) == 0 {
		delete(root, "integrations")
	} else {
		node, err := config.EncodeIntegrationsNode(instances)
		if err != nil {
			return fmt.Errorf("worker: encode integrations block: %w", err)
		}
		root["integrations"] = node
	}
	if err := atomicWriteWorkerConfig(w.configPath, root); err != nil {
		return err
	}
	if err := w.pipeline.ReloadManager(toWorkerInstances(instances)); err != nil {
		return err
	}
	w.logger.Info("worker: integrations updated via dashboard", "count", len(instances))
	return nil
}

// writeDetection persists an edited detection block to the worker's OWN config file
// and hot-reloads the embedded detection engine — the local-only analogue of the
// control plane's WriteDetection. It round-trips the config file through a top-level
// YAML map so every other block survives byte-for-byte; only the `detection` key is
// replaced. The candidate is validated by the full loader before it can replace the
// good file. Detection config carries no secrets.
func (w *workerAlerts) writeDetection(dc config.DetectionConfig) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(w.configPath); err == nil {
		_ = yaml.Unmarshal(cur, &root)
	}
	node, err := config.EncodeDetectionNode(dc)
	if err != nil {
		return fmt.Errorf("worker: encode detection block: %w", err)
	}
	root["detection"] = node
	if err := atomicWriteWorkerConfig(w.configPath, root); err != nil {
		return err
	}
	detectCfg, enabled, _ := alertpipeline.DetectConfigFrom(dc)
	if err := w.pipeline.ReloadDetection(detectCfg, enabled); err != nil {
		return err
	}
	w.detectionMu.Lock()
	w.detectionConfig = dc
	w.detectionMu.Unlock()
	w.logger.Info("worker: detection updated via dashboard", "enabled", dc.Enabled)
	return nil
}

// atomicWriteWorkerConfig marshals the top-level config map, writes it to a temp
// file in the config file's directory, validates it with the full loader (so a bad
// edit can never replace a good config — default-deny is enforced there), then
// renames it into place. It mirrors the control plane's atomicWriteConfig, against
// the worker's own config path.
func atomicWriteWorkerConfig(configPath string, root map[string]yaml.Node) error {
	data, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("worker: marshal config: %w", err)
	}
	dir := filepath.Dir(configPath)
	tmp, err := os.CreateTemp(dir, ".warden-config-*.yaml")
	if err != nil {
		return fmt.Errorf("worker: create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("worker: write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("worker: close temp config: %w", err)
	}
	// Validate the candidate with the full loader before it can replace the live
	// file (this enforces default-deny: an empty allowlist is rejected here).
	if _, err := config.NewLocalYAMLProvider(tmpName); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := os.Rename(tmpName, configPath); err != nil {
		return fmt.Errorf("worker: persist config: %w", err)
	}
	return nil
}

// toWorkerInstances maps persisted config instances to the integration package's
// InstanceConfig (mirrors the cmd/CP mapping). The opaque config map passes through
// untouched; secrets inside it stay as ${ENV} strings, expanded later at Start.
func toWorkerInstances(insts []config.IntegrationInstance) []integration.InstanceConfig {
	if len(insts) == 0 {
		return nil
	}
	out := make([]integration.InstanceConfig, 0, len(insts))
	for _, in := range insts {
		ic := integration.InstanceConfig{Type: in.Type, Name: in.Name, Config: in.Config}
		for _, m := range in.Match {
			ic.Match = append(ic.Match, integration.MatchClause{
				Severity: m.Severity, Category: m.Category, Domain: m.Domain, Rule: m.Rule,
			})
		}
		out = append(out, ic)
	}
	return out
}
