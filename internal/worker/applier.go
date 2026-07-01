package worker

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/internal/secrets"
)

// SettingsApplier is the named hot-reload seam: it rebuilds + atomically swaps the
// proxy's MCP gateway, inline judge, log level, compliance tagging layer, and
// secret cache TTL from the control-plane-distributed settings. It runs only for
// MANAGED workers, so a local-only worker's seeded gateway/judge are never touched.
//
// It replaces the anonymous `applySettings` closure that previously lived in
// cmd/proxy: the captured locals become fields set at construction, and Apply
// holds the exact same rebuild+swap logic (unchanged behavior).
type SettingsApplier struct {
	// cp supplies the currently-distributed behavioral settings.
	cp ControlPlaneClient

	// Data-plane target and its live-rebuild inputs. mcpScanner, store, and agentID
	// are LOCAL — never distributed — and are reused on every gateway/judge rebuild.
	p          *proxy.Proxy
	mcpScanner scan.Scanner
	store      *analytics.SQLiteStore
	agentID    string
	logger     *slog.Logger
	logCtrl    *observability.LogControl

	// Compliance tagging is rebuilt around this stable base signed store using the
	// reusable mapper, so a toggle never disturbs the signing layer or base store.
	signedStore      analytics.AnalyticsStore
	complianceMapper *audit.Mapper

	// Secret cache rebuild inputs (fetcher + placeholders are LOCAL).
	secretFetcher secrets.Fetcher
	placeholders  []string

	// pol is the worker's LOCAL boot policy (observability fallback + judge agents
	// come from settings, but the pending-restart comparison uses local fallback).
	pol config.Policy
	// obsCfg is the observability config OTel actually booted from, compared against
	// the distributed one so a change is surfaced once as a pending-restart log.
	obsCfg config.ObservabilityConfig

	// Live-state trackers. mcpMu guards liveMCPGW against the shutdown defer; the
	// others are touched only from the single apply goroutine.
	mcpMu          *sync.Mutex
	liveMCPGW      **gateway.Gateway
	liveCompliance bool
	liveCacheTTL   time.Duration
}

// Apply rebuilds + atomically swaps the proxy's MCP gateway AND its inline judge
// (plus log level, compliance tagging, and secret cache TTL) from the
// control-plane-distributed settings. It is the long-poll onApply callback.
func (a *SettingsApplier) Apply() {
	settings := a.cp.Settings()

	// --- MCP gateway swap ---
	// newGW is the concrete gateway (or nil) used for lifecycle (Close via
	// liveMCPGW). swapGW is the interface value handed to the proxy: it MUST
	// stay an untyped-nil proxy.MCPGateway when disabled — assigning a
	// typed-nil *gateway.Gateway would make the proxy's mcpGateway() return a
	// non-nil interface wrapping a nil pointer and panic on the hot path.
	var newGW *gateway.Gateway
	var swapGW proxy.MCPGateway
	if settings != nil && settings.MCP != nil && settings.MCP.Enabled {
		newGW = gateway.New(config.MCPConfigFromSettings(settings.MCP), a.mcpScanner, a.logger,
			gateway.WithStore(a.store), gateway.WithAgentID(a.agentID))
		swapGW = newGW
	}
	a.p.SetMCPGateway(swapGW)
	a.mcpMu.Lock()
	old := *a.liveMCPGW
	*a.liveMCPGW = newGW
	a.mcpMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	switch {
	case newGW != nil:
		a.logger.Info("MCP gateway swapped from control-plane settings", "mode", settings.MCP.Mode)
	case old != nil:
		a.logger.Info("MCP gateway disabled by control-plane settings")
	default:
		a.logger.Debug("control-plane settings applied; MCP remains disabled")
	}

	// --- Judge swap ---
	// The API key is resolved LOCALLY inside buildJudgeFrom (the distributed
	// settings carry only the env NAME). agentID is the worker's LOCAL
	// identity and stays fixed across rebuilds.
	if settings != nil && settings.Judge != nil && settings.Judge.Enabled {
		newJudge, jErr := buildJudgeFrom(
			config.JudgeConfigFromSettings(settings.Judge),
			config.AgentsFromSettings(settings.Agents),
			a.agentID,
		)
		if jErr != nil {
			// Fail-safe: the judge is advisory (NoMatch default-denies without
			// it), not default-deny. A transient build error (e.g. bad client
			// config, momentarily-unset key) must NOT nil out a working judge,
			// so leave the current judge in place and retry on the next apply.
			a.logger.Warn("judge rebuild from control-plane settings failed; keeping current judge", "error", jErr)
		} else {
			a.p.SetJudge(newJudge)
			a.logger.Info("inline judge swapped from control-plane settings", "model", settings.Judge.Model)
		}
	} else {
		// No judge distributed (or explicitly disabled): disable it.
		a.p.SetJudge(nil)
		a.logger.Debug("control-plane settings applied; judge disabled")
	}

	// --- Logging level (live) + format (restart-only) ---
	// Level rides a *slog.LevelVar so changing it does NOT swap the
	// widely-captured logger instance. Format is the handler TYPE, baked in
	// at construction; with the logger captured everywhere a live handler
	// swap is unsafe, so a format change is applied on the NEXT RESTART only.
	if settings != nil && settings.Logging != nil {
		if settings.Logging.Level != "" {
			a.logCtrl.SetLevel(settings.Logging.Level)
			a.logger.Debug("logging level applied from control-plane settings", "level", settings.Logging.Level)
		}
		if f := settings.Logging.Format; f != "" && !strings.EqualFold(strings.TrimSpace(f), a.logCtrl.Format()) {
			a.logger.Info("logging format change pending restart",
				"requested", f, "running", a.logCtrl.Format())
		}
	}

	// --- Secret cache TTL (live) ---
	// Rebuild the cache with the new TTL and atomic-swap it in. Rebuilding
	// drops cached entries (they re-fetch on next use — acceptable). Only
	// rebuild when the distributed TTL actually differs from the running one.
	if settings != nil && settings.CacheTTLSeconds != nil {
		newTTL := time.Duration(*settings.CacheTTLSeconds) * time.Second
		if newTTL != a.liveCacheTTL {
			newCache, cErr := secrets.NewCache(a.secretFetcher, newTTL, a.placeholders)
			if cErr != nil {
				// Fail-safe: a rebuild error (e.g. an env var transiently unset
				// at prefetch) must NOT drop a working provider. Keep the current
				// cache and retry on the next apply.
				a.logger.Warn("secret cache rebuild from control-plane settings failed; keeping current cache", "error", cErr)
			} else {
				a.p.SetSecrets(newCache)
				a.liveCacheTTL = newTTL
				a.logger.Info("secret cache TTL applied from control-plane settings", "ttlSeconds", *settings.CacheTTLSeconds)
			}
		}
	}

	// --- Compliance tagging (live) ---
	// A clean live toggle is safe here: the dashboard and central forwarding
	// hold the BASE store directly, never this wrapped chain, so rebuilding
	// ONLY the tagging layer around the shared signedStore and swapping the
	// proxy's analytics pointer leaves those consumers untouched. Only swap
	// when the desired state actually changes.
	wantCompliance := settings != nil && settings.Compliance != nil && settings.Compliance.Enabled
	if wantCompliance != a.liveCompliance {
		if wantCompliance {
			a.p.SetAnalytics(audit.NewTaggingStore(a.signedStore, a.complianceMapper))
			a.logger.Info("compliance tagging enabled by control-plane settings")
		} else {
			a.p.SetAnalytics(a.signedStore)
			a.logger.Info("compliance tagging disabled by control-plane settings")
		}
		a.liveCompliance = wantCompliance
	}

	// --- Observability (apply-on-RESTART, NOT live) ---
	// OTel meter/exporter providers init ONCE at boot and cannot be safely
	// hot-swapped, so a distributed observability change is NOT applied live.
	// Surface it as an operator signal: the new config takes effect on the
	// next (re)start, when the worker re-pulls settings and boots OTel from
	// resolveObservability. Compared against the boot config so the line logs
	// once per distinct change, not on every poll.
	if settings != nil {
		wantObs := resolveObservability(settings, a.pol)
		if !observabilityConfigsEqual(wantObs, a.obsCfg) {
			a.logger.Info("observability change pending restart",
				"runningEnabled", a.obsCfg.Enabled, "requestedEnabled", wantObs.Enabled,
				"runningOTLPEndpoint", a.obsCfg.OTLPEndpoint, "requestedOTLPEndpoint", wantObs.OTLPEndpoint)
		}
	}
}
