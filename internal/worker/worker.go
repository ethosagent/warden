// Package worker holds the data-plane assembler: it wires the concrete
// implementations behind their interfaces, boots the proxy (fail-closed in
// managed mode), and runs the control-plane long-poll + heartbeat + MCP-push
// loops and the hot-reload apply loop. cmd/proxy only parses flags and calls Run.
package worker

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ethosagent/warden/internal/admin"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/internal/secrets"
)

// Params are the flag-derived inputs the worker boots from. cmd/proxy parses the
// cobra flags into this struct; the worker owns everything after that.
type Params struct {
	ConfigPath string
	ListenAddr string
	DBPath     string
	CACert     string
	CAKey      string
	AdminAddr  string
	Version    string
	LocalOnly  bool
}

// Run loads config, wires dependencies behind their interfaces, constructs the
// proxy, and starts serving. out replaces cmd.OutOrStdout(); ctx replaces
// cmd.Context(); p.Version replaces the cmd package's version var used for the
// observability ServiceVersion.
func Run(ctx context.Context, out io.Writer, p Params) error {
	configPath := p.ConfigPath
	listenAddr := p.ListenAddr
	dbPath := p.DBPath
	caCert := p.CACert
	caKey := p.CAKey
	adminAddr := p.AdminAddr
	localOnlyFlag := p.LocalOnly

	cfgProvider, err := config.NewLocalYAMLProvider(configPath)
	if err != nil {
		return err
	}
	pol, err := cfgProvider.GetPolicy()
	if err != nil {
		return err
	}

	mapping := make(map[string]string, len(pol.Secrets))
	placeholders := make([]string, 0, len(pol.Secrets))
	for _, m := range pol.Secrets {
		mapping[m.Placeholder] = m.EnvVar
		placeholders = append(placeholders, m.Placeholder)
	}
	// Keep the fetcher + placeholders so the managed apply loop can rebuild the
	// cache with a new TTL on a control-plane cache.ttl change. liveCacheTTL tracks
	// the running TTL so the loop only rebuilds when it actually differs.
	secretFetcher := secrets.NewEnvFetcher(mapping)
	liveCacheTTL := time.Duration(pol.CacheTTLSeconds) * time.Second
	secretProvider, err := secrets.NewCache(secretFetcher, liveCacheTTL, placeholders)
	if err != nil {
		return err
	}

	// Structured logger from logging.{level,format}. Built once and threaded into
	// the proxy; lifecycle logs below also use it. logCtrl is the live handle the
	// managed apply loop uses to change the level at runtime WITHOUT swapping the
	// (widely-captured) logger instance. Format is restart-only (see LogControl).
	logger, logCtrl := observability.NewLogger(out, pol.LogLevel, pol.LogFormat)

	// Managed vs local-only. Managed = a control plane is configured and
	// --local-only is not set: the worker's allow/deny policy comes ONLY from the
	// control plane and it boots fail-closed (deny all) until the first pull.
	// Otherwise the worker enforces its local policy (standalone).
	localOnly := localOnlyFlag || pol.ControlPlane.LocalOnly
	managed := pol.ControlPlane.Endpoint != "" && !localOnly

	// Optional control plane (managed mode only): pull allow/deny policy AND the
	// behavioral settings document from the remote endpoint. The first pull happens
	// HERE, before OTel init, so observability can be resolved from the distributed
	// settings.Observability (apply-on-restart: OTel providers initialize once per
	// process and cannot be safely hot-swapped on the long-poll). A best-effort
	// initial pull narrows the fail-closed window; if it fails the worker stays
	// fail-closed and the long-poll loop applies policy once the CP is reachable.
	// Secrets/judge/audit-signing stay local.
	var (
		controlPlane *config.RemoteProvider
		remotePolicy *config.Policy // last-known-good remote allow/deny, applied to the evaluator below
	)
	if managed {
		token := os.Getenv(pol.ControlPlane.TokenEnv)
		rp, cpErr := config.NewRemoteProvider(pol.ControlPlane.Endpoint, token)
		if cpErr != nil {
			return cpErr
		}
		// Trust a privately-signed control plane via a per-connection CA, without
		// altering this worker's upstream TLS trust.
		if pol.ControlPlane.CACert != "" {
			if caErr := rp.SetCACert(pol.ControlPlane.CACert); caErr != nil {
				return caErr
			}
		}
		// Announce this worker's id on each pull/heartbeat so the control plane
		// lists it as connected even before it forwards analytics.
		rp.SetProxyID(expandEnv(pol.Central.ProxyID))
		if pullErr := rp.Pull(); pullErr != nil {
			logger.Warn("control plane unreachable at boot; starting FAIL-CLOSED (deny all) until policy arrives", "error", pullErr)
		} else if remote, gErr := rp.GetPolicy(); gErr == nil {
			remotePolicy = &remote
			logger.Info("control plane policy applied", "endpoint", pol.ControlPlane.Endpoint)
		}
		controlPlane = rp
	} else if pol.ControlPlane.Endpoint != "" && localOnly {
		logger.Info("control plane configured but --local-only set; enforcing LOCAL policy")
	}

	// Resolve the observability config OTel boots from. A managed worker prefers
	// the control-plane-distributed settings.Observability (so central config
	// actually takes effect on restart), falling back to local pol.Observability
	// when the distributed block is absent or the CP was unreachable at boot. A
	// local-only worker always uses its local config (unchanged behavior).
	obsCfg := pol.Observability
	if managed {
		var distributed *config.SettingsWire
		if controlPlane != nil {
			distributed = controlPlane.Settings()
		}
		obsCfg = resolveObservability(distributed, pol)
	}

	// OTel metrics emitter (off by default). New returns a nil *Metrics + nil
	// handler when disabled, and record calls are nil-safe no-ops. OTel providers
	// init ONCE here; a distributed observability change applies on the NEXT
	// restart (the worker re-pulls settings at boot), never on a live long-poll.
	metrics, metricsHandler, shutdownObs, err := observability.New(observability.Config{
		Enabled:            obsCfg.Enabled,
		ServiceName:        obsCfg.ServiceName,
		ServiceVersion:     p.Version,
		MetricsEnabled:     obsCfg.MetricsEnabled,
		OTLPEndpoint:       obsCfg.OTLPEndpoint,
		ResourceAttributes: obsCfg.ResourceAttributes,
	})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownObs(ctx)
	}()

	store, err := analytics.NewSQLiteStore(dbPath, 0)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Optional inline judge. When judge.enabled is false, judge is nil and the
	// proxy behaves exactly as before (NoMatch default-denies).
	judge, agentID, err := buildJudge(pol, listenAddr)
	if err != nil {
		return err
	}

	// Reusable scanner for the MCP gateway. Constructed once from local config and
	// reused on every control-plane-driven gateway rebuild (the scanner, store,
	// and agentID are LOCAL — never distributed).
	mcpScanner := scan.NewScanner(
		scan.WithPhonePII(pol.MCP.Scan.PII.Phone),
		scan.WithEvidence(pol.MCP.Scan.Evidence),
	)

	// Optional MCP egress gateway. When mcp.enabled is false, mcpGW stays nil and
	// handleHTTP is byte-identical to before. A managed worker may later receive an
	// MCP settings block over the long-poll and rebuild+swap this at runtime.
	// bootGW is the interface value seeded into proxy.Config. It MUST stay an
	// untyped-nil proxy.MCPGateway when MCP is disabled — assigning a typed-nil
	// *gateway.Gateway would make the proxy's mcpGateway() return a non-nil
	// interface wrapping a nil pointer and panic on the hot path. mcpGW keeps the
	// concrete handle for lifecycle (Close) and the dashboard MCP provider.
	var mcpGW *gateway.Gateway
	var bootGW proxy.MCPGateway
	if pol.MCP.Enabled {
		mcpGW = gateway.New(pol.MCP, mcpScanner, logger, gateway.WithStore(store), gateway.WithAgentID(agentID))
		bootGW = mcpGW
		logger.Info("MCP egress gateway enabled", "mode", pol.MCP.Mode)
	}
	// Close the gateway before the store: deferred LIFO runs this first, so the
	// gateway's final flush completes while the store handle is still open. A
	// runtime swap replaces p's live gateway; the apply loop owns closing the old
	// one, so this defer only handles the gateway live at shutdown.

	// Optional non-MCP HTTP response scanner. Off unless responseScan.enabled; when
	// off, respScanner stays nil and handleHTTP forwards non-MCP responses
	// byte-identically. LOCAL config (scanner + evidence never distributed).
	var respScanner *proxy.ResponseScanner
	if pol.ResponseScan.Enabled && pol.ResponseScan.Mode != "off" {
		respScanner = proxy.NewResponseScanner(
			pol.ResponseScan.Mode,
			pol.ResponseScan.MaxBodyBytes,
			pol.ResponseScan.PII.Phone,
			pol.ResponseScan.Evidence,
		)
		logger.Info("HTTP response scanning enabled", "mode", pol.ResponseScan.Mode)
	}

	// Hot-swappable policy evaluator. In managed mode it starts EMPTY (deny all)
	// and is filled by the control plane; otherwise it enforces local policy. The
	// control-plane provider + first pull happened above (before OTel init); if
	// that pull succeeded, remotePolicy holds the remote allow/deny and we seed the
	// evaluator with it so the fail-closed window is as narrow as it was before.
	var evaluator *policy.Evaluator
	if managed {
		evaluator = policy.NewEvaluator(config.Policy{})
		if remotePolicy != nil {
			evaluator.Replace(*remotePolicy)
		}
	} else {
		evaluator = policy.NewEvaluator(pol)
	}

	// Cost estimator: always on. It only attributes a heuristic dollar figure to
	// traffic that matches a known provider domain; everything else is untouched.
	costEstimator := cost.NewEstimator()

	// Optional auth transforms (OAuth2 / SigV4 / HMAC / API-key) per destination.
	var transformers []*auth.MatchedTransformer
	if len(pol.Auth) > 0 {
		authClient, acErr := newSafeHTTPClient(10*time.Second, "")
		if acErr != nil {
			return acErr
		}
		transformers, err = buildTransformers(pol.Auth, authClient)
		if err != nil {
			return err
		}
		logger.Info("auth transforms enabled", "count", len(transformers))
	}

	// Async analytics write decorator (D1). The base SQLiteStore.StoreEvent does
	// an INSERT + prune (SELECT COUNT/DELETE) on the request goroutine through a
	// single connection (~420µs/event). asyncWriter enqueues onto a bounded
	// channel and a single writer goroutine batch-inserts + prunes off the hot
	// path, so the request goroutine pays only the sub-µs enqueue. Overflow is
	// BACKPRESSURE, never drop — events are the audit trail. It closes on
	// shutdown (drains + flushes) below.
	asyncStore := analytics.NewAsyncWriter(store, analytics.WithLogger(logger))
	// Drain + flush the async queue on shutdown BEFORE the store handle closes.
	// Deferred LIFO: store.Close() was registered earlier, so this runs first and
	// the final batch lands while the DB is still open. Close is idempotent, so
	// this fires exactly once even if shutdown paths overlap.
	defer func() { _ = asyncStore.Close() }()
	// Expose queue depth as warden_analytics_queue_depth (observable gauge). Nil-
	// safe when metrics are disabled. Read live from the writer on each scrape.
	if rqErr := metrics.RegisterAnalyticsQueueDepth(func() int64 {
		return int64(asyncStore.QueueDepth())
	}); rqErr != nil {
		logger.Warn("analytics queue depth metric not registered", "error", rqErr)
	}

	// Audit decorators wrap the analytics WRITE chain. Order matters and is load-
	// bearing — the final chain (outer→inner) is:
	//
	//	tagging → signing → async → sqlite
	//
	// tagging is OUTER so each event is stamped with compliance control IDs
	// BEFORE the signer signs it (the receipt then covers the tags). async sits
	// JUST ABOVE the base store so the signer signs, and the receipt covers, the
	// exact event that is persisted — the async layer only defers the write, it
	// never alters the event. Reads (dashboard, central forwarding) still hold
	// the BASE store directly (see dashData/syncWorker below) and bypass the
	// queue; only this WRITE chain gets the async decorator.
	//
	// signedStore is the async writer OR the signing layer over it. It is the
	// stable inner store the (optional) compliance tagging layer wraps. The
	// managed apply loop rebuilds ONLY the tagging layer around signedStore on a
	// compliance toggle, so the signing/async layers and the base store are never
	// disturbed by a live swap.
	var signedStore analytics.AnalyticsStore = asyncStore
	if pol.Audit.SignedReceipts.Enabled {
		signer, sErr := loadOrCreateSigner(pol.Audit.SignedReceipts.KeyFile)
		if sErr != nil {
			return sErr
		}
		receiptLog, oErr := os.OpenFile(pol.Audit.SignedReceipts.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if oErr != nil {
			return fmt.Errorf("audit: open receipts log: %w", oErr)
		}
		defer func() { _ = receiptLog.Close() }()
		signedStore = audit.NewSigningStore(signedStore, signer, receiptLog)
		logger.Info("signed audit receipts enabled",
			"log", pol.Audit.SignedReceipts.Log,
			"pubkey", hex.EncodeToString(signer.PubKey()))
	}
	// complianceMapper is reused on each toggle so enable rebuilds the same tagging
	// behavior. liveCompliance tracks the running state so the apply loop only
	// rebuilds the tagging layer when it actually changes.
	complianceMapper := audit.NewMapper()
	liveCompliance := pol.Audit.Compliance.Enabled
	analyticsStore := signedStore
	if liveCompliance {
		analyticsStore = audit.NewTaggingStore(signedStore, complianceMapper)
		logger.Info("compliance mapping enabled")
	}

	// Optional central aggregation. aggregator: host an ingest endpoint into an
	// in-memory central store the dashboard reads from. worker: forward local
	// events to a remote aggregator. off: single-node (default).
	var (
		centralStore  *analytics.CentralStore
		ingestHandler http.Handler
		syncWorker    *analytics.SyncWorker
		centralRemote *analytics.HTTPRemoteStore
	)
	switch pol.Central.Mode {
	case "aggregator":
		centralStore = analytics.NewCentralStore(pol.Central.MaxEvents)
		ingestHandler = analytics.NewIngestHandler(centralStore, os.Getenv(pol.Central.TokenEnv))
		logger.Info("central aggregator enabled", "ingest", "/central/ingest")
	case "worker":
		// The control plane is the worker's own trusted, operator-configured
		// endpoint (often on a private network), so forwarding does NOT go through
		// the SafeDialer — SSRF protection is for agent-driven egress only.
		centralClient, ccErr := newControlPlaneHTTPClient(10*time.Second, pol.Central.CACert)
		if ccErr != nil {
			return ccErr
		}
		remote, rErr := analytics.NewHTTPRemoteStore(pol.Central.Endpoint, os.Getenv(pol.Central.TokenEnv), expandEnv(pol.Central.ProxyID), centralClient)
		centralRemote = remote
		if rErr != nil {
			return rErr
		}
		syncWorker = analytics.NewSyncWorker(store, remote, pol.Central.BatchSize, pol.Central.BufferCap, pol.Central.Interval)
		logger.Info("central worker enabled", "endpoint", pol.Central.Endpoint, "proxyID", expandEnv(pol.Central.ProxyID))
	}

	cfg := proxy.Config{
		ListenAddr:       listenAddr,
		Policy:           evaluator,
		Secrets:          secretProvider,
		Analytics:        analyticsStore,
		PlaceholderNames: placeholders,
		CACertPath:       caCert,
		CAKeyPath:        caKey,
		AgentID:          agentID,
		Metrics:          metrics,
		Logger:           logger,
		MCP:              bootGW,
		ResponseScan:     respScanner,
		Transformers:     transformers,
		Cost:             costEstimator,
	}
	if judge != nil {
		cfg.Judge = judge
		logger.Info("inline LLM judge enabled", "agent", agentID, "model", pol.Judge.Model)
	}

	pxy, err := proxy.New(cfg)
	if err != nil {
		return err
	}

	// liveMCPGW tracks the gateway currently swapped into the proxy so shutdown
	// (and each rebuild) closes the right one. It starts as the boot-time gateway
	// (possibly nil); the managed apply loop below replaces it on each change.
	// mcpMu guards it against the concurrent apply goroutine.
	var mcpMu sync.Mutex
	liveMCPGW := mcpGW
	// Close the gateway live at shutdown before the store: deferred LIFO runs this
	// first, so the gateway's final flush completes while the store is still open.
	defer func() {
		mcpMu.Lock()
		gw := liveMCPGW
		mcpMu.Unlock()
		if gw != nil {
			_ = gw.Close()
		}
	}()

	// Start admin + dashboard HTTP server. In aggregator mode the dashboard reads
	// the fleet-wide central store instead of this node's local SQLite store.
	var dashData dashboard.DataSource = store
	if centralStore != nil {
		dashData = centralStore
	}
	adminMux := http.NewServeMux()
	adminSrv := admin.NewServer(secretProvider)
	dashSrv := dashboard.NewServer(dashData, pol, secretProvider)
	// Policy panel reflects the live (hot-reloadable) allow/deny, not the startup
	// snapshot, so a control-plane reload is visible in the dashboard.
	dashSrv.SetLivePolicy(evaluator.CurrentPolicy)
	if mcpGW != nil {
		dashSrv.SetMCPProvider(mcpGW)
	}
	adminMux.Handle("/healthz", adminSrv.Handler())
	adminMux.Handle("/admin/", adminSrv.Handler())
	adminMux.Handle("/dashboard/", dashSrv.Handler())
	// Central ingest endpoint (aggregator mode only): workers POST event batches
	// here. It lives on the admin (private) listener, never the agent-facing port.
	if ingestHandler != nil {
		adminMux.Handle("/central/ingest", ingestHandler)
		logger.Info("central ingest endpoint enabled", "path", "/central/ingest", "addr", adminAddr)
	}
	// Prometheus /metrics lives ONLY on the admin (loopback/private) listener,
	// never the agent-facing proxy port. Registered only when metrics are on.
	if metricsHandler != nil {
		adminMux.Handle("/metrics", metricsHandler)
		logger.Info("metrics endpoint enabled", "path", "/metrics", "addr", adminAddr)
	}

	go func() {
		logger.Info("admin+dashboard listening", "url", fmt.Sprintf("http://%s/dashboard/", adminAddr))
		if err := http.ListenAndServe(adminAddr, adminMux); err != nil {
			logger.Error("admin server stopped", "error", err)
		}
	}()

	logger.Info("proxy listening", "addr", listenAddr)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Background workers tied to the proxy lifetime: control-plane policy polling
	// and central event forwarding. Both stop when ctx is cancelled.
	if controlPlane != nil {
		// applier rebuilds + atomically swaps the proxy's MCP gateway AND its
		// inline judge from the control-plane-distributed settings. It runs only for
		// MANAGED workers (this branch), so a local-only worker's seeded pol.MCP
		// gateway and pol.Judge are never touched. mcpMu (declared above) guards
		// liveMCPGW against the shutdown defer.
		applier := &SettingsApplier{
			cp:               controlPlane,
			p:                pxy,
			mcpScanner:       mcpScanner,
			store:            store,
			agentID:          agentID,
			logger:           logger,
			logCtrl:          logCtrl,
			signedStore:      signedStore,
			complianceMapper: complianceMapper,
			secretFetcher:    secretFetcher,
			placeholders:     placeholders,
			pol:              pol,
			obsCfg:           obsCfg,
			mcpMu:            &mcpMu,
			liveMCPGW:        &liveMCPGW,
			liveCompliance:   liveCompliance,
			liveCacheTTL:     liveCacheTTL,
		}
		go longPollControlPlane(ctx, controlPlane, evaluator, pol.ControlPlane.LongPollWait, logger, applier.Apply)
		go heartbeatControlPlane(ctx, controlPlane, pol.ControlPlane.HeartbeatInterval, logger)
	}
	if syncWorker != nil {
		syncWorker.Start(ctx)
	}
	// Forward this worker's MCP inventory + observed schema to the control plane
	// (only when both MCP and central worker forwarding are on).
	if centralRemote != nil && mcpGW != nil {
		go pushMCPSnapshots(ctx, mcpGW, centralRemote, pol.Central.MCPPushInterval, logger)
	}

	return pxy.Serve(ctx)
}
