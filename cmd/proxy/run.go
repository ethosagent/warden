package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/admin"
	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/llm"
	"github.com/ethosagent/warden/internal/llmpolicy"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/internal/secrets"
)

// newRunCmd builds the `run` subcommand. Its RunE loads config, wires the
// concrete implementations behind their interfaces, and starts the proxy.
func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Load config, wire dependencies, and start the proxy.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			listenAddr, err := cmd.Flags().GetString("listen")
			if err != nil {
				return err
			}
			dbPath, err := cmd.Flags().GetString("db")
			if err != nil {
				return err
			}
			caCert, err := cmd.Flags().GetString("ca-cert")
			if err != nil {
				return err
			}
			caKey, err := cmd.Flags().GetString("ca-key")
			if err != nil {
				return err
			}
			adminAddr, err := cmd.Flags().GetString("admin-listen")
			if err != nil {
				return err
			}
			localOnly, err := cmd.Flags().GetBool("local-only")
			if err != nil {
				return err
			}
			return runProxy(cmd, configPath, listenAddr, dbPath, caCert, caKey, adminAddr, localOnly)
		},
	}

	cmd.Flags().String("listen", "127.0.0.1:8080", "loopback/pod-internal listen address")
	cmd.Flags().String("db", "warden.db", "SQLite analytics database path")
	cmd.Flags().String("ca-cert", "", "path to proxy CA certificate for TLS termination")
	cmd.Flags().String("ca-key", "", "path to proxy CA private key for TLS termination")
	cmd.Flags().String("admin-listen", "127.0.0.1:9090", "admin + dashboard HTTP listen address")
	cmd.Flags().Bool("local-only", false, "ignore the control plane and enforce local policy (standalone)")

	return cmd
}

// runProxy loads config, wires dependencies behind their interfaces,
// constructs the proxy, and starts serving.
func runProxy(cmd *cobra.Command, configPath, listenAddr, dbPath, caCert, caKey, adminAddr string, localOnlyFlag bool) error {
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
	logger, logCtrl := observability.NewLogger(cmd.OutOrStdout(), pol.LogLevel, pol.LogFormat)

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
		ServiceVersion:     version,
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
	mcpScanner := scan.NewScanner(scan.WithPhonePII(pol.MCP.Scan.PII.Phone))

	// Optional MCP egress gateway. When mcp.enabled is false, mcpGW stays nil and
	// handleHTTP is byte-identical to before. A managed worker may later receive an
	// MCP settings block over the long-poll and rebuild+swap this at runtime.
	var mcpGW *gateway.Gateway
	if pol.MCP.Enabled {
		mcpGW = gateway.New(pol.MCP, mcpScanner, logger, gateway.WithStore(store), gateway.WithAgentID(agentID))
		logger.Info("MCP egress gateway enabled", "mode", pol.MCP.Mode)
	}
	// Close the gateway before the store: deferred LIFO runs this first, so the
	// gateway's final flush completes while the store handle is still open. A
	// runtime swap replaces p's live gateway; the apply loop owns closing the old
	// one, so this defer only handles the gateway live at shutdown.

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

	// Audit decorators wrap the analytics store. Order matters: tagging is the
	// OUTER wrapper so each event is tagged with compliance control IDs BEFORE
	// the inner signer signs it — the receipt then covers the tags too.
	//
	// signedStore is the base store OR the signing layer over it. It is the stable
	// inner store the (optional) compliance tagging layer wraps. The managed apply
	// loop rebuilds ONLY the tagging layer around signedStore on a compliance
	// toggle, so the signing layer and the base store (which the dashboard and
	// central forwarding hold directly — see dashData/syncWorker below) are never
	// disturbed by a live swap.
	var signedStore analytics.AnalyticsStore = store
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
		MCP:              mcpGW,
		Transformers:     transformers,
		Cost:             costEstimator,
	}
	if judge != nil {
		cfg.Judge = judge
		logger.Info("inline LLM judge enabled", "agent", agentID, "model", pol.Judge.Model)
	}

	p, err := proxy.New(cfg)
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

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Background workers tied to the proxy lifetime: control-plane policy polling
	// and central event forwarding. Both stop when ctx is cancelled.
	if controlPlane != nil {
		// applySettings rebuilds + atomically swaps the proxy's MCP gateway AND its
		// inline judge from the control-plane-distributed settings. It runs only for
		// MANAGED workers (this branch), so a local-only worker's seeded pol.MCP
		// gateway and pol.Judge are never touched. mcpMu (declared above) guards
		// liveMCPGW against the shutdown defer.
		applySettings := func() {
			settings := controlPlane.Settings()

			// --- MCP gateway swap ---
			var newGW *gateway.Gateway
			if settings != nil && settings.MCP != nil && settings.MCP.Enabled {
				newGW = gateway.New(config.MCPConfigFromSettings(settings.MCP), mcpScanner, logger,
					gateway.WithStore(store), gateway.WithAgentID(agentID))
			}
			p.SetMCPGateway(newGW)
			mcpMu.Lock()
			old := liveMCPGW
			liveMCPGW = newGW
			mcpMu.Unlock()
			if old != nil {
				_ = old.Close()
			}
			switch {
			case newGW != nil:
				logger.Info("MCP gateway swapped from control-plane settings", "mode", settings.MCP.Mode)
			case old != nil:
				logger.Info("MCP gateway disabled by control-plane settings")
			default:
				logger.Debug("control-plane settings applied; MCP remains disabled")
			}

			// --- Judge swap ---
			// The API key is resolved LOCALLY inside buildJudgeFrom (the distributed
			// settings carry only the env NAME). agentID is the worker's LOCAL
			// identity and stays fixed across rebuilds.
			if settings != nil && settings.Judge != nil && settings.Judge.Enabled {
				newJudge, jErr := buildJudgeFrom(
					config.JudgeConfigFromSettings(settings.Judge),
					config.AgentsFromSettings(settings.Agents),
					agentID,
				)
				if jErr != nil {
					// Fail-safe: the judge is advisory (NoMatch default-denies without
					// it), not default-deny. A transient build error (e.g. bad client
					// config, momentarily-unset key) must NOT nil out a working judge,
					// so leave the current judge in place and retry on the next apply.
					logger.Warn("judge rebuild from control-plane settings failed; keeping current judge", "error", jErr)
				} else {
					p.SetJudge(newJudge)
					logger.Info("inline judge swapped from control-plane settings", "model", settings.Judge.Model)
				}
			} else {
				// No judge distributed (or explicitly disabled): disable it.
				p.SetJudge(nil)
				logger.Debug("control-plane settings applied; judge disabled")
			}

			// --- Logging level (live) + format (restart-only) ---
			// Level rides a *slog.LevelVar so changing it does NOT swap the
			// widely-captured logger instance. Format is the handler TYPE, baked in
			// at construction; with the logger captured everywhere a live handler
			// swap is unsafe, so a format change is applied on the NEXT RESTART only.
			if settings != nil && settings.Logging != nil {
				if settings.Logging.Level != "" {
					logCtrl.SetLevel(settings.Logging.Level)
					logger.Debug("logging level applied from control-plane settings", "level", settings.Logging.Level)
				}
				if f := settings.Logging.Format; f != "" && !strings.EqualFold(strings.TrimSpace(f), logCtrl.Format()) {
					logger.Info("logging format change pending restart",
						"requested", f, "running", logCtrl.Format())
				}
			}

			// --- Secret cache TTL (live) ---
			// Rebuild the cache with the new TTL and atomic-swap it in. Rebuilding
			// drops cached entries (they re-fetch on next use — acceptable). Only
			// rebuild when the distributed TTL actually differs from the running one.
			if settings != nil && settings.CacheTTLSeconds != nil {
				newTTL := time.Duration(*settings.CacheTTLSeconds) * time.Second
				if newTTL != liveCacheTTL {
					newCache, cErr := secrets.NewCache(secretFetcher, newTTL, placeholders)
					if cErr != nil {
						// Fail-safe: a rebuild error (e.g. an env var transiently unset
						// at prefetch) must NOT drop a working provider. Keep the current
						// cache and retry on the next apply.
						logger.Warn("secret cache rebuild from control-plane settings failed; keeping current cache", "error", cErr)
					} else {
						p.SetSecrets(newCache)
						liveCacheTTL = newTTL
						logger.Info("secret cache TTL applied from control-plane settings", "ttlSeconds", *settings.CacheTTLSeconds)
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
			if wantCompliance != liveCompliance {
				if wantCompliance {
					p.SetAnalytics(audit.NewTaggingStore(signedStore, complianceMapper))
					logger.Info("compliance tagging enabled by control-plane settings")
				} else {
					p.SetAnalytics(signedStore)
					logger.Info("compliance tagging disabled by control-plane settings")
				}
				liveCompliance = wantCompliance
			}

			// --- Observability (apply-on-RESTART, NOT live) ---
			// OTel meter/exporter providers init ONCE at boot and cannot be safely
			// hot-swapped, so a distributed observability change is NOT applied live.
			// Surface it as an operator signal: the new config takes effect on the
			// next (re)start, when the worker re-pulls settings and boots OTel from
			// resolveObservability. Compared against the boot config so the line logs
			// once per distinct change, not on every poll.
			if settings != nil {
				wantObs := resolveObservability(settings, pol)
				if !observabilityConfigsEqual(wantObs, obsCfg) {
					logger.Info("observability change pending restart",
						"runningEnabled", obsCfg.Enabled, "requestedEnabled", wantObs.Enabled,
						"runningOTLPEndpoint", obsCfg.OTLPEndpoint, "requestedOTLPEndpoint", wantObs.OTLPEndpoint)
				}
			}
		}
		go longPollControlPlane(ctx, controlPlane, evaluator, pol.ControlPlane.LongPollWait, logger, applySettings)
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

	return p.Serve(ctx)
}

// resolveObservability picks the observability config a MANAGED worker boots OTel
// from. The control-plane-distributed settings.Observability wins when present
// (so central config actually takes effect on restart); otherwise it falls back
// to the worker's LOCAL pol.Observability (e.g. the CP sent no observability
// block, or was unreachable at boot so distributed is nil). It is a pure function
// (no OTel side effects) so the precedence is unit-testable without standing up a
// meter provider.
//
// Apply-on-RESTART, not live: OTel meter/exporter providers initialize once per
// process and cannot be safely hot-swapped on the long-poll, so a later
// distributed change is honored only when the worker re-pulls settings at its
// next (re)start.
func resolveObservability(distributed *config.SettingsWire, local config.Policy) config.ObservabilityConfig {
	if distributed != nil && distributed.Observability != nil {
		return config.ObservabilityConfigFromSettings(distributed.Observability)
	}
	return local.Observability
}

// observabilityConfigsEqual reports whether two resolved observability configs are
// equivalent, including their ResourceAttributes maps. Used by the long-poll to
// detect a distributed observability change worth surfacing as a pending-restart
// log (OTel is never reconfigured live).
func observabilityConfigsEqual(a, b config.ObservabilityConfig) bool {
	if a.Enabled != b.Enabled ||
		a.ServiceName != b.ServiceName ||
		a.MetricsEnabled != b.MetricsEnabled ||
		a.OTLPEndpoint != b.OTLPEndpoint ||
		len(a.ResourceAttributes) != len(b.ResourceAttributes) {
		return false
	}
	for k, v := range a.ResourceAttributes {
		if b.ResourceAttributes[k] != v {
			return false
		}
	}
	return true
}

// buildJudge constructs the inline judge when judge.enabled, returning the
// judge and the agent id derived from the listen port. When the judge is
// disabled it returns (nil, "", nil) and the proxy default-denies NoMatch as
// before. Config has already validated cross-field requirements; here we only
// resolve the API key from its env var.
func buildJudge(pol config.Policy, listenAddr string) (proxy.Judge, string, error) {
	// Resolve the agent id from the listen port (one proxy per agent).
	agentID := defaultAgentID(pol, listenAddr)
	judge, err := buildJudgeFrom(pol.Judge, pol.Agents, agentID)
	if err != nil {
		return nil, "", err
	}
	return judge, agentID, nil
}

// buildJudgeFrom constructs the inline judge from a JudgeConfig + agent policies,
// shared by the boot path (buildJudge) and the control-plane runtime rebuild (the
// apply loop in runProxy). It returns a nil judge when jc.Enabled is false (the
// proxy then default-denies NoMatch as before). agentID is the worker's LOCAL
// identity and is passed in unchanged across rebuilds — it is never distributed.
//
// SECRET-LOCAL INVARIANT: the API key is resolved here from the worker's OWN
// environment via os.Getenv(jc.APIKeyEnv). Distributed settings carry only the
// env NAME (jc.APIKeyEnv), never a key value, so a control plane can point the
// judge at a different env var but can never inject a credential.
func buildJudgeFrom(jc config.JudgeConfig, agents []config.AgentPolicy, agentID string) (proxy.Judge, error) {
	if !jc.Enabled {
		return nil, nil
	}

	apiKey := os.Getenv(jc.APIKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("judge.enabled but env var %s is empty (it holds the LLM API key)", jc.APIKeyEnv)
	}
	client, err := llm.NewClient(llm.Config{
		BaseURL: jc.BaseURL,
		Model:   jc.Model,
		APIKey:  apiKey,
		Timeout: jc.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("build LLM client: %w", err)
	}

	policies := make(map[string]string, len(agents))
	for _, a := range agents {
		policies[a.ID] = a.Policy
	}

	judge := llmpolicy.NewJudge(client, policies, llmpolicy.JudgeOptions{
		CacheTTL:    jc.CacheTTL,
		Timeout:     jc.Timeout,
		MaxFailures: jc.CircuitBreaker.MaxFailures,
		Cooldown:    jc.CircuitBreaker.Cooldown,
	})
	return judgeAdapter{judge}, nil
}

// judgeAdapter bridges *llmpolicy.Judge to the proxy.Judge interface. The proxy
// deliberately does not import llmpolicy (its Judge/Verdict are consumer-side);
// this thin wiring adapter lives in cmd/, where both packages are already in
// scope.
type judgeAdapter struct{ j *llmpolicy.Judge }

func (a judgeAdapter) Evaluate(agentID, method, url, host, contentType string, hasAuth bool) proxy.Verdict {
	v := a.j.Evaluate(agentID, method, url, host, contentType, hasAuth)
	return proxy.Verdict{Decision: v.Decision, Reason: v.Reason}
}

// defaultAgentID derives the agent identity. When exactly one agent policy is
// configured, its id is used directly so it matches the configured policy key;
// otherwise the port-binding identifier labels the agent by listen port.
func defaultAgentID(pol config.Policy, listenAddr string) string {
	if len(pol.Agents) == 1 {
		return pol.Agents[0].ID
	}
	port := 0
	if _, p, err := proxy.SplitHostPort(listenAddr); err == nil {
		port = p
	}
	return agentid.NewPortBindingIdentifier("agent").Identify(port)
}
