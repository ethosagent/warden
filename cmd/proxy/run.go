package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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
			return runProxy(cmd, configPath, listenAddr, dbPath, caCert, caKey, adminAddr)
		},
	}

	cmd.Flags().String("listen", "127.0.0.1:8080", "loopback/pod-internal listen address")
	cmd.Flags().String("db", "warden.db", "SQLite analytics database path")
	cmd.Flags().String("ca-cert", "", "path to proxy CA certificate for TLS termination")
	cmd.Flags().String("ca-key", "", "path to proxy CA private key for TLS termination")
	cmd.Flags().String("admin-listen", "127.0.0.1:9090", "admin + dashboard HTTP listen address")

	return cmd
}

// runProxy loads config, wires dependencies behind their interfaces,
// constructs the proxy, and starts serving.
func runProxy(cmd *cobra.Command, configPath, listenAddr, dbPath, caCert, caKey, adminAddr string) error {
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
	ttl := time.Duration(pol.CacheTTLSeconds) * time.Second
	secretProvider, err := secrets.NewCache(secrets.NewEnvFetcher(mapping), ttl, placeholders)
	if err != nil {
		return err
	}

	// Structured logger from logging.{level,format}. Built once and threaded into
	// the proxy; lifecycle logs below also use it.
	logger := observability.NewLogger(cmd.OutOrStdout(), pol.LogLevel, pol.LogFormat)

	// OTel metrics emitter (off by default). New returns a nil *Metrics + nil
	// handler when disabled, and record calls are nil-safe no-ops.
	metrics, metricsHandler, shutdownObs, err := observability.New(observability.Config{
		Enabled:            pol.Observability.Enabled,
		ServiceName:        pol.Observability.ServiceName,
		ServiceVersion:     version,
		MetricsEnabled:     pol.Observability.MetricsEnabled,
		OTLPEndpoint:       pol.Observability.OTLPEndpoint,
		ResourceAttributes: pol.Observability.ResourceAttributes,
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

	// Optional MCP egress gateway. When mcp.enabled is false, mcpGW stays nil and
	// handleHTTP is byte-identical to before.
	var mcpGW *gateway.Gateway
	if pol.MCP.Enabled {
		scanner := scan.NewScanner(scan.WithPhonePII(pol.MCP.Scan.PII.Phone))
		mcpGW = gateway.New(pol.MCP, scanner, logger, gateway.WithStore(store), gateway.WithAgentID(agentID))
		logger.Info("MCP egress gateway enabled", "mode", pol.MCP.Mode)
	}
	// Close the gateway before the store: deferred LIFO runs this first, so the
	// gateway's final flush completes while the store handle is still open.
	if mcpGW != nil {
		defer func() { _ = mcpGW.Close() }()
	}

	// Hot-swappable policy evaluator. Built from local policy first so a
	// control-plane outage falls back to the local allowlist.
	evaluator := policy.NewEvaluator(pol)

	// Optional control plane: pull allow/deny policy from a remote endpoint and
	// apply it now (poll-based hot-reload starts after the proxy is built). Local
	// secrets/judge/observability stay from the local config.
	var controlPlane *config.RemoteProvider
	if pol.ControlPlane.Endpoint != "" {
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
		if pullErr := rp.Pull(); pullErr != nil {
			logger.Warn("control plane initial pull failed; using local policy", "error", pullErr)
		} else if remote, gErr := rp.GetPolicy(); gErr == nil {
			evaluator.Replace(remote)
			logger.Info("control plane policy applied", "endpoint", pol.ControlPlane.Endpoint)
		}
		controlPlane = rp
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
	var analyticsStore analytics.AnalyticsStore = store
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
		analyticsStore = audit.NewSigningStore(analyticsStore, signer, receiptLog)
		logger.Info("signed audit receipts enabled",
			"log", pol.Audit.SignedReceipts.Log,
			"pubkey", hex.EncodeToString(signer.PubKey()))
	}
	if pol.Audit.Compliance.Enabled {
		analyticsStore = audit.NewTaggingStore(analyticsStore, audit.NewMapper())
		logger.Info("compliance mapping enabled")
	}

	// Optional central aggregation. aggregator: host an ingest endpoint into an
	// in-memory central store the dashboard reads from. worker: forward local
	// events to a remote aggregator. off: single-node (default).
	var (
		centralStore  *analytics.CentralStore
		ingestHandler http.Handler
		syncWorker    *analytics.SyncWorker
	)
	switch pol.Central.Mode {
	case "aggregator":
		centralStore = analytics.NewCentralStore(pol.Central.MaxEvents)
		ingestHandler = analytics.NewIngestHandler(centralStore, os.Getenv(pol.Central.TokenEnv))
		logger.Info("central aggregator enabled", "ingest", "/central/ingest")
	case "worker":
		centralClient, ccErr := newSafeHTTPClient(10*time.Second, pol.Central.CACert)
		if ccErr != nil {
			return ccErr
		}
		remote, rErr := analytics.NewHTTPRemoteStore(pol.Central.Endpoint, os.Getenv(pol.Central.TokenEnv), expandEnv(pol.Central.ProxyID), centralClient)
		if rErr != nil {
			return rErr
		}
		syncWorker = analytics.NewSyncWorker(store, remote, pol.Central.BatchSize, pol.Central.BufferCap, pol.Central.Interval)
		logger.Info("central worker enabled", "endpoint", pol.Central.Endpoint, "proxyID", pol.Central.ProxyID)
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
		go pollControlPlane(ctx, controlPlane, evaluator, pol.ControlPlane.PollInterval, logger)
	}
	if syncWorker != nil {
		syncWorker.Start(ctx)
	}

	return p.Serve(ctx)
}

// buildJudge constructs the inline judge when judge.enabled, returning the
// judge and the agent id derived from the listen port. When the judge is
// disabled it returns (nil, "", nil) and the proxy default-denies NoMatch as
// before. Config has already validated cross-field requirements; here we only
// resolve the API key from its env var.
func buildJudge(pol config.Policy, listenAddr string) (proxy.Judge, string, error) {
	// Resolve the agent id from the listen port (one proxy per agent).
	agentID := defaultAgentID(pol, listenAddr)
	if !pol.Judge.Enabled {
		return nil, agentID, nil
	}

	apiKey := os.Getenv(pol.Judge.APIKeyEnv)
	if apiKey == "" {
		return nil, "", fmt.Errorf("judge.enabled but env var %s is empty (it holds the LLM API key)", pol.Judge.APIKeyEnv)
	}
	client, err := llm.NewClient(llm.Config{
		BaseURL: pol.Judge.BaseURL,
		Model:   pol.Judge.Model,
		APIKey:  apiKey,
		Timeout: pol.Judge.Timeout,
	})
	if err != nil {
		return nil, "", fmt.Errorf("build LLM client: %w", err)
	}

	policies := make(map[string]string, len(pol.Agents))
	for _, a := range pol.Agents {
		policies[a.ID] = a.Policy
	}

	judge := llmpolicy.NewJudge(client, policies, llmpolicy.JudgeOptions{
		CacheTTL:    pol.Judge.CacheTTL,
		Timeout:     pol.Judge.Timeout,
		MaxFailures: pol.Judge.CircuitBreaker.MaxFailures,
		Cooldown:    pol.Judge.CircuitBreaker.Cooldown,
	})
	return judgeAdapter{judge}, agentID, nil
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
