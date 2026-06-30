package main

import (
	"context"
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
	"github.com/ethosagent/warden/internal/config"
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

	cfg := proxy.Config{
		ListenAddr:       listenAddr,
		Policy:           policy.NewEvaluator(pol),
		Secrets:          secretProvider,
		Analytics:        store,
		PlaceholderNames: placeholders,
		CACertPath:       caCert,
		CAKeyPath:        caKey,
		AgentID:          agentID,
		Metrics:          metrics,
		Logger:           logger,
		MCP:              mcpGW,
	}
	if judge != nil {
		cfg.Judge = judge
		logger.Info("inline LLM judge enabled", "agent", agentID, "model", pol.Judge.Model)
	}

	p, err := proxy.New(cfg)
	if err != nil {
		return err
	}

	// Start admin + dashboard HTTP server.
	adminMux := http.NewServeMux()
	adminSrv := admin.NewServer(secretProvider)
	dashSrv := dashboard.NewServer(store, pol, secretProvider)
	if mcpGW != nil {
		dashSrv.SetMCPProvider(mcpGW)
	}
	adminMux.Handle("/healthz", adminSrv.Handler())
	adminMux.Handle("/admin/", adminSrv.Handler())
	adminMux.Handle("/dashboard/", dashSrv.Handler())
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
