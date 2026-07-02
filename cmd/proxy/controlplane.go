package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/integration"
	_ "github.com/ethosagent/warden/internal/integration/webhook" // register the webhook sink
	"github.com/ethosagent/warden/internal/observability"
)

// newControlPlaneCmd builds the `control-plane` subcommand. The control plane
// serves allow/deny policy to data-plane workers and aggregates their analytics
// for a fleet dashboard. It is the same binary as the worker but a distinct
// role and process, so it can later be deployed on a separate host with no code
// change. It deliberately serves policy ONLY — secrets never cross this boundary.
func newControlPlaneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control-plane",
		Short: "Serve allow/deny policy to workers and aggregate fleet analytics.",
		Long: "Run Warden as a control plane: it serves allow/deny policy to " +
			"data-plane workers (which pull and hot-reload it) and ingests their " +
			"analytics into a fleet dashboard. Policy only — secrets never cross " +
			"this boundary. Provide --ca-cert/--ca-key to serve HTTPS with a cert " +
			"minted from that CA (workers trust it via controlPlane.caCert).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			listenAddr, _ := cmd.Flags().GetString("listen")
			tokenEnv, _ := cmd.Flags().GetString("token-env")
			caCert, _ := cmd.Flags().GetString("ca-cert")
			caKey, _ := cmd.Flags().GetString("ca-key")
			tlsHost, _ := cmd.Flags().GetString("tls-host")
			stateDir, _ := cmd.Flags().GetString("state-dir")
			maxEvents, _ := cmd.Flags().GetInt("central-max-events")
			aProvider, _ := cmd.Flags().GetString("analytics-provider")
			aDB, _ := cmd.Flags().GetString("analytics-db")
			aRetention, _ := cmd.Flags().GetInt("analytics-retention-days")
			alertsDB, _ := cmd.Flags().GetString("alerts-db")
			return runControlPlane(cmd, cpOptions{
				configPath: configPath, listenAddr: listenAddr, tokenEnv: tokenEnv,
				caCert: caCert, caKey: caKey, tlsHost: tlsHost, stateDir: stateDir,
				maxEvents: maxEvents, analyticsProvider: aProvider, analyticsDB: aDB,
				retentionDays: aRetention, alertsDB: alertsDB,
			})
		},
	}
	cmd.Flags().String("listen", "0.0.0.0:7070", "control-plane HTTP(S) listen address")
	cmd.Flags().String("token-env", "", "env var holding the bearer token workers must present")
	cmd.Flags().String("ca-cert", "", "CA cert to mint the server TLS cert from (enables HTTPS)")
	cmd.Flags().String("ca-key", "", "CA key to mint the server TLS cert from")
	cmd.Flags().String("tls-host", "localhost,127.0.0.1", "comma-separated SANs for the minted server cert")
	cmd.Flags().String("state-dir", "", "writable directory for the served/editable config (enables dashboard editing; seeded once from --config). Empty = edit --config in place")
	cmd.Flags().Int("central-max-events", 0, "central analytics store retention cap (0 = default)")
	cmd.Flags().String("analytics-provider", "sqlite", "fleet analytics store: sqlite (default, persistent + Query Builder) | memory (ephemeral)")
	cmd.Flags().String("analytics-db", "", "sqlite fleet analytics DB path (default: <state-dir>/warden-fleet.db, else ./warden-fleet.db)")
	cmd.Flags().Int("analytics-retention-days", 30, "prune fleet analytics events older than N days (0 = keep forever)")
	cmd.Flags().String("alerts-db", "", "sqlite alert store DB path (default: sibling of the analytics DB, named warden-alerts.db)")
	return cmd
}

// cpOptions carries the resolved control-plane flags so runControlPlane keeps a
// readable signature as the option set grows.
type cpOptions struct {
	configPath, listenAddr, tokenEnv string
	caCert, caKey, tlsHost, stateDir string
	maxEvents                        int
	analyticsProvider, analyticsDB   string
	retentionDays                    int
	alertsDB                         string
}

func runControlPlane(cmd *cobra.Command, opts cpOptions) error {
	configPath, listenAddr, tokenEnv := opts.configPath, opts.listenAddr, opts.tokenEnv
	caCert, caKey, tlsHost, stateDir := opts.caCert, opts.caKey, opts.tlsHost, opts.stateDir
	maxEvents := opts.maxEvents
	// Resolve the SERVED path. With no --state-dir we serve+edit --config in place
	// (unchanged behavior). With --state-dir we serve+edit a writable copy seeded
	// once from --config, so the dashboard can persist edits even when --config is
	// a read-only mount and the container runs as a non-root user.
	servedPath := configPath
	seeded := false
	if stateDir != "" {
		servedPath = filepath.Join(stateDir, "config.yaml")
		var serr error
		seeded, serr = seedServedConfig(servedPath, configPath)
		if serr != nil {
			return fmt.Errorf("control-plane: %w", serr)
		}
	}

	// Validate the SERVED file up front so the control plane fails loudly on a
	// bad/corrupt config (incl. a corrupt persisted copy) rather than only when a
	// worker first polls.
	prov, err := config.NewLocalYAMLProvider(servedPath)
	if err != nil {
		return fmt.Errorf("control-plane: %w", err)
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		return err
	}
	logger, _ := observability.NewLogger(cmd.OutOrStdout(), pol.LogLevel, pol.LogFormat)

	if stateDir != "" {
		if seeded {
			logger.Info("control plane serving writable config", "served", servedPath, "seededFrom", configPath)
		} else {
			logger.Info("control plane serving writable config", "served", servedPath, "reused", true)
		}
	} else {
		logger.Info("control plane serving config in place", "served", servedPath)
	}

	// Dashboard policy/settings editing writes a temp file next to the served file
	// then atomic-renames it into place. If that directory is not writable the edit
	// fails at runtime; warn now (actionably) but keep serving — read/serve is fine.
	if dir := filepath.Dir(servedPath); !dirWritable(dir) {
		logger.Warn("control-plane: served-config directory is not writable; dashboard policy/settings editing will FAIL",
			"dir", dir,
			"hint", "pass --state-dir pointing at a writable, container-user-owned volume (e.g. /data) so the control plane can seed and edit a writable copy")
	}

	var token string
	if tokenEnv != "" {
		token = os.Getenv(tokenEnv)
		if token == "" {
			logger.Warn("control-plane: token-env set but empty; serving WITHOUT auth", "env", tokenEnv)
		}
	} else {
		logger.Warn("control-plane: no token configured; serving WITHOUT auth (set --token-env for production)")
	}

	// Build the fleet analytics store. sqlite (default) persists events and powers
	// the read-only Query Builder; memory is ephemeral. The DB path defaults under
	// --state-dir (a writable volume) when set, else the working directory.
	dbPath := opts.analyticsDB
	if dbPath == "" {
		if stateDir != "" {
			dbPath = filepath.Join(stateDir, "warden-fleet.db")
		} else {
			dbPath = "warden-fleet.db"
		}
	}
	store, err := analytics.NewFleetStore(analytics.FleetConfig{
		Provider:      opts.analyticsProvider,
		SQLitePath:    dbPath,
		RetentionDays: opts.retentionDays,
		MaxEvents:     maxEvents,
	})
	if err != nil {
		return fmt.Errorf("control-plane: analytics store: %w", err)
	}
	defer func() { _ = store.Close() }()
	if opts.analyticsProvider == "memory" {
		logger.Info("control plane analytics store", "provider", "memory", "persistent", false)
	} else {
		logger.Info("control plane analytics store", "provider", "sqlite", "db", dbPath, "retentionDays", opts.retentionDays)
	}

	// Alert store path: an explicit --alerts-db wins; otherwise a sibling of the
	// analytics DB (which already encodes --state-dir vs the working dir), named
	// warden-alerts.db. The CP builds no manager when no integrations are
	// configured, so this path is unused in that case.
	alertDBPath := opts.alertsDB
	if alertDBPath == "" {
		alertDBPath = filepath.Join(filepath.Dir(dbPath), "warden-alerts.db")
	}
	integrations := toInstanceConfigs(pol.Integrations)
	if len(integrations) > 0 {
		logger.Info("control plane integrations", "count", len(integrations), "alertsDB", alertDBPath)
	}

	// Build the WRITE-scoped secret store from the CP's OWN secretStore.backend.
	// echo/aws mount the /central/secrets endpoints; env/none return a nil store so
	// the endpoints stay unmounted — back-compatible. An aws backend with missing
	// ENV credentials fails fast here rather than silently disabling writes.
	secretStore, err := controlplane.NewSecretStore(pol.SecretStore, logger)
	if err != nil {
		return fmt.Errorf("control-plane: secret store: %w", err)
	}

	srv := controlplane.New(controlplane.Config{
		PolicyPath:   servedPath,
		Token:        token,
		MaxEvents:    maxEvents,
		Store:        store,
		Logger:       logger,
		Integrations: integrations,
		AlertDBPath:  alertDBPath,
		SecretStore:  secretStore,
	})

	httpSrv := &http.Server{
		Addr:    listenAddr,
		Handler: srv.Handler(),
		// ReadHeaderTimeout bounds request-header reads; WriteTimeout is left 0 so
		// long-poll responses (held up to ~60s) are never cut off mid-flight.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// TLS: mint a server cert from the provided CA so workers trust it via their
	// configured controlPlane.caCert. Both flags required together.
	haveCA := caCert != "" && caKey != ""
	if (caCert != "") != (caKey != "") {
		return fmt.Errorf("control-plane: both --ca-cert and --ca-key must be set together")
	}
	if haveCA {
		tlsCfg, tErr := controlplane.MintServerTLS(caCert, caKey, strings.Split(tlsHost, ","))
		if tErr != nil {
			return tErr
		}
		httpSrv.TLSConfig = tlsCfg
	} else {
		logger.Warn("control-plane: serving plain HTTP; workers require HTTPS for the policy pull (provide --ca-cert/--ca-key)")
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodic re-read so external edits to the policy file propagate to workers.
	srv.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		scheme := "http"
		if haveCA {
			scheme = "https"
		}
		logger.Info("control plane listening",
			"addr", listenAddr,
			"policy", scheme+"://"+listenAddr+"/policy",
			"dashboard", scheme+"://"+listenAddr+"/dashboard/")
		if haveCA {
			errCh <- httpSrv.ListenAndServeTLS("", "")
		} else {
			errCh <- httpSrv.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// seedServedConfig ensures servedPath exists, seeding it once from seedPath when
// absent. It returns (true, nil) when it created servedPath from the seed, and
// (false, nil) when servedPath already existed (so dashboard edits persist across
// restarts — that is the point of the writable volume). The seed copy is written
// 0600 in a 0700 directory: only the container user can read or edit the served
// config.
func seedServedConfig(servedPath, seedPath string) (bool, error) {
	if _, err := os.Stat(servedPath); err == nil {
		return false, nil // already present — keep persisted edits
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat served config %s: %w", servedPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(servedPath), 0o700); err != nil {
		return false, fmt.Errorf("create state dir %s: %w", filepath.Dir(servedPath), err)
	}
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		return false, fmt.Errorf("read seed config %s: %w", seedPath, err)
	}
	if err := os.WriteFile(servedPath, seed, 0o600); err != nil {
		return false, fmt.Errorf("write served config %s: %w", servedPath, err)
	}
	return true, nil
}

// toInstanceConfigs maps the CP-local integrations config onto the integration
// package's InstanceConfig, keeping internal/config free of an integration
// import (the mapping is trivial glue that belongs in the thin cmd layer). The
// opaque config map is passed through untouched; secrets inside it stay as
// ${ENV} strings and are expanded later by the integration at Start.
func toInstanceConfigs(insts []config.IntegrationInstance) []integration.InstanceConfig {
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

// dirWritable reports whether dir is writable by creating and removing a temp
// file in it. A non-existent dir or one the process cannot write to returns
// false. It is used to warn early when dashboard policy/settings editing (which
// writes a temp file next to the served config, then atomic-renames it) would
// fail at runtime.
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".warden-writecheck-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}
