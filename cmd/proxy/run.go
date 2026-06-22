package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/admin"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/proxy"
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

	store, err := analytics.NewSQLiteStore(dbPath, 0)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	p, err := proxy.New(proxy.Config{
		ListenAddr:       listenAddr,
		Policy:           policy.NewEvaluator(pol),
		Secrets:          secretProvider,
		Analytics:        store,
		PlaceholderNames: placeholders,
		CACertPath:       caCert,
		CAKeyPath:        caKey,
	})
	if err != nil {
		return err
	}

	// Start admin + dashboard HTTP server.
	adminMux := http.NewServeMux()
	adminSrv := admin.NewServer(secretProvider)
	dashSrv := dashboard.NewServer(store, pol, secretProvider)
	adminMux.Handle("/healthz", adminSrv.Handler())
	adminMux.Handle("/admin/", adminSrv.Handler())
	adminMux.Handle("/dashboard/", dashSrv.Handler())

	go func() {
		fmt.Fprintf(cmd.OutOrStdout(), "warden admin+dashboard on http://%s/dashboard/\n", adminAddr)
		if err := http.ListenAndServe(adminAddr, adminMux); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "admin server: %v\n", err)
		}
	}()

	fmt.Fprintf(cmd.OutOrStdout(), "warden proxy listening on %s\n", listenAddr)

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return p.Serve(ctx)
}
