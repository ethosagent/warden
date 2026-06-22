package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
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
			return runProxy(cmd, configPath, listenAddr, dbPath)
		},
	}

	cmd.Flags().String("listen", "127.0.0.1:8080", "loopback/pod-internal listen address")
	cmd.Flags().String("db", "warden.db", "SQLite analytics database path")

	return cmd
}

// runProxy loads config, wires dependencies behind their interfaces,
// constructs the proxy, and starts serving.
func runProxy(cmd *cobra.Command, configPath, listenAddr, dbPath string) error {
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
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "warden listening on %s\n", listenAddr)

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return p.Serve(ctx)
}
