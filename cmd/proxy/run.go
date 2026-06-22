package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/secrets"
)

// newRunCmd builds the `run` subcommand. Its RunE loads config and wires the
// concrete phase-1 implementations behind their interfaces — wiring only, no
// business logic. Serving lands in M1.
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

// runProxy loads config, wires dependencies behind their interfaces, and
// constructs the proxy. Serving is added in M1.
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
		ListenAddr: listenAddr,
		Policy:     policy.NewEvaluator(pol),
		Secrets:    secretProvider,
		Analytics:  store,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "warden configured; listen=%s (serving lands in M1)\n", p.ListenAddr())
	return nil
}
