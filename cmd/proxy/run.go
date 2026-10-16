package main

import (
	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/worker"
)

// explicitListenFlags returns the listen/ca-cert/ca-key/admin-listen values, each
// empty unless the flag was set on the command line (so config can supply it).
func explicitListenFlags(cmd *cobra.Command) (listen, caCert, caKey, admin string, err error) {
	get := func(name string) (string, error) {
		if !cmd.Flags().Changed(name) {
			return "", nil
		}
		return cmd.Flags().GetString(name)
	}
	if listen, err = get("listen"); err != nil {
		return
	}
	if caCert, err = get("ca-cert"); err != nil {
		return
	}
	if caKey, err = get("ca-key"); err != nil {
		return
	}
	admin, err = get("admin-listen")
	return
}

// runParams parses the run flags into worker.Params. The listener/CA fields carry
// only explicitly-set flags so config and defaults apply in the worker.
func runParams(cmd *cobra.Command) (worker.Params, error) {
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return worker.Params{}, err
	}
	listenAddr, caCert, caKey, adminAddr, err := explicitListenFlags(cmd)
	if err != nil {
		return worker.Params{}, err
	}
	dbPath, err := cmd.Flags().GetString("db")
	if err != nil {
		return worker.Params{}, err
	}
	localOnly, err := cmd.Flags().GetBool("local-only")
	if err != nil {
		return worker.Params{}, err
	}
	alertsDB, err := cmd.Flags().GetString("alerts-db")
	if err != nil {
		return worker.Params{}, err
	}
	return worker.Params{
		ConfigPath:   configPath,
		ListenAddr:   listenAddr,
		DBPath:       dbPath,
		CACert:       caCert,
		CAKey:        caKey,
		AdminAddr:    adminAddr,
		Version:      version,
		LocalOnly:    localOnly,
		AlertsDBPath: alertsDB,
	}, nil
}

// newRunCmd builds the `run` subcommand. Its RunE parses flags into
// worker.Params and hands off to internal/worker, which owns all assembly and
// the runtime loops. cmd/proxy stays thin: flag definitions + start.
func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Load config, wire dependencies, and start the proxy.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := runParams(cmd)
			if err != nil {
				return err
			}
			return worker.Run(cmd.Context(), cmd.OutOrStdout(), p)
		},
	}

	cmd.Flags().String("listen", config.DefaultListen, "loopback/pod-internal listen address (overrides config listen:)")
	cmd.Flags().String("db", "warden.db", "SQLite analytics database path")
	cmd.Flags().String("ca-cert", "", "path to proxy CA certificate for TLS termination (overrides config tls.caCert)")
	cmd.Flags().String("ca-key", "", "path to proxy CA private key for TLS termination (overrides config tls.caKey)")
	cmd.Flags().String("admin-listen", config.DefaultAdminListen, "admin + dashboard HTTP listen address (overrides config adminListen:)")
	cmd.Flags().Bool("local-only", false, "ignore the control plane and enforce local policy (standalone)")
	cmd.Flags().String("alerts-db", "", "sqlite alert-store DB path for --local-only (default: sibling of --db, named warden-alerts.db); ignored in managed/fleet mode")

	return cmd
}
