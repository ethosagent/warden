package main

import (
	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/worker"
)

// newRunCmd builds the `run` subcommand. Its RunE parses flags into
// worker.Params and hands off to internal/worker, which owns all assembly and
// the runtime loops. cmd/proxy stays thin: flag definitions + start.
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
			return worker.Run(cmd.Context(), cmd.OutOrStdout(), worker.Params{
				ConfigPath: configPath,
				ListenAddr: listenAddr,
				DBPath:     dbPath,
				CACert:     caCert,
				CAKey:      caKey,
				AdminAddr:  adminAddr,
				Version:    version,
				LocalOnly:  localOnly,
			})
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
