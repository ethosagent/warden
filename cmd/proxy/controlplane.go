package main

import (
	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/controlplane"
)

// newControlPlaneCmd builds the `control-plane` subcommand. The control plane
// serves allow/deny policy to data-plane workers and aggregates their analytics
// for a fleet dashboard. It is the same binary as the worker but a distinct
// role and process, so it can later be deployed on a separate host with no code
// change. It deliberately serves policy ONLY — secrets never cross this boundary.
//
// This command stays thin (rule C1 in #349): it parses flags into
// controlplane.Params and hands them to controlplane.Run, which owns all the
// wiring. That seam is also how the L1 harness boots a real control plane
// in-process on an injected listener.
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
			requireConsoleAuth, _ := cmd.Flags().GetBool("require-console-auth")
			policyStore, _ := cmd.Flags().GetString("policy-store")
			auditKeyFile, _ := cmd.Flags().GetString("admin-audit-key-file")
			auditNewSegment, _ := cmd.Flags().GetString("admin-audit-new-segment")
			return controlplane.Run(cmd.Context(), cmd.OutOrStdout(), controlplane.Params{
				ConfigPath: configPath, ListenAddr: listenAddr, TokenEnv: tokenEnv,
				CACert: caCert, CAKey: caKey, TLSHost: tlsHost, StateDir: stateDir,
				MaxEvents: maxEvents, AnalyticsProvider: aProvider, AnalyticsDB: aDB,
				RetentionDays: aRetention, AlertsDB: alertsDB,
				RequireConsoleAuth: requireConsoleAuth,
				PolicyStore:        policyStore,
				AdminAuditKeyFile:  auditKeyFile, AdminAuditNewSegment: auditNewSegment,
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
	cmd.Flags().String("policy-store", controlplane.PolicyStoreFile, "where served policy comes from: file (default, the served YAML) | versioned (append-only versions in <state-dir>/warden-cp.db; requires --state-dir)")
	cmd.Flags().Bool("require-console-auth", false, "refuse to start unless console.auth is oidc (no open dashboard)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key; the HMAC key sits beside it); used when console.adminAudit.enabled")
	cmd.Flags().String("admin-audit-new-segment", "", "key_id of a new admin audit signing key: start a new chain segment for it (manual rotation; no-op once the chain head is on that key)")
	return cmd
}
