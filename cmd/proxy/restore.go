package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/controlplane"
)

// newRestoreCmd builds `warden control-plane restore`: load one backup set into
// a stopped control plane's state dir. It stays thin (rule C1): the lock, the
// checks and the swap are controlplane.RunRestore. It starts no server.
func newRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a backup set into a stopped control plane's state dir, after verifying it.",
		Long: "Take the state-dir lock, then check the set (sha256 and size of every file against " +
			"manifest.json, SQLite integrity, schema version, the admin audit chain and the audit " +
			"key fingerprint) in a staging directory before touching the target. Replaced files " +
			"are kept under <state-dir>/pre-restore-<ts>/; stale -wal/-shm files are never replayed, " +
			"console sessions are cleared and the restore is appended to the admin audit chain as " +
			"cp.restore. Exits 1 with \"control plane is running\" when a control plane holds the " +
			"state dir. Restoring an old set can bring back revoked access: re-apply later " +
			"worker-token revocations, user blocks and policy versions from the shipped admin_audit log.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			from, _ := cmd.Flags().GetString("from")
			stateDir, _ := cmd.Flags().GetString("state-dir")
			if from == "" || stateDir == "" {
				return usageErr(errors.New("--from and --state-dir are required"))
			}
			analyticsDB, _ := cmd.Flags().GetString("analytics-db")
			alertsDB, _ := cmd.Flags().GetString("alerts-db")
			keyFile, _ := cmd.Flags().GetString("admin-audit-key-file")
			force, _ := cmd.Flags().GetBool("force")
			newKey, _ := cmd.Flags().GetBool("new-audit-key")
			res, err := controlplane.RunRestore(cmd.Context(), controlplane.RestoreParams{
				From: from, StateDir: stateDir, AnalyticsDB: analyticsDB, AlertsDB: alertsDB,
				AuditKeyFile: keyFile, Force: force, NewAuditKey: newKey,
			})
			if err != nil {
				if errors.Is(err, controlplane.ErrRestoreUnaudited) {
					printRestoreSummary(cmd, res)
				}
				return &exitError{code: 1, err: err}
			}
			printRestoreSummary(cmd, res)
			if !res.Audited {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "admin audit is not enabled in the restored state; no cp.restore row appended")
			}
			return nil
		},
	}
	cmd.Flags().String("from", "", "backup set directory (holds manifest.json) to restore (required)")
	cmd.Flags().String("state-dir", "", "the stopped control plane's state directory (required)")
	cmd.Flags().String("analytics-db", "", "fleet analytics DB path, if the control plane uses a non-default --analytics-db")
	cmd.Flags().String("alerts-db", "", "alert DB path, if the control plane uses a non-default --alerts-db")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key of the target (default <state-dir>/cp-audit.key)")
	cmd.Flags().Bool("force", false, "replace existing files in the state dir (they are kept under pre-restore-<ts>/)")
	cmd.Flags().Bool("new-audit-key", false, "accept a target audit key whose fingerprint differs from the backup's (recorded in the audit row)")
	quiet(cmd)
	return cmd
}

// printRestoreSummary prints what the restore did and what the operator must
// re-apply. It never prints file contents, tokens or key material.
func printRestoreSummary(cmd *cobra.Command, res controlplane.RestoreResult) {
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(w, "restored backup created at %s (warden %s)\n", res.CreatedAt.UTC().Format(time.RFC3339), res.WardenVersion)
	_, _ = fmt.Fprintf(w, "restored files: %s\n", strings.Join(res.Files, ", "))
	if res.PreRestoreDir != "" {
		_, _ = fmt.Fprintf(w, "replaced files kept in: %s\n", res.PreRestoreDir)
	}
	if res.NewAuditKey {
		_, _ = fmt.Fprintln(w, "the audit key fingerprint check was skipped (--new-audit-key)")
	}
	_, _ = fmt.Fprintf(w, "WARNING: worker-token revocations, user blocks and policy versions made after %s "+
		"are not in this backup; re-apply them from the admin_audit JSON log.\n", res.CreatedAt.UTC().Format(time.RFC3339))
}
