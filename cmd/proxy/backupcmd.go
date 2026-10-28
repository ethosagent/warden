package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/controlplane"
)

// newBackupCmd builds `warden control-plane backup`: one backup set for a
// stopped control plane. It stays thin (rule C1): the lock, the stores and the
// runner are controlplane.RunOfflineBackup. It never opens the admin audit
// store and starts no server.
func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Write a backup set of a stopped control plane's state.",
		Long: "Take the state-dir lock, open the control plane's databases directly, write one " +
			"complete backup set under --backup-dir (the layout and manifest of the scheduled " +
			"backups) and print its path. It never deletes older sets. Exits 1 with \"control plane is running\" when a " +
			"control plane holds the state dir; use POST /dashboard/api/backup then, or stop it. " +
			"The set has no audit key fingerprint: this command never opens the admin audit store.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			analyticsDB, _ := cmd.Flags().GetString("analytics-db")
			alertsDB, _ := cmd.Flags().GetString("alerts-db")
			if stateDir == "" {
				return usageErr(errors.New("--state-dir is required"))
			}
			dir, _ := cmd.Flags().GetString("backup-dir")
			include, _ := cmd.Flags().GetStringSlice("backup-include")
			if dir == "" {
				return usageErr(errors.New("--backup-dir is required"))
			}
			// Schedule and retention belong to the running control plane; a
			// one-off set neither waits nor prunes (RunOfflineBackup keeps all).
			bc := controlplane.BackupConfig{
				Dir: dir, Include: include,
				Interval: controlplane.DefaultBackupInterval, Keep: controlplane.DefaultBackupKeep,
			}
			if err := bc.Validate(stateDir); err != nil {
				return usageErr(err)
			}
			res, err := controlplane.RunOfflineBackup(cmd.Context(), controlplane.OfflineBackupParams{
				StateDir: stateDir, Backup: bc, AnalyticsDB: analyticsDB, AlertsDB: alertsDB, Version: version,
			})
			if err != nil {
				return &exitError{code: 1, err: err}
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), res.Path)
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "the stopped control plane's state directory (required)")
	cmd.Flags().String("backup-dir", "", "directory to write the backup set under (required; must not be inside --state-dir)")
	cmd.Flags().StringSlice("backup-include", controlplane.DefaultBackupInclude, "what the set contains, from cp,alerts,config,fleet")
	cmd.Flags().String("analytics-db", "", "fleet analytics DB path, if the control plane used a non-default --analytics-db")
	cmd.Flags().String("alerts-db", "", "alert DB path, if the control plane used a non-default --alerts-db")
	quiet(cmd)
	return cmd
}
