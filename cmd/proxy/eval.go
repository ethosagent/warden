package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policyeval"
)

// newEvalCmd builds the `policy eval` subcommand.
func newEvalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Replay events against a candidate policy and diff outcomes.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			candidatePath, _ := cmd.Flags().GetString("candidate")
			sinceStr, _ := cmd.Flags().GetString("since")
			dbPath, _ := cmd.Flags().GetString("db")

			// Parse --since duration (e.g. "30d", "7d", "24h").
			since, err := parseDuration(sinceStr)
			if err != nil {
				return fmt.Errorf("invalid --since value %q: %w", sinceStr, err)
			}

			// Load candidate policy.
			provider, err := config.NewLocalYAMLProvider(candidatePath)
			if err != nil {
				return fmt.Errorf("load candidate policy: %w", err)
			}
			candidate, err := provider.GetPolicy()
			if err != nil {
				return err
			}

			// Open analytics DB.
			store, err := analytics.NewSQLiteStore(dbPath, 0)
			if err != nil {
				return fmt.Errorf("open analytics DB: %w", err)
			}
			defer func() { _ = store.Close() }()

			// Get events.
			events, err := store.GetEvents(analytics.EventFilter{
				Since: time.Now().Add(-since),
			})
			if err != nil {
				return fmt.Errorf("get events: %w", err)
			}

			// Evaluate.
			result := policyeval.Evaluate(events, candidate)

			// Print report.
			fmt.Fprintf(cmd.OutOrStdout(), "Policy Evaluation Report\n")
			fmt.Fprintf(cmd.OutOrStdout(), "========================\n")
			fmt.Fprintf(cmd.OutOrStdout(), "Total events:  %d\n", result.TotalEvents)
			fmt.Fprintf(cmd.OutOrStdout(), "Agreed:        %d\n", result.Agreed)
			if result.TotalEvents > 0 {
				pct := float64(result.Agreed) / float64(result.TotalEvents) * 100
				fmt.Fprintf(cmd.OutOrStdout(), "Agreement:     %.1f%%\n", pct)
			}

			if len(result.NewAllows) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\nSecurity Regressions (was denied, now allowed):\n")
				for _, d := range result.NewAllows {
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s:%d %s (%d events, originally %s)\n",
						d.Domain, d.Port, d.Method, d.Count, d.Decision)
				}
			}

			if len(result.NewDenies) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\nAvailability Regressions (was allowed, now denied):\n")
				for _, d := range result.NewDenies {
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s:%d %s (%d events, originally %s)\n",
						d.Domain, d.Port, d.Method, d.Count, d.Decision)
				}
			}

			return nil
		},
	}

	cmd.Flags().String("candidate", "", "path to candidate policy YAML")
	cmd.Flags().String("since", "30d", "how far back to replay (e.g. 30d, 7d, 24h)")
	cmd.Flags().String("db", "warden.db", "SQLite analytics database path")
	_ = cmd.MarkFlagRequired("candidate")

	return cmd
}
