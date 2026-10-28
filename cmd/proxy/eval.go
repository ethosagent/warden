package main

import (
	"fmt"
	"strings"
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
		Long: `Replay recorded events against a candidate policy and diff the outcomes.

Each event replays with the user recorded on it, so group- and user-scoped allow
entries are evaluated and every regression lists the users it affects (email,
else sub; never tokens or group lists). Events without a valid recorded identity
replay as anonymous and are counted separately. The recorded groups are a
point-in-time snapshot: they are what the token carried then, not the user's
current IdP membership, and a recorded email replays as verified (the
event does not record email_verified). --user limits the replay to one user (sub or email).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			candidatePath, _ := cmd.Flags().GetString("candidate")
			sinceStr, _ := cmd.Flags().GetString("since")
			dbPath, _ := cmd.Flags().GetString("db")
			user, _ := cmd.Flags().GetString("user")

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

			// Shadow lint: warnings only, never a failure.
			for _, w := range config.LintScoped(candidate) {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", w)
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
				User:  user,
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
					printAffected(cmd, d)
				}
			}

			if len(result.NewDenies) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\nAvailability Regressions (was allowed, now denied):\n")
				for _, d := range result.NewDenies {
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s:%d %s (%d events, originally %s)\n",
						d.Domain, d.Port, d.Method, d.Count, d.Decision)
					printAffected(cmd, d)
				}
			}

			if result.AnonymousCount > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\nAnonymous events: %d (no valid recorded identity)\n", result.AnonymousCount)
			}

			return nil
		},
	}

	cmd.Flags().String("candidate", "", "path to candidate policy YAML")
	cmd.Flags().String("since", "30d", "how far back to replay (e.g. 30d, 7d, 24h)")
	cmd.Flags().String("db", "warden.db", "SQLite analytics database path")
	cmd.Flags().String("user", "", "replay only events of this user (sub or email, case-insensitive)")
	_ = cmd.MarkFlagRequired("candidate")

	return cmd
}

// printAffected prints the users behind one regression line.
func printAffected(cmd *cobra.Command, d policyeval.EvalDiff) {
	if d.AffectedUsersTotal == 0 {
		return
	}
	more := ""
	if d.AffectedUsersTotal > len(d.AffectedUsers) {
		more = fmt.Sprintf(" (+%d more)", d.AffectedUsersTotal-len(d.AffectedUsers))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "      Affected users: %s%s\n", strings.Join(d.AffectedUsers, ", "), more)
}
