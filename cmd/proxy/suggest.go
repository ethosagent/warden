package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/policybuilder"
)

// newSuggestCmd builds the `policy suggest` subcommand.
func newSuggestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suggest",
		Short: "Generate policy suggestions from observed traffic.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			sinceStr, _ := cmd.Flags().GetString("since")
			minCount, _ := cmd.Flags().GetInt("min-count")
			dbPath, _ := cmd.Flags().GetString("db")

			// Parse --since duration.
			since, err := parseDuration(sinceStr)
			if err != nil {
				return fmt.Errorf("invalid --since value %q: %w", sinceStr, err)
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

			// Build suggestions.
			suggestions := policybuilder.Build(events, minCount)

			// Output.
			fmt.Fprint(cmd.OutOrStdout(), policybuilder.FormatYAML(suggestions))

			return nil
		},
	}

	cmd.Flags().String("since", "7d", "how far back to analyze (e.g. 7d, 30d, 24h)")
	cmd.Flags().Int("min-count", 5, "minimum event count for a suggestion")
	cmd.Flags().String("db", "warden.db", "SQLite analytics database path")

	return cmd
}
