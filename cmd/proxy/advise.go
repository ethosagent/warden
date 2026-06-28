package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/llm"
	"github.com/ethosagent/warden/internal/llmpolicy"
)

// newAdviseCmd builds the `warden advise` subcommand. It runs the offline
// advisory mode: it reads recent events, asks the LLM advisor to recommend
// policy changes, and PRINTS them. It never mutates policy or config — advisory
// mode can only flag findings to humans for review.
func newAdviseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "advise",
		Short: "Analyze recent traffic and print LLM policy recommendations (read-only).",
		Long: "Reads recent analytics events and asks the configured LLM to recommend " +
			"policy changes for human review. It is strictly advisory: it never " +
			"alters policy or configuration.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			sinceStr, _ := cmd.Flags().GetString("since")
			dbPath, _ := cmd.Flags().GetString("db")
			asJSON, _ := cmd.Flags().GetBool("json")

			since, err := parseDuration(sinceStr)
			if err != nil {
				return fmt.Errorf("invalid --since value %q: %w", sinceStr, err)
			}

			provider, err := config.NewLocalYAMLProvider(configPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			pol, err := provider.GetPolicy()
			if err != nil {
				return err
			}

			client, err := adviseClient(pol)
			if err != nil {
				return err
			}

			store, err := analytics.NewSQLiteStore(dbPath, 0)
			if err != nil {
				return fmt.Errorf("open analytics DB: %w", err)
			}
			defer func() { _ = store.Close() }()

			events, err := store.GetEvents(analytics.EventFilter{Since: time.Now().Add(-since)})
			if err != nil {
				return fmt.Errorf("get events: %w", err)
			}

			recs, err := llmpolicy.NewAdvisor(client).Analyze(events, pol)
			if err != nil {
				return fmt.Errorf("advisor: %w", err)
			}

			// TODO(hard-auto-rules): deterministic threshold-based auto-rules
			// (e.g. auto-denylist a domain after N blocked attempts/hour) are
			// out of scope for this pass and must run independently of the LLM.

			return printRecommendations(cmd, recs, asJSON)
		},
	}

	cmd.Flags().String("since", "7d", "how far back to analyze (e.g. 7d, 30d, 24h)")
	cmd.Flags().String("db", "warden.db", "SQLite analytics database path")
	cmd.Flags().Bool("json", false, "emit recommendations as JSON")

	return cmd
}

// adviseClient builds the LLM client from the judge config block (the shared
// LLM client config) and the API key from its env var. Advisory reuses the same
// provider/model so a single LLM is configured once.
func adviseClient(pol config.Policy) (*llm.Client, error) {
	j := pol.Judge
	if j.Model == "" || j.BaseURL == "" || j.APIKeyEnv == "" {
		return nil, fmt.Errorf("advise: judge.model, judge.baseURL and judge.apiKeyEnv must be configured to run the advisor")
	}
	apiKey := os.Getenv(j.APIKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("advise: env var %s is empty (it holds the LLM API key)", j.APIKeyEnv)
	}
	return llm.NewClient(llm.Config{
		BaseURL: j.BaseURL,
		Model:   j.Model,
		APIKey:  apiKey,
		Timeout: j.Timeout,
	})
}

// printRecommendations renders recommendations as text or JSON.
func printRecommendations(cmd *cobra.Command, recs []llmpolicy.Recommendation, asJSON bool) error {
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if recs == nil {
			recs = []llmpolicy.Recommendation{}
		}
		return enc.Encode(recs)
	}
	if len(recs) == 0 {
		fmt.Fprintln(out, "No recommendations.")
		return nil
	}
	fmt.Fprintf(out, "Advisory Recommendations (%d) — review only, nothing applied:\n", len(recs))
	for _, r := range recs {
		fmt.Fprintf(out, "  [%s] %s %s — %s\n", r.Severity, r.Type, r.Domain, r.Reason)
	}
	return nil
}
