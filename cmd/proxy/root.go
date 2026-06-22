package main

import "github.com/spf13/cobra"

// newRootCmd builds the root `warden` command and registers subcommands. The
// command tree stays thin: it only parses flags and delegates to wiring code.
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "warden",
		Short: "An agent egress guardrail proxy.",
		Long: "Warden wraps an untrusted LLM agent runtime so it is structurally " +
			"incapable of bypassing the guardrail: the only egress is through the " +
			"proxy, which enforces default-deny allow/deny policy on every call and " +
			"swaps placeholder tokens for real secrets at the network edge.",
	}

	rootCmd.PersistentFlags().String(
		"config",
		"configs/config.example.yaml",
		"path to the YAML config file (production: /etc/warden/config.yaml)",
	)

	rootCmd.AddCommand(newRunCmd())
	rootCmd.AddCommand(newVersionCmd())

	policyCmd := newPolicyCmd()
	policyCmd.AddCommand(newSuggestCmd())
	policyCmd.AddCommand(newEvalCmd())
	rootCmd.AddCommand(policyCmd)

	return rootCmd
}

// Execute runs the root command. main exits non-zero on a returned error.
func Execute() error {
	return newRootCmd().Execute()
}
