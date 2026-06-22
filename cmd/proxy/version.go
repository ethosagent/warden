package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is the build version. Overridable via -ldflags at build time.
var version = "0.0.0-dev"

// newVersionCmd builds the `version` subcommand, which prints the build version.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the warden version.",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "warden %s\n", version)
		},
	}
}
