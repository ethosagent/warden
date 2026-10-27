package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
)

// Exit codes of the admin-audit commands: a chain that does not verify exits
// 1; a usage or I/O error (bad flag, missing state dir or database) exits 2.
const (
	exitAuditVerifyFailed = 1
	exitAuditUsage        = 2
)

// newAdminAuditCmd builds `warden control-plane admin-audit`: offline
// commands over the admin audit chain in <state-dir>/warden-cp.db. Both open
// the database read-only, read public keys from the chain itself, never load
// the signing key and write no audit row. It stays thin (rule C1): the logic
// lives in internal/adminaudit.
func newAdminAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin-audit",
		Short: "Verify or export the control plane's admin audit chain offline.",
		Long: "Offline commands over the signed, hash-chained admin audit log in " +
			"<state-dir>/warden-cp.db. They open the database read-only, take public keys " +
			"from the chain (so they work after a key change without any key file) and " +
			"never load the signing key. Safe to run with the control plane stopped or running.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErr(fmt.Errorf("admin-audit needs a subcommand: verify or export"))
		},
	}
	cmd.AddCommand(newAdminAuditVerifyCmd(), newAdminAuditExportCmd())
	quiet(cmd)
	return cmd
}

func newAdminAuditVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the admin audit chain and print the result as JSON.",
		Long: "Check seq continuity, prev_hash links, entry hashes, each signature under the " +
			"key its key_id names and that the key changes only at a segment_start entry, from " +
			"--from-seq (default 1) to the head. Prints {ok, checked, firstBadSeq, reason, headSeq, " +
			"headHash, lastVerifiedSeq}; exits 1 when the chain does not verify and 2 on a usage " +
			"or I/O error. --anchor seq:hash (a head seen earlier, hash in hex) also fails when the " +
			"newest rows were removed.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			fromSeq, _ := cmd.Flags().GetInt64("from-seq")
			anchorFlag, _ := cmd.Flags().GetString("anchor")
			if stateDir == "" {
				return usageErr(errors.New("--state-dir is required"))
			}
			if fromSeq < 0 {
				return usageErr(errors.New("--from-seq must be 1 or more"))
			}
			opts := adminaudit.VerifyOptions{FromSeq: fromSeq}
			if anchorFlag != "" {
				a, err := adminaudit.ParseAnchor(anchorFlag)
				if err != nil {
					return usageErr(err)
				}
				opts.Anchor = a
			}
			st, closeFn, err := adminaudit.OpenReadOnly(cmd.Context(), stateDir, controlplane.StateMigrations())
			if err != nil {
				return usageErr(err)
			}
			defer func() { _ = closeFn() }()
			res, err := st.VerifyAll(cmd.Context(), opts)
			if err != nil {
				return usageErr(err)
			}
			if err := printJSON(cmd, res.Report()); err != nil {
				return usageErr(err)
			}
			if !res.OK {
				return &exitError{code: exitAuditVerifyFailed,
					err: fmt.Errorf("admin audit chain verification failed at seq %d (%s)", res.FirstBadSeq, res.Reason)}
			}
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().Int64("from-seq", 0, "first seq to verify (default 1; earlier rows are trusted)")
	cmd.Flags().String("anchor", "", "a previously seen head as seq:hash (hex entry hash); fails if the chain no longer reaches it")
	quiet(cmd)
	return cmd
}

func newAdminAuditExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the admin audit chain to a JSONL file.",
		Long: "Write one keys record (every key_id with its public key and first seq) and " +
			"then every chained entry in seq order to --out, a new file created 0600 (an " +
			"existing file is never overwritten). The side-table sub and email are left out " +
			"unless --include-identity is set. Verify the file anywhere with no database.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			out, _ := cmd.Flags().GetString("out")
			withID, _ := cmd.Flags().GetBool("include-identity")
			if stateDir == "" || out == "" {
				return usageErr(errors.New("--state-dir and --out are required"))
			}
			st, closeFn, err := adminaudit.OpenReadOnly(cmd.Context(), stateDir, controlplane.StateMigrations())
			if err != nil {
				return usageErr(err)
			}
			defer func() { _ = closeFn() }()
			res, err := st.ExportFile(cmd.Context(), out, adminaudit.ExportOptions{IncludeIdentity: withID})
			if err != nil {
				return usageErr(err)
			}
			if err := printJSON(cmd, res); err != nil {
				return usageErr(err)
			}
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("out", "", "export file to create (required; must not exist)")
	cmd.Flags().Bool("include-identity", false, "also write each entry's actor sub and email (personal data; off by default)")
	quiet(cmd)
	return cmd
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	return enc.Encode(v)
}

// usageErr marks err as a usage or I/O error (exit 2).
func usageErr(err error) error { return &exitError{code: exitAuditUsage, err: err} }

// quiet makes main print the error once (cobra prints neither the error nor
// the usage) and maps flag errors to exit 2.
func quiet(c *cobra.Command) {
	c.SilenceUsage = true
	c.SilenceErrors = true
	c.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr(err) })
}

// usageArgs refuses positional arguments with exit 2.
func usageArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return usageErr(err)
	}
	return nil
}
