package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
)

// Exit codes of the admin-audit commands: a refused operation (a chain that
// does not verify, a rotation while the control plane runs) exits 1; a usage
// or I/O error (bad flag, missing state dir or database) exits 2.
const (
	exitAuditFailed = 1
	exitAuditUsage  = 2
)

// newAdminAuditCmd builds `warden control-plane admin-audit`: offline
// commands over the admin audit chain in <state-dir>/warden-cp.db. verify and
// export open the database read-only, read public keys from the chain itself,
// never load the signing key and write no audit row; rotate-key signs with
// the current key and takes the state-dir lock. They stay thin (rule C1):
// the logic lives in internal/adminaudit.
func newAdminAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin-audit",
		Short: "Verify, export or rotate the control plane's admin audit chain offline.",
		Long: "Offline commands over the signed, hash-chained admin audit log in " +
			"<state-dir>/warden-cp.db. verify and export open the database read-only, take " +
			"public keys from the chain (so they work after a key change without any key " +
			"file) and never load the signing key: safe to run with the control plane " +
			"stopped or running. rotate-key changes the signing key and needs the control " +
			"plane stopped.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErr(fmt.Errorf("admin-audit needs a subcommand: verify, export or rotate-key"))
		},
	}
	cmd.AddCommand(newAdminAuditVerifyCmd(), newAdminAuditExportCmd(), newAdminAuditRotateKeyCmd())
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
				return &exitError{code: exitAuditFailed,
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

// newAdminAuditRotateKeyCmd builds `... admin-audit rotate-key`: the offline
// signing-key rotation (W-P2-KEYS-06). It signs the handover with the current
// key and takes the state-dir lock, so a running control plane is refused
// with exit 1; every other failure (bad path, chain not on the loaded key)
// is a usage error with exit 2.
func newAdminAuditRotateKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "Rotate the admin audit signing key (the control plane must be stopped).",
		Long: "Generate a new Ed25519 signing key and append one audit.key_rotated entry " +
			"signed by the current key handing the admin audit chain to it, then replace " +
			"--admin-audit-key-file with the new key and keep the old one beside it as " +
			"<key>.<old_key_id>.key.retired (0600), so backups taken before the rotation " +
			"still have their key. The HMAC key beside the key file does not change. " +
			"Prints {oldKeyID, newKeyID, seq, retiredPath, recovered}; exits 1 when the " +
			"control plane is running (the state-dir lock is held) and 2 on a usage or " +
			"I/O error. A run interrupted between the entry and the file swap is " +
			"completed by re-running the command.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			keyFile, _ := cmd.Flags().GetString(adminaudit.KeyFileFlag[2:])
			if stateDir == "" {
				return usageErr(errors.New("--state-dir is required"))
			}
			res, err := adminaudit.RotateKeyFile(cmd.Context(), stateDir, keyFile, controlplane.StateMigrations())
			if err != nil {
				if errors.Is(err, adminaudit.ErrControlPlaneRunning) {
					return &exitError{code: exitAuditFailed, err: err}
				}
				return usageErr(err)
			}
			return printJSON(cmd, res)
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String(adminaudit.KeyFileFlag[2:], "",
		"the signing key to rotate (default <state-dir>/"+adminaudit.DefaultKeyFileName+"; the retired key is kept beside it)")
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
