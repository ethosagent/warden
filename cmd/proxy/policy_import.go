package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
)

// newPolicyImportCmd builds `warden policy import`: store a config YAML's
// policy, settings and llmProviders as a new version of the versioned policy
// store, with the control plane running or stopped. It stays thin (rule C1):
// validation, the compare-and-swap and the audit row live in
// internal/controlplane.
func newPolicyImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Create a policy version from a config YAML file.",
		Long: "Validate a config YAML file and store its policy, settings and llmProviders " +
			"blocks as a new version in <state-dir>/warden-cp.db. A running control plane in " +
			"--policy-store=versioned mode serves it within a few seconds. A credential value " +
			"in the file is stored only as its fingerprint. The import is appended to the " +
			"admin audit log when admin audit is enabled in the state dir.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			file, _ := cmd.Flags().GetString("file")
			message, _ := cmd.Flags().GetString("message")
			keyFile, _ := cmd.Flags().GetString("admin-audit-key-file")
			expected, _ := cmd.Flags().GetInt64("expected-head")
			ctx := cmd.Context()

			doc, err := controlplane.ValidatePolicyDocFile(file)
			if err != nil {
				return err
			}
			// Open the audit recorder first: a missing or mismatching key aborts
			// before anything is written.
			rec, closeAudit, err := adminaudit.OpenForCLI(ctx, stateDir, keyFile, controlplane.StateMigrations())
			if err != nil {
				return fmt.Errorf("admin audit: %w", err)
			}
			if closeAudit != nil {
				defer func() { _ = closeAudit() }()
			}
			st, err := controlplane.OpenPolicyStore(ctx, stateDir)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			if rec == nil {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "admin audit is not enabled in "+stateDir+"; no audit row appended")
			}
			res, err := st.Import(ctx, doc, message, expected, rec)
			if err != nil {
				return err
			}
			if !res.Changed {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no change: %s equals the head, version %d\n", file, res.Version)
				return nil
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "imported %s as version %d (parent %d)\n", file, res.Version, res.Parent)
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("file", "", "config YAML file to import (required)")
	cmd.Flags().String("message", "", "version message (default \"import from <file>\")")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	cmd.Flags().Int64("expected-head", -1, "import only if the head is still this version (default: the current head)")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

// newPolicyExportCmd builds `warden policy export`: write one version as a
// loadable config YAML to stdout, for a downgrade, disaster recovery or a
// GitOps hand-off. The database is opened read-only.
func newPolicyExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write a policy version as a config YAML to stdout.",
		Long: "Write the policy, settings and llmProviders blocks of one version of the " +
			"versioned policy store (default: the head) to stdout as a config YAML that the " +
			"loader accepts. Credential values and fingerprints are never written.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			version, _ := cmd.Flags().GetInt64("version")
			st, err := controlplane.OpenPolicyStoreReadOnly(cmd.Context(), stateDir)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			exp, err := st.Export(cmd.Context(), version)
			if err != nil {
				return err
			}
			if exp.CredentialOmitted {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
					"note: secretStore.aws.accessKeyId and secretAccessKey were left out; add them before serving or importing this file")
			}
			_, err = cmd.OutOrStdout().Write(exp.YAML)
			return err
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().Int64("version", 0, "version to export (default: the head)")
	_ = cmd.MarkFlagRequired("state-dir")
	return cmd
}
