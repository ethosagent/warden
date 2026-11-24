package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
)

// newControlPlaneEnrollTokenCmd builds `warden control-plane enroll-token`:
// create, list and revoke worker enrollment tokens (wet_) straight on
// <state-dir>/warden-cp.db, with the control plane running or stopped. It stays
// thin (rule C1): flag parsing only; the store, the audit row and the
// plaintext handling live in internal/controlplane.
func newControlPlaneEnrollTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll-token",
		Short: "Create, list and revoke worker enrollment tokens offline.",
		Long: "Manage the wet_ tokens a worker trades for a worker certificate at POST /control/enroll, " +
			"directly in the control plane's state dir, with the control plane running or stopped (a " +
			"running one picks a change up within about 2 seconds). Create and revoke are appended to " +
			"the admin audit log as auth_method cli when admin audit is enabled in the state dir. The " +
			"plaintext of a token is shown once and is never logged.",
	}
	cmd.AddCommand(newEnrollTokenCreateCmd(), newEnrollTokenListCmd(), newEnrollTokenRevokeCmd())
	return cmd
}

func newEnrollTokenCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Mint an enrollment token, or register an operator-generated one.",
		Long: "Mint a single-use token bound to --worker-id, or a token bound to --worker-id-prefix that " +
			"enrolls up to --max-uses workers (the worker sends a suffix; the id is prefix+suffix). The " +
			"plaintext is printed once to stdout, or written to --out (mode 0600). --from-env and " +
			"--from-file register a value you generated (a wet_ token) so compose and Kubernetes " +
			"Secrets can supply it; re-running with the same name and value changes nothing. The " +
			"lifetime defaults to workerCA.enrollTokenTTL and is capped by workerCA.enrollTokenMaxTTL " +
			"(read from --config when given).",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			name, _ := f.GetString("name")
			workerID, _ := f.GetString("worker-id")
			prefix, _ := f.GetString("worker-id-prefix")
			maxUses, _ := f.GetInt("max-uses")
			expires, _ := f.GetDuration("expires-in")
			fromEnv, _ := f.GetString("from-env")
			fromFile, _ := f.GetString("from-file")
			out, _ := f.GetString("out")
			keyFile, _ := f.GetString("admin-audit-key-file")
			configPath, _ := f.GetString("config")

			if fromEnv != "" && fromFile != "" {
				return errors.New("--from-env and --from-file are mutually exclusive")
			}
			if (workerID == "") == (prefix == "") {
				return errors.New("give exactly one of --worker-id and --worker-id-prefix")
			}
			if f.Changed("expires-in") && expires <= 0 {
				return errors.New("--expires-in must be a positive duration such as 1h")
			}
			value, err := importedValue(fromEnv, fromFile)
			if err != nil {
				return err
			}
			wc := config.DefaultWorkerCA()
			if configPath != "" {
				if wc, err = config.LoadWorkerCA(configPath); err != nil {
					return err
				}
			}
			o, err := controlplane.OpenEnrollTokensOffline(cmd.Context(), stateDir, keyFile, wc.EnrollTokenTTL, wc.EnrollTokenMaxTTL)
			if err != nil {
				return err
			}
			defer func() { _ = o.Close() }()
			if !o.AuditEnabled() {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "admin audit is not enabled in "+stateDir+"; no audit row appended")
			}
			res, err := o.Create(cmd.Context(), controlplane.OfflineEnrollCreate{
				Name: name, WorkerID: workerID, WorkerIDPrefix: prefix, MaxUses: maxUses,
				ExpiresIn: expires, Plaintext: value, OutFile: out,
			})
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			switch {
			case res.Unchanged:
				_, _ = fmt.Fprintf(w, "no change: enrollment token %s (%s) already registered\n", res.Token.ID, res.Token.Name)
			case res.Plaintext != "":
				// The plaintext alone on stdout, so $(...) captures it; the id goes to stderr.
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "created enrollment token "+res.Token.ID+" ("+res.Token.Name+"); the value below is shown once")
				_, _ = fmt.Fprintln(w, res.Plaintext)
			default:
				_, _ = fmt.Fprintf(w, "created enrollment token %s (%s)\n", res.Token.ID, res.Token.Name)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	f.String("worker-id", "", "bind the token to this one worker id")
	f.String("worker-id-prefix", "", "bind the token to worker ids starting with this prefix (replica pools)")
	f.Int("max-uses", 1, "how many workers may enroll with the token (1 to 100; above 1 only with --worker-id-prefix)")
	f.Duration("expires-in", 0, "token lifetime, e.g. 1h (default workerCA.enrollTokenTTL)")
	f.String("name", "", "token name, unique (default enroll-<worker id or prefix>)")
	f.String("from-env", "", "register the wet_ value in this environment variable instead of minting one")
	f.String("from-file", "", "register the wet_ value in this file instead of minting one")
	f.String("out", "", "write the minted token to this new file (mode 0600) instead of stdout")
	f.String("config", "", "operator config file carrying the workerCA: block (default: its defaults)")
	f.String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	_ = cmd.MarkFlagRequired("state-dir")
	return cmd
}

func newEnrollTokenListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List enrollment tokens (never their values).",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			asJSON, _ := cmd.Flags().GetBool("json")
			o, err := controlplane.OpenEnrollTokensOfflineReadOnly(cmd.Context(), stateDir)
			if err != nil {
				return err
			}
			defer func() { _ = o.Close() }()
			toks, err := o.List(cmd.Context())
			if err != nil {
				return err
			}
			return controlplane.WriteEnrollTokenList(cmd.OutOrStdout(), toks, asJSON)
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().Bool("json", false, "print JSON instead of a table")
	_ = cmd.MarkFlagRequired("state-dir")
	return cmd
}

func newEnrollTokenRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke an enrollment token by id.",
		Long: "Revoke an enrollment token: its next use at /control/enroll is a 401. Exits 2 for an " +
			"unknown id. Revoking a revoked token changes nothing. Certificates already issued stay valid.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			id, _ := f.GetString("id")
			keyFile, _ := f.GetString("admin-audit-key-file")
			o, err := controlplane.OpenEnrollTokensOffline(cmd.Context(), stateDir, keyFile, 0, 0)
			if err != nil {
				return err
			}
			defer func() { _ = o.Close() }()
			if !o.AuditEnabled() {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "admin audit is not enabled in "+stateDir+"; no audit row appended")
			}
			tok, changed, err := o.Revoke(cmd.Context(), id)
			switch {
			case errors.Is(err, controlplane.ErrEnrollNotFound):
				return &exitError{code: 2, err: fmt.Errorf("no enrollment token with id %q", id)}
			case err != nil:
				return err
			case !changed:
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no change: enrollment token %s (%s) is already revoked\n", tok.ID, tok.Name)
			default:
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked enrollment token %s (%s)\n", tok.ID, tok.Name)
			}
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("id", "", "id of the token to revoke, as `enroll-token list` shows it (required)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}
