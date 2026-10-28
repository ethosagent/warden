package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/controlplane"
)

// newControlPlaneTokenCmd builds `warden control-plane token`: create, list
// and revoke worker tokens straight on <state-dir>/warden-cp.db, with the
// control plane running or stopped. It stays thin (rule C1): flag parsing
// only; the store, the audit row and the plaintext handling live in
// internal/controlplane.
func newControlPlaneTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Create, list and revoke worker tokens offline.",
		Long: "Manage per-worker tokens directly in the control plane's state dir, with the " +
			"control plane running or stopped (a running one picks a change up within about " +
			"2 seconds). Create and revoke are appended to the admin audit log as auth_method " +
			"cli when admin audit is enabled in the state dir. The plaintext of a token is " +
			"shown once and is never logged.",
	}
	cmd.AddCommand(newTokenCreateCmd(), newTokenListCmd(), newTokenRevokeCmd())
	return cmd
}

func newTokenCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Mint a worker token, or register an operator-generated one.",
		Long: "Mint a worker token bound to one proxy id. The plaintext is printed once to " +
			"stdout, or written to --out (mode 0600) with only the id printed. --from-env and " +
			"--from-file register a value you generated (a wwt_ token) instead, so compose and " +
			"Kubernetes Secrets can supply tokens; the plaintext is then never printed. " +
			"Re-running with the same name and value changes nothing and exits 0; the same name " +
			"with a different value fails.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			name, _ := f.GetString("name")
			proxyID, _ := f.GetString("proxy-id")
			expires, _ := f.GetDuration("expires-in")
			fromEnv, _ := f.GetString("from-env")
			fromFile, _ := f.GetString("from-file")
			out, _ := f.GetString("out")
			keyFile, _ := f.GetString("admin-audit-key-file")

			if fromEnv != "" && fromFile != "" {
				return errors.New("--from-env and --from-file are mutually exclusive")
			}
			if f.Changed("expires-in") && expires <= 0 {
				return errors.New("--expires-in must be a positive duration such as 720h")
			}
			value, err := importedValue(fromEnv, fromFile)
			if err != nil {
				return err
			}
			o, err := controlplane.OpenWorkerTokensOffline(cmd.Context(), stateDir, keyFile)
			if err != nil {
				return err
			}
			defer func() { _ = o.Close() }()
			if !o.AuditEnabled() {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "admin audit is not enabled in "+stateDir+"; no audit row appended")
			}
			res, err := o.Create(cmd.Context(), controlplane.OfflineCreate{
				Name: name, ProxyID: proxyID, ExpiresIn: expires, Plaintext: value, OutFile: out,
			})
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			switch {
			case res.Unchanged:
				_, _ = fmt.Fprintf(w, "no change: token %s (%s) already registered\n", res.Token.ID, res.Token.Name)
			case res.Plaintext != "":
				// The plaintext alone on stdout, so $(...) captures it; the id goes to stderr.
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "created token "+res.Token.ID+" ("+res.Token.Name+"); the value below is shown once")
				_, _ = fmt.Fprintln(w, res.Plaintext)
			default:
				_, _ = fmt.Fprintf(w, "created token %s (%s)\n", res.Token.ID, res.Token.Name)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	f.String("name", "", "token name, 1-64 characters, unique (required)")
	f.String("proxy-id", "", "the one proxy id the token is bound to (required)")
	f.Duration("expires-in", 0, "token lifetime, e.g. 720h (default: never expires)")
	f.String("from-env", "", "register the wwt_ value in this environment variable instead of minting one")
	f.String("from-file", "", "register the wwt_ value in this file instead of minting one")
	f.String("out", "", "write the minted token to this new file (mode 0600) instead of stdout")
	f.String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("proxy-id")
	return cmd
}

// importedValue reads the operator-generated token from the named env var or
// file ("" when neither is set). The value is never echoed in an error.
func importedValue(fromEnv, fromFile string) (string, error) {
	var raw string
	switch {
	case fromEnv != "":
		raw = os.Getenv(fromEnv)
		if strings.TrimSpace(raw) == "" {
			return "", fmt.Errorf("--from-env: %s is unset or empty", fromEnv)
		}
	case fromFile != "":
		b, err := os.ReadFile(fromFile)
		if err != nil {
			return "", fmt.Errorf("--from-file: %w", err)
		}
		raw = string(b)
		if strings.TrimSpace(raw) == "" {
			return "", fmt.Errorf("--from-file: %s is empty", fromFile)
		}
	}
	return strings.TrimSpace(raw), nil
}

func newTokenListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List worker tokens (never their values).",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			asJSON, _ := cmd.Flags().GetBool("json")
			o, err := controlplane.OpenWorkerTokensOfflineReadOnly(cmd.Context(), stateDir)
			if err != nil {
				return err
			}
			defer func() { _ = o.Close() }()
			toks, err := o.List(cmd.Context())
			if err != nil {
				return err
			}
			return controlplane.WriteWorkerTokenList(cmd.OutOrStdout(), toks, asJSON)
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().Bool("json", false, "print JSON instead of a table")
	_ = cmd.MarkFlagRequired("state-dir")
	return cmd
}

func newTokenRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a worker token by id.",
		Long: "Revoke a worker token: its next request is a 401. Exits 2 for an unknown id. " +
			"Revoking a token that is already revoked changes nothing.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			id, _ := f.GetString("id")
			keyFile, _ := f.GetString("admin-audit-key-file")
			o, err := controlplane.OpenWorkerTokensOffline(cmd.Context(), stateDir, keyFile)
			if err != nil {
				return err
			}
			defer func() { _ = o.Close() }()
			if !o.AuditEnabled() {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "admin audit is not enabled in "+stateDir+"; no audit row appended")
			}
			tok, changed, err := o.Revoke(cmd.Context(), id)
			switch {
			case errors.Is(err, controlplane.ErrWorkerTokenNotFound):
				return &exitError{code: 2, err: fmt.Errorf("no worker token with id %q", id)}
			case err != nil:
				return err
			case !changed:
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no change: token %s (%s) is already revoked\n", tok.ID, tok.Name)
			default:
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked token %s (%s)\n", tok.ID, tok.Name)
			}
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("id", "", "id of the token to revoke, as `token list` shows it (required)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}
