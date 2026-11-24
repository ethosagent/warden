package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/controlplane"
)

// newControlPlaneWorkerCmd builds `warden control-plane worker`: manage
// enrolled workers straight on <state-dir>/warden-cp.db. It stays thin (rule
// C1): flag parsing only; the revoke, the audit row and the index refresh live
// in internal/controlplane.
func newControlPlaneWorkerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Manage enrolled workers offline.",
	}
	cmd.AddCommand(newWorkerRevokeCmd())
	return cmd
}

func newWorkerRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a worker's certificates.",
		Long: "Revoke every unexpired certificate of --id (or only --serial), and its unused enrollment " +
			"tokens, directly in the control plane's state dir, with the control plane running or " +
			"stopped. A running control plane enforces it within about 2 seconds: the worker's next " +
			"request, renewal included, is a 401 and its held policy long-polls end. The worker keeps " +
			"its last-known-good policy and must re-enroll with a new token. Revoking again changes " +
			"nothing. A row is appended to the admin audit log as auth_method cli when admin audit is " +
			"enabled in the state dir. Exits 2 for an unknown worker or serial.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			id, _ := f.GetString("id")
			serial, _ := f.GetString("serial")
			keyFile, _ := f.GetString("admin-audit-key-file")
			o, err := controlplane.OpenWorkerCertsOffline(cmd.Context(), stateDir, keyFile)
			if err != nil {
				return err
			}
			defer func() { _ = o.Close() }()
			if !o.AuditEnabled() {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "admin audit is not enabled in "+stateDir+"; no audit row appended")
			}
			n, err := o.Revoke(cmd.Context(), id, serial)
			switch {
			case errors.Is(err, controlplane.ErrCertNotFound):
				return &exitError{code: 2, err: fmt.Errorf("no worker %q (or no such serial) in %s", id, stateDir)}
			case err != nil:
				return err
			case n == 0:
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no change: no unexpired, unrevoked certificate of %s\n", id)
			default:
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked %d certificate(s) of %s\n", n, id)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	f.String("id", "", "worker id to revoke (required)")
	f.String("serial", "", "revoke only this certificate serial (lowercase hex) of the worker")
	f.String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}
