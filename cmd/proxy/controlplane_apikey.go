package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/controlplane"
)

// newControlPlaneAPIKeyCmd builds `warden control-plane api-key`: list and
// revoke the API keys of a state dir directly on its database, with the control
// plane running or stopped. It never creates a key and never prints a secret or
// a hash. It stays thin (rule C1): flag parsing, output and exit codes only; the
// store and the audit row live in internal/controlplane. Exit codes: 0 done
// (including a key that was already revoked), 1 a refusal that changed nothing
// or an audit failure after the revoke, 2 usage.
func newControlPlaneAPIKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api-key",
		Short: "List and revoke API keys offline.",
		Long: "List or revoke the API keys in <state-dir>/warden-cp.db without the console, " +
			"with the control plane running or stopped. A running control plane refuses a " +
			"revoked key within its 2 second database poll. The command takes no state-dir " +
			"lock, creates no key and never prints a key secret or its hash. Each revoke is " +
			"recorded as cli:<os user> in the admin audit log when admin audit is enabled " +
			"in the state dir.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErr(fmt.Errorf("api-key needs a subcommand: list or revoke"))
		},
	}
	cmd.AddCommand(newAPIKeyListCmd(), newAPIKeyRevokeCmd())
	quiet(cmd)
	return cmd
}

type apiKeyListJSON struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	OwnerSub   string   `json:"owner_sub"`
	OwnerEmail string   `json:"owner_email"`
	Scopes     []string `json:"scopes"`
	ExpiresAt  string   `json:"expires_at"`
	Status     string   `json:"status"`
}

func apiKeyTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func newAPIKeyListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API keys (opens the database read-only).",
		Args:  usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "state-dir"); err != nil {
				return err
			}
			stateDir, _ := cmd.Flags().GetString("state-dir")
			asJSON, _ := cmd.Flags().GetBool("json")
			keys, err := controlplane.ListAPIKeysOffline(cmd.Context(), stateDir)
			if err != nil {
				return &exitError{code: 1, err: err}
			}
			now := time.Now()
			rows := make([]apiKeyListJSON, 0, len(keys))
			for _, k := range keys {
				scopes := make([]string, len(k.Scopes))
				for i, s := range k.Scopes {
					scopes[i] = string(s)
				}
				rows = append(rows, apiKeyListJSON{
					ID: k.ID, Name: k.Name, OwnerSub: k.OwnerSub, OwnerEmail: k.OwnerEmail,
					Scopes: scopes, ExpiresAt: apiKeyTime(k.ExpiresAt), Status: string(k.StatusAt(now)),
				})
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tNAME\tOWNER\tSCOPES\tEXPIRES\tSTATUS")
			for _, r := range rows {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Name, r.OwnerEmail,
					strings.Join(r.Scopes, ","), r.ExpiresAt, r.Status)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().Bool("json", false, "write the list as JSON")
	quiet(cmd)
	return cmd
}

func newAPIKeyRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke one API key, or every key of an owner.",
		Long: "Revoke the key --id, or every unrevoked key of the owner --owner-sub, as " +
			"cli:<os user>. A key that is already revoked keeps its first revocation and is " +
			"reported, with no second audit row. Use it when the console is unusable: a leaked " +
			"key stops working within 2 seconds on a running control plane.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "state-dir"); err != nil {
				return err
			}
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			keyFile, _ := f.GetString("admin-audit-key-file")
			id, _ := f.GetString("id")
			sub, _ := f.GetString("owner-sub")
			if (id == "") == (sub == "") {
				return usageErr(errors.New("give exactly one of --id and --owner-sub"))
			}
			res, err := controlplane.RunAPIKeyRevoke(cmd.Context(), stateDir, keyFile,
				controlplane.APIKeyRevokeTarget{ID: id, OwnerSub: sub}, cmd.ErrOrStderr())
			if err != nil {
				if errors.Is(err, apikeys.ErrNotFound) {
					return &exitError{code: 1, err: fmt.Errorf("no API key with id %s", id)}
				}
				if len(res.Revoked) > 0 {
					printAPIKeyRevoked(cmd, res)
				}
				return &exitError{code: 1, err: err}
			}
			if res.Already {
				what := "that key is already revoked"
				if sub != "" {
					what = "the owner has no unrevoked keys"
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "nothing changed: %s\n", what)
				return nil
			}
			printAPIKeyRevoked(cmd, res)
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	cmd.Flags().String("id", "", "id of the key to revoke")
	cmd.Flags().String("owner-sub", "", "revoke every unrevoked key of this owner (identity-provider subject)")
	quiet(cmd)
	return cmd
}

func printAPIKeyRevoked(cmd *cobra.Command, res controlplane.APIKeyRevokeResult) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked %d key(s): %s\n", len(res.Revoked), strings.Join(res.Revoked, ", "))
}
