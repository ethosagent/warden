package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/controlplane"
)

// exitUnknownBlockID is the exit code of `block remove` for an id that is not
// on the list.
const exitUnknownBlockID = 2

// newControlPlaneBlockCmd builds `warden control-plane block`: add, remove and
// list entries of the user block list in a state dir, with the control plane
// running or stopped. It stays thin (rule C1): validation, the store and the
// audit row live in internal/controlplane.
func newControlPlaneBlockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "block",
		Short: "Add, remove or list blocked users in a control-plane state dir.",
		Long: "Manage the user block list in <state-dir>/warden-cp.db without the console. " +
			"A running control plane serves a change to workers within a few seconds. " +
			"Write access to the state dir already allows policy changes, so these " +
			"commands carry no console identity; each write is recorded as cli:<os user> " +
			"in the admin audit log when admin audit is enabled in the state dir.",
	}
	cmd.AddCommand(newBlockAddCmd(), newBlockRemoveCmd(), newBlockListCmd())
	return cmd
}

// blockErr maps a store error to the process exit: 2 for an unknown id, 1 for
// everything else. The text is the store's, as in the admin API.
func blockErr(err error) error {
	if errors.Is(err, controlplane.ErrNotFound) {
		return &exitError{code: exitUnknownBlockID, err: err}
	}
	return err
}

func newBlockAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Block a user by Dex sub, email or both.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			keyFile, _ := cmd.Flags().GetString("admin-audit-key-file")
			sub, _ := cmd.Flags().GetString("sub")
			email, _ := cmd.Flags().GetString("email")
			reason, _ := cmd.Flags().GetString("reason")
			id, err := controlplane.RunBlockAdd(cmd.Context(), stateDir, keyFile,
				controlplane.BlockEntry{Sub: sub, Email: email, Reason: reason}, cmd.ErrOrStderr())
			if err != nil {
				return blockErr(err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), id)
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	cmd.Flags().String("sub", "", "Dex subject (exact match)")
	cmd.Flags().String("email", "", "email address (case-insensitive)")
	cmd.Flags().String("reason", "", "why the user is blocked (up to 512 bytes)")
	_ = cmd.MarkFlagRequired("state-dir")
	return cmd
}

func newBlockRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Unblock the entry with the given id.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			keyFile, _ := cmd.Flags().GetString("admin-audit-key-file")
			id, _ := cmd.Flags().GetString("id")
			if err := controlplane.RunBlockRemove(cmd.Context(), stateDir, keyFile, id, cmd.ErrOrStderr()); err != nil {
				return blockErr(err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "removed "+id)
			return nil
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	cmd.Flags().String("id", "", "id of the entry to remove (required)")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

// blockListJSON is one entry of `block list --json`.
type blockListJSON struct {
	ID        string `json:"id"`
	Sub       string `json:"sub,omitempty"`
	Email     string `json:"email,omitempty"`
	Reason    string `json:"reason,omitempty"`
	CreatedBy string `json:"createdBy,omitempty"`
	CreatedAt string `json:"createdAt"`
}

func newBlockListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List blocked users (opens the database read-only).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			stateDir, _ := cmd.Flags().GetString("state-dir")
			asJSON, _ := cmd.Flags().GetBool("json")
			entries, err := controlplane.ListBlockedOffline(cmd.Context(), stateDir)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				rows := make([]blockListJSON, 0, len(entries))
				for _, e := range entries {
					rows = append(rows, blockListJSON{
						ID: e.ID, Sub: e.Sub, Email: e.Email, Reason: e.Reason, CreatedBy: e.CreatedBy,
						CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339),
					})
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tSUB\tEMAIL\tCREATED\tBY\tREASON")
			for _, e := range entries {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.Sub, e.Email,
					e.CreatedAt.UTC().Format(time.RFC3339), e.CreatedBy, e.Reason)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().Bool("json", false, "write the list as JSON")
	_ = cmd.MarkFlagRequired("state-dir")
	return cmd
}
