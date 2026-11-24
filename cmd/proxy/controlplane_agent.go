package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/controlplane"
)

// newControlPlaneAgentCmd builds `warden control-plane agent`: register,
// update, list, disable and enable agents of a state dir's registry directly
// on its database, with the control plane running or stopped (a running one
// picks a change up within about 2 seconds). It stays thin (rule C1): flag
// parsing and exit codes only; the store, the validator and the audit rows
// live in internal/agentreg and internal/controlplane. Exit codes: 0 done, 1 a
// refusal that changed nothing (validation, conflict, key in use, unknown
// id), 2 usage.
func newControlPlaneAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Register, update, list, disable and enable agents offline.",
		Long: "Manage the agent registry in <state-dir>/warden-cp.db without the console, " +
			"with the control plane running or stopped (a running one serves a change " +
			"within about 2 seconds). Only public keys are accepted; a file with a private " +
			"member is refused naming the field path. Output never includes JWK " +
			"coordinates. Each write is recorded as cli:<os user> in the admin audit log " +
			"when admin audit is enabled in the state dir.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErr(fmt.Errorf("agent needs a subcommand: register, update, list, disable or enable"))
		},
	}
	cmd.AddCommand(newAgentRegisterCmd(), newAgentUpdateCmd(), newAgentListCmd(),
		newAgentStatusCmd("disable", agentreg.StatusDisabled), newAgentStatusCmd("enable", agentreg.StatusActive))
	quiet(cmd)
	return cmd
}

// requireFlags is the usage check cobra's MarkFlagRequired would do, but
// exiting 2 like every other usage error.
func requireFlags(cmd *cobra.Command, names ...string) error {
	for _, n := range names {
		if !cmd.Flags().Changed(n) {
			return usageErr(fmt.Errorf("required flag --%s not set", n))
		}
	}
	return nil
}

func agentWriteFlags(cmd *cobra.Command) {
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
}

func agentContentFlags(cmd *cobra.Command) {
	cmd.Flags().StringArray("jwk-file", nil, "file with a public JWK or a JWKS; repeat for a second key (1 or 2 keys per agent)")
	cmd.Flags().StringSlice("groups", nil, "comma-separated user groups that may delegate to the agent")
	cmd.Flags().StringSlice("scopes", nil, "comma-separated scopes a delegation may carry")
	cmd.Flags().String("display-name", "", "human-readable name")
}

// agentOut prints the one-line result of a write.
func agentOut(cmd *cobra.Command, verb string, a agentreg.Agent) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s (revision %d)\n", verb, a.ID, a.Revision)
}

func newAgentRegisterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register an agent with its public key(s).",
		Args:  usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "state-dir", "id", "jwk-file"); err != nil {
				return err
			}
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			keyFile, _ := f.GetString("admin-audit-key-file")
			id, _ := f.GetString("id")
			files, _ := f.GetStringArray("jwk-file")
			groups, _ := f.GetStringSlice("groups")
			scopes, _ := f.GetStringSlice("scopes")
			name, _ := f.GetString("display-name")
			ks, err := controlplane.ReadAgentJWKFiles(files)
			if err != nil {
				return &exitError{code: 1, err: err}
			}
			a, err := controlplane.RunAgentRegister(cmd.Context(), stateDir, keyFile, agentreg.Agent{
				ID: id, DisplayName: name, Keys: ks, AllowedGroups: groups, AllowedScopes: scopes,
			}, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			agentOut(cmd, "registered", a)
			return nil
		},
	}
	agentWriteFlags(cmd)
	agentContentFlags(cmd)
	cmd.Flags().String("id", "", "agent id (required)")
	quiet(cmd)
	return cmd
}

func newAgentUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Change an agent's keys, groups, scopes or display name.",
		Long: "Change the fields whose flags are given; the others keep their value. " +
			"--jwk-file replaces the agent's whole key set (pass both keys during a rotation). " +
			"--revision is the revision `agent list` showed: a stale one is refused.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "state-dir", "id", "revision"); err != nil {
				return err
			}
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			keyFile, _ := f.GetString("admin-audit-key-file")
			id, _ := f.GetString("id")
			rev, _ := f.GetInt64("revision")
			var ch controlplane.AgentChange
			if f.Changed("jwk-file") {
				files, _ := f.GetStringArray("jwk-file")
				ks, err := controlplane.ReadAgentJWKFiles(files)
				if err != nil {
					return &exitError{code: 1, err: err}
				}
				ch.Keys = ks
			}
			if f.Changed("groups") {
				ch.Groups, _ = f.GetStringSlice("groups")
				ch.SetGroups = true
			}
			if f.Changed("scopes") {
				ch.Scopes, _ = f.GetStringSlice("scopes")
				ch.SetScopes = true
			}
			if f.Changed("display-name") {
				v, _ := f.GetString("display-name")
				ch.DisplayName = &v
			}
			if ch.Keys == nil && !ch.SetGroups && !ch.SetScopes && ch.DisplayName == nil {
				return usageErr(fmt.Errorf("nothing to update: give --jwk-file, --groups, --scopes or --display-name"))
			}
			a, err := controlplane.RunAgentUpdate(cmd.Context(), stateDir, keyFile, id, rev, ch, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			agentOut(cmd, "updated", a)
			return nil
		},
	}
	agentWriteFlags(cmd)
	agentContentFlags(cmd)
	cmd.Flags().String("id", "", "agent id (required)")
	cmd.Flags().Int64("revision", 0, "the agent's revision as `agent list` showed it (required)")
	quiet(cmd)
	return cmd
}

func newAgentStatusCmd(verb string, status agentreg.Status) *cobra.Command {
	past := verb + "d"
	cmd := &cobra.Command{
		Use:   verb,
		Short: strings.ToUpper(verb[:1]) + verb[1:] + " an agent.",
		Long: "Set the agent's status to " + string(status) + " if --revision is still the stored one. " +
			"A disabled agent keeps its row and keys; workers deny all traffic for it.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "state-dir", "id", "revision"); err != nil {
				return err
			}
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			keyFile, _ := f.GetString("admin-audit-key-file")
			id, _ := f.GetString("id")
			rev, _ := f.GetInt64("revision")
			a, err := controlplane.RunAgentSetStatus(cmd.Context(), stateDir, keyFile, id, status, rev, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			agentOut(cmd, past, a)
			return nil
		},
	}
	agentWriteFlags(cmd)
	cmd.Flags().String("id", "", "agent id (required)")
	cmd.Flags().Int64("revision", 0, "the agent's revision as `agent list` showed it (required)")
	quiet(cmd)
	return cmd
}

// agentListKey and agentListJSON are the public view of an agent in `list`:
// ids and an 8-character thumbprint prefix, never JWK coordinates.
type agentListKey struct {
	KID       string `json:"kid"`
	JKTPrefix string `json:"jkt_prefix"`
}

type agentListJSON struct {
	ID          string         `json:"id"`
	DisplayName string         `json:"display_name,omitempty"`
	Status      string         `json:"status"`
	Revision    int64          `json:"revision"`
	Groups      []string       `json:"groups"`
	Scopes      []string       `json:"scopes"`
	Keys        []agentListKey `json:"keys"`
	UpdatedAt   string         `json:"updated_at"`
	UpdatedBy   string         `json:"updated_by"`
}

func newAgentListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List agents (opens the database read-only).",
		Args:  usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "state-dir"); err != nil {
				return err
			}
			stateDir, _ := cmd.Flags().GetString("state-dir")
			asJSON, _ := cmd.Flags().GetBool("json")
			agents, err := controlplane.ListAgentsOffline(cmd.Context(), stateDir)
			if err != nil {
				return err
			}
			rows := make([]agentListJSON, 0, len(agents))
			for _, a := range agents {
				r := agentListJSON{
					ID: a.ID, DisplayName: a.DisplayName, Status: string(a.Status), Revision: a.Revision,
					Groups: nonNilStrings(a.AllowedGroups), Scopes: nonNilStrings(a.AllowedScopes),
					Keys:      make([]agentListKey, 0, len(a.Keys)),
					UpdatedAt: a.UpdatedAt.UTC().Format(time.RFC3339), UpdatedBy: a.UpdatedBy,
				}
				for _, k := range a.Keys {
					r.Keys = append(r.Keys, agentListKey{KID: k.KID, JKTPrefix: agentreg.ThumbprintPrefix(k.JKT)})
				}
				rows = append(rows, r)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tSTATUS\tREVISION\tKIDS\tJKT")
			for _, r := range rows {
				var kids, jkts []string
				for _, k := range r.Keys {
					kids = append(kids, k.KID)
					jkts = append(jkts, k.JKTPrefix)
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", r.ID, r.Status, r.Revision,
					strings.Join(kids, ","), strings.Join(jkts, ","))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().Bool("json", false, "write the list as JSON")
	quiet(cmd)
	return cmd
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
