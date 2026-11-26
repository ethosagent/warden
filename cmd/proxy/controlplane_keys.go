package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/internal/keys"
)

// newControlPlaneKeysCmd builds `warden control-plane keys`: list, rotate,
// export and reset a state dir's signing keys directly on its database and
// key store, as the token CLI does, so rotation needs no console session.
// list, rotate and export work with the control plane running or stopped (a
// running one picks a change up within about 2 seconds); reset takes the
// state dir's instance lock and refuses while the control plane holds it.
// It stays thin (rule C1): flag parsing only; the store, the audit rows and
// the rotation live in internal/controlplane.
func newControlPlaneKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "List, rotate, export and reset the control plane's signing keys offline.",
		Long: "Manage the signing keys of a control-plane state dir directly in " +
			"<state-dir>/warden-cp.db and the key store, with the control plane running or " +
			"stopped (a running one picks a change up within about 2 seconds). Every output " +
			"is public metadata only — never a private key. Writes append to the admin audit " +
			"log as auth_method cli when admin audit is enabled in the state dir.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErr(fmt.Errorf("keys needs a subcommand: list, rotate, export or reset"))
		},
	}
	cmd.AddCommand(newKeysListCmd(), newKeysRotateCmd(), newKeysExportCmd(), newKeysResetCmd())
	quiet(cmd)
	return cmd
}

// Exit codes of the keys commands: a failure that changed nothing exits 1
// (the default), a usage error exits 2 (usageErr), and a standing emergency
// rotation exits exitKeysRotationStood.
const exitKeysRotationStood = 3

// keysFlags adds the flags every keys subcommand shares. --config is the
// operator-owned file carrying the keys: block; without it the keys defaults
// apply (the file store under <state-dir>/keys and the default timings).
func keysFlags(cmd *cobra.Command) {
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required)")
	cmd.Flags().String("config", "", "operator config file carrying the keys: block (default: the keys defaults)")
	_ = cmd.MarkFlagRequired("state-dir")
}

// keysPurposeFlag reads and validates --purpose against the valid purposes.
// allowEmpty accepts the flag's absence, meaning every purpose (list only).
func keysPurposeFlag(cmd *cobra.Command, allowEmpty bool) (string, error) {
	purpose, _ := cmd.Flags().GetString("purpose")
	if purpose == "" && allowEmpty {
		return "", nil
	}
	if !keys.ValidPurpose(purpose) {
		return "", fmt.Errorf("--purpose %q is not one of %s", purpose, strings.Join(keys.Purposes(), ", "))
	}
	return purpose, nil
}

// keysOptions is the shared KeysCLIOptions of the subcommands.
func keysOptions(configPath, keyFile string) controlplane.KeysCLIOptions {
	return controlplane.KeysCLIOptions{ConfigPath: configPath, AuditKeyFile: keyFile}
}

// noticeNoAudit prints the audit notice the writable commands share.
func noticeNoAudit(cmd *cobra.Command, o *controlplane.OfflineKeys, stateDir string) {
	if !o.AuditEnabled() {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "admin audit is not enabled in "+stateDir+"; no audit row appended")
	}
}

func newKeysListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List signing keys (public metadata only).",
		Long: "List the signing keys of a state dir, oldest first: kid, purpose, state and " +
			"lifecycle times — public metadata only, never key material. --jwks prints the " +
			"published key set instead (what verifiers fetch for token, what workers pin for " +
			"bundle): purpose's own document with --purpose, one document per purpose without.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			configPath, _ := f.GetString("config")
			purpose, err := keysPurposeFlag(cmd, true)
			if err != nil {
				return usageErr(err)
			}
			jwks, _ := f.GetBool("jwks")
			asJSON, _ := f.GetBool("json")
			o, err := controlplane.OpenKeysOfflineReadOnly(cmd.Context(), stateDir, keysOptions(configPath, ""))
			if err != nil {
				return usageErr(err)
			}
			defer func() { _ = o.Close() }()
			ctx := cmd.Context()
			if jwks {
				purposes := keys.Purposes()
				if purpose != "" {
					purposes = []string{purpose}
				}
				docs := make(map[string]keys.JWKS, len(purposes))
				for _, p := range purposes {
					doc, err := o.JWKS(ctx, p)
					if err != nil {
						return usageErr(err)
					}
					if len(doc.Keys) > 0 {
						docs[p] = doc
					}
				}
				return controlplane.WriteKeysJWKS(cmd.OutOrStdout(), docs, purpose)
			}
			var rows []keys.Record
			if purpose == "" {
				rows, err = o.List(ctx)
			} else {
				rows, err = o.Rows(ctx, purpose)
			}
			if err != nil {
				return usageErr(err)
			}
			return controlplane.WriteKeysList(cmd.OutOrStdout(), rows, asJSON)
		},
	}
	keysFlags(cmd)
	cmd.Flags().String("purpose", "", "only this purpose: token, bundle or ca")
	cmd.Flags().Bool("jwks", false, "print the published key set (JWKS) instead of the rows")
	cmd.Flags().Bool("json", false, "print JSON instead of a table")
	quiet(cmd)
	return cmd
}

func newKeysRotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate a purpose's signing key (token; bundle is --stage then --activate).",
		Long: "Promote a purpose's published next key to the signing slot and publish a " +
			"fresh next key. The control plane picks the change up within about 2 seconds, " +
			"and verifiers already hold the new key (it was published one prepublish window " +
			"ahead). --emergency promotes at once, past the prepublish window, and revokes " +
			"the old key instead of retiring it: tokens it signed stop verifying once " +
			"verifiers refresh — on a non-interactive stdin it refuses without --yes. The " +
			"bundle purpose rotates only in two steps, because workers pin its keys out of " +
			"band: --stage makes the control plane sign every envelope with both the active " +
			"and the next key (a worker pinning either verifies it); --activate then makes " +
			"the next key the only signer and keeps the old one published for keys.bundle.overlap. " +
			"--activate is refused, naming the proxy ids, unless every online worker reports " +
			"the next kid in its heartbeat pinnedKids, which it reads from the running control " +
			"plane (--admin-url, an API key with the traffic:read scope in --api-key-file or " +
			"$WARDEN_API_KEY); --force overrides that and writes the missing ids to the audit " +
			"row. Without --stage or --activate the bundle purpose is refused and the next " +
			"key to pin is named (see docs/runbooks/key-rotation.md).",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			configPath, _ := f.GetString("config")
			purpose, err := keysPurposeFlag(cmd, false)
			if err != nil {
				return usageErr(err)
			}
			if purpose == keys.PurposeCA {
				return usageErr(fmt.Errorf("the ca key is imported, not rotated (warden control-plane keys reset --purpose ca clears it)"))
			}
			emergency, _ := f.GetBool("emergency")
			yes, _ := f.GetBool("yes")
			keyFile, _ := f.GetString("admin-audit-key-file")
			stage, _ := f.GetBool("stage")
			unstage, _ := f.GetBool("unstage")
			activate, _ := f.GetBool("activate")
			force, _ := f.GetBool("force")
			if err := checkRotateSteps(purpose, stage, unstage, activate, force, emergency); err != nil {
				return usageErr(err)
			}
			if emergency && !yes {
				if !stdinIsTerminal(os.Stdin) {
					return usageErr(errors.New("--emergency also needs --yes on a non-interactive stdin (it revokes the current key at once)"))
				}
				ok, err := confirmYes(cmd, "Emergency rotation revokes the current "+purpose+
					" key at once: in-flight tokens it signed stop verifying once verifiers refresh. Type yes to continue")
				if err != nil {
					return err
				}
				if !ok {
					return usageErr(errors.New("aborted; nothing changed"))
				}
			}
			opt := keysOptions(configPath, keyFile)
			opt.Logger = slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
			var workers controlplane.WorkersSource
			if activate {
				var err error
				if workers, err = workersFromFlags(cmd); err != nil {
					return usageErr(err)
				}
			}
			o, err := controlplane.OpenKeysOffline(cmd.Context(), stateDir, opt)
			if err != nil {
				return usageErr(err)
			}
			defer func() { _ = o.Close() }()
			noticeNoAudit(cmd, o, stateDir)
			switch {
			case stage:
				return runBundleStage(cmd, o)
			case unstage:
				return runBundleUnstage(cmd, o)
			case activate:
				return runBundleActivate(cmd, o, controlplane.ActivateBundleOptions{Workers: workers, Force: force, Emergency: emergency})
			}
			res, err := o.Rotate(cmd.Context(), purpose, emergency)
			if err != nil {
				if errors.Is(err, keys.ErrRotationStood) {
					// The promotion committed, so this is not a failed
					// rotation but a standing one with recovery left: say
					// what stands, and exit 3 so a script can tell it from a
					// refusal that changed nothing.
					if emergency {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
							"the %s emergency rotation stood: the compromised key IS revoked and its signatures stop verifying as verifiers refresh; "+
								"only the fresh next key is missing — the control plane's scheduler republishes one, `keys list` shows when it is there\n", purpose)
					} else {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
							"the %s rotation stood: the old key was retired and the next key signs, but the fresh next key is missing — "+
								"the control plane's scheduler republishes one, `keys list` shows when it is there\n", purpose)
					}
					return &exitError{code: exitKeysRotationStood, err: err}
				}
				// The staged bundle refusal is a clean outcome, not a failure of
				// the command: main prints its next-kid-to-pin message and exits 1.
				return err
			}
			line := "rotation complete: " + purpose + " now signs with " + res.KID +
				"; the previous key stays published for its overlap window"
			if emergency {
				line = "emergency rotation complete: " + purpose + " now signs with " + res.KID +
					"; the previous key is revoked and out of the published set"
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
			return nil
		},
	}
	keysFlags(cmd)
	cmd.Flags().String("purpose", "", "the purpose to rotate: token, or bundle with --stage or --activate (required)")
	cmd.Flags().Bool("stage", false, "bundle: sign every envelope with both the active and the next key (creates the next key if missing)")
	cmd.Flags().Bool("unstage", false, "bundle: stop signing with the staged next key (recovery when its material is lost; works without it)")
	cmd.Flags().Bool("activate", false, "bundle: make the staged next key the only signer; needs every online worker to report it pinned")
	cmd.Flags().Bool("force", false, "bundle --activate: go on although workers lack the next kid or their pins cannot be read (audited)")
	cmd.Flags().String("admin-url", "", "bundle --activate: base URL of the running control plane, for the workers' heartbeat pins")
	cmd.Flags().String("api-key-file", "", "bundle --activate: file holding an API key with the traffic:read scope (default: $WARDEN_API_KEY)")
	cmd.Flags().String("ca-cert", "", "bundle --activate: PEM certificate authority of --admin-url, added to the system roots")
	cmd.Flags().Bool("emergency", false, "promote the next key at once and revoke the current one instead of retiring it (bundle: with --activate)")
	cmd.Flags().Bool("yes", false, "confirm an emergency rotation (required with --emergency on a non-interactive stdin)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	quiet(cmd)
	return cmd
}

// checkRotateSteps validates the staged-rotation flags: --stage and --activate
// are the bundle purpose's steps, exclusive of each other, and --force goes with
// --activate only.
func checkRotateSteps(purpose string, stage, unstage, activate, force, emergency bool) error {
	switch {
	case stage && activate, unstage && (stage || activate):
		return errors.New("--stage, --unstage and --activate are separate steps: stage, pin, then activate")
	case (stage || unstage || activate) && purpose != keys.PurposeBundle:
		return fmt.Errorf("--stage, --unstage and --activate are for --purpose bundle; %s rotates in one step", purpose)
	case unstage && emergency:
		return errors.New("--emergency goes with --activate; an unstage only takes a signature away")
	case force && !activate:
		return errors.New("--force overrides the pin check of --activate")
	case stage && emergency:
		return errors.New("--emergency goes with --activate (it promotes the next key at once); a stage only adds a signature")
	}
	return nil
}

// maxFleetBody caps the fleet list the activate gate reads (a few KiB a worker).
const maxFleetBody = 8 << 20

// checkAdminURL refuses an --admin-url that would send the API key in clear
// text over a network: https always, http only to a loopback host.
func checkAdminURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("--admin-url is not a valid URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errors.New("--admin-url must be https (http only for localhost or a loopback address): the API key is sent with every request")
}

// workersFromFlags builds the activate gate's view of the fleet from
// --admin-url and the API key. Without --admin-url the source is nil, and the
// gate refuses unless --force is given.
func workersFromFlags(cmd *cobra.Command) (controlplane.WorkersSource, error) {
	f := cmd.Flags()
	adminURL, _ := f.GetString("admin-url")
	if adminURL == "" {
		return nil, nil
	}
	if err := checkAdminURL(adminURL); err != nil {
		return nil, err
	}
	keyFile, _ := f.GetString("api-key-file")
	ca, _ := f.GetString("ca-cert")
	key := strings.TrimSpace(os.Getenv("WARDEN_API_KEY"))
	if keyFile != "" {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("--api-key-file: %w", err)
		}
		key = strings.TrimSpace(string(raw))
	}
	if key == "" {
		return nil, errors.New("--admin-url needs an API key with the traffic:read scope: --api-key-file or $WARDEN_API_KEY")
	}
	client, err := identityclient.NewCPHTTPClientCapped(ca, maxFleetBody)
	if err != nil {
		return nil, fmt.Errorf("--ca-cert: %w", err)
	}
	return controlplane.AdminAPIWorkers(client, adminURL, key)
}

// runBundleStage is `keys rotate --purpose bundle --stage`.
func runBundleStage(cmd *cobra.Command, o *controlplane.OfflineKeys) error {
	res, err := o.StageBundle(cmd.Context())
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if res.Already {
		_, _ = fmt.Fprintf(out, "already staged: bundle signs with %s and %s; nothing changed\n", res.ActiveKID, res.NextKID)
		return nil
	}
	_, _ = fmt.Fprintf(out, "staged: the control plane signs every bundle with %s (active) and %s (next) within about 2 seconds.\n"+
		"Workers pinning either key verify them. Pin %s on every worker (keys export --purpose bundle), "+
		"wait for them to report it, then run keys rotate --purpose bundle --activate.\n", res.ActiveKID, res.NextKID, res.NextKID)
	return nil
}

// runBundleUnstage is `keys rotate --purpose bundle --unstage`.
func runBundleUnstage(cmd *cobra.Command, o *controlplane.OfflineKeys) error {
	res, err := o.UnstageBundle(cmd.Context())
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	switch {
	case res.Already:
		_, _ = fmt.Fprintln(out, "nothing is staged; nothing changed")
	case res.Dropped:
		_, _ = fmt.Fprintf(out, "unstaged: the staged key %s could not be loaded, so it was dropped; the control plane signs with the active key alone and publishes a fresh next key. "+
			"Workers pinned only to %s must be re-pinned to the active key.\n", res.NextKID, res.NextKID)
	default:
		_, _ = fmt.Fprintf(out, "unstaged: the control plane signs with the active key alone within about 2 seconds; %s is a plain next key again. "+
			"Workers pinned only to %s must be re-pinned to the active key.\n", res.NextKID, res.NextKID)
	}
	return nil
}

// runBundleActivate is `keys rotate --purpose bundle --activate`.
func runBundleActivate(cmd *cobra.Command, o *controlplane.OfflineKeys, opt controlplane.ActivateBundleOptions) error {
	res, err := o.ActivateBundle(cmd.Context(), opt)
	stderr := cmd.ErrOrStderr()
	if len(res.Report.Offline) > 0 {
		_, _ = fmt.Fprintf(stderr, "warning: %d known worker(s) are offline and do not report %s pinned; they reject bundles until pinned: %s\n",
			len(res.Report.Offline), res.KID, strings.Join(res.Report.Offline, ", "))
	}
	if err != nil {
		if errors.Is(err, keys.ErrRotationStood) {
			_, _ = fmt.Fprintf(stderr, "the bundle activation stood: %s signs and %s stopped, but publishing the fresh next key failed — "+
				"the control plane's scheduler republishes one, `keys list` shows when it is there\n", res.KID, res.Previous)
			return &exitError{code: exitKeysRotationStood, err: err}
		}
		return err
	}
	if res.Forced {
		missing := strings.Join(res.Report.Missing, ", ")
		if res.PinsUnread {
			missing = "the workers' pins could not be read"
		}
		_, _ = fmt.Fprintf(stderr, "forced: activated although %s; recorded in the admin audit log\n", missing)
	}
	line := "activated: the control plane now signs bundles with " + res.KID + " alone within about 2 seconds; " +
		res.Previous + " stays published for its overlap, so keep it pinned until then (keys export --purpose bundle lists what to pin)"
	if res.Emergency {
		line = "emergency activation complete: the control plane now signs bundles with " + res.KID +
			" alone; " + res.Previous + " is revoked and out of the published set — unpin it on every worker"
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
	return nil
}

func newKeysExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a purpose's public keys as a JWKS, or one key's public JWK.",
		Long: "Print public keys only. Without --state the output is the published key set " +
			"as a JWKS document — the exact content of controlPlane.bundleKeysFile for " +
			"--purpose bundle. --state next or --state active prints that one key's public " +
			"JWK instead, for staging a bundle key pin before the key activates. Private " +
			"keys never leave the key store.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			configPath, _ := f.GetString("config")
			purpose, err := keysPurposeFlag(cmd, false)
			if err != nil {
				return usageErr(err)
			}
			state, _ := f.GetString("state")
			if state != "" && state != string(keys.StateNext) && state != string(keys.StateActive) {
				return usageErr(fmt.Errorf("--state %q is not next or active", state))
			}
			o, err := controlplane.OpenKeysOfflineReadOnly(cmd.Context(), stateDir, keysOptions(configPath, ""))
			if err != nil {
				return usageErr(err)
			}
			defer func() { _ = o.Close() }()
			rows, err := o.Rows(cmd.Context(), purpose)
			if err != nil {
				return usageErr(err)
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if state != "" {
				for _, r := range rows {
					if string(r.State) == state {
						return enc.Encode(r.PublicJWK)
					}
				}
				return &exitError{code: 1, err: fmt.Errorf("keys: %s has no %s key (list shows what the state dir holds)", purpose, state)}
			}
			doc, err := o.JWKS(cmd.Context(), purpose)
			if err != nil {
				return usageErr(err)
			}
			if len(doc.Keys) == 0 {
				return &exitError{code: 1, err: fmt.Errorf("keys: %s has no published key yet (start the control plane with keys.enabled to create one)", purpose)}
			}
			return enc.Encode(doc)
		},
	}
	keysFlags(cmd)
	cmd.Flags().String("purpose", "", "the purpose to export: token, bundle or ca (required)")
	cmd.Flags().String("state", "", "print one key's public JWK instead of the JWKS: next or active")
	quiet(cmd)
	return cmd
}

func newKeysResetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Delete and regenerate a purpose's signing keys.",
		Long: "Delete every key of one purpose — metadata rows and private material — and " +
			"generate a fresh active and next key (the ca purpose is only cleared; its key is " +
			"imported). This is the recovery after a restore that lost the key directory: " +
			"every old token or bundle signature stops verifying. It refuses while the " +
			"control plane holds the state dir's instance lock; stop the control plane " +
			"first. Requires --yes.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			stateDir, _ := f.GetString("state-dir")
			configPath, _ := f.GetString("config")
			purpose, err := keysPurposeFlag(cmd, false)
			if err != nil {
				return usageErr(err)
			}
			yes, _ := f.GetBool("yes")
			keyFile, _ := f.GetString("admin-audit-key-file")
			if !yes {
				return usageErr(errors.New("--yes is required: reset deletes every key of the purpose and old signatures stop verifying"))
			}
			o, err := controlplane.OpenKeysOffline(cmd.Context(), stateDir, keysOptions(configPath, keyFile))
			if err != nil {
				return usageErr(err)
			}
			defer func() { _ = o.Close() }()
			noticeNoAudit(cmd, o, stateDir)
			res, err := o.Reset(cmd.Context(), purpose)
			if err != nil {
				// The running-control-plane refusal is a clean outcome: main
				// prints it and exits 1.
				return err
			}
			if res.KID == "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed %d %s key(s); import a fresh ca key when ready\n", res.Removed, purpose)
				return nil
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed %d %s key(s); %s now signs with fresh key %s\n", res.Removed, purpose, purpose, res.KID)
			return nil
		},
	}
	keysFlags(cmd)
	cmd.Flags().String("purpose", "", "the purpose to reset: token, bundle or ca (required)")
	cmd.Flags().Bool("yes", false, "confirm the reset (required)")
	cmd.Flags().String("admin-audit-key-file", "", "admin audit signing key (default <state-dir>/cp-audit.key)")
	quiet(cmd)
	return cmd
}

// confirmYes asks the operator to type yes on an interactive stdin.
func confirmYes(cmd *cobra.Command, prompt string) (bool, error) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return false, usageErr(fmt.Errorf("aborted; nothing changed (%v)", err))
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}
