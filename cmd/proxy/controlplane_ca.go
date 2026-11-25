package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
)

// newControlPlaneCACmd builds `warden control-plane ca`: create the worker CA's
// root and intermediate (init) or the intermediate key and a CSR for an offline
// root (csr). It stays thin (rule C1): flag parsing only; the work lives in
// internal/controlplane. It never reads the proxy CA.
func newControlPlaneCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Create the worker CA (root, intermediate) or an intermediate CSR.",
		Long: "Create the worker CA that issues short-lived worker client certificates. " +
			"It is a separate trust root from the proxy MITM CA (--ca-cert), which it never reads.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErr(fmt.Errorf("ca needs a subcommand: init or csr"))
		},
	}
	cmd.AddCommand(newCAInitCmd(), newCACSRCmd())
	quiet(cmd)
	return cmd
}

// caSourceFlags adds the flags init and csr share.
func caSourceFlags(cmd *cobra.Command) {
	cmd.Flags().String("key-source", config.WorkerCAKeySourceKeys, "where the intermediate key lives: keys (the key manager; needs --state-dir) or file (development only)")
	cmd.Flags().String("state-dir", "", "control-plane state dir holding warden-cp.db (required for --key-source keys)")
	cmd.Flags().String("config", "", "operator config file carrying the keys: block (default: the keys defaults)")
	cmd.Flags().Bool("force", false, "replace existing files and an existing ca key")
}

func caOptions(cmd *cobra.Command) controlplane.CAOptions {
	f := cmd.Flags()
	src, _ := f.GetString("key-source")
	stateDir, _ := f.GetString("state-dir")
	configPath, _ := f.GetString("config")
	force, _ := f.GetBool("force")
	return controlplane.CAOptions{
		KeySource: src, StateDir: stateDir, ConfigPath: configPath, Force: force,
		Out: cmd.OutOrStdout(), ErrOut: cmd.ErrOrStderr(),
	}
}

func newCAInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the worker root and intermediate; store the intermediate key.",
		Long: "Create a P-256 root (10 years) and an intermediate (1 year, path length 0, " +
			"restricted to the trust domain). root.key is written to --out-dir at mode 0600: " +
			"move it offline and delete it from this host. intermediate-chain.pem is what " +
			"workerCA.certFile points at. The intermediate key goes to the key source. " +
			"Existing files and keys are never overwritten without --force.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			outDir, _ := f.GetString("out-dir")
			td, _ := f.GetString("trust-domain")
			err := controlplane.CAInit(cmd.Context(), controlplane.CAInitOptions{CAOptions: caOptions(cmd), OutDir: outDir, TrustDomain: td})
			if err != nil {
				return usageErr(err)
			}
			return nil
		},
	}
	caSourceFlags(cmd)
	cmd.Flags().String("out-dir", "", "directory for root.key, root.crt and intermediate-chain.pem (required)")
	cmd.Flags().String("trust-domain", "", "SPIFFE trust domain of worker identities, e.g. warden.local (required)")
	_ = cmd.MarkFlagRequired("out-dir")
	_ = cmd.MarkFlagRequired("trust-domain")
	return cmd
}

func newCACSRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Generate the intermediate key and print a CSR for an offline root.",
		Long: "Generate the intermediate key in the key source and print a certificate request " +
			"(PEM, public) on stdout for an offline root to sign. Install the signed chain at " +
			"workerCA.certFile.",
		Args: usageArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyFile, _ := cmd.Flags().GetString("key-file")
			if err := controlplane.CACSR(cmd.Context(), controlplane.CACSROptions{CAOptions: caOptions(cmd), KeyFile: keyFile}); err != nil {
				return usageErr(err)
			}
			return nil
		},
	}
	caSourceFlags(cmd)
	cmd.Flags().String("key-file", "", "where --key-source file writes the new key (mode 0600, outside --state-dir)")
	return cmd
}
