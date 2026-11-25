package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/identityclient"
)

// agentFlags are the agent-mode values of the persistent flags.
func (r *identityRunner) agentFlags(scope string) identityclient.AgentFlags {
	return identityclient.AgentFlags{
		AgentID: r.f.agentID, KeyFile: r.f.agentKeyFile, TokenEndpoint: r.f.tokenEndpoint,
		CPCA: r.f.cpCA, SubjectTokenFile: r.f.subjectTokenFile, Scope: scope,
	}
}

// agentMode reports whether `token` and `status` use the Warden token.
func (r *identityRunner) agentMode() bool {
	return identityclient.AgentMode(r.agentFlags(""), r.deps.getenv)
}

// agentTokenSource builds the Warden token source of the configured agent. The
// subject is the --subject-token-file or the P1 login cache.
func (r *identityRunner) agentTokenSource(cmd *cobra.Command, scope string) (*identityclient.WardenTokenSource, error) {
	cfg, err := identityclient.LoadAgentConfig(r.agentFlags(scope), r.deps.getenv)
	if err != nil {
		return nil, err
	}
	var c *identityclient.Client
	if cfg.SubjectTokenFile == "" {
		if c, err = r.client(cmd); err != nil {
			return nil, err
		}
	}
	return cfg.NewTokenSource(cfg.SubjectFor(c), identityclient.AgentDeps{Log: r.logger(cmd)})
}

// agentToken exchanges once (with the library's retry of 429 and 503) and
// returns the Warden token.
func (r *identityRunner) agentToken(cmd *cobra.Command, scope string) (identityclient.WardenToken, error) {
	src, err := r.agentTokenSource(cmd, scope)
	if err != nil {
		return identityclient.WardenToken{}, err
	}
	return src.Token(cmd.Context())
}

func (r *identityRunner) agentStatus(cmd *cobra.Command, scope string) error {
	tok, err := r.agentToken(cmd, scope)
	if err != nil {
		return mapErr(err)
	}
	info, err := identityclient.ParseWardenToken(tok.AccessToken)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "sub: %s\n", info.Subject)
	fmt.Fprintf(out, "act.sub: %s\n", info.ActorSub)
	fmt.Fprintf(out, "cnf.jkt: %s\n", info.JKT)
	fmt.Fprintf(out, "scope: %s\n", info.Scope)
	fmt.Fprintf(out, "exp: %s\n", info.Expiry.UTC().Format("2006-01-02T15:04:05Z07:00"))
	return nil
}

func (r *identityRunner) enrollCmd() *cobra.Command {
	var keyFile string
	var force bool
	cmd := leaf(&cobra.Command{
		Use:   "enroll --agent-id ID [--key-file PATH] [--force]",
		Short: "Create an agent key and print its public JWK.",
		Long: "Generates an Ed25519 key for the agent, writes it as a PKCS#8 PEM to a 0600 file in a " +
			"0700 directory (default <user config dir>/warden/agents/<id>.key) and prints only the " +
			"public JWK, which an operator registers for the agent. It refuses to overwrite a key " +
			"without --force. The private key is never printed.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			id := r.f.agentID
			if id == "" {
				id = r.deps.getenv(identityclient.EnvAgentID)
			}
			if id == "" {
				return errors.New("--agent-id is required")
			}
			if err := agentid.ValidID(id); err != nil {
				return err
			}
			path := keyFile
			if path == "" {
				path = r.f.agentKeyFile
			}
			if path == "" {
				path = r.deps.getenv(identityclient.EnvAgentKeyFile)
			}
			if path == "" {
				p, err := identityclient.DefaultAgentKeyPath(id)
				if err != nil {
					return err
				}
				path = p
			}
			return enrollAgentKey(cmd, path, force)
		},
	})
	cmd.Flags().StringVar(&keyFile, "key-file", "", "where to write the private key `PATH`")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing key file")
	return cmd
}

func enrollAgentKey(cmd *cobra.Command, path string, force bool) error {
	key, err := identityclient.GenerateAgentKey()
	if err != nil {
		return err
	}
	if err := identityclient.SaveAgentKey(path, key, force); err != nil {
		return err
	}
	b, err := json.Marshal(key.PublicJWK())
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "agent key written to %s\n", path)
	fmt.Fprintln(cmd.OutOrStdout(), string(b))
	return nil
}
