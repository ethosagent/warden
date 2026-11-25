package identityclient

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/agentid"
)

// Environment variables of the agent mode.
const (
	EnvTokenEndpoint = "WARDEN_IDENTITY_TOKEN_ENDPOINT"
	EnvCPCA          = "WARDEN_IDENTITY_CP_CA"
	EnvAgentID       = "WARDEN_IDENTITY_AGENT_ID"
	EnvAgentKeyFile  = "WARDEN_IDENTITY_AGENT_KEY_FILE"
)

// AgentFlags are the command-line values of the agent mode; empty means not
// set. Flags win over the environment.
type AgentFlags struct {
	AgentID, KeyFile, TokenEndpoint, CPCA, SubjectTokenFile, Scope string
}

// AgentConfig is the resolved agent-mode configuration.
type AgentConfig struct {
	AgentID       string
	KeyFile       string
	TokenEndpoint string
	// CPCA is a PEM bundle trusted for the control plane's TLS; empty means
	// the system roots.
	CPCA string
	// SubjectTokenFile, when set, supplies the user's ID token (a 0600 file
	// re-read before each exchange) instead of the login cache.
	SubjectTokenFile string
	Scope            string
}

// AgentMode reports whether an agent id is configured, which is what switches
// `token` and `status` to the Warden token. Nothing else changes when it is
// not.
func AgentMode(f AgentFlags, getenv func(string) string) bool {
	return first(f.AgentID, getenv(EnvAgentID)) != ""
}

// LoadAgentConfig resolves the agent mode: flags, then the WARDEN_IDENTITY_*
// variables. The agent id must be valid and the token endpoint is required
// with no implied default. The key file defaults to
// <os.UserConfigDir()>/warden/agents/<id>.key.
func LoadAgentConfig(f AgentFlags, getenv func(string) string) (AgentConfig, error) {
	cfg := AgentConfig{
		AgentID:          first(f.AgentID, getenv(EnvAgentID)),
		KeyFile:          first(f.KeyFile, getenv(EnvAgentKeyFile)),
		TokenEndpoint:    first(f.TokenEndpoint, getenv(EnvTokenEndpoint)),
		CPCA:             first(f.CPCA, getenv(EnvCPCA)),
		SubjectTokenFile: f.SubjectTokenFile,
		Scope:            strings.Join(strings.Fields(f.Scope), " "),
	}
	if cfg.AgentID == "" {
		return AgentConfig{}, errors.New("identityclient: no agent id (--agent-id or " + EnvAgentID + ")")
	}
	if err := agentid.ValidID(cfg.AgentID); err != nil {
		return AgentConfig{}, err
	}
	if err := ValidateTokenEndpoint(cfg.TokenEndpoint); err != nil {
		return AgentConfig{}, err
	}
	if cfg.KeyFile == "" {
		p, err := DefaultAgentKeyPath(cfg.AgentID)
		if err != nil {
			return AgentConfig{}, err
		}
		cfg.KeyFile = p
	}
	return cfg, nil
}

// AgentDeps are the injectable parts of NewTokenSource; the zero value selects
// the real ones.
type AgentDeps struct {
	// HTTP replaces the control-plane client built from CPCA.
	HTTP *http.Client
	Now  func() time.Time
	Log  *slog.Logger
	// Audience overrides the assertion audience (default: the token endpoint).
	Audience string
}

// NewExchanger loads the agent key and builds the Exchanger.
func (c AgentConfig) NewExchanger(d AgentDeps) (*Exchanger, error) {
	key, err := LoadAgentKey(c.KeyFile)
	if err != nil {
		return nil, err
	}
	cl := d.HTTP
	if cl == nil {
		if cl, err = NewCPHTTPClient(c.CPCA); err != nil {
			return nil, err
		}
	}
	return &Exchanger{
		Endpoint: c.TokenEndpoint, Audience: d.Audience, AgentID: c.AgentID, Key: key,
		Scope: c.Scope, HTTP: cl, Now: d.Now, Log: d.Log,
	}, nil
}

// NewTokenSource builds the WardenTokenSource of this agent over subject, the
// source of the user's ID token: a *Client (the P1 login cache) or
// FileSubject{Path: c.SubjectTokenFile}. It is the one call the forwarder and
// `identity exec` make.
func (c AgentConfig) NewTokenSource(subject SubjectSource, d AgentDeps) (*WardenTokenSource, error) {
	if subject == nil {
		return nil, errors.New("identityclient: no subject token source")
	}
	ex, err := c.NewExchanger(d)
	if err != nil {
		return nil, err
	}
	s := NewWardenTokenSource(ex, subject)
	s.Now, s.Log, s.AgentID = d.Now, d.Log, c.AgentID
	return s, nil
}

// SubjectFor picks the subject source of the configuration: the subject token
// file when set, else the P1 client (which reads the shared login cache).
func (c AgentConfig) SubjectFor(cl *Client) SubjectSource {
	if c.SubjectTokenFile != "" {
		return FileSubject{Path: c.SubjectTokenFile}
	}
	return cl
}

func (c AgentConfig) String() string {
	return fmt.Sprintf("AgentConfig(agent=%s endpoint=%s)", c.AgentID, c.TokenEndpoint)
}
