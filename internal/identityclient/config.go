package identityclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/identity"
)

// Defaults: the public device-code client of the reference issuer config.
const (
	DefaultClientID = "warden-cli"
	DefaultAudience = "warden"
)

// Environment variables read by LoadConfig.
const (
	EnvIssuer   = "WARDEN_IDENTITY_ISSUER"
	EnvClientID = "WARDEN_IDENTITY_CLIENT_ID"
	EnvAudience = "WARDEN_IDENTITY_AUDIENCE"
	EnvScopes   = "WARDEN_IDENTITY_SCOPES"
	EnvCacheDir = "WARDEN_IDENTITY_CACHE_DIR"

	configSubdir = "warden"
	configFile   = "identity.yaml"
)

// DefaultScopes are always requested. Extra scopes (for example an
// issuer's cross-client audience scope) are added to them.
var DefaultScopes = []string{"openid", "email", "profile", "groups", "offline_access"}

// Config is the resolved client configuration.
//
// ClientSecretEnv NAMES the environment variable that holds the client secret
// of a confidential client; the secret itself is never part of a Config.
// Scopes is the full list: DefaultScopes plus the added ones.
type Config struct {
	Issuer          string
	ClientID        string
	Audience        string
	ClientSecretEnv string
	Scopes          []string
	CacheDir        string
}

// Flags are the command-line values; an empty field means "not set". Scopes are
// added to the defaults. ConfigFile overrides the identity.yaml location.
type Flags struct {
	Issuer          string
	ClientID        string
	Audience        string
	ClientSecretEnv string
	Scopes          []string
	CacheDir        string
	ConfigFile      string
}

// fileConfig is identity.yaml. Unknown keys are rejected, so a literal
// client_secret key cannot be tucked into the file.
type fileConfig struct {
	Issuer          string   `yaml:"issuer"`
	ClientID        string   `yaml:"client_id"`
	Audience        string   `yaml:"audience"`
	ClientSecretEnv string   `yaml:"client_secret_env"`
	Scopes          []string `yaml:"scopes"`
	CacheDir        string   `yaml:"cache_dir"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LoadConfig resolves the configuration. Precedence per field: flags, then the
// WARDEN_IDENTITY_* environment variables, then the optional file
// <os.UserConfigDir()>/warden/identity.yaml (or Flags.ConfigFile), then the
// defaults. A missing default file is fine. The worker --config is never read.
func LoadConfig(flags Flags, getenv func(string) string, readFile func(string) ([]byte, error)) (Config, error) {
	var fc fileConfig
	path := flags.ConfigFile
	explicit := path != ""
	if !explicit {
		if dir, err := os.UserConfigDir(); err == nil {
			path = filepath.Join(dir, configSubdir, configFile)
		}
	}
	if path != "" {
		b, err := readFile(path)
		switch {
		case err == nil:
			dec := yaml.NewDecoder(bytes.NewReader(b))
			dec.KnownFields(true)
			if err := dec.Decode(&fc); err != nil && !errors.Is(err, io.EOF) {
				return Config{}, fmt.Errorf("identityclient: parse %s: %s", path, yamlProblem(err))
			}
		case errors.Is(err, fs.ErrNotExist) && !explicit:
		default:
			return Config{}, fmt.Errorf("identityclient: read %s: %w", path, err)
		}
	}

	cfg := Config{
		Issuer:          first(flags.Issuer, getenv(EnvIssuer), fc.Issuer),
		ClientID:        first(flags.ClientID, getenv(EnvClientID), fc.ClientID, DefaultClientID),
		Audience:        first(flags.Audience, getenv(EnvAudience), fc.Audience, DefaultAudience),
		ClientSecretEnv: first(flags.ClientSecretEnv, fc.ClientSecretEnv),
		CacheDir:        first(flags.CacheDir, getenv(EnvCacheDir), fc.CacheDir),
	}
	added := flags.Scopes
	if len(added) == 0 {
		added = splitScopes(getenv(EnvScopes))
	}
	if len(added) == 0 {
		added = fc.Scopes
	}
	cfg.Scopes = mergeScopes(DefaultScopes, added)

	if err := identity.CheckClientIssuer(cfg.Issuer); err != nil {
		return Config{}, fmt.Errorf("identityclient: %w", err)
	}
	if cfg.ClientSecretEnv != "" && !envName.MatchString(cfg.ClientSecretEnv) {
		// A literal secret is almost never a valid variable name, and the value
		// must not be echoed back.
		return Config{}, errors.New("identityclient: the client secret setting must be the NAME of an environment variable, never the secret itself")
	}
	if cfg.CacheDir == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return Config{}, errors.New("identityclient: no cache directory: set --cache-dir or " + EnvCacheDir)
		}
		cfg.CacheDir = filepath.Join(dir, configSubdir, "identity")
	}
	return cfg, nil
}

// yamlProblem drops the offending value from a yaml error: the decoder quotes
// unknown keys and bad scalars, which could be a pasted secret.
func yamlProblem(err error) string {
	if strings.Contains(err.Error(), "not found in type") {
		return "unknown key (client secrets are never read from the file; use client_secret_env)"
	}
	return "invalid YAML"
}

func first(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitScopes(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '\n' })
}

func mergeScopes(base, added []string) []string {
	out := append([]string(nil), base...)
	seen := map[string]bool{}
	for _, s := range out {
		seen[s] = true
	}
	for _, s := range added {
		for _, f := range splitScopes(s) {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}
