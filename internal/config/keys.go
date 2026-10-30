package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/keys"
)

// Key store backends. Only the file backend exists today; the AWS Secrets
// Manager backend arrives with W-P2-KEYS-07. echo persists nothing and env has
// no store, so neither can hold a signing key, and the secretStore block is
// shared with workers, so it is never reused for private keys.
const (
	// KeysBackendFile keeps PKCS#8 PEM files under keys.store.file.dir.
	KeysBackendFile = "file"
)

// keysDirName is the directory under --state-dir that holds the key files
// when keys.store.file.dir is unset.
const keysDirName = "keys"

// KeysConfig is the control-plane-local `keys:` block: the signing-key
// subsystem (W-P2-KEYS-02). It is read by the control plane from --config only
// (LoadKeys) and never leaves it: Policy.Keys is json:"-", so it is neither on
// the worker wire nor on the settings wire. Disabled by default; when disabled
// nothing is created and the control plane behaves as before.
type KeysConfig struct {
	// Enabled turns the subsystem on. It needs --state-dir (Resolve).
	Enabled bool
	// Store selects where private keys live.
	Store KeysStore
	// Token and Bundle name the algorithm of each purpose's keys. The block
	// shape keys.<purpose>.* is what the rotation timings (W-P2-KEYS-03) and
	// KMS backends extend. The ca purpose has no settings: its key is created
	// outside the control plane and imported.
	Token  KeysPurpose
	Bundle KeysPurpose
}

// KeysStore is keys.store.
type KeysStore struct {
	// Backend is KeysBackendFile.
	Backend string
	File    KeysFileStore
}

// KeysFileStore is keys.store.file.
type KeysFileStore struct {
	// Dir is the key directory. Empty until Resolve fills <state-dir>/keys; it
	// may point at a separate secret mount.
	Dir string
}

// KeysPurpose is the per-purpose block keys.token / keys.bundle.
type KeysPurpose struct {
	// Alg is keys.AlgEdDSA (default) or, for tokens only, keys.AlgES256.
	Alg string
}

// rawKeys mirrors the on-disk `keys:` block. Pointer-free leaves keep the
// strict KnownFields(true) decode honest: a misspelled key fails to parse.
type rawKeys struct {
	Enabled bool `yaml:"enabled"`
	Store   struct {
		Backend string `yaml:"backend"`
		File    struct {
			Dir string `yaml:"dir"`
		} `yaml:"file"`
	} `yaml:"store"`
	Token struct {
		Alg string `yaml:"alg"`
	} `yaml:"token"`
	Bundle struct {
		Alg string `yaml:"alg"`
	} `yaml:"bundle"`
}

// parseKeys converts the raw block and applies defaults. An absent block is
// the disabled default.
func parseKeys(r *rawKeys) KeysConfig {
	c := KeysConfig{
		Store:  KeysStore{Backend: KeysBackendFile},
		Token:  KeysPurpose{Alg: keys.AlgEdDSA},
		Bundle: KeysPurpose{Alg: keys.AlgEdDSA},
	}
	if r == nil {
		return c
	}
	c.Enabled = r.Enabled
	if b := strings.TrimSpace(r.Store.Backend); b != "" {
		c.Store.Backend = b
	}
	c.Store.File.Dir = strings.TrimSpace(r.Store.File.Dir)
	if a := strings.TrimSpace(r.Token.Alg); a != "" {
		c.Token.Alg = a
	}
	if a := strings.TrimSpace(r.Bundle.Alg); a != "" {
		c.Bundle.Alg = a
	}
	return c
}

// validateKeys enforces the block's invariants. It runs whether or not the
// block is enabled, so a typo surfaces when the file is written rather than
// the day someone flips enabled.
func validateKeys(c KeysConfig) error {
	switch c.Store.Backend {
	case KeysBackendFile:
	case "aws":
		return fmt.Errorf("config: keys.store.backend %q is not supported yet; use %q", c.Store.Backend, KeysBackendFile)
	default:
		return fmt.Errorf("config: keys.store.backend %q is not supported; use %q (echo persists nothing and env has no store)", c.Store.Backend, KeysBackendFile)
	}
	if c.Token.Alg != keys.AlgEdDSA && c.Token.Alg != keys.AlgES256 {
		return fmt.Errorf("config: keys.token.alg %q must be %s or %s", c.Token.Alg, keys.AlgEdDSA, keys.AlgES256)
	}
	// Workers pin bundle keys out of band and the bundle format (W-P2-SBND-03)
	// is EdDSA only.
	if c.Bundle.Alg != keys.AlgEdDSA {
		return fmt.Errorf("config: keys.bundle.alg %q must be %s (workers pin EdDSA bundle keys)", c.Bundle.Alg, keys.AlgEdDSA)
	}
	return nil
}

// Resolve returns c with the file key directory filled in from stateDir, or an
// error when the subsystem is enabled without one. A disabled block is
// returned unchanged: no directory is derived and nothing is checked, so a
// control plane without keys is not affected by the flag.
func (c KeysConfig) Resolve(stateDir string) (KeysConfig, error) {
	if !c.Enabled {
		return c, nil
	}
	if stateDir == "" {
		return c, fmt.Errorf("config: keys.enabled needs --state-dir (signing-key metadata lives in the control-plane state database)")
	}
	if c.Store.File.Dir == "" {
		c.Store.File.Dir = filepath.Join(stateDir, keysDirName)
	}
	return c, nil
}

// LoadKeys reads only the `keys:` block of the YAML file at path, with the
// same strict decoder and validation as a full config load. The control plane
// calls it on the operator-owned --config file (never the served copy).
func LoadKeys(path string) (KeysConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return KeysConfig{}, fmt.Errorf("config: read %q: %w", path, err)
	}
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return KeysConfig{}, fmt.Errorf("config: parse yaml: %w", err)
	}
	c := parseKeys(raw.Keys)
	if err := validateKeys(c); err != nil {
		return KeysConfig{}, err
	}
	return c, nil
}
