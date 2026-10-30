package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// Rotation timing defaults and floors (W-P2-KEYS-03). rotationInterval 0 is
// the manual mode: nothing rotates unless an operator rotates it. prepublish
// covers the 60s bundle long-poll wait plus the 300s JWKS cache with margin;
// overlap covers the 15m token TTL plus clock skew and the long-poll wait, so
// a key that stopped signing keeps verifying while the last token it signed
// lives out its life.
const (
	keysDefaultRotationInterval = 720 * time.Hour
	keysDefaultPrepublish       = time.Hour
	keysMinPrepublish           = 10 * time.Minute
	keysDefaultOverlap          = 48 * time.Hour
	keysMinOverlap              = 20 * time.Minute
)

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
	// Token and Bundle name the algorithm and the rotation timing of each
	// purpose's keys. The block shape keys.<purpose>.* is what the KMS
	// backends (W-P2-KEYS-07) extend. The ca purpose has no settings: its key
	// is created outside the control plane and imported.
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
	// RotationInterval is how long a key signs before the next one takes
	// over. 0 (the default for bundle) is manual: rotation happens only when
	// an operator rotates the purpose, because workers pin bundle keys out of
	// band (W-P2-SBND-07).
	RotationInterval time.Duration
	// Prepublish is how long a next key must be published before it may
	// activate, so every verifier already holds it (default 1h, min 10m).
	Prepublish time.Duration
	// Overlap is how long a retired key stays in the JWKS after it stops
	// signing, so tokens it signed keep verifying (default 48h, min 20m).
	Overlap time.Duration
}

// rawKeys mirrors the on-disk `keys:` block. Pointer-free leaves keep the
// strict KnownFields(true) decode honest: a misspelled key fails to parse;
// durations stay strings so an absent field and an explicit zero differ
// (rotationInterval 0 is the manual mode, not the default).
type rawKeys struct {
	Enabled bool `yaml:"enabled"`
	Store   struct {
		Backend string `yaml:"backend"`
		File    struct {
			Dir string `yaml:"dir"`
		} `yaml:"file"`
	} `yaml:"store"`
	Token  rawKeysPurpose `yaml:"token"`
	Bundle rawKeysPurpose `yaml:"bundle"`
}

// rawKeysPurpose is one purpose's leaf of the raw block.
type rawKeysPurpose struct {
	Alg              string `yaml:"alg"`
	RotationInterval string `yaml:"rotationInterval"`
	Prepublish       string `yaml:"prepublish"`
	Overlap          string `yaml:"overlap"`
}

// parseKeys converts the raw block and applies defaults. An absent block is
// the disabled default.
func parseKeys(r *rawKeys) (KeysConfig, error) {
	c := KeysConfig{
		Store: KeysStore{Backend: KeysBackendFile},
		Token: KeysPurpose{
			Alg: keys.AlgEdDSA, RotationInterval: keysDefaultRotationInterval,
			Prepublish: keysDefaultPrepublish, Overlap: keysDefaultOverlap,
		},
		Bundle: KeysPurpose{
			Alg:        keys.AlgEdDSA,
			Prepublish: keysDefaultPrepublish, Overlap: keysDefaultOverlap,
		},
	}
	if r == nil {
		return c, nil
	}
	c.Enabled = r.Enabled
	if b := strings.TrimSpace(r.Store.Backend); b != "" {
		c.Store.Backend = b
	}
	c.Store.File.Dir = strings.TrimSpace(r.Store.File.Dir)
	var err error
	if c.Token, err = parseKeysPurpose("keys.token", r.Token, c.Token); err != nil {
		return KeysConfig{}, err
	}
	if c.Bundle, err = parseKeysPurpose("keys.bundle", r.Bundle, c.Bundle); err != nil {
		return KeysConfig{}, err
	}
	return c, nil
}

// parseKeysPurpose fills one purpose block over its defaults.
func parseKeysPurpose(field string, r rawKeysPurpose, def KeysPurpose) (KeysPurpose, error) {
	if a := strings.TrimSpace(r.Alg); a != "" {
		def.Alg = a
	}
	// A slice, not a map: a file with two bad durations fails on the first
	// one in block order, deterministically.
	fields := []struct {
		name string
		raw  string
		dst  *time.Duration
	}{
		{"rotationInterval", r.RotationInterval, &def.RotationInterval},
		{"prepublish", r.Prepublish, &def.Prepublish},
		{"overlap", r.Overlap, &def.Overlap},
	}
	for _, f := range fields {
		if err := parseDurationField(field+"."+f.name, f.raw, f.dst); err != nil {
			return KeysPurpose{}, err
		}
	}
	return def, nil
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
	if err := validateKeysTiming("keys.token", c.Token, true); err != nil {
		return err
	}
	return validateKeysTiming("keys.bundle", c.Bundle, false)
}

// validateKeysTiming enforces one purpose's rotation windows. scheduled is
// true for token, whose interval may be 0 (manual) or at least
// prepublish+overlap; bundle must be manual, because workers pin its keys and
// an unannounced switch would break verification (W-P2-SBND-07).
func validateKeysTiming(field string, p KeysPurpose, scheduled bool) error {
	if p.Prepublish < keysMinPrepublish {
		return fmt.Errorf("config: %s.prepublish %s is below the %s minimum (a next key must be published before it activates)", field, p.Prepublish, keysMinPrepublish)
	}
	if p.Overlap < keysMinOverlap {
		return fmt.Errorf("config: %s.overlap %s is below the %s minimum (tokens signed by a retired key must keep verifying)", field, p.Overlap, keysMinOverlap)
	}
	if p.RotationInterval == 0 {
		return nil // manual
	}
	if !scheduled {
		return fmt.Errorf("config: %s.rotationInterval %s must be 0: bundle keys are pinned on workers, so bundle rotates only by hand", field, p.RotationInterval)
	}
	if min := p.Prepublish + p.Overlap; p.RotationInterval < min {
		return fmt.Errorf("config: %s.rotationInterval %s must be 0 (manual) or at least prepublish+overlap (%s)", field, p.RotationInterval, min)
	}
	return nil
}

// Resolve returns c with the file key directory filled in from stateDir, or an
// error when the subsystem is enabled without one. The directory is derived
// for a disabled block too when stateDir is set (the keys CLI reads a state
// dir whose own config may not carry the block); a control plane without keys
// never uses it.
func (c KeysConfig) Resolve(stateDir string) (KeysConfig, error) {
	if !c.Enabled {
		if stateDir == "" {
			return c, nil
		}
		if c.Store.File.Dir == "" {
			c.Store.File.Dir = filepath.Join(stateDir, keysDirName)
		}
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

// DefaultKeys returns the `keys:` block with every default applied and
// enabled false: what a caller resolves when the operator's config carries no
// keys block at all.
func DefaultKeys() KeysConfig {
	c, _ := parseKeys(nil)
	return c
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
	c, err := parseKeys(raw.Keys)
	if err != nil {
		return KeysConfig{}, err
	}
	if err := validateKeys(c); err != nil {
		return KeysConfig{}, err
	}
	return c, nil
}
