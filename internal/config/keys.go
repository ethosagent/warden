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

// Key store backends. echo persists nothing and env has no store, so neither
// can hold a signing key, and the secretStore block is shared with workers, so
// it is never reused for private keys.
const (
	// KeysBackendFile keeps PKCS#8 PEM files under keys.store.file.dir.
	KeysBackendFile = "file"
	// KeysBackendAWS keeps one secret per key in AWS Secrets Manager
	// (W-P2-KEYS-07), under keys.store.aws.namePrefix with credentials from the
	// control plane's environment or IMDS only.
	KeysBackendAWS = "aws"
)

// defaultKeysAWSNamePrefix is the CP-local secret-name namespace applied when
// keys.store.aws.namePrefix is unset. It deliberately does not overlap the
// worker secretStore default "warden/" in either direction (see
// validateKeysSecretStoreOverlap), so a worker IAM role scoped to warden/*
// cannot read signing keys.
const defaultKeysAWSNamePrefix = "warden-cp-keys/"

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
	// Backend is KeysBackendFile or KeysBackendAWS.
	Backend string
	File    KeysFileStore
	// AWS carries the AWS Secrets Manager settings, present only when the aws
	// block is configured. It has NO credential fields — unlike the worker
	// secretStore block, this one never crosses a wire and its client resolves
	// credentials from the control plane's environment or IMDS only.
	AWS *KeysStoreAWS
}

// KeysStoreAWS is keys.store.aws: the CP-local AWS Secrets Manager namespace
// the private keys live under. A key ref <purpose>/<kid> maps to the secret
// name <NamePrefix><purpose>/<kid>, so IAM can scope the control plane role to
// <NamePrefix>*.
type KeysStoreAWS struct {
	// Region is the AWS region the Secrets Manager client targets.
	Region string
	// NamePrefix is the secret-name namespace (default warden-cp-keys/).
	NamePrefix string
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

// rawKeysAWS mirrors keys.store.aws. Deliberately credential-free: the strict
// decoder turns any credential key an operator writes here into a parse error,
// so credentials can never enter the block. Pointer so an absent block is
// distinct from an explicit one.
type rawKeysAWS struct {
	Region     string `yaml:"region"`
	NamePrefix string `yaml:"namePrefix"`
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
		AWS *rawKeysAWS `yaml:"aws,omitempty"`
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
	if r.Store.AWS != nil {
		aws := &KeysStoreAWS{
			Region:     strings.TrimSpace(r.Store.AWS.Region),
			NamePrefix: strings.TrimSpace(r.Store.AWS.NamePrefix),
		}
		if aws.NamePrefix == "" {
			aws.NamePrefix = defaultKeysAWSNamePrefix
		}
		c.Store.AWS = aws
	}
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
	case KeysBackendAWS:
		if c.Store.AWS == nil || c.Store.AWS.Region == "" {
			return fmt.Errorf("config: keys.store.aws.region is required when backend is %q", KeysBackendAWS)
		}
	default:
		return fmt.Errorf("config: keys.store.backend %q is not supported; use %q or %q (echo persists nothing and env has no store)", c.Store.Backend, KeysBackendFile, KeysBackendAWS)
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

// validateKeysSecretStoreOverlap refuses a keys AWS namespace that overlaps
// the worker secretStore's, in either direction: if one prefix nests the
// other, a worker IAM role scoped to secretStore.aws.namePrefix could List —
// and with a mis-scoped role read — the control plane's signing keys. It needs
// the whole policy, so it runs from validate (not validateKeys) and only when
// both aws blocks are configured.
func validateKeysSecretStoreOverlap(k KeysConfig, s SecretStoreConfig) error {
	if k.Store.AWS == nil || s.AWS == nil {
		return nil
	}
	kp, sp := k.Store.AWS.NamePrefix, s.AWS.NamePrefix
	if kp == "" || sp == "" {
		return nil
	}
	if strings.HasPrefix(kp, sp) || strings.HasPrefix(sp, kp) {
		return fmt.Errorf("config: keys.store.aws.namePrefix %q overlaps secretStore.aws.namePrefix %q: a worker scoped to the secretStore namespace could reach signing keys; use a disjoint prefix (the default is %q)",
			kp, sp, defaultKeysAWSNamePrefix)
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
