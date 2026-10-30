package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keysYAML(block string) []byte {
	return []byte("policy:\n  allowlist:\n    - domain: api.example.com\n" + block)
}

func loadKeysYAML(t *testing.T, block string) (KeysConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.yaml")
	if err := os.WriteFile(path, keysYAML(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadKeys(path)
}

// TestKeysConfigDefaults: an absent block is disabled with the file backend and
// EdDSA keys; the same defaults come out of a full policy load.
func TestKeysConfigDefaults(t *testing.T) {
	c, err := loadKeysYAML(t, "")
	if err != nil {
		t.Fatal(err)
	}
	want := KeysConfig{
		Store:  KeysStore{Backend: KeysBackendFile},
		Token:  KeysPurpose{Alg: "EdDSA"},
		Bundle: KeysPurpose{Alg: "EdDSA"},
	}
	if c != want {
		t.Errorf("LoadKeys(absent) = %+v, want %+v", c, want)
	}
	prov, err := parse(keysYAML(""))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	if p.Keys != want {
		t.Errorf("Policy.Keys = %+v, want %+v", p.Keys, want)
	}
}

// TestKeysConfig: the invalid shapes fail naming the offending field.
func TestKeysConfig(t *testing.T) {
	for _, tc := range []struct {
		name, block, field string
	}{
		{"echo backend", "keys:\n  enabled: true\n  store:\n    backend: echo\n", "keys.store.backend"},
		{"env backend", "keys:\n  store:\n    backend: env\n", "keys.store.backend"},
		{"aws backend without a region", "keys:\n  store:\n    backend: aws\n", "keys.store.aws.region"},
		{"aws backend without the aws block", "keys:\n  store:\n    backend: aws\n    aws: {}\n", "keys.store.aws.region"},
		{"aws backend with a credential", "keys:\n  store:\n    backend: aws\n    aws:\n      region: eu-central-1\n      accessKeyId: AKIA...\n", "accessKeyId"},
		{"bundle ES256", "keys:\n  enabled: true\n  bundle:\n    alg: ES256\n", "keys.bundle.alg"},
		{"token RS256", "keys:\n  token:\n    alg: RS256\n", "keys.token.alg"},
		{"misspelled key", "keys:\n  enable: true\n", "enable"},
		{"unknown store key", "keys:\n  store:\n    dir: /x\n", "dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadKeysYAML(t, tc.block)
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("LoadKeys error = %v, want it to name %s", err, tc.field)
			}
			// A full config load rejects the same shapes, so the served copy
			// and --config agree.
			if _, err := parse(keysYAML(tc.block)); err == nil {
				t.Errorf("config load accepted %q", tc.block)
			}
		})
	}
}

func TestKeysConfigValid(t *testing.T) {
	c, err := loadKeysYAML(t, `keys:
  enabled: true
  store:
    backend: file
    file:
      dir: /run/secrets/warden-keys
  token:
    alg: ES256
  bundle:
    alg: EdDSA
`)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enabled || c.Store.File.Dir != "/run/secrets/warden-keys" || c.Token.Alg != "ES256" || c.Bundle.Alg != "EdDSA" {
		t.Errorf("LoadKeys = %+v", c)
	}
	if _, err := LoadKeys(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file must error")
	}
}

// TestKeysConfigResolve: enabled needs --state-dir and defaults the key dir
// under it; disabled is untouched.
func TestKeysConfigResolve(t *testing.T) {
	c, _ := loadKeysYAML(t, "keys:\n  enabled: true\n")
	if _, err := c.Resolve(""); err == nil || !strings.Contains(err.Error(), "keys.enabled") || !strings.Contains(err.Error(), "--state-dir") {
		t.Errorf("enabled without state dir: err = %v", err)
	}
	r, err := c.Resolve("/var/lib/warden")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/var/lib/warden", "keys"); r.Store.File.Dir != want {
		t.Errorf("default dir = %q, want %q", r.Store.File.Dir, want)
	}
	custom, _ := loadKeysYAML(t, "keys:\n  enabled: true\n  store:\n    file:\n      dir: /mnt/k\n")
	if r, _ := custom.Resolve("/var/lib/warden"); r.Store.File.Dir != "/mnt/k" {
		t.Errorf("explicit dir overridden: %q", r.Store.File.Dir)
	}
	off, _ := loadKeysYAML(t, "")
	r, err = off.Resolve("")
	if err != nil || r.Store.File.Dir != "" {
		t.Errorf("disabled Resolve = %+v, %v; want unchanged", r, err)
	}
}

// TestKeysAWSConfig: the aws backend parses region and namePrefix, defaults
// the prefix to the CP-local namespace, and has no credential field at all —
// credentials come from the control plane's environment or IMDS only.
func TestKeysAWSConfig(t *testing.T) {
	c, err := loadKeysYAML(t, "keys:\n  enabled: true\n  store:\n    backend: aws\n    aws:\n      region: eu-central-1\n")
	if err != nil {
		t.Fatal(err)
	}
	wantAWS := &KeysStoreAWS{Region: "eu-central-1", NamePrefix: defaultKeysAWSNamePrefix}
	if c.Store.Backend != KeysBackendAWS || c.Store.AWS == nil || *c.Store.AWS != *wantAWS {
		t.Fatalf("LoadKeys = %+v, want backend aws with %+v", c.Store, wantAWS)
	}
	// An explicit prefix is kept verbatim.
	c, err = loadKeysYAML(t, "keys:\n  store:\n    backend: aws\n    aws:\n      region: us-east-1\n      namePrefix: prod-cp/signing/\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Store.AWS.NamePrefix != "prod-cp/signing/" {
		t.Errorf("explicit namePrefix = %q, want it kept", c.Store.AWS.NamePrefix)
	}
	// The aws block on the file backend is inert, like secretStore's.
	c, err = loadKeysYAML(t, "keys:\n  enabled: true\n  store:\n    backend: file\n    aws:\n      region: us-east-1\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Store.Backend != KeysBackendFile {
		t.Errorf("backend = %q, want file with an inert aws block", c.Store.Backend)
	}
	// No credential field exists to parse: a config carrying one fails strictly.
	if _, err := loadKeysYAML(t, "keys:\n  store:\n    backend: aws\n    aws:\n      region: us-east-1\n      secretAccessKey: wJalr...\n"); err == nil || !strings.Contains(err.Error(), "secretAccessKey") {
		t.Errorf("credential in keys.store.aws: err = %v, want a strict-parse error naming the field", err)
	}
}

// TestKeysAWSPrefixOverlap: a keys namespace that equals, starts with or
// contains the worker secretStore's namespace fails the full config load,
// naming both fields — worker IAM scoped to secretStore.aws.namePrefix must
// never be able to reach signing keys. The default warden-cp-keys/ namespace
// does not overlap warden/ and loads.
func TestKeysAWSPrefixOverlap(t *testing.T) {
	for _, tc := range []struct {
		name, keysPrefix, storePrefix string
		wantErr                       bool
	}{
		{"equal", "warden/", "warden/", true},
		{"keys under store", "warden/cp-keys/", "warden/", true},
		{"store under keys", "warden/", "warden/placeholders/", true},
		{"default keys prefix is disjoint", "", "warden/", false},
		{"disjoint", "warden-cp-keys/", "warden/", false},
		{"shared stem is not an overlap", "warden-cp-keys/", "warden-placeholders/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keysBlock := "keys:\n  enabled: true\n  store:\n    backend: aws\n    aws:\n      region: eu-central-1\n"
			if tc.keysPrefix != "" {
				keysBlock += "      namePrefix: " + tc.keysPrefix + "\n"
			}
			storeBlock := "secretStore:\n  backend: aws\n  aws:\n    region: eu-central-1\n    namePrefix: " + tc.storePrefix + "\n"
			_, err := parse(keysYAML(keysBlock + storeBlock))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "keys.store.aws.namePrefix") || !strings.Contains(err.Error(), "secretStore.aws.namePrefix") {
					t.Fatalf("overlap %q vs %q: err = %v, want it to name both fields", tc.keysPrefix, tc.storePrefix, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("disjoint %q vs %q must load: %v", tc.keysPrefix, tc.storePrefix, err)
			}
		})
	}
	// Only the two aws blocks together can overlap: an aws keys store beside an
	// env secretStore has nothing to overlap with.
	_, err := parse(keysYAML("keys:\n  store:\n    backend: aws\n    aws:\n      region: eu-central-1\n      namePrefix: warden/\n"))
	if err != nil {
		t.Errorf("keys aws prefix warden/ without a secretStore aws block: %v", err)
	}
}

// TestKeysNotOnWire: the block is CP-local; it never reaches the policy JSON.
func TestKeysNotOnWire(t *testing.T) {
	prov, err := parse(keysYAML("keys:\n  enabled: true\n  store:\n    file:\n      dir: /secret/dir\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "/secret/dir") || strings.Contains(strings.ToLower(string(b)), `"keys"`) {
		t.Errorf("keys block leaked onto the policy wire: %s", b)
	}
}
