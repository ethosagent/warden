package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// secretStoreYAML builds a minimal config with the given secretStore + secrets
// snippets, so each case exercises the real parse+validate path.
func secretStoreYAML(secretStore, secrets string) string {
	return `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: info
  format: json
` + secrets + secretStore
}

func TestSecretStore_OmittedResolvesToEnv(t *testing.T) {
	p, err := parse([]byte(secretStoreYAML("", `
secrets:
  - placeholder: openai_secret_001
    envVar: OPENAI_API_KEY
`)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := p.policy.SecretStore.ResolvedBackend(); got != SecretBackendEnv {
		t.Fatalf("omitted secretStore backend = %q, want env", got)
	}
	if p.policy.SecretStore.AWS != nil {
		t.Fatalf("omitted secretStore should carry no aws block")
	}
}

func TestSecretStore_EnvBackendParses(t *testing.T) {
	p, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: env
`, `
secrets:
  - placeholder: openai_secret_001
    envVar: OPENAI_API_KEY
`)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := p.policy.SecretStore.Backend; got != SecretBackendEnv {
		t.Fatalf("backend = %q, want env", got)
	}
}

func TestSecretStore_EnvBackendMissingEnvVar_Errors(t *testing.T) {
	_, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: env
`, `
secrets:
  - placeholder: openai_secret_001
`)))
	if err == nil {
		t.Fatal("expected an error for an env-backend secret with no envVar")
	}
	if !strings.Contains(err.Error(), "envVar is required") {
		t.Fatalf("error = %v, want envVar-required", err)
	}
}

func TestSecretStore_EchoBackendNoEnvVar_OK(t *testing.T) {
	p, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: echo
`, `
secrets:
  - placeholder: openai_secret_001
`)))
	if err != nil {
		t.Fatalf("echo backend with no envVar should be OK, got: %v", err)
	}
	if got := p.policy.SecretStore.ResolvedBackend(); got != SecretBackendEcho {
		t.Fatalf("backend = %q, want echo", got)
	}
}

func TestSecretStore_UnknownBackend_Errors(t *testing.T) {
	_, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: vault
`, `
secrets:
  - placeholder: openai_secret_001
`)))
	if err == nil {
		t.Fatal("expected an error for an unknown backend")
	}
	if !strings.Contains(err.Error(), "secretStore.backend") {
		t.Fatalf("error = %v, want secretStore.backend invalid", err)
	}
}

func TestSecretStore_AWSBackendParses(t *testing.T) {
	p, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: aws
  aws:
    region: us-east-1
    namePrefix: myco/
`, "")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ss := p.policy.SecretStore
	if ss.Backend != SecretBackendAWS {
		t.Fatalf("backend = %q, want aws", ss.Backend)
	}
	if ss.AWS == nil || ss.AWS.Region != "us-east-1" || ss.AWS.NamePrefix != "myco/" {
		t.Fatalf("aws block = %+v, want region us-east-1 / prefix myco/", ss.AWS)
	}
}

func TestSecretStore_AWSBackendDefaultsNamePrefix(t *testing.T) {
	p, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: aws
  aws:
    region: us-east-1
`, "")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := p.policy.SecretStore.AWS.NamePrefix; got != defaultAWSNamePrefix {
		t.Fatalf("namePrefix = %q, want default %q", got, defaultAWSNamePrefix)
	}
}

func TestSecretStore_AWSBackendMissingRegion_Errors(t *testing.T) {
	_, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: aws
  aws:
    namePrefix: warden/
`, "")))
	if err == nil {
		t.Fatal("expected an error for aws backend with no region")
	}
	if !strings.Contains(err.Error(), "secretStore.aws.region") {
		t.Fatalf("error = %v, want aws.region required", err)
	}
}

func TestSecretStore_AWSBackendNoAWSBlock_Errors(t *testing.T) {
	_, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: aws
`, "")))
	if err == nil {
		t.Fatal("expected an error for aws backend with no aws block")
	}
	if !strings.Contains(err.Error(), "secretStore.aws.region") {
		t.Fatalf("error = %v, want aws.region required", err)
	}
}

func TestSecretStore_UnknownField_Errors(t *testing.T) {
	// KnownFields(true) must reject an unregistered key under secretStore.
	_, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: echo
  bogus: nope
`, "")))
	if err == nil {
		t.Fatal("expected a strict-decode error for an unknown secretStore field")
	}
}

// TestEncodeSecretStoreNode_RoundTripsAWS encodes an aws selection, marshals it
// under a `secretStore:` key, and parses back through the full loader — asserting
// the write direction is the faithful inverse of parseSecretStore. Only backend +
// region/namePrefix appear in the encoded block; there is no credential field to
// carry (the secret-free invariant is structural).
func TestEncodeSecretStoreNode_RoundTripsAWS(t *testing.T) {
	orig := SecretStoreConfig{
		Backend: SecretBackendAWS,
		AWS:     &SecretStoreAWS{Region: "us-east-1", NamePrefix: "myco/"},
	}
	node, err := EncodeSecretStoreNode(orig)
	if err != nil {
		t.Fatalf("EncodeSecretStoreNode: %v", err)
	}
	blk, err := yaml.Marshal(map[string]yaml.Node{"secretStore": node})
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	p, err := parse([]byte(secretStoreYAML(string(blk), "")))
	if err != nil {
		t.Fatalf("parse round-tripped config: %v\n%s", err, blk)
	}
	got := p.policy.SecretStore
	if got.Backend != SecretBackendAWS {
		t.Fatalf("backend = %q, want aws\n%s", got.Backend, blk)
	}
	if got.AWS == nil || *got.AWS != *orig.AWS {
		t.Fatalf("aws block mismatch:\n got %+v\nwant %+v\n%s", got.AWS, orig.AWS, blk)
	}
}

// TestEncodeSecretStoreNode_AWSDefaultsNamePrefix asserts the encoder applies the
// same namePrefix default as parseSecretStore when the aws block is present but
// the prefix is empty, so a write→read round-trip is stable (the re-parsed config
// is byte-identical in meaning to what was encoded).
func TestEncodeSecretStoreNode_AWSDefaultsNamePrefix(t *testing.T) {
	node, err := EncodeSecretStoreNode(SecretStoreConfig{
		Backend: SecretBackendAWS,
		AWS:     &SecretStoreAWS{Region: "us-east-1"},
	})
	if err != nil {
		t.Fatalf("EncodeSecretStoreNode: %v", err)
	}
	blk, err := yaml.Marshal(map[string]yaml.Node{"secretStore": node})
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	if !strings.Contains(string(blk), defaultAWSNamePrefix) {
		t.Fatalf("encoded block should carry the default namePrefix %q:\n%s", defaultAWSNamePrefix, blk)
	}
	p, err := parse([]byte(secretStoreYAML(string(blk), "")))
	if err != nil {
		t.Fatalf("parse round-tripped config: %v\n%s", err, blk)
	}
	if got := p.policy.SecretStore.AWS.NamePrefix; got != defaultAWSNamePrefix {
		t.Fatalf("namePrefix = %q, want default %q", got, defaultAWSNamePrefix)
	}
}

// TestEncodeSecretStoreNode_EchoNoAWSChild asserts echo encodes as the backend
// name ONLY — no aws child — and round-trips through the loader unchanged.
func TestEncodeSecretStoreNode_EchoNoAWSChild(t *testing.T) {
	node, err := EncodeSecretStoreNode(SecretStoreConfig{Backend: SecretBackendEcho})
	if err != nil {
		t.Fatalf("EncodeSecretStoreNode: %v", err)
	}
	blk, err := yaml.Marshal(map[string]yaml.Node{"secretStore": node})
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	if strings.Contains(string(blk), "aws") {
		t.Fatalf("echo must not emit an aws child:\n%s", blk)
	}
	p, err := parse([]byte(secretStoreYAML(string(blk), "")))
	if err != nil {
		t.Fatalf("parse round-tripped config: %v\n%s", err, blk)
	}
	got := p.policy.SecretStore
	if got.ResolvedBackend() != SecretBackendEcho || got.AWS != nil {
		t.Fatalf("round-trip = %+v, want echo with no aws block", got)
	}
}

// TestEncodeSecretStoreNode_RoundTripsExplicitKeys proves the OPTIONAL explicit
// aws credentials (accessKeyId + secretAccessKey) survive a write→read round-trip
// through the loader unchanged. This is the sanctioned value-carrying path.
func TestEncodeSecretStoreNode_RoundTripsExplicitKeys(t *testing.T) {
	orig := SecretStoreConfig{
		Backend: SecretBackendAWS,
		AWS: &SecretStoreAWS{
			Region:          "us-east-1",
			NamePrefix:      "myco/",
			AccessKeyID:     "AKIAEXPLICIT",
			SecretAccessKey: "sk-explicit-secret",
		},
	}
	node, err := EncodeSecretStoreNode(orig)
	if err != nil {
		t.Fatalf("EncodeSecretStoreNode: %v", err)
	}
	blk, err := yaml.Marshal(map[string]yaml.Node{"secretStore": node})
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	p, err := parse([]byte(secretStoreYAML(string(blk), "")))
	if err != nil {
		t.Fatalf("parse round-tripped config: %v\n%s", err, blk)
	}
	got := p.policy.SecretStore
	if got.AWS == nil || *got.AWS != *orig.AWS {
		t.Fatalf("aws block mismatch:\n got %+v\nwant %+v\n%s", got.AWS, orig.AWS, blk)
	}
}

// TestEncodeSecretStoreNode_OmitsEmptyKeys proves a value-free aws block (no
// explicit keys) encodes WITHOUT any credential field — byte-identical to before
// the explicit-credentials feature.
func TestEncodeSecretStoreNode_OmitsEmptyKeys(t *testing.T) {
	node, err := EncodeSecretStoreNode(SecretStoreConfig{
		Backend: SecretBackendAWS,
		AWS:     &SecretStoreAWS{Region: "us-east-1", NamePrefix: "warden/"},
	})
	if err != nil {
		t.Fatalf("EncodeSecretStoreNode: %v", err)
	}
	blk, err := yaml.Marshal(map[string]yaml.Node{"secretStore": node})
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	for _, banned := range []string{"accessKeyId", "secretAccessKey"} {
		if strings.Contains(string(blk), banned) {
			t.Fatalf("value-free aws block must not emit %q:\n%s", banned, blk)
		}
	}
}

// TestSecretStore_AWSExplicitKeysBothOrNeither covers the both-or-neither
// validation: a lone accessKeyId or a lone secretAccessKey is rejected; both
// present or both absent are accepted.
func TestSecretStore_AWSExplicitKeysBothOrNeither(t *testing.T) {
	loneID := `
secretStore:
  backend: aws
  aws:
    region: us-east-1
    namePrefix: warden/
    accessKeyId: AKIAONLY
`
	if _, err := parse([]byte(secretStoreYAML(loneID, ""))); err == nil ||
		!strings.Contains(err.Error(), "both or neither") {
		t.Fatalf("lone accessKeyId err = %v, want both-or-neither", err)
	}

	loneSecret := `
secretStore:
  backend: aws
  aws:
    region: us-east-1
    namePrefix: warden/
    secretAccessKey: sk-only
`
	if _, err := parse([]byte(secretStoreYAML(loneSecret, ""))); err == nil ||
		!strings.Contains(err.Error(), "both or neither") {
		t.Fatalf("lone secretAccessKey err = %v, want both-or-neither", err)
	}

	both := `
secretStore:
  backend: aws
  aws:
    region: us-east-1
    namePrefix: warden/
    accessKeyId: AKIABOTH
    secretAccessKey: sk-both
`
	if _, err := parse([]byte(secretStoreYAML(both, ""))); err != nil {
		t.Fatalf("both keys present should validate, got: %v", err)
	}
}

func TestSecretStore_DeepCopyAWSIndependent(t *testing.T) {
	p, err := parse([]byte(secretStoreYAML(`
secretStore:
  backend: aws
  aws:
    region: us-east-1
    namePrefix: warden/
`, "")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	orig := p.policy
	cp := orig.DeepCopy()
	if cp.SecretStore.AWS == orig.SecretStore.AWS {
		t.Fatal("DeepCopy aliased the aws pointer")
	}
	cp.SecretStore.AWS.Region = "eu-west-1"
	if orig.SecretStore.AWS.Region != "us-east-1" {
		t.Fatalf("DeepCopy aliased aws: original mutated to %q", orig.SecretStore.AWS.Region)
	}
}
