package config

import (
	"strings"
	"testing"
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
