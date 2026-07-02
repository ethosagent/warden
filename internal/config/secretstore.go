package config

import (
	"fmt"
	"strings"
)

// Secret-store backend selectors. These name the WORKER read backend that
// resolves a placeholder to its value:
//
//   - env  — the placeholder→envVar mapping in `secrets:` (today's behavior;
//     the default when secretStore is omitted).
//   - echo — the NON-PRODUCTION echo store; the "value" is the placeholder key
//     itself, for proving the write→read→swap wiring with zero cloud deps.
//   - aws  — AWS Secrets Manager (store construction lands in Phase 5; the block
//     shape is parsed + validated now so config is stable ahead of the backend).
const (
	SecretBackendEnv  = "env"
	SecretBackendEcho = "echo"
	SecretBackendAWS  = "aws"
)

// defaultAWSNamePrefix is the key→secret-name convention applied when the aws
// block omits namePrefix: a key K lives under the secret name `warden/K`, so IAM
// can scope a worker/CP to `warden/*`.
const defaultAWSNamePrefix = "warden/"

// SecretStoreConfig selects the backend the worker resolves placeholders through.
//
// DESIGN NOTE — non-breaking sibling block. This is a deliberate, non-breaking
// deviation from the plan's illustrative `secrets: {backend, aws}` YAML: the
// `secrets:` key is already a LIST (the placeholder set), and restructuring it
// into a struct would ripple through the CP-served config, the examples, and the
// tests. So the backend selector lives in a NEW, optional sibling block,
// `secretStore:`. Omitting it (or setting backend: env) is byte-identical to
// today's env path.
//
// This block is LOCAL only this phase (Policy.SecretStore is json:"-"); it never
// crosses Warden's config wire. Control-plane distribution of the key→backend
// mapping is Phase 4.
type SecretStoreConfig struct {
	// Backend is one of env|echo|aws. Empty normalizes to env (see
	// ResolvedBackend), so an absent block is byte-identical to before.
	Backend string
	// AWS carries the AWS Secrets Manager settings, present only when the aws
	// block is configured. Credentials are NEVER here — they resolve from the
	// process environment / IAM, same rule as Judge.APIKeyEnv.
	AWS *SecretStoreAWS
}

// SecretStoreAWS holds the AWS Secrets Manager backend settings. The store is
// built in Phase 5; the shape is parsed + validated now so operators can pin
// config ahead of the backend landing.
type SecretStoreAWS struct {
	// Region is the AWS region the Secrets Manager client targets.
	Region string
	// NamePrefix is the key→secret-name namespace (default warden/): key K maps
	// to the secret name `<NamePrefix>K`, scoping IAM to `<NamePrefix>*`.
	NamePrefix string
}

// ResolvedBackend returns the effective backend, normalizing the empty zero
// value to env (today's behavior) so an omitted secretStore block resolves to
// the original EnvFetcher path.
func (c SecretStoreConfig) ResolvedBackend() string {
	if c.Backend == "" {
		return SecretBackendEnv
	}
	return c.Backend
}

// rawSecretStore mirrors the on-disk `secretStore:` block. Pointer so an absent
// block is distinct from an explicit one. KnownFields(true) is strict, so every
// field MUST be registered here or a config carrying it fails to parse.
type rawSecretStore struct {
	Backend string             `yaml:"backend"`
	AWS     *rawSecretStoreAWS `yaml:"aws"`
}

type rawSecretStoreAWS struct {
	Region     string `yaml:"region"`
	NamePrefix string `yaml:"namePrefix"`
}

// parseSecretStore converts the raw secretStore block into a typed
// SecretStoreConfig, applying documented defaults and normalizing case. An
// absent block yields the env backend (byte-identical to today). Cross-field
// validation (enum + aws shape) happens in validateSecretStore.
func parseSecretStore(r *rawSecretStore) SecretStoreConfig {
	c := SecretStoreConfig{Backend: SecretBackendEnv}
	if r == nil {
		return c
	}
	if b := strings.ToLower(strings.TrimSpace(r.Backend)); b != "" {
		c.Backend = b
	}
	if r.AWS != nil {
		aws := &SecretStoreAWS{
			Region:     strings.TrimSpace(r.AWS.Region),
			NamePrefix: strings.TrimSpace(r.AWS.NamePrefix),
		}
		if aws.NamePrefix == "" {
			aws.NamePrefix = defaultAWSNamePrefix
		}
		c.AWS = aws
	}
	return c
}

// validateSecretStore enforces the secretStore block's invariants. The empty
// zero value validates as env (Policy.SecretStore never crosses the wire, so a
// managed worker decodes an empty block that must pass). The per-secret envVar
// requirement is enforced in config.validate, which knows the resolved backend.
func validateSecretStore(c SecretStoreConfig) error {
	switch c.ResolvedBackend() {
	case SecretBackendEnv, SecretBackendEcho:
		// env: envVar-per-secret is enforced in validate (backend-aware).
		// echo: the placeholder IS the key; no aws block, no envVar needed.
	case SecretBackendAWS:
		if c.AWS == nil || strings.TrimSpace(c.AWS.Region) == "" {
			return fmt.Errorf("config: secretStore.aws.region is required when backend is aws")
		}
		if strings.TrimSpace(c.AWS.NamePrefix) == "" {
			return fmt.Errorf("config: secretStore.aws.namePrefix is required when backend is aws")
		}
	default:
		return fmt.Errorf("config: secretStore.backend %q is invalid; must be one of: env, echo, aws", c.Backend)
	}
	return nil
}
