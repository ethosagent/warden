package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
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
	// AccessKeyID and SecretAccessKey are OPTIONAL explicit AWS credentials for
	// the Secrets Manager client. DELIBERATE INVARIANT RELAXATION (product-owner
	// decision): unlike every other block, SecretAccessKey is a real credential
	// VALUE that IS persisted to the served config and distributed to workers over
	// SettingsWire. They are both-or-neither (validateSecretStore enforces it) and
	// take precedence over env / IMDS credential resolution. When empty, the client
	// falls back to the process env then the instance IAM role — the original,
	// value-free behavior. The value is masked in the dashboard GET and never
	// logged raw.
	AccessKeyID     string
	SecretAccessKey string
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
// The `omitempty` on aws matters for the write direction (EncodeSecretStoreNode):
// a nil AWS (env/echo) must omit the child entirely, not emit `aws: null`.
type rawSecretStore struct {
	Backend string             `yaml:"backend"`
	AWS     *rawSecretStoreAWS `yaml:"aws,omitempty"`
}

type rawSecretStoreAWS struct {
	Region     string `yaml:"region"`
	NamePrefix string `yaml:"namePrefix"`
	// accessKeyId/secretAccessKey are OPTIONAL explicit credentials (omitempty so a
	// value-free aws block stays byte-identical to before). secretAccessKey is the
	// one credential VALUE Warden persists on disk (product decision — see
	// SecretStoreAWS).
	AccessKeyID     string `yaml:"accessKeyId,omitempty"`
	SecretAccessKey string `yaml:"secretAccessKey,omitempty"`
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
			// accessKeyId is an identifier (safe to trim); the secret VALUE is kept
			// verbatim so parsing never mutates the credential.
			AccessKeyID:     strings.TrimSpace(r.AWS.AccessKeyID),
			SecretAccessKey: r.AWS.SecretAccessKey,
		}
		if aws.NamePrefix == "" {
			aws.NamePrefix = defaultAWSNamePrefix
		}
		c.AWS = aws
	}
	return c
}

// EncodeSecretStoreNode encodes a typed SecretStoreConfig into a yaml.Node
// matching the on-disk `secretStore:` block — the write-direction counterpart of
// parseSecretStore and the analogue of EncodeDetectionNode/EncodeLLMProvidersNode.
// It round-trips through rawSecretStore so the YAML tags stay in lockstep with
// the read path (a single source of tag truth). Only the backend NAME and (aws)
// region/namePrefix are encoded — the raw type has no credential field to carry,
// so the secret-free invariant is structural. The aws child is emitted only when
// AWS is set (echo encodes as the backend name alone); namePrefix defaults to
// defaultAWSNamePrefix when the aws block is present but the prefix is empty,
// matching parseSecretStore so a write→read round-trip is stable. Callers decide
// what env/empty means (the settings writer DELETES the key so a worker falls
// back to its local placeholder→env map).
func EncodeSecretStoreNode(c SecretStoreConfig) (yaml.Node, error) {
	raw := rawSecretStore{Backend: c.ResolvedBackend()}
	if c.AWS != nil {
		prefix := strings.TrimSpace(c.AWS.NamePrefix)
		if prefix == "" {
			prefix = defaultAWSNamePrefix
		}
		raw.AWS = &rawSecretStoreAWS{
			Region:     strings.TrimSpace(c.AWS.Region),
			NamePrefix: prefix,
			// Explicit credentials are emitted only when present (omitempty). The
			// secret VALUE is written verbatim; callers that want preserve-on-empty
			// (the settings writer) must fill it in before encoding.
			AccessKeyID:     strings.TrimSpace(c.AWS.AccessKeyID),
			SecretAccessKey: c.AWS.SecretAccessKey,
		}
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return yaml.Node{}, fmt.Errorf("config: encode secretStore: %w", err)
	}
	return node, nil
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
		// Explicit credentials are OPTIONAL, but both-or-neither: a lone accessKeyId
		// or a lone secretAccessKey is a misconfiguration (SigV4 needs both). Empty
		// means "fall back to env / IAM", so the pair is only validated together.
		hasID := strings.TrimSpace(c.AWS.AccessKeyID) != ""
		hasSecret := c.AWS.SecretAccessKey != ""
		if hasID != hasSecret {
			return fmt.Errorf("config: secretStore.aws.accessKeyId and secretAccessKey must be set together (both or neither)")
		}
	default:
		return fmt.Errorf("config: secretStore.backend %q is invalid; must be one of: env, echo, aws", c.Backend)
	}
	return nil
}
