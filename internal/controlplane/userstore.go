package controlplane

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/secrets"
)

// UserStoreOptions is what NewUserStore checks consent.store against.
type UserStoreOptions struct {
	// Distributed is the secretStore whose selector (and, when configured, its
	// explicit credential) the CP hands workers over SettingsWire.Secrets.
	Distributed config.SecretStoreConfig
	// Keys is the CP-local keys block; its AWS namespace must not collide with
	// the user store's either.
	Keys config.KeysConfig
	// Dev is the control plane's --dev flag: only it allows the echo backend.
	Dev bool
	// AWSClient, when set, replaces the client built from the CP environment or
	// instance role (tests and the harness inject a fake).
	AWSClient secrets.AWSSecretsClient
	Logger    *slog.Logger
}

// NewUserStore builds the CP-only user credential store from consent.store
// (W-P3-CSIG-06), or returns nil when the block is absent. The store holds
// every per-user credential in P3 under the reserved namespaces (see
// secrets/userkey.go). It is never mounted on /central/secrets or the dashboard
// secret-store tab, and no worker ever gets a credential for it: its client
// takes credentials only from the CP environment or instance role, never from
// YAML or the wire.
//
// It refuses to start (each error naming the keys involved) when:
//   - the backend is echo without --dev, or vault (until W-P3-PUS-02 wires the
//     W-P3-PUS-01 store);
//   - consent.store resolves to the same backend as the distributed secretStore
//     (or keys.store) and either namePrefix is a prefix of the other, so a
//     worker credential scoped to the secretStore namespace could reach it.
func NewUserStore(cfg *config.ConsentStore, opts UserStoreOptions) (secrets.SecretStore, error) {
	if cfg == nil {
		return nil, nil
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if err := checkUserStoreOverlap(cfg, opts.Distributed); err != nil {
		return nil, err
	}
	if err := checkUserStoreKeysOverlap(cfg, opts.Keys); err != nil {
		return nil, err
	}
	switch cfg.Backend {
	case config.ConsentStoreBackendEcho:
		if !opts.Dev {
			return nil, errors.New("control-plane: consent.store.backend echo is development only and needs --dev (it keeps no value; use aws, or vault once available)")
		}
		logger.Warn("control plane ECHO user credential store active (--dev) — NON-PRODUCTION: it keeps no value; never use it for real users")
		return secrets.NewEchoStore(), nil
	case config.ConsentStoreBackendAWS:
		if cfg.AWS == nil || cfg.AWS.Region == "" {
			return nil, errors.New("control-plane: consent.store.backend aws requires consent.store.aws.region")
		}
		client := opts.AWSClient
		if client == nil {
			// Credentials from the CP environment or instance role only (env →
			// IMDS): the consent.store block has no credential fields.
			var err error
			if client, err = awsSecretsClientFactory(cfg.AWS.Region, "", ""); err != nil {
				return nil, fmt.Errorf("control-plane: consent.store.aws: %w", err)
			}
		}
		logger.Info("control plane user credential store active",
			"backend", cfg.Backend, "region", cfg.AWS.Region, "namePrefix", cfg.NamePrefix)
		return secrets.NewAWSSecretStore(client, cfg.AWS.Region, cfg.NamePrefix), nil
	case config.ConsentStoreBackendVault:
		// TODO(W-P3-PUS-02): build secrets.NewVaultSecretStore (W-P3-PUS-01)
		// from cfg.Vault, the token read from the CP environment variable
		// cfg.Vault.TokenEnv, probe the KV v2 mount at startup (fail closed),
		// and give the store Persists() true.
		return nil, errors.New("control-plane: consent.store.backend vault needs W-P3-PUS-01 (the Vault KV v2 store is not available in this build; use aws)")
	default:
		return nil, fmt.Errorf("control-plane: consent.store.backend %q is invalid", cfg.Backend)
	}
}

// storeNamespace is one backend namespace: the backend, the identity of the
// backend instance a single credential can span, and the name prefix in it.
type storeNamespace struct {
	backend  string
	identity string
	prefix   string
	key      string // the config key that sets prefix, for error text
}

// userStoreNamespace returns the namespace consent.store writes into; ok is
// false for echo, which has no shared backend (each process keeps its own
// empty in-memory instance, so nothing a worker holds can reach it).
func userStoreNamespace(cfg *config.ConsentStore) (storeNamespace, bool) {
	switch cfg.Backend {
	case config.ConsentStoreBackendAWS:
		return storeNamespace{backend: config.ConsentStoreBackendAWS, identity: awsIdentity, prefix: cfg.NamePrefix, key: "consent.store.namePrefix"}, true
	case config.ConsentStoreBackendVault:
		id := ""
		if cfg.Vault != nil {
			id = vaultIdentity(cfg.Vault.Addr, cfg.Vault.Namespace, cfg.Vault.Mount)
		}
		return storeNamespace{backend: config.ConsentStoreBackendVault, identity: id, prefix: cfg.NamePrefix, key: "consent.store.namePrefix"}, true
	default:
		return storeNamespace{}, false
	}
}

// awsIdentity is the identity of every AWS Secrets Manager namespace. Region
// and account are deliberately NOT part of it: an IAM grant on a name prefix
// usually spans regions (arn:aws:secretsmanager:*:...), and the account behind
// a credential cannot be known before calling AWS, so two AWS namespaces are
// the same backend unless their prefixes are disjoint (fail closed).
const awsIdentity = "aws"

// vaultIdentity normalizes a Vault address, namespace and mount into the
// identity of one KV mount: a token scoped to a path under that mount reaches
// the same names whatever spelling of the address it is used with.
func vaultIdentity(addr, namespace, mount string) string {
	a := strings.ToLower(strings.TrimRight(strings.TrimSpace(addr), "/"))
	if u, err := url.Parse(a); err == nil && u.Host != "" {
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
		}
		a = host + ":" + port
	}
	return a + "|" + strings.Trim(namespace, "/") + "|" + strings.Trim(mount, "/")
}

// distributedNamespaces returns the namespaces the distributed secretStore
// gives workers a credential for: today only an aws secretStore has one (env
// is a local env-var map, echo keeps nothing). When the distributed store
// gains another shared backend it must be added here with its identity.
func distributedNamespaces(ss config.SecretStoreConfig) []storeNamespace {
	if ss.ResolvedBackend() != config.SecretBackendAWS {
		return nil
	}
	prefix := secrets.DefaultAWSNamePrefix
	if ss.AWS != nil && ss.AWS.NamePrefix != "" {
		prefix = ss.AWS.NamePrefix
	}
	return []storeNamespace{{backend: config.SecretBackendAWS, identity: awsIdentity, prefix: prefix, key: "secretStore.aws.namePrefix"}}
}

// overlaps reports whether a and b are the same backend instance and one
// prefix nests the other (an empty prefix nests everything).
func (a storeNamespace) overlaps(b storeNamespace) bool {
	if a.backend != b.backend || a.identity != b.identity {
		return false
	}
	return strings.HasPrefix(a.prefix, b.prefix) || strings.HasPrefix(b.prefix, a.prefix)
}

// checkUserStoreOverlap refuses a distributed secretStore that shares a
// backend namespace with consent.store, in either direction. It is pure, so
// startup, every settings writer and the offline policy import share it. A nil
// store (no consent.store) never overlaps. The error is a
// *dashboard.UserStoreOverlapError (400 user_store_overlap).
func checkUserStoreOverlap(cfg *config.ConsentStore, ss config.SecretStoreConfig) error {
	if cfg == nil {
		return nil
	}
	us, ok := userStoreNamespace(cfg)
	if !ok {
		return nil
	}
	for _, d := range distributedNamespaces(ss) {
		if us.overlaps(d) {
			return &dashboard.UserStoreOverlapError{Err: fmt.Errorf("control-plane: %s %q overlaps %s %q on the same %s backend: workers hold a credential for the secretStore namespace, so it could reach per-user credentials; use a disjoint prefix (the default is %q)",
				us.key, us.prefix, d.key, d.prefix, d.backend, config.DefaultConsentStoreNamePrefix)}
		}
	}
	return nil
}

// checkUserStoreKeysOverlap refuses a consent.store that shares an AWS
// namespace with keys.store: both are CP-only, but a nested prefix would let a
// user key name collide with a signing-key name.
func checkUserStoreKeysOverlap(cfg *config.ConsentStore, k config.KeysConfig) error {
	if cfg == nil || !k.Enabled || k.Store.Backend != config.KeysBackendAWS || k.Store.AWS == nil {
		return nil
	}
	us, ok := userStoreNamespace(cfg)
	if !ok {
		return nil
	}
	ks := storeNamespace{backend: config.SecretBackendAWS, identity: awsIdentity, prefix: k.Store.AWS.NamePrefix, key: "keys.store.aws.namePrefix"}
	if us.overlaps(ks) {
		return fmt.Errorf("control-plane: %s %q overlaps %s %q: use disjoint prefixes", us.key, us.prefix, ks.key, ks.prefix)
	}
	return nil
}

// checkUserStoreBinding refuses settings whose distributed secretStore would
// overlap consent.store while it is configured. Startup checks the served
// file (NewUserStore); this covers secretStore changing at runtime (settings
// writes, versioned publishes, rollbacks, applied drafts, the versioned head
// at startup). nil settings carry no secrets block (the env backend).
func (s *Server) checkUserStoreBinding(settings *config.SettingsWire) error {
	if s.cfg.Consent == nil || s.cfg.Consent.Store == nil {
		return nil
	}
	return checkUserStoreOverlap(s.cfg.Consent.Store, settingsSecretStore(settings))
}

// settingsSecretStore is the secretStore a settings block distributes.
func settingsSecretStore(settings *config.SettingsWire) config.SecretStoreConfig {
	if settings == nil {
		return config.SecretStoreConfig{}
	}
	return config.SecretStoreConfigFromSettings(settings.Secrets)
}
