package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

const (
	userStoreVaultToken = "hvs.cp-user-store-token-4c1d"
	userStoreVaultEnv   = "WARDEN_TEST_CP_VAULT_TOKEN"
)

func vaultUserStore(addr, namespace string) *config.ConsentStore {
	return &config.ConsentStore{Backend: config.ConsentStoreBackendVault, NamePrefix: config.DefaultConsentStoreNamePrefix,
		Vault: &config.ConsentStoreVault{Addr: addr, Mount: "secret", Namespace: namespace, TokenEnv: userStoreVaultEnv}}
}

func vaultEnv(token string) func(string) string {
	return func(k string) string {
		if k == userStoreVaultEnv {
			return token
		}
		return ""
	}
}

// TestUserStoreVault: consent.store {backend: vault} builds a working,
// persistent, compare-and-swap store against the KV v2 fake, with the token
// read only from the CP environment and the KV v2 mount probed at startup;
// every misconfiguration fails closed without the token in the error.
func TestUserStoreVault(t *testing.T) {
	ctx := context.Background()

	t.Run("builds a working store", func(t *testing.T) {
		kv := fakes.NewFakeVaultKV(t, userStoreVaultToken)
		st, err := NewUserStore(ctx, vaultUserStore(kv.URL(), "team-a"), UserStoreOptions{Getenv: vaultEnv(userStoreVaultToken), VaultClient: kv.Client()})
		if err != nil || st == nil {
			t.Fatalf("NewUserStore = %v, %v", st, err)
		}
		if !secrets.IsPersistent(st) {
			t.Fatal("the vault user store must be persistent")
		}
		reqs := kv.Requests()
		if len(reqs) != 1 || reqs[0].Path != "/v1/sys/internal/ui/mounts/secret" || reqs[0].Namespace != "team-a" {
			t.Fatalf("startup requests = %+v, want exactly the mount probe with namespace team-a", reqs)
		}
		uk, err := secrets.UserKey("https://idp.example.com", "alice")
		if err != nil {
			t.Fatal(err)
		}
		key, err := secrets.UserGrantKey(uk, "google")
		if err != nil {
			t.Fatal(err)
		}
		vs, ok := st.(secrets.VersionedStore)
		if !ok {
			t.Fatal("the vault user store must be a VersionedStore")
		}
		if err := vs.PutIfVersion(ctx, key, `{"v":1}`, 0); err != nil {
			t.Fatalf("create-only write: %v", err)
		}
		if got, ok := kv.Value("warden-cp/" + key); !ok || got != `{"v":1}` {
			t.Fatalf("backend value at warden-cp/%s = %q, %v", key, got, ok)
		}
		if err := vs.PutIfVersion(ctx, key, `{"v":2}`, 0); !errors.Is(err, secrets.ErrVersionConflict) {
			t.Fatalf("second create-only write = %v, want ErrVersionConflict", err)
		}
		if _, err := st.Get(ctx, "users/"+uk+"/github"); !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("missing grant = %v, want ErrNotFound", err)
		}
	})

	fails := []struct {
		name    string
		setup   func(t *testing.T) (*config.ConsentStore, UserStoreOptions)
		wantErr []string
		isNotKV bool
	}{
		{"token env empty", func(t *testing.T) (*config.ConsentStore, UserStoreOptions) {
			kv := fakes.NewFakeVaultKV(t, userStoreVaultToken)
			return vaultUserStore(kv.URL(), ""), UserStoreOptions{Getenv: vaultEnv("  "), VaultClient: kv.Client()}
		}, []string{userStoreVaultEnv, "consent.store.vault.tokenEnv", "is empty"}, false},
		{"kv v1 mount", func(t *testing.T) (*config.ConsentStore, UserStoreOptions) {
			kv := fakes.NewFakeVaultKV1(t, userStoreVaultToken)
			return vaultUserStore(kv.URL(), ""), UserStoreOptions{Getenv: vaultEnv(userStoreVaultToken), VaultClient: kv.Client()}
		}, []string{"consent.store.vault", "KV version 2"}, true},
		{"missing mount or namespace", func(t *testing.T) (*config.ConsentStore, UserStoreOptions) {
			kv := fakes.NewFakeVaultKV(t, userStoreVaultToken)
			kv.ForceResponse(http.MethodGet, "/v1/sys/internal/ui/mounts/secret", http.StatusNotFound, `{"errors":["no handler for route"]}`)
			return vaultUserStore(kv.URL(), "nope"), UserStoreOptions{Getenv: vaultEnv(userStoreVaultToken), VaultClient: kv.Client()}
		}, []string{"consent.store.vault", "status 404", `namespace "nope"`}, false},
		{"wrong token", func(t *testing.T) (*config.ConsentStore, UserStoreOptions) {
			kv := fakes.NewFakeVaultKV(t, "a-different-token")
			return vaultUserStore(kv.URL(), ""), UserStoreOptions{Getenv: vaultEnv(userStoreVaultToken), VaultClient: kv.Client()}
		}, []string{"consent.store.vault", "status 403", userStoreVaultEnv}, false},
		{"unreachable", func(t *testing.T) (*config.ConsentStore, UserStoreOptions) {
			gone := httptest.NewServer(http.NotFoundHandler())
			addr := gone.URL
			gone.Close()
			return vaultUserStore(addr, ""), UserStoreOptions{Getenv: vaultEnv(userStoreVaultToken)}
		}, []string{"consent.store.vault", "startup check"}, false},
		{"plain http to a remote host", func(t *testing.T) (*config.ConsentStore, UserStoreOptions) {
			return vaultUserStore("http://vault.example.com:8200", ""), UserStoreOptions{Getenv: vaultEnv(userStoreVaultToken)}
		}, []string{"consent.store.vault", "https unless the host is loopback"}, false},
		{"reserved mount", func(t *testing.T) (*config.ConsentStore, UserStoreOptions) {
			c := vaultUserStore("https://vault.example.com", "")
			c.Vault.Mount = "sys"
			return c, UserStoreOptions{Getenv: vaultEnv(userStoreVaultToken)}
		}, []string{"consent.store.vault", "reserved Vault system path"}, false},
		{"no vault block", func(t *testing.T) (*config.ConsentStore, UserStoreOptions) {
			return &config.ConsentStore{Backend: config.ConsentStoreBackendVault, NamePrefix: config.DefaultConsentStoreNamePrefix}, UserStoreOptions{}
		}, []string{"consent.store.vault {addr, mount}"}, false},
	}
	for _, tc := range fails {
		t.Run(tc.name, func(t *testing.T) {
			cfg, opts := tc.setup(t)
			st, err := NewUserStore(ctx, cfg, opts)
			if st != nil || err == nil {
				t.Fatalf("NewUserStore = %v, %v; want a startup error", st, err)
			}
			for _, w := range tc.wantErr {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err = %v, want it to contain %q", err, w)
				}
			}
			if tc.isNotKV && !errors.Is(err, secrets.ErrNotKV2) {
				t.Errorf("err = %v, want it to wrap secrets.ErrNotKV2", err)
			}
			if strings.Contains(err.Error(), userStoreVaultToken) {
				t.Fatal("the startup error carries the vault token")
			}
		})
	}

	t.Run("overlap still refused", func(t *testing.T) {
		// A vault consent.store never overlaps the distributed secretStore (no
		// vault backend there), but the aws keys check is unaffected.
		kv := fakes.NewFakeVaultKV(t, userStoreVaultToken)
		st, err := NewUserStore(ctx, vaultUserStore(kv.URL(), ""), UserStoreOptions{
			Distributed: awsSecretStoreCfg(config.DefaultConsentStoreNamePrefix), Getenv: vaultEnv(userStoreVaultToken), VaultClient: kv.Client(),
		})
		if err != nil || st == nil {
			t.Fatalf("vault user store with an aws secretStore under the same prefix = %v, %v", st, err)
		}
	})
}

// perUserOn is an enabled perUserSecrets block with one google mapping.
func perUserOn() config.PerUserSecretsConfig {
	return config.PerUserSecretsConfig{Enabled: true, WorkerCacheTTL: config.DefaultPerUserWorkerCacheTTL, Mappings: []config.PerUserMapping{{
		Placeholder: "GOOGLE_USER", Provider: "google", Domains: []string{"gmail.googleapis.com"}, In: []string{"header"}, Agents: []string{"support-bot"},
	}}}
}

// TestUserStoreVaultPerUserPreconditions: enabling perUserSecrets refuses to
// start without consent.store (naming it), with a non-persistent store,
// without the token service, with --bundles off and with a provider missing
// from consent.providers; each error names the missing key.
func TestUserStoreVaultPerUserPreconditions(t *testing.T) {
	persistent := fakes.NewMemorySecretStore()
	withStore := func() *config.ConsentConfig {
		c := fullConsent()
		c.Store = vaultUserStore("https://vault.example.com", "")
		c.Providers = []config.OAuthProviderConfig{{ID: "google"}, {ID: "github"}}
		return &c
	}
	noStore := func() *config.ConsentConfig { c := withStore(); c.Store = nil; return c }
	echo := func() *config.ConsentConfig {
		c := withStore()
		c.Store = &config.ConsentStore{Backend: config.ConsentStoreBackendEcho, NamePrefix: config.DefaultConsentStoreNamePrefix}
		return c
	}
	offer := BundlesConfig{Mode: BundlesOffer}
	for _, tc := range []struct {
		name    string
		pus     config.PerUserSecretsConfig
		consent *config.ConsentConfig
		store   secrets.SecretStore
		token   bool
		bundles BundlesConfig
		wantErr []string
	}{
		{"no consent block", perUserOn(), nil, nil, true, offer, []string{"perUserSecrets.enabled", "consent.store", "consent.enabled"}},
		{"no consent.store", perUserOn(), noStore(), nil, true, offer, []string{"perUserSecrets.enabled", "consent.store is not configured"}},
		{"echo store", perUserOn(), echo(), secrets.NewEchoStore(), true, offer, []string{"persistent consent.store", "consent.store.backend echo"}},
		{"no token service", perUserOn(), withStore(), persistent, false, offer, []string{"tokenService.enabled"}},
		{"bundles off", perUserOn(), withStore(), persistent, true, BundlesConfig{Mode: BundlesOff}, []string{"--bundles", "resolved to off"}},
		{"provider not registered", func() config.PerUserSecretsConfig {
			p := perUserOn()
			p.Mappings[0].Provider = "dropbox"
			return p
		}(), withStore(), persistent, true, offer, []string{"perUserSecrets.mappings[0].provider \"dropbox\"", "consent.providers", "google, github"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPerUserSecretsStartup(tc.pus, tc.consent, tc.store, tc.token, tc.bundles)
			if err == nil {
				t.Fatal("want a startup error")
			}
			for _, w := range tc.wantErr {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err = %v, want it to name %q", err, w)
				}
			}
		})
	}
	if err := checkPerUserSecretsStartup(perUserOn(), withStore(), persistent, true, BundlesConfig{Mode: BundlesRequire}); err != nil {
		t.Fatalf("all preconditions met: %v", err)
	}
	// Disabled or absent: nothing is required.
	if err := checkPerUserSecretsStartup(config.PerUserSecretsConfig{Mappings: perUserOn().Mappings}, nil, nil, false, BundlesConfig{Mode: BundlesOff}); err != nil {
		t.Fatalf("disabled block: %v", err)
	}
}

// perUserRunConfig is a CP config with consent, a vault consent.store on kv,
// the google provider, signing keys, the token service and perUserSecrets on.
func perUserRunConfig(t *testing.T, kvURL, consentExtra string) string {
	t.Helper()
	body := basePolicy + identityBlockYAML + consoleBlock + consentBlockYAML + consentExtra +
		"  store:\n    backend: vault\n    vault:\n      addr: " + kvURL + "\n      mount: secret\n      tokenEnv: " + userStoreVaultEnv + "\n" +
		"  providers:\n    - id: google\n      type: google\n      clientID: cid\n      clientSecretEnv: WARDEN_TEST_GOOGLE_SECRET\n" +
		keysEnabledYAML + tokenServiceBlock +
		"perUserSecrets:\n  enabled: true\n  mappings:\n    - placeholder: GOOGLE_USER\n      provider: google\n      domains: [gmail.googleapis.com]\n      agents: [support-bot]\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func perUserRunEnv(t *testing.T) {
	t.Setenv("WARDEN_CONSOLE_SECRET", "console-secret")
	t.Setenv("WARDEN_PORTAL_DEX_CLIENT_SECRET", "portal-secret")
	t.Setenv("WARDEN_TEST_GOOGLE_SECRET", "google-secret")
	t.Setenv(userStoreVaultEnv, userStoreVaultToken)
}

// TestUserStoreVaultRunRefusals: Run itself stops before it listens when
// perUserSecrets is enabled with --bundles=off (naming --bundles), with no
// consent.store (naming consent.store), and when the vault consent.store mount
// is KV v1 (the startup probe fails closed).
func TestUserStoreVaultRunRefusals(t *testing.T) {
	perUserRunEnv(t)

	t.Run("bundles off", func(t *testing.T) {
		kv := fakes.NewFakeVaultKV(t, userStoreVaultToken)
		err := bootErr(t, Params{ConfigPath: perUserRunConfig(t, kv.URL(), ""), StateDir: filepath.Join(t.TempDir(), "state"), Bundles: BundlesOff})
		if !strings.Contains(err.Error(), "--bundles") || !strings.Contains(err.Error(), "perUserSecrets.enabled") {
			t.Fatalf("Run err = %v, want it to name --bundles", err)
		}
		if len(kv.Requests()) == 0 {
			t.Fatal("the vault consent.store was never probed")
		}
	})

	t.Run("no consent.store", func(t *testing.T) {
		body := basePolicy + identityBlockYAML + consoleBlock + consentBlockYAML + "  idpLink:\n    enabled: false\n" +
			keysEnabledYAML + tokenServiceBlock +
			"perUserSecrets:\n  enabled: true\n"
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		err := bootErr(t, Params{ConfigPath: path, StateDir: filepath.Join(t.TempDir(), "state"), Bundles: BundlesOff})
		if !strings.Contains(err.Error(), "consent.store") || !strings.Contains(err.Error(), "perUserSecrets.enabled") {
			t.Fatalf("Run err = %v, want it to name consent.store", err)
		}
	})

	t.Run("kv v1 mount", func(t *testing.T) {
		kv := fakes.NewFakeVaultKV1(t, userStoreVaultToken)
		err := bootErr(t, Params{ConfigPath: perUserRunConfig(t, kv.URL(), ""), StateDir: filepath.Join(t.TempDir(), "state"), Bundles: BundlesOff})
		if !errors.Is(err, secrets.ErrNotKV2) || !strings.Contains(err.Error(), "consent.store.vault") {
			t.Fatalf("Run err = %v, want the KV v2 probe failure", err)
		}
		if strings.Contains(err.Error(), userStoreVaultToken) {
			t.Fatal("the boot error carries the vault token")
		}
	})
}
