package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/secrets"
)

// The distributed secretStore's default namespace and two prefixes nested in
// it, built from the owner constant (X5).
var (
	workerPrefix = secrets.DefaultAWSNamePrefix
	nestedUsers  = secrets.DefaultAWSNamePrefix + "users/"
	nestedTeam   = secrets.DefaultAWSNamePrefix + "team/"
)

func awsUserStore(prefix, region string) *config.ConsentStore {
	return &config.ConsentStore{Backend: config.ConsentStoreBackendAWS, NamePrefix: prefix, AWS: &config.ConsentStoreAWS{Region: region}}
}

func awsSecretStoreCfg(prefix string) config.SecretStoreConfig {
	return config.SecretStoreConfig{Backend: config.SecretBackendAWS, AWS: &config.SecretStoreAWS{Region: "us-east-1", NamePrefix: prefix}}
}

func wantOverlap(t *testing.T, what string, err error) {
	t.Helper()
	var uo *dashboard.UserStoreOverlapError
	if !errors.As(err, &uo) {
		t.Fatalf("%s: err = %v, want *dashboard.UserStoreOverlapError", what, err)
	}
	if !strings.Contains(err.Error(), "consent.store.namePrefix") || !strings.Contains(err.Error(), "secretStore.aws.namePrefix") {
		t.Fatalf("%s: err = %v, want it to name both keys", what, err)
	}
}

// TestUserStoreOverlap: consent.store must not share a backend namespace with
// the distributed secretStore in either direction; the default warden-cp/
// starts; echo needs --dev; vault waits for W-P3-PUS-01.
func TestUserStoreOverlap(t *testing.T) {
	client := newFakeAWSClient()
	opts := func(ss config.SecretStoreConfig) UserStoreOptions {
		return UserStoreOptions{Distributed: ss, AWSClient: client}
	}

	t.Run("overlap refused", func(t *testing.T) {
		for name, c := range map[string]struct {
			us *config.ConsentStore
			ss config.SecretStoreConfig
		}{
			"user store nested in secretStore": {awsUserStore(nestedUsers, "us-east-1"), awsSecretStoreCfg(workerPrefix)},
			"secretStore nested in user store": {awsUserStore(workerPrefix, "us-east-1"), awsSecretStoreCfg(nestedTeam)},
			"equal prefixes":                   {awsUserStore(config.DefaultConsentStoreNamePrefix, "us-east-1"), awsSecretStoreCfg(config.DefaultConsentStoreNamePrefix)},
			// A worker IAM grant on a prefix usually spans regions.
			"other region": {awsUserStore(nestedUsers, "eu-west-1"), awsSecretStoreCfg(workerPrefix)},
			// An aws secretStore without a block uses the default namespace.
			"default secretStore prefix": {awsUserStore(nestedUsers, "us-east-1"), config.SecretStoreConfig{Backend: config.SecretBackendAWS}},
			"empty secretStore prefix":   {awsUserStore(nestedUsers, "us-east-1"), config.SecretStoreConfig{Backend: config.SecretBackendAWS, AWS: &config.SecretStoreAWS{Region: "us-east-1"}}},
		} {
			st, err := NewUserStore(c.us, opts(c.ss))
			if st != nil {
				t.Errorf("%s: got a store", name)
			}
			wantOverlap(t, name, err)
		}
	})

	t.Run("disjoint starts", func(t *testing.T) {
		st, err := NewUserStore(awsUserStore(config.DefaultConsentStoreNamePrefix, "us-east-1"), opts(awsSecretStoreCfg(workerPrefix)))
		if err != nil || st == nil {
			t.Fatalf("NewUserStore = %v, %v", st, err)
		}
		if !secrets.IsPersistent(st) {
			t.Error("the aws user store must be persistent")
		}
		uk, err := secrets.UserKey("https://idp.example.com", "alice")
		if err != nil {
			t.Fatal(err)
		}
		key, err := secrets.IdPLinkKey(uk)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Put(context.Background(), key, "refresh-token"); err != nil {
			t.Fatal(err)
		}
		if _, ok := client.store["warden-cp/idp/"+uk]; !ok {
			t.Fatalf("backend names = %v, want warden-cp/idp/<userKey>", client.store)
		}
		// Backends that cannot share a namespace never overlap.
		for name, ss := range map[string]config.SecretStoreConfig{
			"env": {}, "echo": {Backend: config.SecretBackendEcho},
		} {
			if _, err := NewUserStore(awsUserStore(workerPrefix, "us-east-1"), opts(ss)); err != nil {
				t.Errorf("%s secretStore: %v", name, err)
			}
		}
	})

	t.Run("keys store overlap refused", func(t *testing.T) {
		keys := config.KeysConfig{Enabled: true, Store: config.KeysStore{Backend: config.KeysBackendAWS, AWS: &config.KeysStoreAWS{Region: "us-east-1", NamePrefix: config.DefaultConsentStoreNamePrefix + "keys/"}}}
		o := opts(awsSecretStoreCfg(workerPrefix))
		o.Keys = keys
		_, err := NewUserStore(awsUserStore(config.DefaultConsentStoreNamePrefix, "us-east-1"), o)
		if err == nil || !strings.Contains(err.Error(), "keys.store.aws.namePrefix") {
			t.Fatalf("err = %v, want the keys overlap", err)
		}
	})

	t.Run("echo needs dev", func(t *testing.T) {
		echo := &config.ConsentStore{Backend: config.ConsentStoreBackendEcho, NamePrefix: config.DefaultConsentStoreNamePrefix}
		if _, err := NewUserStore(echo, opts(config.SecretStoreConfig{Backend: config.SecretBackendEcho})); err == nil || !strings.Contains(err.Error(), "--dev") {
			t.Fatalf("echo without --dev err = %v", err)
		}
		o := opts(config.SecretStoreConfig{Backend: config.SecretBackendEcho})
		o.Dev = true
		st, err := NewUserStore(echo, o)
		if err != nil || st == nil || secrets.IsPersistent(st) {
			t.Fatalf("echo with --dev = %v, %v (want a non-persistent store)", st, err)
		}
	})

	t.Run("vault not yet available", func(t *testing.T) {
		v := &config.ConsentStore{Backend: config.ConsentStoreBackendVault, NamePrefix: config.DefaultConsentStoreNamePrefix,
			Vault: &config.ConsentStoreVault{Addr: "https://vault.example.com", Mount: "secret", TokenEnv: "VAULT_TOKEN"}}
		if _, err := NewUserStore(v, opts(config.SecretStoreConfig{})); err == nil || !strings.Contains(err.Error(), "consent.store.backend vault needs W-P3-PUS-01") {
			t.Fatalf("vault err = %v", err)
		}
	})

	t.Run("absent", func(t *testing.T) {
		if st, err := NewUserStore(nil, opts(awsSecretStoreCfg(workerPrefix))); st != nil || err != nil {
			t.Fatalf("nil block = %v, %v", st, err)
		}
	})

	t.Run("vault identity", func(t *testing.T) {
		a := storeNamespace{backend: "vault", identity: vaultIdentity("https://Vault.example.com", "team", "/secret/"), prefix: "x/"}
		b := storeNamespace{backend: "vault", identity: vaultIdentity("https://vault.example.com:443/", "team/", "secret"), prefix: "x/y/"}
		if !a.overlaps(b) {
			t.Error("the same vault mount spelled differently must overlap")
		}
		b.identity = vaultIdentity("https://vault.example.com", "team", "other")
		if a.overlaps(b) {
			t.Error("another mount must not overlap")
		}
	})
}

// userStoreConsent is the consent block with an aws consent.store under the
// default prefix.
func userStoreConsent() *config.ConsentConfig {
	c := fullConsent()
	c.Store = awsUserStore(config.DefaultConsentStoreNamePrefix, "us-east-1")
	return &c
}

func overlappingSecrets() *config.SecretsSettings {
	return &config.SecretsSettings{Backend: config.SecretBackendAWS, Region: "us-east-1", NamePrefix: config.DefaultConsentStoreNamePrefix}
}

// TestUserStoreOverlapWriters: a settings write that would move the
// distributed secretStore onto consent.store's namespace is refused in file
// and versioned mode (400 user_store_overlap over HTTP), and a disjoint one
// is accepted.
func TestUserStoreOverlapWriters(t *testing.T) {
	t.Run("file mode", func(t *testing.T) {
		cfg := detectionEditorConfig(t)
		cfg.Consent = userStoreConsent()
		srv := New(cfg)
		before := readFile(t, cfg.PolicyPath)
		err := srv.writeSettings(config.SettingsWire{Identity: matchingIdentity(), Secrets: overlappingSecrets()})
		var uo *dashboard.UserStoreOverlapError
		if !errors.As(err, &uo) {
			t.Fatalf("err = %v, want *dashboard.UserStoreOverlapError", err)
		}
		if after := readFile(t, cfg.PolicyPath); after != before {
			t.Fatal("served file changed by a refused write")
		}
		ok := &config.SecretsSettings{Backend: config.SecretBackendAWS, Region: "us-east-1", NamePrefix: workerPrefix}
		if err := srv.writeSettings(config.SettingsWire{Identity: matchingIdentity(), Secrets: ok}); err != nil {
			t.Fatalf("disjoint secretStore rejected: %v", err)
		}
	})
	t.Run("versioned HTTP", func(t *testing.T) {
		srv := New(Config{PolicyPath: consentPolicyFile(t, ""), Token: dashTestToken, State: openPolicyState(t), PolicyStore: PolicyStoreVersioned, Consent: userStoreConsent()})
		if err := srv.importInitialVersion(context.Background()); err != nil {
			t.Fatal(err)
		}
		e := &contractEnv{srv: srv, h: srv.Handler()}
		body := `{"identity":{"defaultMode":"attribute","issuer":"` + consentIssuer + `","audience":"warden"},"secrets":{"backend":"aws","region":"us-east-1","namePrefix":"` + config.DefaultConsentStoreNamePrefix + `idp/"}}`
		rec := e.send("", http.MethodPut, "/dashboard/api/settings", body, ifMatch(1))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("settings PUT = %d %s, want 400", rec.Code, rec.Body.String())
		}
		m := map[string]string{}
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if m["error"] != "user_store_overlap" || !strings.Contains(m["detail"], "consent.store.namePrefix") {
			t.Fatalf("body = %v", m)
		}
		if h := mustHead(t, srv.versions); h != 1 {
			t.Fatalf("head = %d after a refused write, want 1", h)
		}
	})
}

// TestUserStoreOverlapStartup: the CP refuses to start when consent.store
// overlaps the served secretStore, naming both keys, and the offline policy
// import refuses a doc that would introduce the overlap.
func TestUserStoreOverlapStartup(t *testing.T) {
	withFakeAWSClient(t, newFakeAWSClient(), nil)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	body := basePolicy + identityBlockYAML + consoleBlock + consentBlockYAML +
		"  store:\n    backend: aws\n    namePrefix: " + nestedUsers + "\n    aws:\n      region: us-east-1\n" +
		"secretStore:\n  backend: aws\n  aws:\n    region: us-east-1\n    namePrefix: " + workerPrefix + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_CONSOLE_SECRET", "console-secret")
	t.Setenv("WARDEN_PORTAL_DEX_CLIENT_SECRET", "portal-secret")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	err := bootErr(t, Params{ConfigPath: cfg, StateDir: stateDir, UserStoreAWSClient: newFakeAWSClient()})
	if err == nil || !strings.Contains(err.Error(), "consent.store.namePrefix") || !strings.Contains(err.Error(), "secretStore.aws.namePrefix") {
		t.Fatalf("Run err = %v, want the overlap naming both keys", err)
	}

	t.Run("offline import", func(t *testing.T) {
		sd := t.TempDir()
		served := basePolicy + identityBlockYAML + consentBlockYAML + "  store:\n    backend: aws\n    aws:\n      region: us-east-1\n"
		if err := os.WriteFile(filepath.Join(sd, "config.yaml"), []byte(served), 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := cpstate.Open(context.Background(), filepath.Join(sd, "warden-cp.db"), StateMigrations())
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		o, err := OpenPolicyStore(context.Background(), sd)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = o.Close() })
		p := filepath.Join(t.TempDir(), "policy.yaml")
		doc := basePolicy + identityBlockYAML + "secretStore:\n  backend: aws\n  aws:\n    region: us-east-1\n    namePrefix: " + config.DefaultConsentStoreNamePrefix + "\n"
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		pd, err := ValidatePolicyDocFile(p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = o.Import(context.Background(), pd, "", -1, nil)
		var uo *dashboard.UserStoreOverlapError
		if !errors.As(err, &uo) {
			t.Fatalf("import err = %v, want *dashboard.UserStoreOverlapError", err)
		}
		if h, _ := o.Head(context.Background()); h != 0 {
			t.Fatalf("head = %d after a refused import, want 0", h)
		}
	})
}
