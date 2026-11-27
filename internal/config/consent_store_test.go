package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReservedSecretNamespace: a static secrets[] placeholder under a P3
// per-user namespace fails to parse naming the reserved namespace (and never
// echoing the placeholder), and so does an auth credential field naming one.
func TestReservedSecretNamespace(t *testing.T) {
	for _, tc := range []struct{ placeholder, ns string }{
		{"idp/x", "idp/"},
		{"users/x/y", "users/"},
		{"oauth-clients/google", "oauth-clients/"},
		{"revoking/x/google", "revoking/"},
		{" /users/x/y ", "users/"},
		{"cp/keys/ca/k1", "cp/"},
	} {
		t.Run(tc.placeholder, func(t *testing.T) {
			_, err := NewLocalYAMLProvider(writeTemp(t, baseAllow+"secrets:\n  - placeholder: \""+tc.placeholder+"\"\n    envVar: X\n"))
			if err == nil {
				t.Fatal("want a validation error")
			}
			msg := err.Error()
			if !strings.Contains(msg, "secrets[0]") || !strings.Contains(msg, "invalid_secret_key: reserved namespace") || !strings.Contains(msg, `"`+tc.ns+`"`) {
				t.Fatalf("err = %v, want secrets[0] invalid_secret_key: reserved namespace %q", err, tc.ns)
			}
			if tail := strings.TrimPrefix(strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(tc.placeholder), "/")), tc.ns); strings.Contains(msg, tail) {
				t.Fatalf("err echoes the placeholder tail %q: %v", tail, err)
			}
		})
	}
	_, err := NewLocalYAMLProvider(writeTemp(t, baseAllow+`
auth:
  - match: x.com
    type: api_key
    location: header
    name: X-Key
    value: users/a/google
`))
	if err == nil || !strings.Contains(err.Error(), "auth[0]") || !strings.Contains(err.Error(), `"users/"`) {
		t.Fatalf("auth value under users/ err = %v, want auth[0] naming users/", err)
	}
	// Look-alikes stay valid placeholders.
	for _, ok := range []string{"usersx", "my-idp/x", "{{users/x}}", "OPENAI_API_KEY"} {
		if _, err := NewLocalYAMLProvider(writeTemp(t, baseAllow+"secrets:\n  - placeholder: \""+ok+"\"\n    envVar: X\n")); err != nil {
			t.Errorf("placeholder %q rejected: %v", ok, err)
		}
	}
	if got := ReservedSecretNamespaces(); len(got) != 5 || got[0] != ReservedSecretNamespace {
		t.Fatalf("ReservedSecretNamespaces = %v", got)
	}
}

func TestConsentStore(t *testing.T) {
	cases := []struct {
		name, store, wantErr string
	}{
		{"aws", "  store:\n    backend: aws\n    aws:\n      region: us-east-1\n", ""},
		{"aws custom prefix", "  store:\n    backend: AWS\n    namePrefix: corp/warden-cp/\n    aws:\n      region: us-east-1\n", ""},
		{"echo", "  store:\n    backend: echo\n", ""},
		{"vault", "  store:\n    backend: vault\n    vault:\n      addr: https://vault.example.com:8200\n      mount: secret\n      namespace: team\n", ""},
		{"missing backend", "  store:\n    namePrefix: x/\n", "consent.store.backend is required"},
		{"bad backend", "  store:\n    backend: env\n", `consent.store.backend "env" is invalid`},
		{"aws without region", "  store:\n    backend: aws\n", "consent.store.aws.region"},
		{"prefix without slash", "  store:\n    backend: echo\n    namePrefix: warden-cp\n", "must end with /"},
		{"prefix leading slash", "  store:\n    backend: echo\n    namePrefix: /warden-cp/\n", "namePrefix"},
		{"prefix double slash", "  store:\n    backend: echo\n    namePrefix: a//b/\n", "namePrefix"},
		{"prefix bad char", "  store:\n    backend: echo\n    namePrefix: \"a b/\"\n", "namePrefix"},
		{"aws block on echo", "  store:\n    backend: echo\n    aws:\n      region: us-east-1\n", "consent.store.aws is set"},
		{"vault block on aws", "  store:\n    backend: aws\n    aws:\n      region: us-east-1\n    vault:\n      addr: https://v\n      mount: m\n", "consent.store.vault is set"},
		{"vault without block", "  store:\n    backend: vault\n", "consent.store.vault {addr, mount}"},
		{"vault bad addr", "  store:\n    backend: vault\n    vault:\n      addr: vault:8200\n      mount: secret\n", "vault.addr"},
		{"vault no mount", "  store:\n    backend: vault\n    vault:\n      addr: https://v\n", "vault.mount is required"},
		{"vault plain http", "  store:\n    backend: vault\n    vault:\n      addr: http://vault.example.com:8200\n      mount: secret\n", "must use https unless its host is loopback"},
		{"vault loopback http", "  store:\n    backend: vault\n    vault:\n      addr: http://127.0.0.1:8200\n      mount: secret\n", ""},
		{"vault localhost http", "  store:\n    backend: vault\n    vault:\n      addr: http://localhost:8200\n      mount: secret\n", ""},
		{"vault sys mount", "  store:\n    backend: vault\n    vault:\n      addr: https://v\n      mount: sys\n", "reserved Vault system path"},
		{"vault auth sub mount", "  store:\n    backend: vault\n    vault:\n      addr: https://v\n      mount: Auth/kv\n", "reserved Vault system path"},
		{"vault cubbyhole mount", "  store:\n    backend: vault\n    vault:\n      addr: https://v\n      mount: cubbyhole\n", "reserved Vault system path"},
		{"vault identity mount", "  store:\n    backend: vault\n    vault:\n      addr: https://v\n      mount: identity\n", "reserved Vault system path"},
		{"vault bad tokenEnv", "  store:\n    backend: vault\n    vault:\n      addr: https://v\n      mount: m\n      tokenEnv: \"1X\"\n", "tokenEnv"},
		// Credentials are never YAML: the strict parse refuses any such key.
		{"aws credential key", "  store:\n    backend: aws\n    aws:\n      region: us-east-1\n      secretAccessKey: x\n", "field secretAccessKey not found"},
		{"vault token key", "  store:\n    backend: vault\n    vault:\n      addr: https://v\n      mount: m\n      token: x\n", "field token not found"},
		{"unknown store key", "  store:\n    backend: echo\n    bogus: 1\n", "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := consentBlock(cIssuer+cSecret+cRedir, tc.store)
			_, perr := parse(consoleYAML(block))
			path := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(path, consoleYAML(block), 0o600); err != nil {
				t.Fatal(err)
			}
			c, lerr := LoadConsent(path)
			for what, err := range map[string]error{"parse": perr, "LoadConsent": lerr} {
				if tc.wantErr == "" {
					if err != nil {
						t.Errorf("%s: unexpected error %v", what, err)
					}
					continue
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("%s: error = %v, want containing %q", what, err, tc.wantErr)
				}
			}
			if tc.wantErr == "" && c.Store == nil {
				t.Fatal("Store = nil for a configured block")
			}
		})
	}
}

func TestConsentStoreDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	write := func(body string) ConsentConfig {
		t.Helper()
		if err := os.WriteFile(path, consoleYAML(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConsent(path)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := write(validConsent); c.Store != nil {
		t.Fatalf("absent store = %+v, want nil", c.Store)
	}
	c := write(consentBlock(cIssuer+cSecret+cRedir, "  store:\n    backend: aws\n    aws:\n      region: eu-west-1\n"))
	if c.Store.Backend != ConsentStoreBackendAWS || c.Store.NamePrefix != DefaultConsentStoreNamePrefix || c.Store.AWS.Region != "eu-west-1" {
		t.Fatalf("aws store = %+v", c.Store)
	}
	c = write(consentBlock(cIssuer+cSecret+cRedir, "  store:\n    backend: vault\n    vault:\n      addr: https://v\n      mount: /secret/\n"))
	if v := c.Store.Vault; v.TokenEnv != DefaultConsentStoreVaultTokenEnv || v.Mount != "secret" {
		t.Fatalf("vault store = %+v", v)
	}
	// A disabled consent block never validates its store (a stale served copy
	// cannot block a start that does not use it).
	if _, err := parse(consoleYAML("consent:\n  enabled: false\n  store:\n    backend: nonsense\n")); err != nil {
		t.Fatalf("disabled block with a bad store: %v", err)
	}
}
