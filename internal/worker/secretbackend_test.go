package worker

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// fakeAWSClient is a minimal in-memory secrets.AWSSecretsClient for the worker's
// aws-backend tests: it lets a value be seeded and read back through the store,
// with no AWS and no network. Only the verbs the worker read path exercises need
// real behavior; the write verbs are enough to seed.
type fakeAWSClient struct {
	store map[string]string
}

func newFakeAWSClient() *fakeAWSClient { return &fakeAWSClient{store: map[string]string{}} }

func (c *fakeAWSClient) GetSecretValue(name string) (string, error) {
	v, ok := c.store[name]
	if !ok {
		return "", secrets.ErrSecretNotFound
	}
	return v, nil
}

func (c *fakeAWSClient) PutSecretValue(name, value string) (string, error) {
	if _, ok := c.store[name]; !ok {
		return "", secrets.ErrSecretNotFound
	}
	c.store[name] = value
	return "1", nil
}

func (c *fakeAWSClient) CreateSecret(name, value string) (string, error) {
	c.store[name] = value
	return "1", nil
}

func (c *fakeAWSClient) DeleteSecret(name string) error {
	delete(c.store, name)
	return nil
}

func (c *fakeAWSClient) ListSecrets(prefix string) ([]secrets.AWSSecretEntry, error) {
	var out []secrets.AWSSecretEntry
	for name := range c.store {
		if strings.HasPrefix(name, prefix) {
			out = append(out, secrets.AWSSecretEntry{Name: name, Version: "1"})
		}
	}
	return out, nil
}

// TestNewSecretFetcher_EnvIsDefault proves an omitted secretStore block resolves
// to the original EnvFetcher path (byte-identical to today).
func TestNewSecretFetcher_EnvIsDefault(t *testing.T) {
	pol := config.Policy{} // SecretStore zero value => backend env
	f, err := newSecretFetcher(pol, map[string]string{"openai_secret_001": "OPENAI_API_KEY"})
	if err != nil {
		t.Fatalf("newSecretFetcher(env): %v", err)
	}
	if _, ok := f.(*secrets.EnvFetcher); !ok {
		t.Fatalf("omitted secretStore fetcher = %T, want *secrets.EnvFetcher", f)
	}
}

// TestNewSecretFetcher_ExplicitEnv covers backend: env explicitly.
func TestNewSecretFetcher_ExplicitEnv(t *testing.T) {
	pol := config.Policy{SecretStore: config.SecretStoreConfig{Backend: config.SecretBackendEnv}}
	f, err := newSecretFetcher(pol, map[string]string{"k": "V"})
	if err != nil {
		t.Fatalf("newSecretFetcher(env): %v", err)
	}
	if _, ok := f.(*secrets.EnvFetcher); !ok {
		t.Fatalf("fetcher = %T, want *secrets.EnvFetcher", f)
	}
}

// TestSecretBackend_EchoResolvesKeyEndToEnd drives the REAL worker read path
// (newSecretFetcher + secrets.NewCache + GetSecret) with backend: echo and
// asserts a placeholder resolves to the KEY itself through the cache — exactly
// what the proxy swap stage calls.
func TestSecretBackend_EchoResolvesKeyEndToEnd(t *testing.T) {
	pol := config.Policy{
		SecretStore: config.SecretStoreConfig{Backend: config.SecretBackendEcho},
		Secrets:     []config.SecretMapping{{Placeholder: "openai_secret_001"}},
	}
	// mapping is unused for echo (the placeholder IS the key); pass nil to prove it.
	fetcher, err := newSecretFetcher(pol, nil)
	if err != nil {
		t.Fatalf("newSecretFetcher(echo): %v", err)
	}
	cache, err := secrets.NewCache(fetcher, time.Hour, []string{"openai_secret_001"})
	if err != nil {
		t.Fatalf("NewCache(echo): %v", err)
	}
	got, err := cache.GetSecret("openai_secret_001")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "openai_secret_001" {
		t.Fatalf("echo GetSecret = %q, want the placeholder key itself", got)
	}
}

// withFakeAWSClient swaps awsSecretsClientFactory for one returning client, and
// restores it on cleanup, so aws-backend tests never touch AWS or the network.
func withFakeAWSClient(t *testing.T, client secrets.AWSSecretsClient, err error) {
	t.Helper()
	prev := awsSecretsClientFactory
	awsSecretsClientFactory = func(string) (secrets.AWSSecretsClient, error) {
		return client, err
	}
	t.Cleanup(func() { awsSecretsClientFactory = prev })
}

// TestNewSecretFetcher_AWSResolvesThroughStore proves the aws backend now builds
// a real store→cache→GetSecret path using an INJECTED fake client (no AWS, no
// network): a value Put into the fake resolves through the worker's cache.
func TestNewSecretFetcher_AWSResolvesThroughStore(t *testing.T) {
	client := newFakeAWSClient()
	// Seed a value under the warden/ name convention for key "openai_secret_001".
	if _, err := client.CreateSecret("warden/openai_secret_001", "sk-from-aws"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withFakeAWSClient(t, client, nil)

	pol := config.Policy{SecretStore: config.SecretStoreConfig{
		Backend: config.SecretBackendAWS,
		AWS:     &config.SecretStoreAWS{Region: "us-east-1", NamePrefix: "warden/"},
	}}
	fetcher, err := newSecretFetcher(pol, nil)
	if err != nil {
		t.Fatalf("newSecretFetcher(aws): %v", err)
	}
	cache, err := secrets.NewCache(fetcher, time.Hour, []string{"openai_secret_001"})
	if err != nil {
		t.Fatalf("NewCache(aws): %v", err)
	}
	got, err := cache.GetSecret("openai_secret_001")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "sk-from-aws" {
		t.Fatalf("aws GetSecret = %q, want sk-from-aws", got)
	}
}

// TestNewSecretFetcher_AWSMissingCredsFailFast proves a factory error (e.g.
// missing ENV credentials) surfaces from newSecretFetcher rather than silently
// mis-wiring the store.
func TestNewSecretFetcher_AWSMissingCredsFailFast(t *testing.T) {
	withFakeAWSClient(t, nil, errors.New("aws credentials missing"))
	pol := config.Policy{SecretStore: config.SecretStoreConfig{
		Backend: config.SecretBackendAWS,
		AWS:     &config.SecretStoreAWS{Region: "us-east-1", NamePrefix: "warden/"},
	}}
	if _, err := newSecretFetcher(pol, nil); err == nil {
		t.Fatal("expected a fail-fast error when the aws client factory errors")
	}
}

// TestRun_SecretStore_Echo exercises the full worker assembly with backend: echo:
// the secret cache prefetches through the echo store (no envVar needed) and the
// whole proxy builds + shuts down cleanly.
func TestRun_SecretStore_Echo(t *testing.T) {
	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
secrets:
  - placeholder: openai_secret_001
secretStore:
  backend: echo
logging:
  level: info
  format: json
`
	if err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg))); err != nil {
		t.Fatalf("Run (secretStore echo) returned error on clean shutdown: %v", err)
	}
}

// TestRun_SecretStore_AWSMissingCredsFailsFast proves the worker build fails fast
// when backend: aws is selected but no ENV credentials are present — a clear
// startup error rather than a silently mis-wired store.
func TestRun_SecretStore_AWSMissingCredsFailsFast(t *testing.T) {
	// Ensure no AWS credentials leak in from the host environment.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	cfg := `
policy:
  allowlist:
    - domain: api.openai.com
secretStore:
  backend: aws
  aws:
    region: us-east-1
logging:
  level: info
  format: json
`
	err := Run(context.Background(), io.Discard, runParams(t, writeConfig(t, cfg)))
	if err == nil {
		t.Fatal("expected Run to fail for backend aws with no credentials")
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("Run error = %v, want a missing-credentials fail-fast message", err)
	}
}

// TestResolveSecretStore_Precedence proves a managed worker prefers the
// CP-distributed settings.Secrets backend selector, and falls back to local
// pol.SecretStore when no secrets block is distributed (nil wire or nil block).
func TestResolveSecretStore_Precedence(t *testing.T) {
	local := config.Policy{SecretStore: config.SecretStoreConfig{Backend: config.SecretBackendEnv}}

	// No distributed settings at all → local backend (env).
	if got := resolveSecretStore(nil, local).ResolvedBackend(); got != config.SecretBackendEnv {
		t.Fatalf("nil wire resolved %q, want local env", got)
	}
	// Distributed wire present but no secrets block → local backend.
	if got := resolveSecretStore(&config.SettingsWire{}, local).ResolvedBackend(); got != config.SecretBackendEnv {
		t.Fatalf("wire without secrets block resolved %q, want local env", got)
	}
	// Distributed secrets block wins: echo overrides the local env backend.
	dist := &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: config.SecretBackendEcho}}
	if got := resolveSecretStore(dist, local).ResolvedBackend(); got != config.SecretBackendEcho {
		t.Fatalf("distributed echo resolved %q, want echo", got)
	}
	// aws selector round-trips region/name-prefix into the resolved config.
	awsDist := &config.SettingsWire{Secrets: &config.SecretsSettings{
		Backend: config.SecretBackendAWS, Region: "us-east-1", NamePrefix: "warden/",
	}}
	got := resolveSecretStore(awsDist, local)
	if got.Backend != config.SecretBackendAWS || got.AWS == nil ||
		got.AWS.Region != "us-east-1" || got.AWS.NamePrefix != "warden/" {
		t.Fatalf("distributed aws resolved %+v, want aws/us-east-1/warden/", got)
	}
}
