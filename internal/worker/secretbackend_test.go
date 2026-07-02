package worker

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

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

// TestNewSecretFetcher_AWSNotYet proves the aws backend returns a clear
// not-yet-available error this phase rather than half-wiring a missing store.
func TestNewSecretFetcher_AWSNotYet(t *testing.T) {
	pol := config.Policy{SecretStore: config.SecretStoreConfig{
		Backend: config.SecretBackendAWS,
		AWS:     &config.SecretStoreAWS{Region: "us-east-1", NamePrefix: "warden/"},
	}}
	_, err := newSecretFetcher(pol, nil)
	if err == nil {
		t.Fatal("expected a not-yet-available error for backend aws")
	}
	if !strings.Contains(err.Error(), "Phase 5") {
		t.Fatalf("error = %v, want a Phase 5 not-yet message", err)
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

// TestRun_SecretStore_AWSNotYet proves the worker build fails fast with the clear
// not-yet error when backend: aws is selected this phase (store lands in Phase 5).
func TestRun_SecretStore_AWSNotYet(t *testing.T) {
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
		t.Fatal("expected Run to fail for backend aws (Phase 5)")
	}
	if !strings.Contains(err.Error(), "Phase 5") {
		t.Fatalf("Run error = %v, want a Phase 5 not-yet message", err)
	}
}
