package controlplane

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

const testClientSecret = "client-secret-value-xyz"

// TestClientSecretResolver: the resolver reads oauth-clients/<id> from
// consent.store, refuses any other key, and surfaces a store failure as its
// type only (never its text).
func TestClientSecretResolver(t *testing.T) {
	st := fakes.NewMemorySecretStore()
	if err := st.Put(context.Background(), "oauth-clients/google", testClientSecret); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(context.Background(), "users/0123456789abcdef0123456789abcdef/google", "token-bytes"); err != nil {
		t.Fatal(err)
	}
	r := NewClientSecretResolver(st)
	if v, err := r.ResolveSecret(context.Background(), "oauth-clients/google"); err != nil || v != testClientSecret {
		t.Fatalf("ResolveSecret = %q, %v", v, err)
	}
	for _, k := range []string{"users/0123456789abcdef0123456789abcdef/google", "idp/x", "oauth-clients/", "oauth-clients/../users/x", "plain"} {
		if v, err := r.ResolveSecret(context.Background(), k); !errors.Is(err, ErrNotClientSecretKey) || v != "" {
			t.Errorf("ResolveSecret(%q) = %q, %v, want ErrNotClientSecretKey", k, v, err)
		}
	}

	st.SetErrors(errors.New("backend leaked "+testClientSecret), nil, nil, nil)
	_, err := r.ResolveSecret(context.Background(), "oauth-clients/google")
	if err == nil || strings.Contains(err.Error(), testClientSecret) || !strings.Contains(err.Error(), "oauth-clients/google") {
		t.Fatalf("store failure err = %v, want key + type only", err)
	}
	if _, err := (*ClientSecretResolver)(nil).ResolveSecret(context.Background(), "oauth-clients/google"); err == nil {
		t.Error("nil resolver must fail, not panic")
	}
}

type blockingStore struct{ secrets.SecretStore }

func (blockingStore) Get(ctx context.Context, _ string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

// TestClientSecretResolverTimeout: a hung consent.store read ends at the
// resolver's own deadline.
func TestClientSecretResolverTimeout(t *testing.T) {
	r := NewClientSecretResolver(blockingStore{})
	r.timeout = 20 * time.Millisecond
	_, err := r.ResolveSecret(context.Background(), "oauth-clients/google")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

// TestClientSecretResolverRegistry: wired into the registry, a failed startup
// read logs the key only and the first use answers ErrProviderUnavailable; once
// the store has the secret the retry succeeds.
func TestClientSecretResolverRegistry(t *testing.T) {
	st := fakes.NewMemorySecretStore()
	st.SetErrors(errors.New("down "+testClientSecret), nil, nil, nil)
	var logs bytes.Buffer
	cfg := []config.OAuthProviderConfig{{ID: "google", Type: "google", ClientID: "c", ClientSecretKey: "oauth-clients/google"}}
	reg, err := oauthbroker.NewRegistry(cfg, oauthbroker.Options{
		LookupEnv: func(string) (string, bool) { return "", false },
		Resolver:  NewClientSecretResolver(st),
		Logger:    slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "oauth-clients/google") || strings.Contains(logs.String(), testClientSecret) {
		t.Fatalf("startup log = %s", logs.String())
	}
	p, _ := reg.Get("google")
	if _, err := p.ClientSecret(context.Background()); !errors.Is(err, oauthbroker.ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
	st.SetErrors(nil, nil, nil, nil)
	if err := st.Put(context.Background(), "oauth-clients/google", testClientSecret); err != nil {
		t.Fatal(err)
	}
	s, err := p.ClientSecret(context.Background())
	if err != nil || s.Reveal() != testClientSecret {
		t.Fatalf("retry = %v, %v", s, err)
	}
}

// TestOAuthBrokerRequiresPersistentStore: providers with no or an echo
// consent.store are refused at startup, with or without idpLink.
func TestOAuthBrokerRequiresPersistentStore(t *testing.T) {
	provs := []config.OAuthProviderConfig{{ID: "google", Type: "google", ClientID: "c", ClientSecretEnv: "X"}}
	mk := func(idp bool, store *config.ConsentStore) *config.ConsentConfig {
		c := userStoreConsent()
		c.IdPLink.Enabled = idp
		c.Providers = provs
		c.Store = store
		return c
	}
	echo := &config.ConsentStore{Backend: config.ConsentStoreBackendEcho, NamePrefix: config.DefaultConsentStoreNamePrefix}
	for name, c := range map[string]struct {
		consent *config.ConsentConfig
		store   secrets.SecretStore
		ok      bool
	}{
		"persistent":      {mk(false, userStoreConsent().Store), fakes.NewMemorySecretStore(), true},
		"no store":        {mk(false, nil), nil, false},
		"echo":            {mk(false, echo), secrets.NewEchoStore(), false},
		"echo with idp":   {mk(true, echo), secrets.NewEchoStore(), false},
		"no providers":    {func() *config.ConsentConfig { c := mk(false, nil); c.Providers = nil; return c }(), nil, true},
		"consent disable": {func() *config.ConsentConfig { c := mk(false, nil); c.Enabled = false; return c }(), nil, true},
	} {
		err := checkUserStorePersistent(c.consent, c.store)
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v, want ok=%v", name, err, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "persistent consent.store") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
