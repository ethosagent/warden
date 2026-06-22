package proxy

import (
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

func goodConfig(t *testing.T) Config {
	t.Helper()
	store, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return Config{
		ListenAddr: "127.0.0.1:8080",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "x"}}}),
		Secrets:    &fakeSecrets{},
		Analytics:  store,
	}
}

type fakeSecrets struct{}

func (fakeSecrets) GetSecret(string) (string, error) { return "", nil }
func (fakeSecrets) RefreshSecrets() error            { return nil }

func TestNew_OK(t *testing.T) {
	p, err := New(goodConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.ListenAddr() != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q", p.ListenAddr())
	}
}

func TestNew_MissingDeps(t *testing.T) {
	base := goodConfig(t)

	mutators := map[string]func(c *Config){
		"no addr":      func(c *Config) { c.ListenAddr = "" },
		"no policy":    func(c *Config) { c.Policy = nil },
		"no secrets":   func(c *Config) { c.Secrets = nil },
		"no analytics": func(c *Config) { c.Analytics = nil },
	}
	for name, mut := range mutators {
		c := base
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	host, port, err := SplitHostPort("api.openai.com:443")
	if err != nil || host != "api.openai.com" || port != 443 {
		t.Fatalf("SplitHostPort = %q,%d,%v", host, port, err)
	}
	if _, _, err := SplitHostPort("no-port"); err == nil {
		t.Error("expected error for missing port")
	}
	if _, _, err := SplitHostPort("host:notaport"); err == nil {
		t.Error("expected error for non-numeric port")
	}
}
