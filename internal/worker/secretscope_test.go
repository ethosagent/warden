package worker

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/proxy"
)

func TestSecretScopes_WarnsOnlyForUnscoped(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	scopes := secretScopes([]config.SecretMapping{
		{Placeholder: "scoped_001", EnvVar: "A", MatchHosts: []string{"api.example.com"}},
		{Placeholder: "legacy_001", EnvVar: "B"},
	}, logger)
	if got := scopes["scoped_001"]; len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("scopes = %v", scopes)
	}
	if _, ok := scopes["legacy_001"]; ok {
		t.Fatal("unscoped placeholder must be absent from the scope map")
	}
	out := buf.String()
	if !strings.Contains(out, "legacy_001") || strings.Contains(out, "scoped_001") && !strings.Contains(out, "legacy_001") {
		t.Fatalf("expected one warning naming legacy_001, got %q", out)
	}
	if strings.Count(out, "level=WARN") != 1 {
		t.Fatalf("want exactly one warning, got %q", out)
	}
}

// TestRun_SecretScopesReachProxy guards the one place the matchHosts scopes enter
// the proxy: dropping PlaceholderScopes from the worker's proxy.Config would
// silently restore swap-everywhere.
func TestRun_SecretScopesReachProxy(t *testing.T) {
	var got proxy.Config
	orig := newProxy
	newProxy = func(cfg proxy.Config) (*proxy.Proxy, error) {
		got = cfg
		return orig(cfg)
	}
	t.Cleanup(func() { newProxy = orig })
	t.Setenv("WARDEN_SCOPE_A", "a-secret")
	t.Setenv("WARDEN_SCOPE_B", "b-secret")
	cfg := `
policy:
  allowlist:
    - domain: api.example.com
secrets:
  - placeholder: scoped_001
    envVar: WARDEN_SCOPE_A
    matchHosts: ["api.example.com", "*.llm.example.com"]
  - placeholder: legacy_001
    envVar: WARDEN_SCOPE_B
`
	if err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg))); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"api.example.com", "*.llm.example.com"}
	if g := got.PlaceholderScopes["scoped_001"]; !reflect.DeepEqual(g, want) {
		t.Fatalf("PlaceholderScopes[scoped_001] = %v, want %v (full: %v)", g, want, got.PlaceholderScopes)
	}
	if _, ok := got.PlaceholderScopes["legacy_001"]; ok {
		t.Fatal("unscoped placeholder must not appear in PlaceholderScopes")
	}
}
