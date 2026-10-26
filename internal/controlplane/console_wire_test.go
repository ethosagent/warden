package controlplane

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
)

const consoleBlock = `console:
  auth: oidc
  oidc:
    issuer: https://idp.example.com
    clientSecretEnv: WARDEN_CONSOLE_SECRET
    redirectURL: https://warden.example.com/auth/callback
  roles:
    admin: [warden-admins]
    viewer: [everyone]
`

func fullConsole() config.ConsoleConfig {
	return config.ConsoleConfig{
		Auth: config.ConsoleAuthOIDC,
		OIDC: config.ConsoleOIDC{
			Issuer: "https://idp.example.com", ClientID: "warden-console", ClientSecretEnv: "WARDEN_CONSOLE_SECRET",
			RedirectURL: "https://warden.example.com/auth/callback", Scopes: []string{"openid"},
		},
		Roles:   config.ConsoleRoles{Admin: []string{"warden-admins"}, Viewer: []string{"everyone"}},
		Session: config.ConsoleSession{Idle: time.Hour, Absolute: 12 * time.Hour},
	}
}

func TestConsoleNotOnWire(t *testing.T) {
	p := config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "api.example.com"}},
		Console:   fullConsole(),
		// Give the settings projection something to emit so the check is not vacuous.
		Identity: config.IdentitySettings{DefaultMode: "attribute", Issuer: "https://idp.example.com", Audience: "warden"},
	}
	sw := config.SettingsWireFromPolicy(p)
	if sw == nil {
		t.Fatal("SettingsWireFromPolicy returned nil; the check would be vacuous")
	}
	pw, err := json.Marshal(policyWire{Allowlist: p.Allowlist, Denylist: p.Denylist, Settings: sw})
	if err != nil {
		t.Fatal(err)
	}
	sj, err := json.Marshal(sw)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"policyWire": pw, "SettingsWire": sj} {
		for _, banned := range []string{"console", "clientSecretEnv", "roles", "WARDEN_CONSOLE_SECRET", "warden-admins"} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s JSON contains %q: %s", name, banned, b)
			}
		}
	}
}

// consoleNode returns the re-marshalled on-disk `console:` node.
func consoleNode(t *testing.T, path string) string {
	t.Helper()
	root := map[string]yaml.Node{}
	if err := yaml.Unmarshal([]byte(readFile(t, path)), &root); err != nil {
		t.Fatal(err)
	}
	n, ok := root["console"]
	if !ok {
		t.Fatal("console node missing")
	}
	out, err := yaml.Marshal(&n)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestWritersPreserveConsoleBlock(t *testing.T) {
	cfg := detectionEditorConfig(t)
	path := cfg.PolicyPath
	if err := os.WriteFile(path, []byte(readFile(t, path)+consoleBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	before := consoleNode(t, path)
	srv := New(cfg)

	writers := map[string]func() error{
		"WritePolicy": func() error {
			prov, err := config.NewLocalYAMLProvider(path)
			if err != nil {
				return err
			}
			p, err := prov.GetPolicy()
			if err != nil {
				return err
			}
			p.Allowlist = append(p.Allowlist, config.AllowlistEntry{Domain: "added.example.com"})
			return srv.WritePolicy(p)
		},
		"WriteSettings": func() error {
			return srv.WriteSettings(config.SettingsWire{Identity: &config.IdentitySettings{
				DefaultMode: "attribute", Issuer: "https://idp.example.com", Audience: "warden",
			}})
		},
		"WriteIntegrations": func() error {
			return srv.WriteIntegrations([]config.IntegrationInstance{{
				Type: "webhook", Name: "x", Config: map[string]any{"url": "${WEBHOOK_URL}"},
				Match: []config.IntegrationMatch{{Category: "security"}},
			}})
		},
		"WriteDetection": func() error { return srv.WriteDetection(config.DetectionConfig{Enabled: false}) },
	}
	for _, name := range []string{"WritePolicy", "WriteSettings", "WriteIntegrations", "WriteDetection"} {
		if err := writers[name](); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if after := consoleNode(t, path); after != before {
			t.Errorf("%s changed the console block:\n%s\nvs\n%s", name, before, after)
		}
	}
}

func testLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func writeFileT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const basePolicy = "policy:\n  allowlist:\n    - domain: api.example.com\n"

func TestResolveConsoleFromConfigFlag(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	served := filepath.Join(state, "config.yaml")
	writeFileT(t, cfg, basePolicy+consoleBlock)
	writeFileT(t, served, basePolicy) // seeded earlier, no console block
	logger, logs := testLogger()
	getenv := func(string) string { return "s3cret-value" }

	got, err := resolveConsole(logger, cfg, served, state, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if got.Auth != config.ConsoleAuthOIDC || got.OIDC.Issuer != "https://idp.example.com" {
		t.Errorf("got %+v, want the --config block", got)
	}
	if !strings.Contains(logs.String(), "different console block") {
		t.Errorf("expected a warning about the differing served copy, logs: %s", logs)
	}
	if strings.Contains(logs.String(), "s3cret-value") {
		t.Error("logs contain the secret value")
	}

	// Without a state dir there is no second copy and no warning.
	logger, logs = testLogger()
	if _, err := resolveConsole(logger, cfg, cfg, "", getenv); err == nil {
		t.Error("oidc without --state-dir must fail")
	}
	if strings.Contains(logs.String(), "different console block") {
		t.Error("no served-copy warning expected without a state dir")
	}

	// auth none needs neither secret nor state dir.
	writeFileT(t, cfg, basePolicy)
	got, err = resolveConsole(logger, cfg, cfg, "", func(string) string { return "" })
	if err != nil || got.Auth != config.ConsoleAuthNone {
		t.Errorf("none mode: %+v, %v", got, err)
	}
}

func TestResolveConsoleSecretEnv(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	writeFileT(t, cfg, basePolicy+consoleBlock)
	logger, logs := testLogger()

	_, err := resolveConsole(logger, cfg, cfg, dir, func(string) string { return "  " })
	if err == nil || !strings.Contains(err.Error(), "WARDEN_CONSOLE_SECRET") {
		t.Fatalf("want error naming WARDEN_CONSOLE_SECRET, got %v", err)
	}

	// Dev profile: plain-http issuer with an internal URL warns, never leaks the secret.
	dev := strings.Replace(consoleBlock, "https://idp.example.com", "http://localhost:5556/dex", 1)
	dev = strings.Replace(dev, "    clientSecretEnv", "    internalIssuerURL: http://dex:5556\n    clientSecretEnv", 1)
	writeFileT(t, cfg, basePolicy+dev)
	if _, err := resolveConsole(logger, cfg, cfg, dir, func(string) string { return "top-secret-xyz" }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "development profile") {
		t.Errorf("expected dev-profile warning, logs: %s", logs)
	}
	if strings.Contains(logs.String(), "top-secret-xyz") {
		t.Error("logs contain the secret value")
	}
}

func TestResolveConsoleTemporaryOIDCGuard(t *testing.T) {
	const want = "console oidc enforcement is not available in this build"
	if err := checkConsoleSupported(fullConsole()); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("oidc guard = %v, want %q", err, want)
	}
	if err := checkConsoleSupported(config.ConsoleConfig{Auth: config.ConsoleAuthNone}); err != nil {
		t.Errorf("none must pass the guard: %v", err)
	}

	// End to end: Run refuses to start with console.auth=oidc.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	writeFileT(t, cfg, basePolicy+consoleBlock)
	t.Setenv("WARDEN_CONSOLE_SECRET", "x")
	err := Run(t.Context(), &bytes.Buffer{}, Params{
		ConfigPath: cfg, ListenAddr: "127.0.0.1:0", StateDir: filepath.Join(dir, "state"),
		AnalyticsProvider: "memory",
	})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Run = %v, want %q", err, want)
	}
}
