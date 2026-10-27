package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// lockedBuffer is a log sink Run can write to while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runServing boots Run in-process on a loopback port and returns the bound
// address. The control plane is stopped, and Run required to return nil, when
// the test ends.
func runServing(t *testing.T, p Params, out io.Writer) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	p.OnReady = func(addr string) { ready <- addr }
	if p.ListenAddr == "" && p.Listener == nil {
		p.ListenAddr = "127.0.0.1:0"
	}
	if p.AnalyticsProvider == "" {
		p.AnalyticsProvider = "memory"
	}
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, out, p) }()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		cancel()
		t.Fatalf("Run returned before serving: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for OnReady")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("Run after cancel = %v, want nil", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("timed out waiting for Run to return")
		}
	})
	return addr
}

// noneModeWarning is the startup line none mode logs.
const noneModeWarning = "console.auth=none: dashboard reads are unauthenticated; writes need the admin bearer"

// TestNoneModeWarning: a control plane in console.auth none logs the open-console
// warning exactly once at startup and reports authMode "none" on /dashboard/api/setup.
func TestNoneModeWarning(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	writeFileT(t, cfg, basePolicy)
	out := &lockedBuffer{}
	addr := runServing(t, Params{ConfigPath: cfg, StateDir: filepath.Join(dir, "state")}, out)

	resp, err := http.Get("http://" + addr + "/dashboard/api/setup")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var setup struct {
		AuthMode string `json:"authMode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&setup); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || setup.AuthMode != config.ConsoleAuthNone {
		t.Errorf("GET /dashboard/api/setup = %d authMode %q, want 200 %q", resp.StatusCode, setup.AuthMode, config.ConsoleAuthNone)
	}
	if n := strings.Count(out.String(), noneModeWarning); n != 1 {
		t.Errorf("none-mode warning logged %d times, want exactly 1:\n%s", n, out.String())
	}
}

// oidcStartBlock is a valid oidc console block whose issuer is an unused
// loopback port: discovery runs in the background and simply fails, which must
// not stop the control plane from serving.
const oidcStartBlock = `console:
  auth: oidc
  oidc:
    issuer: https://127.0.0.1:1/dex
    clientSecretEnv: WARDEN_CONSOLE_SECRET
    redirectURL: https://warden.example.com/auth/callback
  roles:
    admin: [warden-admins]
`

// TestResolveConsoleOIDCStarts: with a valid oidc block, an existing state dir
// and the client secret in the environment, the control plane serves. The
// temporary startup guard of W-P1-SSO-02 is gone; workers still pull /policy
// and the console asks for a session.
func TestResolveConsoleOIDCStarts(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	writeFileT(t, cfg, basePolicy+oidcStartBlock)
	t.Setenv("WARDEN_CONSOLE_SECRET", "x-client-secret")
	out := &lockedBuffer{}
	addr := runServing(t, Params{ConfigPath: cfg, StateDir: state}, out)

	for path, want := range map[string]int{
		"/healthz":               http.StatusOK,
		"/policy":                http.StatusOK, // no --token-env: the worker route is open, as before
		"/dashboard/api/traffic": http.StatusUnauthorized,
	} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
	logs := out.String()
	if strings.Contains(logs, "not available in this build") || strings.Contains(logs, noneModeWarning) {
		t.Errorf("oidc start logged a guard or none-mode line:\n%s", logs)
	}
	if strings.Contains(logs, "x-client-secret") {
		t.Error("logs contain the client secret")
	}
}

// TestRequireConsoleAuth: with RequireConsoleAuth the control plane refuses to
// start in none mode (closing an injected listener) and starts in oidc mode.
func TestRequireConsoleAuth(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	writeFileT(t, cfg, basePolicy)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), &bytes.Buffer{}, Params{
		ConfigPath: cfg, Listener: ln, AnalyticsProvider: "memory", RequireConsoleAuth: true,
	})
	if err == nil || !strings.Contains(err.Error(), "--require-console-auth") {
		t.Fatalf("Run in none mode with RequireConsoleAuth = %v, want a refusal naming --require-console-auth", err)
	}
	if _, aerr := ln.Accept(); !errors.Is(aerr, net.ErrClosed) {
		t.Errorf("Accept after refusal = %v, want net.ErrClosed", aerr)
	}

	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFileT(t, cfg, basePolicy+oidcStartBlock)
	t.Setenv("WARDEN_CONSOLE_SECRET", "x")
	runServing(t, Params{ConfigPath: cfg, StateDir: state, RequireConsoleAuth: true}, io.Discard)
}
