package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
)

// The break-glass startup guards, WARNs and degraded mode (W-P1-OPS1-09).

const (
	bgTestUser     = "ops-admin"
	bgTestPassword = "correct horse battery staple"
	bgTestSecret   = "cp-console-client-secret"
	bgTestSecretEn = "WARDEN_TEST_BG_CLIENT_SECRET"
	bgTestHashEnv  = "WARDEN_TEST_BG_HASH"
	bgTestToken    = "bg-test-worker-token"
	bgTestTokenEnv = "WARDEN_TEST_BG_TOKEN"
)

// bgTestHash is the argon2id hash of bgTestPassword.
func bgTestHash(t *testing.T) string {
	t.Helper()
	h, err := controlplane.HashPassword(bgTestPassword, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// deadIssuer returns an http origin nothing listens on.
func deadIssuer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "http://" + addr
}

// bgConsoleYAML renders a console block with OIDC against issuer and the
// break-glass block extra (already indented by two spaces).
func bgConsoleYAML(issuer, extra string) string {
	return fmt.Sprintf(`
console:
  auth: oidc
  oidc:
    issuer: %[1]s
    internalIssuerURL: %[1]s
    clientID: warden-console
    clientSecretEnv: %[2]s
    redirectURL: http://127.0.0.1:7070/auth/callback
  roles:
    admin: [console-admins]
%[3]s`, issuer, bgTestSecretEn, extra)
}

func bgBlock(hashKey, hashVal string, more string) string {
	return "  breakGlass:\n    enabled: true\n    username: " + bgTestUser + "\n    " + hashKey + ": " + hashVal + "\n" + more
}

const bgInfoConfig = `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: info
  format: json
`

func TestControlPlaneBreakGlassStartup(t *testing.T) {
	t.Setenv(bgTestSecretEn, bgTestSecret)
	good := bgTestHash(t)
	hashFile := filepath.Join(t.TempDir(), "hash")
	if err := os.WriteFile(hashFile, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// m=1024 is below the 19456 floor.
	salt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	key := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	weak := "$argon2id$v=19$m=1024,t=3,p=2$" + salt + "$" + key
	weakFile := filepath.Join(t.TempDir(), "weak")
	if err := os.WriteFile(weakFile, []byte(weak), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(bgTestHashEnv, good)

	oidc := config.ConsoleConfig{Auth: config.ConsoleAuthOIDC}
	enabled := func(mut func(*config.ConsoleBreakGlass)) config.ConsoleConfig {
		cc := oidc
		cc.BreakGlass = config.ConsoleBreakGlass{Enabled: true, Username: bgTestUser, PasswordHashFile: hashFile, SessionTTL: time.Hour}
		if mut != nil {
			mut(&cc.BreakGlass)
		}
		return cc
	}
	withState := controlplane.Params{StateDir: t.TempDir()}
	withCA := controlplane.Params{StateDir: t.TempDir(), CACert: "ca.pem", CAKey: "ca.key"}

	for _, tc := range []struct {
		name   string
		cc     config.ConsoleConfig
		p      controlplane.Params
		listen string
		want   string // "" = must pass
	}{
		{"loopback ip", enabled(nil), withState, "127.0.0.1:7070", ""},
		{"loopback range", enabled(nil), withState, "127.9.9.9:7070", ""},
		{"loopback v6", enabled(nil), withState, "[::1]:7070", ""},
		{"localhost", enabled(nil), withState, "localhost:7070", ""},
		{"hash env", enabled(func(b *config.ConsoleBreakGlass) { b.PasswordHashFile, b.PasswordHashEnv = "", bgTestHashEnv }), withState, "127.0.0.1:0", ""},
		{"tls flags on any address", enabled(nil), withCA, "0.0.0.0:7070", ""},
		{"behind a terminator", enabled(func(b *config.ConsoleBreakGlass) { b.AllowBehindTLSTerminator = true }), withState, "0.0.0.0:7070", ""},
		{"disabled skips every check", config.ConsoleConfig{Auth: config.ConsoleAuthOIDC}, controlplane.Params{}, "0.0.0.0:7070", ""},

		{"no state dir", enabled(nil), controlplane.Params{}, "127.0.0.1:7070", "--state-dir"},
		{"hash below the memory floor", enabled(func(b *config.ConsoleBreakGlass) { b.PasswordHashFile = weakFile }), withState, "127.0.0.1:7070", "console.breakGlass.passwordHashFile"},
		{"hash env unset", enabled(func(b *config.ConsoleBreakGlass) { b.PasswordHashFile, b.PasswordHashEnv = "", "WARDEN_TEST_BG_UNSET" }), withState, "127.0.0.1:7070", "console.breakGlass.passwordHashEnv"},
		{"hash file missing", enabled(func(b *config.ConsoleBreakGlass) { b.PasswordHashFile = filepath.Join(t.TempDir(), "nope") }), withState, "127.0.0.1:7070", "console.breakGlass.passwordHashFile"},
		{"plain http on 0.0.0.0", enabled(nil), withState, "0.0.0.0:7070", "allowBehindTLSTerminator"},
		{"plain http on an empty host", enabled(nil), withState, ":7070", "allowBehindTLSTerminator"},
		{"plain http on ::", enabled(nil), withState, "[::]:7070", "allowBehindTLSTerminator"},
		{"plain http on a public ip", enabled(nil), withState, "203.0.113.5:7070", "allowBehindTLSTerminator"},
		{"plain http on a hostname", enabled(nil), withState, "cp.example.com:7070", "allowBehindTLSTerminator"},
		{"half a CA pair is not TLS", enabled(nil), controlplane.Params{StateDir: t.TempDir(), CACert: "ca.pem"}, "0.0.0.0:7070", "allowBehindTLSTerminator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := controlplane.ValidateBreakGlassStartup(tc.cc, tc.p, tc.listen)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want a pass, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one naming %s", err, tc.want)
			}
			for _, secret := range []string{good, weak, key, salt} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error carries the hash: %v", err)
				}
			}
		})
	}

	// The same refusals through the real command, before it binds anything.
	t.Run("command: console.auth none", func(t *testing.T) {
		cfg := writeTempConfig(t, minimalConfig+"console:\n  breakGlass:\n    enabled: true\n    username: u\n    passwordHashFile: "+hashFile+"\n")
		err := executeRoot(t, "control-plane", "--config", cfg, "--listen", "127.0.0.1:0",
			"--state-dir", filepath.Join(t.TempDir(), "state"), "--analytics-provider", "memory")
		if err == nil || !strings.Contains(err.Error(), "console.breakGlass.enabled") {
			t.Fatalf("auth none with break-glass = %v, want an error naming console.breakGlass.enabled", err)
		}
	})
	t.Run("command: plain http on a non-loopback address", func(t *testing.T) {
		cfg := writeTempConfig(t, minimalConfig+bgConsoleYAML(deadIssuer(t), bgBlock("passwordHashFile", hashFile, "")))
		for _, listen := range []string{"0.0.0.0:0", ":0"} {
			err := executeRoot(t, "control-plane", "--config", cfg, "--listen", listen,
				"--state-dir", filepath.Join(t.TempDir(), "state"), "--analytics-provider", "memory")
			if err == nil || !strings.Contains(err.Error(), "allowBehindTLSTerminator") {
				t.Fatalf("listen %s = %v, want an error naming allowBehindTLSTerminator", listen, err)
			}
		}
	})
	t.Run("command: no state dir", func(t *testing.T) {
		cfg := writeTempConfig(t, minimalConfig+bgConsoleYAML(deadIssuer(t), bgBlock("passwordHashFile", hashFile, "")))
		err := executeRoot(t, "control-plane", "--config", cfg, "--listen", "127.0.0.1:0", "--analytics-provider", "memory")
		if err == nil || !strings.Contains(err.Error(), "--state-dir") {
			t.Fatalf("no state dir = %v, want an error naming --state-dir", err)
		}
	})
	t.Run("command: bad hash", func(t *testing.T) {
		cfg := writeTempConfig(t, minimalConfig+bgConsoleYAML(deadIssuer(t), bgBlock("passwordHashFile", weakFile, "")))
		err := executeRoot(t, "control-plane", "--config", cfg, "--listen", "127.0.0.1:0",
			"--state-dir", filepath.Join(t.TempDir(), "state"), "--analytics-provider", "memory")
		if err == nil || !strings.Contains(err.Error(), "console.breakGlass.passwordHashFile") || strings.Contains(err.Error(), weak) {
			t.Fatalf("weak hash = %v, want an error naming passwordHashFile and not the hash", err)
		}
	})
	t.Run("command: loopback starts", func(t *testing.T) {
		cfg := writeTempConfig(t, minimalConfig+bgConsoleYAML(deadIssuer(t), bgBlock("passwordHashFile", hashFile, "")))
		if err := executeRoot(t, "control-plane", "--config", cfg, "--listen", "127.0.0.1:0",
			"--state-dir", filepath.Join(t.TempDir(), "state"), "--analytics-provider", "memory"); err != nil {
			t.Fatalf("loopback break-glass start = %v", err)
		}
	})
}

// bgCP is a control plane running in-process on a loopback listener.
type bgCP struct {
	base     string
	stateDir string
	out      *cpSyncBuffer
}

// startBreakGlassCP boots a control plane from configBody on an ephemeral
// loopback port and stops it at test cleanup.
func startBreakGlassCP(t *testing.T, configBody string) *bgCP {
	t.Helper()
	t.Setenv(bgTestTokenEnv, bgTestToken)
	cp := &bgCP{stateDir: filepath.Join(t.TempDir(), "state"), out: &cpSyncBuffer{}}
	cfg := writeTempConfig(t, configBody)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- controlplane.Run(ctx, cp.out, controlplane.Params{
			ConfigPath: cfg, StateDir: cp.stateDir, Listener: ln, TokenEnv: bgTestTokenEnv,
			AnalyticsProvider: "memory", AlertsDB: filepath.Join(t.TempDir(), "alerts.db"),
			OnReady: func(a string) { ready <- a },
		})
	}()
	select {
	case addr := <-ready:
		cp.base = "http://" + addr
	case err := <-errCh:
		cancel()
		t.Fatalf("control plane exited before ready: %v\n%s", err, cp.out.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("timed out waiting for the control plane")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("control plane: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("control plane did not stop")
		}
	})
	return cp
}

func (cp *bgCP) do(t *testing.T, method, path, ctype, body string, hdr map[string]string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, cp.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), resp.Header
}

// logLines returns how many log lines carry the JSON message msg at level.
func logLines(logs, msg, level string) int {
	n := 0
	for _, l := range strings.Split(logs, "\n") {
		var rec struct{ Msg, Level string }
		if json.Unmarshal([]byte(l), &rec) == nil && strings.Contains(rec.Msg, msg) && (level == "" || rec.Level == level) {
			n++
		}
	}
	return n
}

const (
	warnNoRoute = "no integration's alerts.match routes a critical breakglass_login Finding"
	warnNoAudit = "console.adminAudit.enabled is false"
)

func TestControlPlaneBreakGlassWarns(t *testing.T) {
	t.Setenv(bgTestSecretEn, bgTestSecret)
	t.Setenv(bgTestHashEnv, bgTestHash(t))
	issuer := deadIssuer(t)
	bg := bgBlock("passwordHashEnv", bgTestHashEnv, "")
	hook := func(match string) string {
		return "integrations:\n  - type: webhook\n    name: oncall\n    config:\n      url: http://127.0.0.1:1/hook\n    match:\n" + match
	}
	for _, tc := range []struct {
		name                   string
		cfg                    string
		wantNoRoute, wantAudit int
	}{
		{"no route and no audit", bgInfoConfig + bgConsoleYAML(issuer, bg), 1, 1},
		{"an unrelated route", bgInfoConfig + hook("      - rule: egress_blocked\n      - severity: low\n") + bgConsoleYAML(issuer, bg), 1, 1},
		{"a route by rule and audit on", bgInfoConfig + hook("      - rule: breakglass_login\n") + bgConsoleYAML(issuer, bg+"  adminAudit:\n    enabled: true\n"), 0, 0},
		{"a route by severity", bgInfoConfig + hook("      - severity: critical\n") + bgConsoleYAML(issuer, bg), 0, 1},
		{"a route by category", bgInfoConfig + hook("      - category: security\n") + bgConsoleYAML(issuer, bg), 0, 1},
		{"disabled", bgInfoConfig + bgConsoleYAML(issuer, "  breakGlass:\n    enabled: false\n"), 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := startBreakGlassCP(t, tc.cfg)
			logs := cp.out.String()
			if n := logLines(logs, warnNoRoute, "WARN") + logLines(logs, "no alert pipeline", "WARN"); n != tc.wantNoRoute {
				t.Errorf("alert-route warns = %d, want %d\n%s", n, tc.wantNoRoute, logs)
			}
			if n := logLines(logs, warnNoAudit, "WARN"); n != tc.wantAudit {
				t.Errorf("admin-audit warns = %d, want %d\n%s", n, tc.wantAudit, logs)
			}
		})
	}
}

// TestControlPlaneBreakGlassDegraded: console.auth oidc with the issuer
// unreachable at start. The control plane starts and serves workers, sign-in
// answers 503 idp_unavailable, and the break-glass login opens an admin
// session with one signed audit row and one ERROR line, with zero integrations.
func TestControlPlaneBreakGlassDegraded(t *testing.T) {
	t.Setenv(bgTestSecretEn, bgTestSecret)
	t.Setenv(bgTestHashEnv, bgTestHash(t))
	cp := startBreakGlassCP(t, bgInfoConfig+bgConsoleYAML(deadIssuer(t),
		bgBlock("passwordHashEnv", bgTestHashEnv, "")+"  adminAudit:\n    enabled: true\n"))
	bearer := map[string]string{"Authorization": "Bearer " + bgTestToken}

	if code, _, _ := cp.do(t, http.MethodGet, "/policy", "", "", bearer); code != http.StatusOK {
		t.Fatalf("/policy = %d, want 200", code)
	}
	if code, _, _ := cp.do(t, http.MethodPost, "/control/heartbeat", "", "", bearer); code != http.StatusNoContent {
		t.Fatalf("/control/heartbeat = %d, want 204", code)
	}
	if code, body, _ := cp.do(t, http.MethodPost, "/central/ingest", "application/json", `{"events":[]}`, bearer); code/100 != 2 {
		t.Fatalf("/central/ingest = %d %s, want 2xx", code, body)
	}
	if code, body, _ := cp.do(t, http.MethodGet, "/auth/login", "", "", nil); code != http.StatusServiceUnavailable || !strings.Contains(body, `"idp_unavailable"`) {
		t.Fatalf("/auth/login = %d %s, want 503 idp_unavailable", code, body)
	}

	login := fmt.Sprintf(`{"username":%q,"password":%q}`, bgTestUser, bgTestPassword)
	code, body, hdr := cp.do(t, http.MethodPost, "/auth/breakglass", "application/json", login, nil)
	if code != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("/auth/breakglass = %d %s, want 200", code, body)
	}
	var cookie string
	for _, c := range (&http.Response{Header: hdr}).Cookies() {
		cookie = c.Name + "=" + c.Value
	}
	if cookie == "" {
		t.Fatal("no session cookie")
	}
	code, body, _ = cp.do(t, http.MethodGet, "/auth/me", "", "", map[string]string{"Cookie": cookie})
	var me map[string]string
	if err := json.Unmarshal([]byte(body), &me); err != nil || code != http.StatusOK || me["role"] != "admin" || me["authMethod"] != "breakglass" {
		t.Fatalf("/auth/me = %d %s, want an admin break-glass session", code, body)
	}

	if n := logLines(cp.out.String(), "breakglass_login", "ERROR"); n != 1 {
		t.Fatalf("breakglass_login ERROR lines = %d, want 1\n%s", n, cp.out.String())
	}
	if strings.Contains(cp.out.String(), bgTestPassword) {
		t.Fatal("the password reached the logs")
	}
	db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(cp.stateDir, "warden-cp.db"), controlplane.StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var rows int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM admin_audit WHERE action = 'auth.breakglass'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("auth.breakglass admin_audit rows = %d (%v), want 1", rows, err)
	}
}

// TestControlPlaneBreakGlassDisabledIs404: with break-glass absent the route
// does not exist.
func TestControlPlaneBreakGlassDisabledIs404(t *testing.T) {
	t.Setenv(bgTestSecretEn, bgTestSecret)
	cp := startBreakGlassCP(t, bgInfoConfig+bgConsoleYAML(deadIssuer(t), ""))
	if code, _, _ := cp.do(t, http.MethodPost, "/auth/breakglass", "application/json", `{}`, nil); code != http.StatusNotFound {
		t.Fatalf("/auth/breakglass = %d, want 404", code)
	}
}
