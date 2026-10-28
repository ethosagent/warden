package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// newStrictWA builds a strict-mode control plane over a real token store. shared
// is a Config.Token that strict mode must ignore (Run refuses the combination;
// New must still never accept it).
func newStrictWA(t *testing.T, shared string) *waEnv {
	t.Helper()
	e := newWT(t)
	logs := &syncBuf{}
	srv := New(Config{
		PolicyPath:          writePolicyFile(t, "api.openai.com"),
		Token:               shared,
		RequireWorkerTokens: true,
		TLS:                 true,
		WorkerTokens:        e.store,
		Logger:              slog.New(slog.NewTextHandler(logs, nil)),
		Clock:               e.clk,
		Store:               analytics.NewCentralStore(100),
	})
	return &waEnv{wtEnv: e, srv: srv, h: srv.Handler(), logs: logs}
}

func TestWorkerAuthModesStrict(t *testing.T) {
	e := newStrictWA(t, waLegacy)
	a, _ := e.create(t, "a", "worker-1")
	for _, rt := range waRoutes {
		for name, bearer := range map[string]string{"shared token": waLegacy, "no bearer": "", "other bearer": "nope"} {
			rec := e.call(rt.method, rt.path, bearer, "worker-1", "")
			if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("%s with %s = %d, want 401 with WWW-Authenticate", rt.path, name, rec.Code)
			}
		}
		if rec := e.call(rt.method, rt.path, a, "", ""); rec.Code != rt.ok {
			t.Errorf("%s with a worker token = %d, want %d", rt.path, rec.Code, rt.ok)
		}
	}
	if got := e.srv.workerAuth.Count(KindLegacy, "ok"); got != 0 {
		t.Errorf("legacy ok counter = %d, want 0", got)
	}
	if got := e.srv.workerAuth.LegacyRequests("worker-1"); got != 0 {
		t.Errorf("legacy requests = %d, want 0", got)
	}
	out := e.logs.String()
	if !strings.Contains(out, "auth_mode=strict") {
		t.Errorf("startup line missing auth_mode=strict:\n%s", out)
	}
	if strings.Contains(out, waLegacy) || strings.Contains(out, a) {
		t.Error("a credential reached the log")
	}
	if !strings.Contains(out, "reason=worker_token_required") {
		t.Errorf("the rejection reason is not logged:\n%s", out)
	}
}

func TestWorkerAuthStartupLine(t *testing.T) {
	e := newWA(t, waLegacy, false)
	e.create(t, "a", "worker-1")
	e.create(t, "b", "worker-2")
	New(Config{
		PolicyPath: writePolicyFile(t, "x.com"), Token: waLegacy, WorkerTokens: e.store,
		Logger: slog.New(slog.NewTextHandler(e.logs, nil)), Clock: e.clk,
	})
	out := e.logs.String()
	for _, want := range []string{"auth_mode=mixed", "legacy_token=true", "tls=false", "active_worker_tokens=2", "sent in clear text"} {
		if !strings.Contains(out, want) {
			t.Errorf("startup log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, waLegacy) {
		t.Error("the shared token reached the log")
	}
}

func TestLegacyWorkerTokenWarning(t *testing.T) {
	e := newWA(t, waLegacy, false)
	warns := func(id string) int {
		return strings.Count(e.logs.String(), "msg=\"legacy worker token in use\" proxy_id="+id+" ")
	}
	for i := 0; i < 5; i++ {
		e.call(http.MethodGet, "/policy", waLegacy, "w1", "")
	}
	e.call(http.MethodGet, "/policy", waLegacy, "w2", "")
	if warns("w1") != 1 || warns("w2") != 1 {
		t.Fatalf("w1 warned %d times, w2 %d, want 1 each:\n%s", warns("w1"), warns("w2"), e.logs.String())
	}
	e.clk.Advance(59 * time.Minute)
	e.call(http.MethodGet, "/policy", waLegacy, "w1", "")
	if warns("w1") != 1 {
		t.Fatalf("w1 warned again inside the hour: %d", warns("w1"))
	}
	e.clk.Advance(2 * time.Minute)
	e.call(http.MethodGet, "/policy", waLegacy, "w1", "")
	if warns("w1") != 2 {
		t.Fatalf("w1 warned %d times after the hour, want 2", warns("w1"))
	}
	// A worker token and a refused request never warn.
	tok, _ := e.create(t, "t", "w3")
	e.call(http.MethodGet, "/policy", tok, "", "")
	e.call(http.MethodGet, "/policy", "wrong", "w4", "")
	if warns("w3") != 0 || warns("w4") != 0 {
		t.Errorf("a token or refused request warned:\n%s", e.logs.String())
	}
	if strings.Contains(e.logs.String(), waLegacy) {
		t.Error("the shared token reached the log")
	}

	// The fleet view shows the auth kind and the legacy request count.
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard/api/workers", nil))
	var views []struct {
		ProxyID        string `json:"proxyID"`
		AuthKind       string `json:"authKind"`
		LegacyRequests int64  `json:"legacyRequests"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, v := range views {
		seen[v.ProxyID] = v.AuthKind
		if v.ProxyID == "w1" && v.LegacyRequests != 7 {
			t.Errorf("w1 legacyRequests = %d, want 7", v.LegacyRequests)
		}
	}
	if seen["w1"] != "legacy" || seen["w3"] != "token" {
		t.Errorf("authKind per worker = %v, want w1 legacy and w3 token", seen)
	}
}

func TestLegacyWorkerWarningBounded(t *testing.T) {
	e := newWA(t, waLegacy, false)
	a := e.srv.workerAuth
	for i := 0; i < maxLegacyIDs+50; i++ {
		a.warnLegacy("id-" + strconv.Itoa(i))
	}
	if n := len(a.legacyWarn); n != maxLegacyIDs {
		t.Fatalf("warned set = %d, want the cap %d", n, maxLegacyIDs)
	}
	// Past the cap an unseen id is not warned, and a seen one is still limited.
	before := strings.Count(e.logs.String(), "legacy worker token in use")
	a.warnLegacy("new-id")
	a.warnLegacy("id-0")
	if got := strings.Count(e.logs.String(), "legacy worker token in use"); got != before {
		t.Errorf("warned past the cap: %d -> %d", before, got)
	}
	// After the hour the entries expire and a new id gets in again.
	e.clk.Advance(legacyWarnEvery + time.Minute)
	a.warnLegacy("new-id")
	if got := strings.Count(e.logs.String(), "legacy worker token in use"); got != before+1 {
		t.Errorf("no warning after the entries expired: %d -> %d", before, got)
	}
	if len(a.legacyWarn) > maxLegacyIDs {
		t.Errorf("warned set grew past the cap: %d", len(a.legacyWarn))
	}
}

func TestRunStrictValidation(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	cases := []struct {
		name string
		p    Params
		want string // substring of the error naming the flag; "" = starts
	}{
		{"no state dir", Params{RequireWorkerTokens: true, CACert: ca, CAKey: ca}, "--require-worker-tokens requires --state-dir"},
		{"legacy token", Params{RequireWorkerTokens: true, StateDir: "x", LegacyTokenEnv: "E", AllowInsecureWorkerAuth: true}, "cannot be combined with --legacy-token-env"},
		{"token-env alias", Params{RequireWorkerTokens: true, StateDir: "x", TokenEnv: "E", AllowInsecureWorkerAuth: true}, "--token-env"},
		{"no tls", Params{RequireWorkerTokens: true, StateDir: "x"}, "--allow-insecure-worker-auth"},
		{"half tls", Params{RequireWorkerTokens: true, StateDir: "x", CACert: ca}, "--ca-cert and --ca-key"},
		{"different names", Params{TokenEnv: "A", LegacyTokenEnv: "B"}, "--token-env and --legacy-token-env name different variables"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			p := c.p
			p.ConfigPath = writePolicyFile(t, "api.openai.com")
			p.Listener = ln
			err = Run(context.Background(), &bytes.Buffer{}, p)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Run = %v, want an error containing %q", err, c.want)
			}
			// Nothing listens: Run closed the injected listener.
			if _, aerr := ln.Accept(); aerr == nil {
				t.Error("the listener is still open after a validation error")
			}
		})
	}
	t.Run("same name twice is fine", func(t *testing.T) {
		if got, err := validateWorkerAuth(Params{TokenEnv: "A", LegacyTokenEnv: "A"}); err != nil || got != "A" {
			t.Errorf("validateWorkerAuth = %q, %v", got, err)
		}
	})
	t.Run("no flags keeps today's behaviour", func(t *testing.T) {
		if got, err := validateWorkerAuth(Params{}); err != nil || got != "" {
			t.Errorf("validateWorkerAuth = %q, %v", got, err)
		}
	})
}

func TestRunTokenEnvAliasIsMixedWithNotice(t *testing.T) {
	t.Setenv("WARDEN_TEST_CP_TOKEN", workerTok)
	_, logs, stop := runCPServing(t, Params{ConfigPath: writePolicyFile(t, "api.openai.com"), TokenEnv: "WARDEN_TEST_CP_TOKEN"})
	stop()
	out := logs.String()
	mixed := strings.Contains(out, "auth_mode=mixed") || strings.Contains(out, `"auth_mode":"mixed"`)
	if !strings.Contains(out, "--token-env is deprecated") || !mixed {
		t.Errorf("want the deprecation notice and mixed mode:\n%s", out)
	}
	if strings.Contains(out, workerTok) {
		t.Error("the shared token reached the log")
	}
}

// strictConfig writes a CP config with an echo secret store, so /central/secrets
// would be mounted if strict mode allowed it.
func strictConfig(t *testing.T) string {
	t.Helper()
	path := writePolicyFile(t, "api.openai.com")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, []byte("secretStore:\n  backend: echo\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func strictParams(t *testing.T) Params {
	return Params{
		ConfigPath: strictConfig(t), StateDir: t.TempDir(),
		RequireWorkerTokens: true, AllowInsecureWorkerAuth: true,
	}
}

func doBearer(t *testing.T, method, url, bearer, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestStrictModeAdminTokenKeepsWrites(t *testing.T) {
	t.Setenv("WARDEN_TEST_CP_ADMIN_TOKEN", adminTok)
	p := strictParams(t)
	p.AdminTokenEnv = "WARDEN_TEST_CP_ADMIN_TOKEN"
	base, logs, stop := runCPServing(t, p)
	defer stop()
	if c := putPolicy(t, base, adminTok); c != http.StatusOK {
		t.Errorf("dashboard write with the admin token = %d, want 200", c)
	}
	if c := putPolicy(t, base, workerTok); c != http.StatusUnauthorized {
		t.Errorf("dashboard write with another bearer = %d, want 401", c)
	}
	secret := `{"key":"K","value":"v"}`
	if c := doBearer(t, http.MethodPost, base+"/central/secrets", adminTok, secret); c != http.StatusNoContent {
		t.Errorf("POST /central/secrets with the admin token = %d, want 204", c)
	}
	if c := doBearer(t, http.MethodPost, base+"/central/secrets", workerTok, secret); c != http.StatusUnauthorized {
		t.Errorf("POST /central/secrets with another bearer = %d, want 401", c)
	}
	// The admin token is no worker credential in strict mode either.
	if c := doBearer(t, http.MethodGet, base+"/policy", adminTok, ""); c != http.StatusUnauthorized {
		t.Errorf("GET /policy with the admin token = %d, want 401", c)
	}
	out := logs.String()
	if strings.Contains(out, "dashboard writes are disabled") {
		t.Errorf("the fail-closed error was logged although an admin token is set:\n%s", out)
	}
	if strings.Contains(out, adminTok) {
		t.Error("the admin token reached the log")
	}
}

func TestStrictModeNoAdminTokenFailsClosed(t *testing.T) {
	for name, env := range map[string]string{"flag unset": "", "flag names an empty variable": "WARDEN_TEST_EMPTY_ADMIN"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("WARDEN_TEST_EMPTY_ADMIN", "")
			p := strictParams(t)
			p.AdminTokenEnv = env
			base, logs, stop := runCPServing(t, p)
			defer stop()
			for _, bearer := range []string{"", workerTok, adminTok} {
				if c := putPolicy(t, base, bearer); c != http.StatusForbidden {
					t.Errorf("dashboard write with bearer %q = %d, want the guard's 403", bearer, c)
				}
			}
			for _, m := range []string{http.MethodGet, http.MethodPost} {
				if c := doBearer(t, m, base+"/central/secrets", adminTok, `{"key":"K","value":"v"}`); c != http.StatusNotFound {
					t.Errorf("%s /central/secrets = %d, want 404 (not mounted)", m, c)
				}
			}
			if !strings.Contains(logs.String(), "level=ERROR") && !strings.Contains(logs.String(), `"level":"ERROR"`) {
				t.Errorf("no ERROR line:\n%s", logs.String())
			}
			if !strings.Contains(logs.String(), "dashboard writes are disabled: set --admin-token-env") {
				t.Errorf("the error does not name --admin-token-env:\n%s", logs.String())
			}
		})
	}
}

func TestStrictModeOIDCNeedsNoAdminToken(t *testing.T) {
	// console.auth oidc replaces the admin bearer with sessions, so strict mode
	// without --admin-token-env neither logs the error nor unmounts the secrets.
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "x.com"), RequireWorkerTokens: true,
		SecretStore: secrets.NewEchoStore(), Console: config.ConsoleConfig{Auth: config.ConsoleAuthOIDC, OIDC: config.ConsoleOIDC{RedirectURL: testRedirectHTTPS}},
		Logger: slog.New(slog.DiscardHandler),
	})
	if srv.secretStore == nil {
		t.Error("the secret store was unmounted in oidc mode")
	}
}

// TestWorkerAuthDocsMentionFlags keeps the migration guide in docs/control-plane.md
// naming every flag, mode, step and log line the code defines.
func TestWorkerAuthDocsMentionFlags(t *testing.T) {
	b, err := os.ReadFile(authzDocPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	start := strings.Index(doc, "## Migrating from WARDEN_CP_TOKEN")
	if start < 0 {
		t.Fatal("docs/control-plane.md has no \"Migrating from WARDEN_CP_TOKEN\" section")
	}
	end := strings.Index(doc[start+1:], "\n## ")
	section := doc[start:]
	if end >= 0 {
		section = doc[start : start+1+end]
	}
	for _, want := range []string{
		"--legacy-token-env", "--token-env", "--require-worker-tokens", "--allow-insecure-worker-auth",
		"--admin-token-env", "--state-dir", "--ca-cert",
		"auth_mode=strict", string(modeOpen), string(modeMixed), string(modeStrict),
		"controlPlane.tokenEnv", "central.tokenEnv", "central.proxyID",
		"authKind", "legacy worker token in use", "dashboard writes are disabled: set --admin-token-env",
		"### Migration steps", "### Rotation", "### One token per replica", "### A revoked worker",
		"two active tokens", "default-deny", "W-P2-WCA",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the migration guide does not mention %q", want)
		}
	}
	// The doc's claims match the code constants.
	if maxActiveWorkerTokens != 2 {
		t.Errorf("maxActiveWorkerTokens = %d: update the rotation text", maxActiveWorkerTokens)
	}
	if legacyWarnEvery != time.Hour {
		t.Errorf("legacyWarnEvery = %v: update the migration text (once per proxy id per hour)", legacyWarnEvery)
	}
}
