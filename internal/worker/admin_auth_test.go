package worker

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
)

const adminTestToken = "admin-s3cret"

// startAdmin boots the real worker on injected port-0 listeners with p's admin
// token settings and returns the admin base URL and the captured worker log.
func startAdmin(t *testing.T, p Params) (base string, logs *syncBuffer) {
	t.Helper()
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if p.Config == nil {
		pol := goPolicy()
		pol.LogLevel = "info"
		p.Config = &fakes.FakeConfigProvider{Policy: pol}
	}
	p.DBPath = filepath.Join(t.TempDir(), "warden.db")
	p.Version = "test"
	p.ProxyListener, p.AdminListener = proxyLn, adminLn
	ready := make(chan string, 1)
	p.OnReady = func(_, adminAddr string) { ready <- adminAddr }
	logs = &syncBuffer{}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, logs, p) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(10 * time.Second):
			t.Error("worker did not stop")
		}
	})
	select {
	case addr := <-ready:
		return "http://" + addr, logs
	case err := <-errCh:
		t.Fatalf("Run returned before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for ready")
	}
	return "", nil
}

func adminWrite(t *testing.T, method, url, auth string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// dashboardAPIPaths lists every "/dashboard/api/..." literal registered on a mux in
// the dashboard package's sources (same source walk as the control plane's test),
// so a writer added there is walked here with no test edit.
func dashboardAPIPaths(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("../dashboard/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot find dashboard sources: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if p, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(p, "/dashboard/api/") {
					seen[p] = true
				}
			}
			return true
		})
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// TestWorkerAdmin_DashboardWritesNeedToken walks the worker's dashboard API: every
// route refuses every write method without the token and with a wrong one (401),
// and lets the right one through to the handler.
func TestWorkerAdmin_DashboardWritesNeedToken(t *testing.T) {
	t.Setenv("WARDEN_TEST_ADMIN_TOKEN", " "+adminTestToken+"\n")
	base, _ := startAdmin(t, Params{AdminTokenEnv: "WARDEN_TEST_ADMIN_TOKEN"})
	paths := dashboardAPIPaths(t)
	if len(paths) < 15 {
		t.Fatalf("route table suspiciously small: %v", paths)
	}
	for _, p := range paths {
		for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete} {
			if c, _ := adminWrite(t, m, base+p, ""); c != http.StatusUnauthorized {
				t.Errorf("%s %s unauthenticated = %d, want 401", m, p, c)
			}
			if c, _ := adminWrite(t, m, base+p, "Bearer wrong"); c != http.StatusUnauthorized {
				t.Errorf("%s %s wrong token = %d, want 401", m, p, c)
			}
			if c, _ := adminWrite(t, m, base+p, "Bearer "+adminTestToken); c == http.StatusUnauthorized || c == http.StatusForbidden {
				t.Errorf("%s %s right token = %d, want the handler to run", m, p, c)
			}
		}
	}
	if c, _ := adminWrite(t, http.MethodPut, base+"/dashboard/api/brand-new-writer", ""); c != http.StatusUnauthorized {
		t.Errorf("unlisted writer unauthenticated = %d, want 401", c)
	}
}

// TestWorkerAdmin_FailsClosedWithoutToken: no token configured (flag unset, env
// var unset or whitespace-only) refuses every write with 403 naming the flag and
// config key, even when the caller sends a header.
func TestWorkerAdmin_FailsClosedWithoutToken(t *testing.T) {
	t.Setenv("WARDEN_TEST_ADMIN_EMPTY", "  \t\n")
	for name, p := range map[string]Params{
		"flag unset":     {},
		"env var unset":  {AdminTokenEnv: "WARDEN_TEST_ADMIN_NOT_SET"},
		"whitespace env": {AdminTokenEnv: "WARDEN_TEST_ADMIN_EMPTY"},
	} {
		t.Run(name, func(t *testing.T) {
			base, _ := startAdmin(t, p)
			for _, auth := range []string{"", "Bearer ", "Bearer anything"} {
				c, body := adminWrite(t, http.MethodPut, base+"/dashboard/api/detection", auth)
				if c != http.StatusForbidden || !strings.Contains(body, "--admin-token-env") || !strings.Contains(body, "admin.tokenEnv") {
					t.Errorf("auth %q: PUT = %d %q, want 403 naming --admin-token-env and admin.tokenEnv", auth, c, body)
				}
			}
		})
	}
}

// TestWorkerAdmin_ReadsStayOpen: GET and HEAD need no token, configured or not,
// and the non-dashboard admin routes are untouched.
func TestWorkerAdmin_ReadsStayOpen(t *testing.T) {
	t.Setenv("WARDEN_TEST_ADMIN_TOKEN", adminTestToken)
	for _, env := range []string{"WARDEN_TEST_ADMIN_TOKEN", ""} {
		base, _ := startAdmin(t, Params{AdminTokenEnv: env})
		for _, p := range []string{"/dashboard/api/policy", "/dashboard/api/traffic", "/dashboard/", "/healthz"} {
			for _, m := range []string{http.MethodGet, http.MethodHead} {
				req, _ := http.NewRequest(m, base+p, nil)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				// The handlers are GET-only (HEAD may 405); the point is no auth gate.
				if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
					(m == http.MethodGet && resp.StatusCode != http.StatusOK) {
					t.Errorf("env=%q %s %s = %d, want open (200 for GET)", env, m, p, resp.StatusCode)
				}
			}
		}
	}
}

// TestWorkerAdmin_RefusalLoggedWithoutToken: a refused write logs a WARN with the
// route, never the configured token nor the presented header.
func TestWorkerAdmin_RefusalLoggedWithoutToken(t *testing.T) {
	t.Setenv("WARDEN_TEST_ADMIN_TOKEN", adminTestToken)
	base, logs := startAdmin(t, Params{AdminTokenEnv: "WARDEN_TEST_ADMIN_TOKEN"})
	adminWrite(t, http.MethodPut, base+"/dashboard/api/detection", "Bearer leaked-guess-value")
	out := logs.String()
	if !strings.Contains(out, "worker dashboard write refused") || !strings.Contains(out, "/dashboard/api/detection") {
		t.Fatalf("refusal not logged: %q", out)
	}
	if strings.Contains(out, "leaked-guess-value") || strings.Contains(out, adminTestToken) {
		t.Fatalf("log contains a token value: %q", out)
	}
}

// TestWorkerAdmin_TokenEnvFromConfig: with no flag, admin.tokenEnv in the policy
// names the env var.
func TestWorkerAdmin_TokenEnvFromConfig(t *testing.T) {
	t.Setenv("WARDEN_TEST_ADMIN_CFG", adminTestToken)
	cfg := writeConfig(t, "admin:\n  tokenEnv: WARDEN_TEST_ADMIN_CFG\npolicy:\n  allowlist:\n    - domain: api.openai.com\nlogging:\n  level: error\n")
	prov, err := config.NewLocalYAMLProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := startAdmin(t, Params{Config: prov})
	if c, _ := adminWrite(t, http.MethodPut, base+"/dashboard/api/detection", "Bearer "+adminTestToken); c == http.StatusUnauthorized || c == http.StatusForbidden {
		t.Errorf("config-named token rejected: %d", c)
	}
	if c, _ := adminWrite(t, http.MethodPut, base+"/dashboard/api/detection", ""); c != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d, want 401", c)
	}
}
