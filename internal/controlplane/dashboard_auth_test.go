package controlplane

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/secrets"
)

const dashTestToken = "dash-s3cret"

var writeMethods = []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete}

func dashWrite(t *testing.T, h http.Handler, method, path, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// dashboardAPIPaths is the dashboard's route table: every "/dashboard/api/..."
// literal passed to a mux Handle/HandleFunc in the dashboard package's non-test
// sources. Reading the source (not a hand-kept list) means a writer added there
// is walked, and refused without a token, with no test edit. It is a source walk
// because http.ServeMux cannot enumerate its patterns and exposing them from
// production code just for this test is not worth it; routes registered any other
// way are invisible here and rely on the guard's prefix match.
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

// TestDashboardWrites_RouteTableWalk walks the dashboard route table: EVERY API
// path (as found by dashboardAPIPaths) refuses EVERY write method without the token (and with a wrong one), so a
// writer registered with a literal path cannot ship unauthenticated. The
// guarantee for any other registration (helper, const, another package) is the
// guard's default-on /dashboard/api/ prefix, pinned by the unlisted-path check below.
// With the right token the guard lets the
// request through to the handler (whatever status the handler itself returns).
func TestDashboardWrites_RouteTableWalk(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken})
	h := srv.Handler()
	paths := dashboardAPIPaths(t)
	if len(paths) < 15 {
		t.Fatalf("route table suspiciously small: %v", paths)
	}
	for _, p := range paths {
		for _, m := range writeMethods {
			if rec := dashWrite(t, h, m, p, ""); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s unauthenticated = %d, want 401", m, p, rec.Code)
			}
			if rec := dashWrite(t, h, m, p, "Bearer wrong"); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s wrong token = %d, want 401", m, p, rec.Code)
			}
			if rec := dashWrite(t, h, m, p, "Bearer "+dashTestToken); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("%s %s right token = %d, want the handler to run", m, p, rec.Code)
			}
		}
	}
	// Path-cleaning tricks: the CP's outer mux may redirect (307) to the cleaned
	// path first; the redirected request must then be refused. (The guard's own
	// path.Clean is pinned with an exact 401 in the dashboard package.)
	for _, p := range []string{"/dashboard/api//policy", "/dashboard/x/../api/policy"} {
		rec := dashWrite(t, h, http.MethodPut, p, "")
		if rec.Code == http.StatusTemporaryRedirect || rec.Code == http.StatusPermanentRedirect {
			rec = dashWrite(t, h, http.MethodPut, rec.Header().Get("Location"), "")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("PUT %s unauthenticated = %d, want 401", p, rec.Code)
		}
	}
	// An unlisted path under the API prefix is guarded by default.
	if rec := dashWrite(t, h, http.MethodPut, "/dashboard/api/brand-new-writer", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("unlisted writer unauthenticated = %d, want 401", rec.Code)
	}
}

func TestDashboardWrites_PolicyPutByToken(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken})
	h := srv.Handler()
	body := `{"allowlist":[{"domain":"evil.example.com"}],"denylist":[]}`
	put := func(auth string) int {
		req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := put(""); c != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PUT = %d, want 401", c)
	}
	if c := put("Bearer nope"); c != http.StatusUnauthorized {
		t.Fatalf("wrong-token PUT = %d, want 401", c)
	}
	if c := put("Bearer " + dashTestToken); c != http.StatusOK {
		t.Fatalf("right-token PUT = %d, want 200", c)
	}
}

func TestDashboardWrites_FailClosedWithoutToken(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com")})
	h := srv.Handler()
	for _, auth := range []string{"", "Bearer ", "Bearer anything"} {
		rec := dashWrite(t, h, http.MethodPut, "/dashboard/api/policy", auth)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("no token configured, auth %q: PUT = %d, want 403", auth, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "--admin-token-env") {
			t.Fatalf("body should say how to configure the token: %s", rec.Body.String())
		}
	}
}

func TestDashboardReads_StayOpen(t *testing.T) {
	for _, tok := range []string{dashTestToken, ""} {
		srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: tok})
		h := srv.Handler()
		for _, p := range []string{"/dashboard/api/policy", "/dashboard/api/workers", "/dashboard/api/traffic", "/dashboard/"} {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("token=%q GET %s = %d, want 200", tok, p, rec.Code)
			}
		}
	}
}

func TestDashboardWrites_RefusalIsLoggedWithoutToken(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, Logger: lg})
	h := srv.Handler()
	dashWrite(t, h, http.MethodPut, "/dashboard/api/policy", "Bearer leaked-guess-value")
	out := buf.String()
	if !strings.Contains(out, "dashboard write refused") || !strings.Contains(out, "/dashboard/api/policy") {
		t.Fatalf("refusal not logged: %q", out)
	}
	if strings.Contains(out, "leaked-guess-value") || strings.Contains(out, dashTestToken) {
		t.Fatalf("log line contains a token value: %q", out)
	}
}

func TestDashboardWrites_WhitespaceTokenCountsAsUnset(t *testing.T) {
	for _, tok := range []string{"   ", "\t\n ", " "} {
		srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: tok})
		rec := dashWrite(t, srv.Handler(), http.MethodPut, "/dashboard/api/policy", "Bearer "+strings.TrimSpace(tok))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "--admin-token-env") {
			t.Errorf("token %q: write = %d %q, want 403 with the --admin-token-env hint", tok, rec.Code, rec.Body.String())
		}
	}
	// A real token with stray whitespace (env files, trailing newline) still works trimmed.
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken + "\n"})
	if rec := dashWrite(t, srv.Handler(), http.MethodPut, "/dashboard/api/policy", "Bearer "+dashTestToken); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Errorf("trimmed token rejected: %d", rec.Code)
	}
}

// Separate CP admin bearer (W-P1-WTOK-07). adminTok is the --admin-token-env
// value, workerTok the shared --token-env value workers present.
const (
	adminTok  = "cp-admin-s3cret"
	workerTok = "cp-worker-s3cret"
)

const policyPutBody = `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[]}`

func dashPolicyPut(t *testing.T, h http.Handler, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", strings.NewReader(policyPutBody))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestAdminTokenSeparatesWriteAuth: with an admin token configured, dashboard
// writes and /central/secrets take only the admin token; the shared worker
// token is refused with 401.
func TestAdminTokenSeparatesWriteAuth(t *testing.T) {
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"),
		Token:      workerTok, AdminToken: adminTok,
		SecretStore: secrets.NewEchoStore(),
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	if rec := dashPolicyPut(t, srv.Handler(), workerTok); rec.Code != http.StatusUnauthorized {
		t.Errorf("dashboard write with the worker token = %d, want 401", rec.Code)
	}
	if rec := dashPolicyPut(t, srv.Handler(), adminTok); rec.Code != http.StatusOK {
		t.Errorf("dashboard write with the admin token = %d %q, want 200", rec.Code, rec.Body.String())
	}
	secretReqs := []struct{ method, path, body string }{
		{http.MethodPost, "/central/secrets", `{"key":"K","value":"V123456"}`},
		{http.MethodGet, "/central/secrets", ""},
		{http.MethodDelete, "/central/secrets/K", ""},
	}
	for _, r := range secretReqs {
		if code, _ := do(t, r.method, ts.URL+r.path, workerTok, r.body); code != http.StatusUnauthorized {
			t.Errorf("%s %s with the worker token = %d, want 401", r.method, r.path, code)
		}
	}
	wants := []int{http.StatusNoContent, http.StatusOK, http.StatusNoContent}
	for i, r := range secretReqs {
		if code, _ := do(t, r.method, ts.URL+r.path, adminTok, r.body); code != wants[i] {
			t.Errorf("%s %s with the admin token = %d, want %d", r.method, r.path, code, wants[i])
		}
	}
}

// TestAdminTokenFallbackToSharedToken: with only the shared token, dashboard
// and secret writes still take it, and startup warns once naming the flag.
func TestAdminTokenFallbackToSharedToken(t *testing.T) {
	logger, buf := testLogger()
	srv := New(Config{
		PolicyPath:  writePolicyFile(t, "api.openai.com"),
		Token:       workerTok,
		Logger:      logger,
		SecretStore: secrets.NewEchoStore(),
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	if rec := dashPolicyPut(t, srv.Handler(), workerTok); rec.Code != http.StatusOK {
		t.Errorf("dashboard write with the shared token = %d, want 200", rec.Code)
	}
	if code, _ := do(t, http.MethodPost, ts.URL+"/central/secrets", workerTok, `{"key":"K","value":"V123456"}`); code != http.StatusNoContent {
		t.Errorf("secret write with the shared token = %d, want 204", code)
	}
	const warn = "dashboard writes use the shared worker token; set --admin-token-env"
	if n := strings.Count(buf.String(), warn); n != 1 {
		t.Errorf("fallback WARN logged %d times, want once:\n%s", n, buf.String())
	}
	if strings.Contains(buf.String(), workerTok) {
		t.Errorf("log carries the token value:\n%s", buf.String())
	}
}

// TestDashboardWritesRefusedWithoutAnyToken: neither token configured, the
// guard fails closed with a 403 that names --admin-token-env, and no fallback
// warning is logged (there is nothing to fall back to).
func TestDashboardWritesRefusedWithoutAnyToken(t *testing.T) {
	logger, buf := testLogger()
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Logger: logger})
	for _, bearer := range []string{"", "anything"} {
		rec := dashPolicyPut(t, srv.Handler(), bearer)
		if rec.Code != http.StatusForbidden ||
			!strings.Contains(rec.Body.String(), "dashboard writes are disabled") ||
			!strings.Contains(rec.Body.String(), "--admin-token-env") {
			t.Errorf("bearer %q: write = %d %q, want 403 'dashboard writes are disabled' naming --admin-token-env", bearer, rec.Code, rec.Body.String())
		}
	}
	if strings.Contains(buf.String(), "shared worker token") {
		t.Errorf("fallback WARN logged with no shared token:\n%s", buf.String())
	}
}

// TestAdminTokenNotAWorkerCredential: the admin token opens no worker route
// while a shared token is configured, and the shared token opens no dashboard
// write while an admin token is set.
func TestAdminTokenNotAWorkerCredential(t *testing.T) {
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"),
		Token:      workerTok, AdminToken: adminTok,
	})
	h := srv.Handler()
	type req struct{ method, path, body string }
	worker := []req{
		{http.MethodGet, "/policy", ""},
		{http.MethodPost, "/control/heartbeat", `{"policyETag":""}`},
		{http.MethodPost, "/central/ingest", `{"events":[]}`},
	}
	send := func(r req, bearer string) int {
		hr := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
		hr.Header.Set(analytics.ProxyIDHeader, "w1")
		hr.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, hr)
		return rec.Code
	}
	for _, r := range worker {
		if c := send(r, adminTok); c != http.StatusUnauthorized {
			t.Errorf("%s %s with the admin token = %d, want 401", r.method, r.path, c)
		}
		if c := send(r, workerTok); c == http.StatusUnauthorized {
			t.Errorf("%s %s with the worker token = 401, want it accepted", r.method, r.path)
		}
	}
	if rec := dashPolicyPut(t, h, workerTok); rec.Code != http.StatusUnauthorized {
		t.Errorf("dashboard write with the worker token = %d, want 401", rec.Code)
	}
}

// TestAdminTokenRequiredDoesNotFallBack: when --admin-token-env names an empty
// variable (RequireAdminToken with no AdminToken) the shared token must not
// reopen writes: dashboard writes are 403 and secret routes 401.
func TestAdminTokenRequiredDoesNotFallBack(t *testing.T) {
	logger, buf := testLogger()
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"),
		Token:      workerTok, RequireAdminToken: true,
		Logger: logger, SecretStore: secrets.NewEchoStore(),
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	if rec := dashPolicyPut(t, srv.Handler(), workerTok); rec.Code != http.StatusForbidden {
		t.Errorf("dashboard write with the worker token = %d, want 403", rec.Code)
	}
	for _, bearer := range []string{workerTok, ""} {
		if code, _ := do(t, http.MethodGet, ts.URL+"/central/secrets", bearer, ""); code != http.StatusUnauthorized {
			t.Errorf("secret list with bearer %q = %d, want 401", bearer, code)
		}
	}
	if strings.Contains(buf.String(), "shared worker token") {
		t.Errorf("fallback WARN logged although the fallback is off:\n%s", buf.String())
	}
}

// TestAdminTokenEqualsSharedTokenWarns: the same value for both tokens starts
// but warns that they should differ, without logging the value.
func TestAdminTokenEqualsSharedTokenWarns(t *testing.T) {
	logger, buf := testLogger()
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"),
		Token:      adminTok, AdminToken: adminTok, Logger: logger,
	})
	if rec := dashPolicyPut(t, srv.Handler(), adminTok); rec.Code != http.StatusOK {
		t.Errorf("dashboard write = %d, want 200", rec.Code)
	}
	if !strings.Contains(buf.String(), "admin token equals the shared worker token") {
		t.Errorf("no WARN for equal tokens:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), adminTok) {
		t.Errorf("log carries the token value:\n%s", buf.String())
	}
}
