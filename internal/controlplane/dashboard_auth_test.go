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
// is walked, and refused without a token, with no test edit.
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
// path refuses EVERY write method without the token (and with a wrong one), so a
// new writer cannot ship unauthenticated. With the right token the guard lets the
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
	// Path-cleaning tricks are guarded too: no 200 without the token.
	for _, p := range []string{"/dashboard/api//policy", "/dashboard/x/../api/policy"} {
		if rec := dashWrite(t, h, http.MethodPut, p, ""); rec.Code == http.StatusOK {
			t.Errorf("PUT %s unauthenticated = 200", p)
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
		if !strings.Contains(rec.Body.String(), "--token-env") {
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
