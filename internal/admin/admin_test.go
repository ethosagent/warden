package admin

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// stubProvider is a minimal SecretProvider for handler tests.
type stubProvider struct {
	refreshErr error
}

func (s *stubProvider) GetSecret(string) (string, error) { return "", nil }
func (s *stubProvider) RefreshSecrets() error            { return s.refreshErr }

func doReq(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
	return rr
}

func TestHealthz_OK(t *testing.T) {
	h := NewServer(&stubProvider{}).Handler()
	rr := doReq(t, h, http.MethodGet, "/healthz")
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Errorf("healthz body = %q", rr.Body.String())
	}
}

func TestHealthz_MethodNotAllowed(t *testing.T) {
	h := NewServer(&stubProvider{}).Handler()
	if rr := doReq(t, h, http.MethodPost, "/healthz"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("healthz POST = %d, want 405", rr.Code)
	}
}

func TestRefreshSecrets_Success(t *testing.T) {
	h := serverWithGuard(t, allowingGuard) // the write gate is TestAdmin_WritesNeedGuard's job
	rr := doReq(t, h, http.MethodPost, "/admin/refresh-secrets")
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200", rr.Code)
	}
}

func TestRefreshSecrets_HardFail(t *testing.T) {
	s := NewServer(&stubProvider{refreshErr: errors.New("backend down")})
	s.SetWriteGuard(allowingGuard)
	rr := doReq(t, s.Handler(), http.MethodPost, "/admin/refresh-secrets")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("refresh failure status = %d, want 503", rr.Code)
	}
}

func TestRefreshSecrets_MethodNotAllowed(t *testing.T) {
	h := NewServer(&stubProvider{}).Handler()
	if rr := doReq(t, h, http.MethodGet, "/admin/refresh-secrets"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("refresh GET = %d, want 405", rr.Code)
	}
}

// adminRoutes lists every path literal registered on a mux in this package's
// sources — the same source walk the worker's #425 test does across the
// dashboard package — so a writer added here is walked with no test edit.
func adminRoutes(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot find admin sources: %v", err)
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
				if p, err := strconv.Unquote(lit.Value); err == nil {
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

// refusingGuard stands in for the shared bearer guard the worker installs (the
// admin package cannot import the dashboard: the data plane never imports the
// control plane). The gate mechanics — prefix, method, fail-closed — are this
// package's job; the token compare is not.
func refusingGuard(*http.Request) (int, string) {
	return http.StatusUnauthorized, "unauthorized: test guard"
}

func allowingGuard(*http.Request) (int, string) { return 0, "" }

func serverWithGuard(t *testing.T, g WriteGuard) http.Handler {
	t.Helper()
	s := NewServer(&stubProvider{})
	s.SetWriteGuard(g)
	return s.Handler()
}

// TestAdmin_WritesFailClosedWithoutGuard: with no guard installed every write
// under /admin/ is refused 403 — the same default as the dashboard — even when
// the caller sends an Authorization header.
func TestAdmin_WritesFailClosedWithoutGuard(t *testing.T) {
	h := NewServer(&stubProvider{}).Handler()
	for _, auth := range []string{"", "Bearer anything"} {
		req := httptest.NewRequest(http.MethodPost, "/admin/refresh-secrets", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "no write guard configured") {
			t.Errorf("auth %q: POST = %d %q, want 403 naming the missing guard", auth, rr.Code, rr.Body.String())
		}
	}
}

// TestAdmin_WritesNeedGuard walks every /admin/ route the package registers
// (plus one never registered): every write method passes through the installed
// guard, so a refusal reaches the caller and an allowance reaches the handler.
func TestAdmin_WritesNeedGuard(t *testing.T) {
	var adminRoutesWalked []string
	for _, p := range adminRoutes(t) {
		if strings.HasPrefix(p, "/admin/") {
			adminRoutesWalked = append(adminRoutesWalked, p)
		}
	}
	if len(adminRoutesWalked) == 0 {
		t.Fatalf("route walk found no /admin/ routes: %v", adminRoutes(t))
	}
	paths := append(adminRoutesWalked, "/admin/brand-new-writer")
	for _, p := range paths {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			rr := doReq(t, serverWithGuard(t, refusingGuard), m, p)
			if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "unauthorized: test guard") {
				t.Errorf("%s %s guarded refusal = %d %q, want the guard's 401", m, p, rr.Code, rr.Body.String())
			}
			rr = doReq(t, serverWithGuard(t, allowingGuard), m, p)
			if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
				t.Errorf("%s %s guarded allowance = %d, want the handler to run", m, p, rr.Code)
			}
		}
	}
	// The one real route today, with the guard allowing: the handler answered.
	rr := doReq(t, serverWithGuard(t, allowingGuard), http.MethodPost, "/admin/refresh-secrets")
	if rr.Code != http.StatusOK || rr.Body.String() != "refreshed" {
		t.Errorf("guarded POST /admin/refresh-secrets = %d %q, want 200 \"refreshed\"", rr.Code, rr.Body.String())
	}
}

// TestAdmin_ReadsStayOpen: GET and HEAD never see the guard, on /admin/ or
// outside it — /healthz stays open and /admin/refresh-secrets answers its own
// 405 method check, not an auth refusal.
func TestAdmin_ReadsStayOpen(t *testing.T) {
	for _, p := range []string{"/healthz", "/admin/refresh-secrets"} {
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			rr := doReq(t, serverWithGuard(t, refusingGuard), m, p)
			if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
				t.Errorf("%s %s with a refusing guard = %d, want the open method gate", m, p, rr.Code)
			}
		}
	}
	if rr := doReq(t, serverWithGuard(t, refusingGuard), http.MethodGet, "/healthz"); rr.Code != http.StatusOK {
		t.Errorf("GET /healthz with a refusing guard = %d, want 200", rr.Code)
	}
	if rr := doReq(t, serverWithGuard(t, refusingGuard), http.MethodGet, "/admin/refresh-secrets"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /admin/refresh-secrets with a refusing guard = %d, want the handler's 405", rr.Code)
	}
}

// TestAdmin_GuardCoversOnlyAdminPrefix: /healthz sits outside the guarded
// prefix, so an always-refusing guard cannot touch it — POST there is still the
// handler's own 405.
func TestAdmin_GuardCoversOnlyAdminPrefix(t *testing.T) {
	if rr := doReq(t, serverWithGuard(t, refusingGuard), http.MethodPost, "/healthz"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz with a refusing guard = %d, want the handler's 405", rr.Code)
	}
}
