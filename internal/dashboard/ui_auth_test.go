package dashboard

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// TestWriteGuard_GatesWritesNotReads covers the guard hook itself: reads pass,
// every write method is passed to the guard.
func TestWriteGuard_GatesWritesNotReads(t *testing.T) {
	s := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	s.SetWriteGuard(func(r *http.Request) (int, string) {
		if r.Header.Get("Authorization") == "Bearer ok" {
			return 0, ""
		}
		return http.StatusUnauthorized, "nope"
	})
	h := s.Handler()
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/dashboard/api/policy", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth = %d, want 401", m, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard/api/setup", nil))
	if rec.Code == http.StatusUnauthorized {
		t.Error("GET must not be guarded")
	}
}

// TestWriteGuard_DeniesByDefault: a server nobody installed a guard on refuses
// every write (403) instead of serving it open; reads still work.
func TestWriteGuard_DeniesByDefault(t *testing.T) {
	h := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}}).Handler()
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/dashboard/api/policy", nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s with no guard set = %d, want 403", m, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard/api/setup", nil))
	if rec.Code == http.StatusForbidden {
		t.Error("GET must not be refused by the default guard")
	}
}

// TestWriteGuard_PathTricksAreRefused: the dashboard handler (no mux in front)
// refuses cleaned-path tricks itself with exactly the guard's status, so the
// guard's path.Clean cannot be dropped unnoticed.
func TestWriteGuard_PathTricksAreRefused(t *testing.T) {
	s := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	s.SetWriteGuard(func(*http.Request) (int, string) { return http.StatusUnauthorized, "nope" })
	h := s.Handler()
	for _, p := range []string{"/dashboard/api//policy", "/dashboard/x/../api/policy", "/dashboard/./api/policy", "/dashboard/api/policy/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, p, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("PUT %s = %d, want 401", p, rec.Code)
		}
	}
}

// TestIndexHTML_TokenPrompt pins the UI contract: every state-changing API call
// goes through authFetch, the token lives in sessionStorage only, and a 401
// clears it. A prompt happens only after a 401.
func TestIndexHTML_TokenPrompt(t *testing.T) {
	b, err := indexHTML, error(nil)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	// localStorage still holds UI prefs (tab, saved queries); the token must not.
	for _, bad := range []string{"document.cookie", "localStorage.setItem(CP_TOKEN_KEY", "localStorage.getItem(CP_TOKEN_KEY"} {
		if strings.Contains(html, bad) {
			t.Errorf("index.html uses %s; the token must live in sessionStorage only", bad)
		}
	}
	for _, want := range []string{"sessionStorage.getItem", "sessionStorage.setItem", "sessionStorage.removeItem", "'Authorization'", "r.status===401"} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	// authFetch sends the write first and prompts only after a 401 (a worker
	// dashboard needs no token, so it must never ask), then retries once.
	a := strings.Index(html, "async function authFetch(")
	if a < 0 {
		t.Fatal("authFetch not found")
	}
	body := html[a:]
	if e := strings.Index(body, "\n}\n"); e > 0 {
		body = body[:e]
	}
	first, prompt, retry := strings.Index(body, "await send("), strings.Index(body, "window.prompt("), strings.LastIndex(body, "await send(")
	if first < 0 || prompt < 0 || first >= prompt || prompt >= retry {
		t.Errorf("authFetch must send, then prompt, then retry once (send@%d prompt@%d retry@%d)", first, prompt, retry)
	}
	if st := strings.Index(body, "status!==401"); st < 0 || st > prompt {
		t.Error("authFetch must return a non-401 response before it can prompt")
	}
	// No raw fetch() to a dashboard API with a non-GET method.
	raw := regexp.MustCompile(`(?s)[^h]fetch\(\s*['"\x60]/dashboard/api[^;]*?method\s*:`)
	if loc := raw.FindStringIndex(html); loc != nil {
		t.Errorf("raw fetch with a write method; use authFetch: %.120s", html[loc[0]:])
	}
}

// TestAllowUngatedWritesForTests_NotUsedInProduction: the open-writes guard may
// appear only in test files and its own declaration.
func TestAllowUngatedWritesForTests_NotUsedInProduction(t *testing.T) {
	err := filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || filepath.Base(p) == "dashboard.go" {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr == nil && strings.Contains(string(b), "AllowUngatedWritesForTests") {
			t.Errorf("%s references AllowUngatedWritesForTests; it is for tests only", p)
		}
		return rerr
	})
	if err != nil {
		t.Fatal(err)
	}
}
