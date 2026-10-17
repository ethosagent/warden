package dashboard

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// TestWriteGuard_GatesWritesNotReads covers the guard hook itself: reads pass,
// every write method is passed to the guard, and no guard means no gating.
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

// TestIndexHTML_TokenPrompt pins the UI contract: every state-changing API call
// goes through authFetch, the token lives in sessionStorage only, and a 401
// clears it.
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
	// No raw fetch() to a dashboard API with a non-GET method.
	raw := regexp.MustCompile(`(?s)[^h]fetch\(\s*['"\x60]/dashboard/api[^;]*?method\s*:`)
	if loc := raw.FindStringIndex(html); loc != nil {
		t.Errorf("raw fetch with a write method; use authFetch: %.120s", html[loc[0]:])
	}
}
