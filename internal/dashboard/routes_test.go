package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// TestRoutesMatchHandler pins Routes() to what the handlers accept: a method a
// handler serves must be listed, and a listed method must reach its handler
// rather than the default method-not-allowed reply. Without it a handler could
// grow a method that no authorization table knows about.
func TestRoutesMatchHandler(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	// Writers on, so a listed write is not refused for lack of one.
	srv.SetPolicyWriter(func(context.Context, config.Policy, WriteMeta) error { return nil })
	srv.SetSettingsWriter(func(context.Context, config.SettingsWire, WriteMeta) error { return nil })
	srv.SetIntegrationsWriter(func([]config.IntegrationInstance) error { return nil })
	srv.SetDetectionWriter(func(config.DetectionConfig) error { return nil })
	srv.SetLLMProvidersWriter(func(context.Context, []config.LLMProvider, WriteMeta) error { return nil })
	srv.SetSecretStore(secrets.NewEchoStore(), "echo")
	srv.SetPolicyHistory(&fakeHistory{})
	srv.SetBackup(func() error { return nil })
	srv.SetWorkerTokens(&fakeWorkerTokens{})
	srv.SetAuthMode("oidc")
	h := srv.Handler()

	listed := map[string]bool{}
	paths := map[string]bool{}
	for _, rt := range Routes() {
		if rt.Action == "" {
			t.Errorf("%s %s has no action", rt.Method, rt.Path)
		}
		key := rt.Method + " " + rt.Path
		if listed[key] {
			t.Errorf("duplicate route %s", key)
		}
		listed[key] = true
		paths[rt.Path] = true
	}
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for path := range paths {
		for _, m := range methods {
			req := httptest.NewRequest(m, path, strings.NewReader("{}"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if m == http.MethodGet && listed[m+" "+path] && path != "/dashboard/" &&
				strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
				t.Errorf("GET %s fell through to the index page: it is listed but not registered", path)
			}
			notAllowed := rec.Code == http.StatusMethodNotAllowed && strings.Contains(rec.Body.String(), "method not allowed")
			switch {
			case listed[m+" "+path] && notAllowed:
				t.Errorf("%s %s is listed but its handler refuses the method", m, path)
			case !listed[m+" "+path] && !notAllowed:
				t.Errorf("%s %s is served (status %d) but missing from Routes()", m, path, rec.Code)
			}
		}
	}
}

func TestRoutesFreshSlice(t *testing.T) {
	a := Routes()
	a[0].Path = "/mutated"
	if Routes()[0].Path == "/mutated" {
		t.Fatal("Routes() shares its backing array between calls")
	}
}

func TestRouteMuxRefusesUnlistedPath(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering a path missing from Routes() must panic")
		}
	}()
	newRouteMux().HandleFunc("/dashboard/api/not-listed", func(http.ResponseWriter, *http.Request) {})
}
