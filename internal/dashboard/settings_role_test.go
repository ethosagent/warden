package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

type ctxKey struct{}

// TestSettingsWriterContext: the context-aware writer receives the request
// context, and a *RoleRequiredError becomes 403 role_required with the fields;
// a wrapped one is recognized too.
func TestSettingsWriterContext(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	var sawCtx bool
	var refuse error
	srv.SetSettingsWriterContext(func(ctx context.Context, _ config.SettingsWire) error {
		sawCtx = ctx.Value(ctxKey{}) == "marker"
		return refuse
	})
	h := srv.Handler()
	send := func() (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/dashboard/api/settings", strings.NewReader(`{"dlp":{"mode":"monitor"}}`))
		req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, "marker"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, strings.TrimSpace(rec.Body.String())
	}

	if code, body := send(); code != http.StatusOK || !sawCtx {
		t.Fatalf("allowed write = %d %s (saw ctx %v), want 200 with the request context", code, body, sawCtx)
	}
	refuse = fmt.Errorf("authz: %w", &RoleRequiredError{Need: "admin", Fields: []string{"llmProviders", "agents[0].identity"}})
	if code, body := send(); code != http.StatusForbidden ||
		body != `{"error":"role_required","need":"admin","fields":["llmProviders","agents[0].identity"]}` {
		t.Fatalf("per-field refusal = %d %s", code, body)
	}
	refuse = &RoleRequiredError{Need: "editor"}
	if code, body := send(); code != http.StatusForbidden || body != `{"error":"role_required","need":"editor"}` {
		t.Fatalf("role refusal = %d %s", code, body)
	}
	if got := (&RoleRequiredError{Need: "admin", Fields: []string{"a", "b"}}).Error(); got != "role admin required to change a, b" {
		t.Errorf("Error() = %q", got)
	}
	if got := refuse.Error(); got != "role editor required" {
		t.Errorf("Error() = %q", got)
	}

	// Clearing the writer makes settings read-only again.
	srv.SetSettingsWriter(nil)
	if code, _ := send(); code != http.StatusMethodNotAllowed {
		t.Fatalf("nil writer = %d, want 405", code)
	}
}
