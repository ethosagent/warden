package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPolicyEditableFlag(t *testing.T) {
	// No writer configured (worker dashboard) -> not editable.
	h := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	var p policyResponse
	doGetJSON(t, h, "/dashboard/api/policy", &p)
	if p.Editable {
		t.Error("editable should be false without a policy writer")
	}

	// Writer configured (control plane) -> editable.
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetPolicyWriter(func(config.Policy) error { return nil })
	var p2 policyResponse
	doGetJSON(t, srv.Handler(), "/dashboard/api/policy", &p2)
	if !p2.Editable {
		t.Error("editable should be true with a policy writer")
	}
}

func TestPolicyWriteRejectedWithoutWriter(t *testing.T) {
	h := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	rec := postJSON(t, h, "/dashboard/api/policy", `{"allowlist":[{"domain":"x.com"}]}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("worker policy write: status %d, want 405", rec.Code)
	}
}

func TestPolicyWriteCallsWriter(t *testing.T) {
	var got config.Policy
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetPolicyWriter(func(p config.Policy) error { got = p; return nil })
	srv.SetLivePolicy(func() config.Policy { return got }) // echo reflects the write

	rec := postJSON(t, srv.Handler(), "/dashboard/api/policy",
		`{"allowlist":[{"domain":"api.example.com","port":443}],"denylist":[{"domain":"bad.com"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(got.Allowlist) != 1 || got.Allowlist[0].Domain != "api.example.com" || got.Allowlist[0].Port != 443 {
		t.Errorf("writer received allowlist %+v", got.Allowlist)
	}
	if len(got.Denylist) != 1 || got.Denylist[0].Domain != "bad.com" {
		t.Errorf("writer received denylist %+v", got.Denylist)
	}
}

func TestPolicyWriteSurfacesValidationError(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetPolicyWriter(func(config.Policy) error { return fmt.Errorf("invalid policy: allowlist empty") })
	rec := postJSON(t, srv.Handler(), "/dashboard/api/policy", `{"allowlist":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "allowlist empty") {
		t.Errorf("writer error not surfaced: %s", rec.Body.String())
	}
}

func TestSettingsEditableFlagAndLiveValue(t *testing.T) {
	// No writer configured (worker dashboard) -> not editable, settings echoed.
	h := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	var s settingsResponse
	doGetJSON(t, h, "/dashboard/api/settings", &s)
	if s.Editable {
		t.Error("editable should be false without a settings writer")
	}

	// Writer + live settings configured (control plane) -> editable, settings served.
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetSettingsWriter(func(config.SettingsWire) error { return nil })
	srv.SetLiveSettings(func() *config.SettingsWire {
		return &config.SettingsWire{MCP: &config.MCPSettings{Enabled: true, Mode: "enforce"}}
	})
	var s2 settingsResponse
	doGetJSON(t, srv.Handler(), "/dashboard/api/settings", &s2)
	if !s2.Editable {
		t.Error("editable should be true with a settings writer")
	}
	if s2.Settings == nil || s2.Settings.MCP == nil || s2.Settings.MCP.Mode != "enforce" {
		t.Fatalf("live settings not served: %+v", s2.Settings)
	}
}

func TestSettingsWriteRejectedWithoutWriter(t *testing.T) {
	h := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	rec := postJSON(t, h, "/dashboard/api/settings", `{"mcp":{"enabled":true,"mode":"monitor"}}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("worker settings write: status %d, want 405", rec.Code)
	}
}

func TestSettingsWriteCallsWriterAndEchoes(t *testing.T) {
	var got config.SettingsWire
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetSettingsWriter(func(s config.SettingsWire) error { got = s; return nil })
	srv.SetLiveSettings(func() *config.SettingsWire { return &got }) // echo reflects the write

	rec := postJSON(t, srv.Handler(), "/dashboard/api/settings",
		`{"mcp":{"enabled":true,"mode":"enforce","tools":{"allow":["read_file"],"deny":["delete"]}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.MCP == nil || !got.MCP.Enabled || got.MCP.Mode != "enforce" {
		t.Fatalf("writer received mcp %+v", got.MCP)
	}
	if got.MCP.Tools == nil || len(got.MCP.Tools.Allow) != 1 || got.MCP.Tools.Allow[0] != "read_file" {
		t.Fatalf("writer received tools %+v", got.MCP.Tools)
	}
	// The echo returns the now-current settings via the GET path.
	var echoed settingsResponse
	if err := json.NewDecoder(rec.Body).Decode(&echoed); err != nil {
		t.Fatalf("decode echo: %v", err)
	}
	if echoed.Settings == nil || echoed.Settings.MCP == nil || echoed.Settings.MCP.Mode != "enforce" {
		t.Fatalf("echoed settings = %+v", echoed.Settings)
	}
}

func TestSettingsWriteSurfacesWriterError(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetSettingsWriter(func(config.SettingsWire) error { return fmt.Errorf("invalid mcp: mode bad") })
	rec := postJSON(t, srv.Handler(), "/dashboard/api/settings", `{"mcp":{"enabled":true,"mode":"bad"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "mode bad") {
		t.Errorf("writer error not surfaced: %s", rec.Body.String())
	}
}

func TestWorkersEndpoint(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWorkers(func() []WorkerView {
		return []WorkerView{{ProxyID: "w1", Online: true, EventsForwarded: 5}}
	})
	var ws []WorkerView
	doGetJSON(t, srv.Handler(), "/dashboard/api/workers", &ws)
	if len(ws) != 1 || ws[0].ProxyID != "w1" || !ws[0].Online {
		t.Fatalf("workers = %+v", ws)
	}

	// No registry (worker dashboard) -> empty list, so the UI hides the panel.
	h := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	var ws2 []WorkerView
	doGetJSON(t, h, "/dashboard/api/workers", &ws2)
	if len(ws2) != 0 {
		t.Fatalf("worker dashboard should report no workers, got %+v", ws2)
	}
}
