package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetPolicyWriter(func(context.Context, config.Policy, WriteMeta) error { return nil })
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
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetPolicyWriter(func(_ context.Context, p config.Policy, _ WriteMeta) error { got = p; return nil })
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
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetPolicyWriter(func(context.Context, config.Policy, WriteMeta) error {
		return fmt.Errorf("invalid policy: allowlist empty")
	})
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
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSettingsWriter(func(context.Context, config.SettingsWire, WriteMeta) error { return nil })
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
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSettingsWriter(func(_ context.Context, s config.SettingsWire, _ WriteMeta) error { got = s; return nil })
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
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSettingsWriter(func(context.Context, config.SettingsWire, WriteMeta) error {
		return fmt.Errorf("invalid mcp: mode bad")
	})
	rec := postJSON(t, srv.Handler(), "/dashboard/api/settings", `{"mcp":{"enabled":true,"mode":"bad"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "mode bad") {
		t.Errorf("writer error not surfaced: %s", rec.Body.String())
	}
}

// TestSettingsSurfacesSecretsSelector: GET /dashboard/api/settings surfaces the
// value-free secret-backend selector (settings.secrets = {backend,region,
// namePrefix}) so the Settings-page "Secret backend" card can populate — and on
// a worker (no settings writer) it is served read-only (editable=false).
func TestSettingsSurfacesSecretsSelector(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetLiveSettings(func() *config.SettingsWire {
		return &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws", Region: "us-east-1", NamePrefix: "warden/"}}
	})
	var s settingsResponse
	doGetJSON(t, srv.Handler(), "/dashboard/api/settings", &s)
	if s.Editable {
		t.Error("editable should be false without a settings writer (worker read-only)")
	}
	var sec *secretsSettingsView
	if s.Settings != nil {
		sec = s.Settings.Secrets
	}
	if sec == nil || sec.Backend != "aws" || sec.Region != "us-east-1" || sec.NamePrefix != "warden/" {
		t.Fatalf("secrets selector not surfaced: %+v", sec)
	}
}

// TestSettingsGETMasksSecretAccessKey proves the settings GET NEVER returns the
// raw secretAccessKey: the response carries the accessKeyId and a value-free
// masked indicator (configured + last-4), and the raw secret string appears
// nowhere in the body.
func TestSettingsGETMasksSecretAccessKey(t *testing.T) {
	const rawSecret = "super-secret-access-key-abcd1234WXYZ"
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetLiveSettings(func() *config.SettingsWire {
		return &config.SettingsWire{Secrets: &config.SecretsSettings{
			Backend: "aws", Region: "us-east-1", NamePrefix: "warden/",
			AccessKeyID: "AKIADASH", SecretAccessKey: rawSecret,
		}}
	})

	rec := getRaw(t, srv.Handler(), "/dashboard/api/settings")
	if strings.Contains(rec, rawSecret) {
		t.Fatalf("GET leaked the raw secretAccessKey:\n%s", rec)
	}
	if strings.Contains(rec, `"secretAccessKey"`) {
		t.Fatalf("GET must not carry a secretAccessKey field:\n%s", rec)
	}

	var s settingsResponse
	if err := json.Unmarshal([]byte(rec), &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sec := s.Settings.Secrets
	if sec == nil || sec.AccessKeyID != "AKIADASH" {
		t.Fatalf("accessKeyId not surfaced: %+v", sec)
	}
	if !sec.SecretAccessKeyConfigured || sec.SecretAccessKeyLast4 != "WXYZ" {
		t.Fatalf("masked indicator wrong: %+v", sec)
	}
}

// TestSettingsWriteSecretsRoundTrips: POST with an aws secrets block reaches the
// settingsWriter and echoes back; a follow-up save that OMITS the key (the UI's
// env selection) hands the writer a nil Secrets block so the control plane
// deletes the on-disk secretStore selector.
func TestSettingsWriteSecretsRoundTrips(t *testing.T) {
	var got config.SettingsWire
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSettingsWriter(func(_ context.Context, s config.SettingsWire, _ WriteMeta) error { got = s; return nil })
	srv.SetLiveSettings(func() *config.SettingsWire { return &got }) // echo reflects the write

	rec := postJSON(t, srv.Handler(), "/dashboard/api/settings",
		`{"secrets":{"backend":"aws","region":"eu-west-1","namePrefix":"warden/"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.Secrets == nil || got.Secrets.Backend != "aws" || got.Secrets.Region != "eu-west-1" || got.Secrets.NamePrefix != "warden/" {
		t.Fatalf("writer received secrets %+v", got.Secrets)
	}
	var echoed settingsResponse
	if err := json.NewDecoder(rec.Body).Decode(&echoed); err != nil {
		t.Fatalf("decode echo: %v", err)
	}
	if echoed.Settings == nil || echoed.Settings.Secrets == nil || echoed.Settings.Secrets.Region != "eu-west-1" {
		t.Fatalf("echoed settings = %+v", echoed.Settings)
	}

	// env selection: the UI omits the secrets key entirely.
	rec2 := postJSON(t, srv.Handler(), "/dashboard/api/settings", `{"logging":{"level":"info"}}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("env save: status %d, want 200; body=%s", rec2.Code, rec2.Body.String())
	}
	if got.Secrets != nil {
		t.Fatalf("env selection must reach the writer with no secrets block, got %+v", got.Secrets)
	}
}

func TestWorkersEndpoint(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
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

// TestWritersReceiveContextAndMeta: the policy, settings and llmProviders
// writers get the request context (it carries the caller's identity) and, in
// file mode, an empty WriteMeta (policy_conflict_test.go covers If-Match).
func TestWritersReceiveContextAndMeta(t *testing.T) {
	type seen struct {
		ctx  bool
		meta WriteMeta
	}
	got := map[string]seen{}
	record := func(name string, ctx context.Context, meta WriteMeta) {
		got[name] = seen{ctx: ctx.Value(ctxKey{}) == "marker", meta: meta}
	}
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetPolicyWriter(func(ctx context.Context, _ config.Policy, m WriteMeta) error {
		record("policy", ctx, m)
		return nil
	})
	srv.SetSettingsWriter(func(ctx context.Context, _ config.SettingsWire, m WriteMeta) error {
		record("settings", ctx, m)
		return nil
	})
	srv.SetLLMProvidersWriter(func(ctx context.Context, _ []config.LLMProvider, m WriteMeta) error {
		record("llmproviders", ctx, m)
		return nil
	})
	h := srv.Handler()
	for path, body := range map[string]string{
		"/dashboard/api/policy":       `{"allowlist":[{"domain":"x.com"}]}`,
		"/dashboard/api/settings":     `{}`,
		"/dashboard/api/llmproviders": `[]`,
	} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, "marker"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s = %d %s", path, rec.Code, rec.Body.String())
		}
	}
	for _, name := range []string{"policy", "settings", "llmproviders"} {
		s, ok := got[name]
		if !ok || !s.ctx || s.meta != (WriteMeta{}) {
			t.Errorf("%s writer: called=%v sawCtx=%v meta=%+v, want the request context and an empty WriteMeta", name, ok, s.ctx, s.meta)
		}
	}
}

// TestPolicyDriftField: GET /dashboard/api/policy reports drift from the
// control plane's SetPolicyDrift func, and false without one (a worker).
func TestPolicyDriftField(t *testing.T) {
	var p policyResponse
	doGetJSON(t, newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}}), "/dashboard/api/policy", &p)
	if p.Drift {
		t.Error("drift should be false without a drift func")
	}
	var drift atomic.Bool
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetPolicyDrift(drift.Load)
	for _, want := range []bool{false, true, false} {
		drift.Store(want)
		var got policyResponse
		doGetJSON(t, srv.Handler(), "/dashboard/api/policy", &got)
		if got.Drift != want {
			t.Errorf("drift = %v, want %v", got.Drift, want)
		}
	}
}

// TestPolicyDriftBannerServedHTML: the served console carries the drift
// banner, hidden by default, pointing to `warden policy import`, and shown
// only while /dashboard/api/policy reports drift.
func TestPolicyDriftBannerServedHTML(t *testing.T) {
	rr := doGet(t, newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}}), "/dashboard/")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /dashboard/ = %d", rr.Code)
	}
	html := rr.Body.String()
	start := strings.Index(html, `<div id="policyDriftBanner" role="status" hidden`)
	if start < 0 {
		t.Fatal("the served console lacks the hidden-by-default policyDriftBanner")
	}
	banner := html[start:]
	banner = banner[:strings.Index(banner, "</div>")]
	if !strings.Contains(banner, "<code>warden policy import</code>") {
		t.Errorf("the drift banner does not point to warden policy import: %s", banner)
	}
	if !strings.Contains(html, `b.hidden=!(p&&p.drift===true)`) {
		t.Error("renderPolicyDrift does not drive the banner from the drift field")
	}
	for _, call := range []string{"renderPolicyDrift(pol);", "renderPolicyDrift(p);"} {
		if !strings.Contains(html, call) {
			t.Errorf("the policy load/save path does not call %s", call)
		}
	}
}
