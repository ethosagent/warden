package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
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

// TestPolicyWriteMissingIfMatch428 (W-P1-PVER-04): in versioned mode a
// policy, settings or llmProviders save without If-Match is a 428
// precondition_required and never reaches the writer, like a rollback; with
// If-Match it goes through.
func TestPolicyWriteMissingIfMatch428(t *testing.T) {
	for path, body := range versionedRoutes {
		srv, got := versionedServer(5, nil)
		h := srv.Handler()
		for _, method := range []string{http.MethodPost, http.MethodPut} {
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusPreconditionRequired {
				t.Fatalf("%s %s without If-Match = %d %s, want 428", method, path, rec.Code, rec.Body.String())
			}
			var e map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e["error"] != "precondition_required" || !strings.Contains(e["detail"], "If-Match") {
				t.Errorf("%s %s 428 body = %s, want error precondition_required naming If-Match", method, path, rec.Body.String())
			}
			if _, called := got[path]; called {
				t.Errorf("%s %s without If-Match reached the writer", method, path)
			}
		}
		if rec := sendWrite(h, path, body, `"v5"`); rec.Code != http.StatusOK || got[path].ExpectedHead != 5 {
			t.Errorf("%s with If-Match v5 = %d meta %+v, want 200 at ExpectedHead 5", path, rec.Code, got[path])
		}
	}
}

// TestPolicyWriteMessage: in versioned mode the optional save message travels
// percent-encoded in X-Warden-Policy-Message and reaches the writer decoded,
// with control characters stripped; more than 512 characters or a broken
// encoding is a 400 that never reaches the writer.
func TestPolicyWriteMessage(t *testing.T) {
	send := func(h http.Handler, path, body, msg string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
		req.Header.Set("If-Match", `"v5"`)
		req.Header.Set(PolicyMessageHeader, msg)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for path, body := range versionedRoutes {
		srv, got := versionedServer(5, nil)
		h := srv.Handler()
		if rec := send(h, path, body, "allow%20%C3%A9x%0A.com%20%E2%9C%93"); rec.Code != http.StatusOK {
			t.Fatalf("%s with a message = %d %s", path, rec.Code, rec.Body.String())
		}
		if want := "allow éx.com ✓"; got[path].Message != want || got[path].ExpectedHead != 5 {
			t.Errorf("%s meta = %+v, want message %q at ExpectedHead 5", path, got[path], want)
		}
		if rec := send(h, path, body, strings.Repeat("%C3%A9", maxPolicyMessage)); rec.Code != http.StatusOK || len([]rune(got[path].Message)) != maxPolicyMessage {
			t.Errorf("%s with a %d-character message = %d, want 200", path, maxPolicyMessage, rec.Code)
		}
		for _, bad := range []string{strings.Repeat("a", maxPolicyMessage+1), "bad%zzescape", "%E2%9C"} {
			delete(got, path)
			if rec := send(h, path, body, bad); rec.Code != http.StatusBadRequest {
				t.Errorf("%s message %.20q = %d, want 400", path, bad, rec.Code)
			}
			if _, called := got[path]; called {
				t.Errorf("%s message %.20q reached the writer", path, bad)
			}
		}
	}
}

// TestPolicyFileModeUnchanged: in file mode GET /dashboard/api/policy has no
// version field, saves without If-Match still succeed, and a message header is
// ignored (there are no versions to carry it).
func TestPolicyFileModeUnchanged(t *testing.T) {
	srv, got := versionedServer(0, nil)
	h := srv.Handler()
	rec := doGet(t, h, "/dashboard/api/policy")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["version"]; ok || rec.Header().Get(PolicyVersionHeader) != "" {
		t.Errorf("file mode GET policy reports a version: %s", rec.Body.String())
	}
	for path, body := range versionedRoutes {
		req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
		req.Header.Set(PolicyMessageHeader, "ignored")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || got[path] != (WriteMeta{}) {
			t.Errorf("file mode save %s without If-Match = %d meta %+v, want 200 with an empty WriteMeta", path, rec.Code, got[path])
		}
	}
}

// historyRegion returns the policy history script block (between the
// policyhistory:begin and policyhistory:end markers) of the page served in
// versioned mode.
func historyRegion(t *testing.T) (html, region string) {
	t.Helper()
	srv, _ := versionedServer(5, nil)
	rec := doGet(t, srv.Handler(), "/dashboard/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard/ = %d", rec.Code)
	}
	html = rec.Body.String()
	a, b := strings.Index(html, "/* policyhistory:begin */"), strings.Index(html, "/* policyhistory:end */")
	if a < 0 || b < a {
		t.Fatalf("policyhistory:begin/end markers not found (begin@%d end@%d)", a, b)
	}
	return html, html[a:b]
}

// TestPolicyHistoryPanelServedHTML pins the History panel (W-P1-PVER-04): a
// hidden container shown only when the policy GET reports a version, the
// version list fetched from /dashboard/api/policy/versions with cursor 'load
// more', the server's diff rendered (nothing diffed client-side), a rollback
// that goes through api() (the one place that sets X-Warden-CSRF) with
// If-Match from the head after a confirm dialog naming the target version,
// gated on editor, and the policy, settings and llmProviders saves sending
// If-Match and the optional message and handling a 409.
func TestPolicyHistoryPanelServedHTML(t *testing.T) {
	html, region := historyRegion(t)

	if !regexp.MustCompile(`<div class="card" id="policyHistory" style="display:none[^"]*">`).MatchString(html) {
		t.Error("the History container must be in the page, hidden by default")
	}
	egress := html[strings.Index(html, `id="sub-egress"`):]
	if i := strings.Index(egress, `id="policyHistory"`); i < 0 || i > strings.Index(egress, `id="sub-dlp"`) {
		t.Error("the History panel must sit in the policy (Egress) tab")
	}
	show := funcBody(t, region, "function showPolicyHistory(")
	if !strings.Contains(show, "pol.version") || !strings.Contains(show, "card.style.display=v>0?'':'none'") {
		t.Error("showPolicyHistory must show the panel only when the policy GET has a version")
	}
	if !strings.Contains(funcBody(t, html, "async function loadGuardrails("), "showPolicyHistory(pol)") {
		t.Error("loadGuardrails must hand the policy GET to showPolicyHistory")
	}

	if !strings.Contains(region, "const PH_VERSIONS='/dashboard/api/policy/versions'") {
		t.Error("the panel must fetch /dashboard/api/policy/versions")
	}
	list := funcBody(t, region, "async function loadPolicyHistory(")
	for _, want := range []string{"jget(PH_VERSIONS+", "reset?0:ph.next", "'&cursor='+cursor", "d.next_cursor", "'ph-more'"} {
		if !strings.Contains(list, want) {
			t.Errorf("loadPolicyHistory: %q missing (list through jget with the cursor and load more)", want)
		}
	}
	row := funcBody(t, region, "function phRow(")
	for _, want := range []string{"'v'+x.version", "x.author_email||x.author_sub", "relTime(x.created_at)", "x.message"} {
		if !strings.Contains(row, want) {
			t.Errorf("phRow: %q missing (version, author, relative time, message)", want)
		}
	}
	if !regexp.MustCompile(`<button[^>]*data-min-role="viewer"[^>]*id="ph-more"`).MatchString(html) {
		t.Error("the load more button must be in the panel")
	}

	diff := funcBody(t, region, "async function showPolicyDiff(")
	if !strings.Contains(diff, "jget(PH_VERSIONS+'/'+encodeURIComponent(v)+'/diff')") {
		t.Error("selecting a version must fetch its /diff")
	}
	for _, want := range []string{"d.diff.allow", "d.diff.deny", "d.diff.settings"} {
		if !strings.Contains(diff, want) {
			t.Errorf("showPolicyDiff must render %s", want)
		}
	}
	changes := funcBody(t, region, "function phChangeList(")
	for _, want := range []string{"c.kind", "c.before", "c.after"} {
		if !strings.Contains(changes, want) {
			t.Errorf("phChangeList must render %s (added, removed, changed with old and new)", want)
		}
	}

	rb := funcBody(t, region, "async function rollbackTo(")
	if !regexp.MustCompile(`api\('POST',PH_VERSIONS\+'/'\+encodeURIComponent\(v\)\+'/rollback',[^;]*\{'If-Match':'"v'\+head\+'"'\}\)`).MatchString(rb) {
		t.Error("rollbackTo must POST .../rollback through api() with If-Match set to the head")
	}
	_, apiStart, apiEnd := apiRegion(t, html)
	apiBody := funcBody(t, html[apiStart:apiEnd], "async function api(method,url,body,hdrs){")
	if !strings.Contains(apiBody, "new Headers(hdrs||{})") || !strings.Contains(apiBody, "h.set('X-Warden-CSRF',csrfToken)") {
		t.Error("api() must keep the caller's headers (If-Match) and add X-Warden-CSRF")
	}
	if c, d := strings.Index(rb, "askPolicyDialog('Roll back to v'+v"), strings.Index(rb, "api('POST'"); c < 0 || c > d || !strings.Contains(rb, "if(note===null) return;") {
		t.Error("rollbackTo must confirm in a dialog naming the target version before it POSTs")
	}
	if !strings.Contains(rb, "if(!roleAllows('editor')) return;") {
		t.Error("rollbackTo must refuse below editor")
	}
	if !strings.Contains(row, "setAttribute('data-min-role','editor')") || !strings.Contains(row, "disabled=!roleAllows('editor')") {
		t.Error("the rollback button must be gated on editor (hidden by role and disabled from /auth/me)")
	}

	pw := funcBody(t, region, "async function policyWrite(")
	for _, want := range []string{
		`hdrs['If-Match']='"v'+policyHead+'"'`,
		"hdrs['X-Warden-Policy-Message']=encodeURIComponent(msg)",
		"api(method,url,body,hdrs)",
		"r.status===409",
		"policyHead=e.head",
	} {
		if !strings.Contains(pw, want) {
			t.Errorf("policyWrite: %q missing", want)
		}
	}
	if !strings.Contains(funcBody(t, region, "function conflictError("), "'policy changed by '+(a.email||a.sub") {
		t.Error("a 409 must say 'policy changed by <author> (v<N>)'")
	}
	if !strings.Contains(html, `id="pmd-input" maxlength="512"`) {
		t.Error("the save message input must be capped at 512 characters")
	}
	if !strings.Contains(funcBody(t, html, "async function jget("), "notePolicyHead(r)") {
		t.Error("jget must note the head from the policy, settings and llmProviders GETs")
	}
	// Every policy, settings and llmProviders write goes through policyWrite.
	if m := regexp.MustCompile(`api\('(POST|PUT)','/dashboard/api/(policy|settings|llmproviders)'`).FindString(html); m != "" {
		t.Errorf("a save bypasses policyWrite: %s", m)
	}
	for _, path := range []string{"/dashboard/api/policy", "/dashboard/api/settings", "/dashboard/api/llmproviders"} {
		if !regexp.MustCompile(`policyWrite\('(POST|PUT)','` + regexp.QuoteMeta(path) + `'`).MatchString(html) {
			t.Errorf("no save of %s goes through policyWrite", path)
		}
	}
	// A conflicted policy edit is kept, not reloaded away.
	sp := funcBody(t, html, "async function savePolicy(")
	if c, l := strings.Index(sp, "if(err.conflict)"), strings.Index(sp, "loadGuardrails()"); c < 0 || l < c {
		t.Error("savePolicy must keep the user's edit on a 409 (no reload before the conflict branch)")
	}
}

// TestPolicyHistoryPanelNoInnerHTML: author and message come from whoever
// saved a version, so the history block renders every value with textContent
// and never touches innerHTML (or any other HTML sink). Each read of an
// author or message field is a textContent assignment.
func TestPolicyHistoryPanelNoInnerHTML(t *testing.T) {
	_, region := historyRegion(t)
	for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "createContextualFragment"} {
		if strings.Contains(region, sink) {
			t.Errorf("the policy history block uses %s: render with textContent", sink)
		}
	}
	fields := regexp.MustCompile(`\.(author_email|author_sub|message)\b|\b(a\.email|a\.sub)\b`)
	n := 0
	for _, line := range strings.Split(region, "\n") {
		if !fields.MatchString(line) {
			continue
		}
		n++
		if !strings.Contains(line, ".textContent=") && !strings.Contains(line, "new Error(") {
			t.Errorf("author or message used outside a textContent assignment: %s", strings.TrimSpace(line))
		}
	}
	if n == 0 {
		t.Error("no author or message rendering found in the policy history block")
	}
}
