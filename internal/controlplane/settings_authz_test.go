package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

func TestSettingsFieldsChanged(t *testing.T) {
	const base = `{"dlp":{"mode":"monitor"},"llmProviders":[{"name":"p1","baseURL":"https://api.openai.com/v1"}],` +
		`"secrets":{"backend":"echo"},"explore":{"llmProvider":"p1"},"identity":{"issuer":"https://idp.example"},` +
		`"agents":[{"id":"a","policy":"be careful","identity":"attribute"},{"id":"b","policy":"read only"}]}`
	cases := []struct {
		name     string
		live, in string
		want     []string
	}{
		{"unchanged", base, base, nil},
		{"unchanged, other key order and spacing", `{"dlp":{"mode":"monitor"},"logging":{"level":"info","format":"json"}}`,
			`{ "logging": {"format":"json", "level":"info"}, "dlp": {"mode": "monitor"} }`, nil},
		{"only dlp", base, strings.Replace(base, `"mode":"monitor"`, `"mode":"enforce"`, 1), []string{"dlp"}},
		{"llmProviders baseURL", base, strings.Replace(base, "https://api.openai.com/v1", "https://evil.example/v1", 1), []string{"llmProviders"}},
		{"secrets backend", base, strings.Replace(base, `"backend":"echo"`, `"backend":"aws"`, 1), []string{"secrets"}},
		{"explore", base, strings.Replace(base, `"explore":{"llmProvider":"p1"}`, `"explore":{"llmProvider":"p2"}`, 1), []string{"explore"}},
		{"identity block", base, strings.Replace(base, "https://idp.example", "https://other.example", 1), []string{"identity"}},
		{"identity block removed", base, strings.Replace(base, `"identity":{"issuer":"https://idp.example"},`, "", 1), []string{"identity"}},
		{"new unknown top-level field", base, strings.Replace(base, "{", `{"futureBlock":{"x":1},`, 1), []string{"futureBlock"}},
		{"agents[].policy", base, strings.Replace(base, "be careful", "be very careful", 1), []string{"agents[0].policy"}},
		{"agents[].identity", base, strings.Replace(base, `"identity":"attribute"`, `"identity":"off"`, 1), []string{"agents[0].identity"}},
		{"agents[].identity added", base, strings.Replace(base, `"policy":"read only"`, `"policy":"read only","identity":"off"`, 1), []string{"agents[1].identity"}},
		{"agents reordered", base,
			strings.Replace(base, `{"id":"a","policy":"be careful","identity":"attribute"},{"id":"b","policy":"read only"}`,
				`{"id":"b","policy":"read only"},{"id":"a","policy":"be careful","identity":"attribute"}`, 1), nil},
		{"agent ids swapped carry identity", base,
			strings.Replace(base, `{"id":"a","policy":"be careful","identity":"attribute"},{"id":"b","policy":"read only"}`,
				`{"id":"b","policy":"be careful","identity":"attribute"},{"id":"a","policy":"read only"}`, 1),
			[]string{"agents[0].identity", "agents[0].policy", "agents[1].identity", "agents[1].policy"}},
		{"agent with identity removed", base, strings.Replace(base, `{"id":"a","policy":"be careful","identity":"attribute"},`, "", 1),
			[]string{"agents[0].id", "agents[0].identity", "agents[0].policy"}},
		{"agent without identity added", base, strings.Replace(base, `{"id":"b","policy":"read only"}`, `{"id":"b","policy":"read only"},{"id":"c"}`, 1),
			[]string{"agents[2].id"}},
		{"duplicate id reorders identity", `{"agents":[{"id":"a","identity":"off"},{"id":"a","identity":"attribute"}]}`,
			`{"agents":[{"id":"a","identity":"attribute"},{"id":"a","identity":"off"}]}`, []string{"agents[0].identity"}},
		{"no live settings", "null", `{"dlp":{"mode":"monitor"}}`, []string{"dlp"}},
		{"everything removed", base, `{}`, []string{"agents[0].id", "agents[0].identity", "agents[0].policy", "agents[1].id", "agents[1].policy",
			"dlp", "explore", "identity", "llmProviders", "secrets"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := settingsFieldsChanged([]byte(c.live), []byte(c.in))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("settingsFieldsChanged = %v, want %v", got, c.want)
			}
		})
	}

	for _, bad := range []struct{ live, in string }{
		{`{"agents":{"id":"a"}}`, `{}`},
		{`{}`, `{"agents":[1]}`},
		{`[]`, `{}`},
		{`{}`, `not json`},
	} {
		if _, err := settingsFieldsChanged([]byte(bad.live), []byte(bad.in)); err == nil {
			t.Errorf("settingsFieldsChanged(%s, %s) = nil error, want one", bad.live, bad.in)
		}
	}
}

// TestSettingsFieldsChangedNormalized: a document the dashboard read and posts
// back unchanged reports no change, even where the wire form differs from the
// live one in a way WriteSettings treats as equal.
func TestSettingsFieldsChangedNormalized(t *testing.T) {
	ttl := 60
	live := &config.SettingsWire{
		Secrets:    &config.SecretsSettings{Backend: "aws", Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "s3cr3t-value"},
		Logging:    &config.LoggingSettings{Level: "info", Format: "json"},
		Compliance: &config.ToggleSetting{Enabled: true},
	}
	cases := []struct {
		name string
		in   config.SettingsWire
		want []string
	}{
		{"masked secret omitted keeps it", config.SettingsWire{
			Secrets: &config.SecretsSettings{Backend: "aws", Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE"},
		}, nil},
		{"disabled blocks equal absent ones", config.SettingsWire{
			Secrets:       &config.SecretsSettings{Backend: "aws", Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE"},
			MCP:           &config.MCPSettings{Enabled: false, Mode: "enforce"},
			Judge:         &config.JudgeSettings{Enabled: false, Model: "m"},
			Observability: &config.ObservabilitySettings{Enabled: false},
			Explore:       &config.ExploreSettings{},
		}, nil},
		{"new secret value is a change", config.SettingsWire{
			Secrets: &config.SecretsSettings{Backend: "aws", Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "other"},
		}, []string{"secrets"}},
		{"new access key id is a change", config.SettingsWire{
			Secrets: &config.SecretsSettings{Backend: "aws", Region: "us-east-1", AccessKeyID: "AKIDOTHER"},
		}, []string{"secrets"}},
		{"env backend removes the selector", config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "env"}}, []string{"secrets"}},
		{"enabling a disabled block is a change", config.SettingsWire{
			Secrets: &config.SecretsSettings{Backend: "aws", Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE"},
			MCP:     &config.MCPSettings{Enabled: true, Mode: "monitor"},
		}, []string{"mcp"}},
		{"cache ttl set", config.SettingsWire{
			Secrets:         &config.SecretsSettings{Backend: "aws", Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE"},
			CacheTTLSeconds: &ttl,
		}, []string{"cacheTTLSeconds"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := settingsWireFieldsChanged(live, c.in)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("settingsWireFieldsChanged = %v, want %v", got, c.want)
			}
		})
	}
	// An env selector on both sides is no change; a nil live document is handled.
	if got, err := settingsWireFieldsChanged(nil, config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "env"}}); err != nil || got != nil {
		t.Fatalf("env selector vs no settings = %v, %v, want no change", got, err)
	}
}

// writePolicyFileForFieldAuthz writes a served config whose settings hold an
// admin-only value in every block the per-field check guards.
func writePolicyFileForFieldAuthz(t *testing.T) string {
	t.Helper()
	path := writePolicyFile(t, "api.openai.com")
	body := readFile(t, path) +
		"llmProviders:\n  - name: p1\n    baseURL: https://api.openai.com/v1\n    model: gpt-4o-mini\n    apiKeyEnv: OPENAI_API_KEY\n" +
		"secretStore:\n  backend: echo\n" +
		"identity:\n  defaultMode: \"off\"\n  issuer: https://idp.example\n  audience: warden\n" +
		"agents:\n  - id: agent-a\n    policy: be careful\n    identity: attribute\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// liveSettingsDoc reads GET /dashboard/api/settings as rawID and returns the
// settings document, the way the UI does before a read-modify-write.
func (e *authzEnv) liveSettingsDoc(t *testing.T, rawID string) map[string]any {
	t.Helper()
	rec := e.do(rawID, http.MethodGet, "/dashboard/api/settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET settings = %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Settings
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAuthzSettingsPerField(t *testing.T) {
	e := newAuthzEnvOn(t, openSessionDB(t), writePolicyFileForFieldAuthz(t), defaultRoles())
	editor := e.session(t, groupEditor)
	admin := e.session(t, groupAdmin)

	type edit func(doc map[string]any)
	agent0 := func(doc map[string]any) map[string]any { return doc["agents"].([]any)[0].(map[string]any) }
	denied := []struct {
		name  string
		edit  edit
		field string
	}{
		{"llmProviders[0].baseURL", func(d map[string]any) {
			d["llmProviders"].([]any)[0].(map[string]any)["baseURL"] = "https://evil.example/v1"
		}, "llmProviders"},
		{"secrets backend", func(d map[string]any) { d["secrets"] = map[string]any{"backend": "aws", "region": "us-east-1"} }, "secrets"},
		{"agents[0].identity", func(d map[string]any) { agent0(d)["identity"] = "off" }, "agents[0].identity"},
	}
	for _, c := range denied {
		doc := e.liveSettingsDoc(t, editor)
		c.edit(doc)
		rec := e.do(editor, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc))
		var body struct {
			Error  string   `json:"error"`
			Need   string   `json:"need"`
			Fields []string `json:"fields"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusForbidden || body.Error != "role_required" || body.Need != "admin" || !slices.Equal(body.Fields, []string{c.field}) {
			t.Errorf("editor changes %s = %d %s, want 403 role_required need admin fields [%s]", c.name, rec.Code, rec.Body.String(), c.field)
		}
	}
	// Nothing was written by the refused edits.
	if got := readFile(t, e.policy); !strings.Contains(got, "identity: attribute") || strings.Contains(got, "evil.example/v1") {
		t.Fatalf("a refused edit reached the config file:\n%s", got)
	}
	if !strings.Contains(e.log.String(), "console_settings_field_denied") {
		t.Errorf("per-field denial not logged:\n%s", e.log.String())
	}

	allowed := []struct {
		name string
		edit edit
		want string // a fragment the config file holds afterwards
	}{
		{"only dlp", func(d map[string]any) { d["dlp"] = map[string]any{"mode": "monitor"} }, "identity: attribute"},
		{"agents[0].policy", func(d map[string]any) { agent0(d)["policy"] = "be very careful" }, "be very careful"},
		{"unchanged round trip", func(map[string]any) {}, "be very careful"},
	}
	for _, c := range allowed {
		doc := e.liveSettingsDoc(t, editor)
		c.edit(doc)
		rec := e.do(editor, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc))
		if rec.Code/100 != 2 {
			t.Errorf("editor changes %s = %d %s, want 2xx", c.name, rec.Code, rec.Body.String())
		}
		if got := readFile(t, e.policy); !strings.Contains(got, c.want) {
			t.Errorf("after editor changes %s the config lacks %q:\n%s", c.name, c.want, got)
		}
	}

	// An admin can change all of them in one write.
	doc := e.liveSettingsDoc(t, admin)
	for _, c := range denied {
		c.edit(doc)
	}
	if rec := e.do(admin, http.MethodPost, "/dashboard/api/settings", mustJSON(t, doc)); rec.Code/100 != 2 {
		t.Fatalf("admin changes everything = %d %s, want 2xx", rec.Code, rec.Body.String())
	}
	got := readFile(t, e.policy)
	for _, want := range []string{"identity: \"off\"", "backend: aws"} {
		if !strings.Contains(got, want) {
			t.Errorf("admin write: config lacks %q:\n%s", want, got)
		}
	}
	// A viewer is refused at the route, before any field check.
	rec := e.do(e.session(t, groupViewer), http.MethodPost, "/dashboard/api/settings", `{}`)
	if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != `{"error":"role_required","need":"editor"}` {
		t.Errorf("viewer POST settings = %d %s, want 403 need editor", rec.Code, rec.Body.String())
	}
}

// TestSettingsWriterFailsClosed: in oidc mode a settings write with no
// Principal, or with a Principal whose groups map to no role, is refused even
// if it changes nothing. None mode applies the write as before.
func TestSettingsWriterFailsClosed(t *testing.T) {
	e := newAuthzEnv(t)
	var re *dashboard.RoleRequiredError
	if err := e.srv.writeSettingsAs(context.Background(), config.SettingsWire{}); !errors.As(err, &re) || re.Need != "editor" {
		t.Fatalf("no Principal = %v, want RoleRequiredError need editor", err)
	}
	ctx := WithPrincipal(context.Background(), Principal{Kind: PrincipalSession, Sub: "u1", Groups: []string{groupViewer}})
	if err := e.srv.writeSettingsAs(ctx, config.SettingsWire{}); !errors.As(err, &re) || re.Need != "editor" {
		t.Fatalf("viewer Principal = %v, want RoleRequiredError need editor", err)
	}
	if !strings.Contains(re.Error(), "editor") {
		t.Errorf("RoleRequiredError text %q does not name the role", re.Error())
	}

	path := writePolicyFile(t, "api.openai.com")
	none := New(Config{PolicyPath: path})
	in := config.SettingsWire{Agents: []config.AgentSettings{{ID: "agent-x", Identity: "off"}}}
	if err := none.writeSettingsAs(context.Background(), in); err != nil {
		t.Fatalf("none mode write = %v, want it applied", err)
	}
	if got := readFile(t, path); !strings.Contains(got, "agent-x") {
		t.Fatalf("none mode write did not reach the config:\n%s", got)
	}
}

func TestAuthzQueryGenerateEditor(t *testing.T) {
	e := newAuthzEnv(t)
	e.srv.dash.SetQueryEngine(fakeQuery{})
	e.srv.dash.SetSQLGenerator(sqlGenFunc(func(string) (string, error) { return "SELECT 1", nil }))
	const path, body = "/dashboard/api/query/generate", `{"question":"count events"}`

	rec := e.do(e.session(t, groupViewer), http.MethodPost, path, body)
	if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != `{"error":"role_required","need":"editor"}` {
		t.Fatalf("viewer generate = %d %s, want 403 need editor", rec.Code, rec.Body.String())
	}

	first := e.session(t, groupEditor)
	for i := 1; i <= queryGenerateLimit; i++ {
		if rec := e.do(first, http.MethodPost, path, body); rec.Code != http.StatusOK {
			t.Fatalf("editor generate call %d = %d %s, want 200", i, rec.Code, rec.Body.String())
		}
	}
	rec = e.do(first, http.MethodPost, path, body)
	if rec.Code != http.StatusTooManyRequests || strings.TrimSpace(rec.Body.String()) != `{"error":"rate_limited"}` || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("11th generate in a minute = %d %s (Retry-After %q), want 429 rate_limited", rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"))
	}
	if !strings.Contains(e.log.String(), "console_rate_limited") {
		t.Errorf("rate limit not logged:\n%s", e.log.String())
	}

	// A second session has its own bucket.
	second := e.session(t, groupEditor)
	if rec := e.do(second, http.MethodPost, path, body); rec.Code != http.StatusOK {
		t.Fatalf("second session generate = %d %s, want 200", rec.Code, rec.Body.String())
	}
	// Other routes are not limited for the exhausted session.
	if rec := e.do(first, http.MethodPost, "/dashboard/api/policy", policyBody); rec.Code != http.StatusOK {
		t.Fatalf("exhausted session POST policy = %d, want 200", rec.Code)
	}

	// Five seconds later the bucket holds less than one token; a new minute
	// refills all ten.
	e.clk.Advance(5 * time.Second)
	if rec := e.do(first, http.MethodPost, path, body); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("generate 5s later = %d, want 429", rec.Code)
	}
	e.clk.Advance(55 * time.Second)
	for i := 1; i <= queryGenerateLimit; i++ {
		if rec := e.do(first, http.MethodPost, path, body); rec.Code != http.StatusOK {
			t.Fatalf("generate call %d in the new minute = %d %s, want 200", i, rec.Code, rec.Body.String())
		}
	}
	if rec := e.do(first, http.MethodPost, path, body); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("11th generate in the new minute = %d, want 429", rec.Code)
	}
}
