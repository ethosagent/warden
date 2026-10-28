package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// W-P1-GPOL-08: the policy views mark scoped entries and tools, carry the
// shadow lint, and the editor round-trips groups/users without letting a chip
// value reach the page as markup.

func scopedPolicy() config.Policy {
	return config.Policy{Allowlist: []config.AllowlistEntry{
		{Domain: "*.github.com"},
		{Domain: "api.github.com", Groups: []string{"eng"}},
		{Domain: "plain.example.com"},
		{Domain: "mail.example.com", Users: []string{"alice@corp.example"}},
	}}
}

func scopedSettings() *config.SettingsWire {
	return &config.SettingsWire{MCP: &config.MCPSettings{Enabled: true, Tools: &config.MCPToolsSettings{
		Allow: []string{"deploy", "read"},
		Constraints: map[string]config.MCPToolConstraints{
			"deploy": {AllowWhen: &config.MCPToolCondition{Groups: []string{"sre"}}},
			"read":   {AllowWhen: &config.MCPToolCondition{AgentID: "ci"}},
		},
	}}}
}

func scopedServer(editable bool) *Server {
	srv := NewServer(&fakeDataSource{}, scopedPolicy(), &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetLiveSettings(scopedSettings)
	if editable {
		srv.SetPolicyWriter(func(context.Context, config.Policy, WriteMeta) error { return nil })
	}
	return srv
}

func TestPolicyGET_ScopedAndLint(t *testing.T) {
	h := scopedServer(true).Handler()
	var p struct {
		Allowlist []map[string]any `json:"allowlist"`
		Lint      []string         `json:"lint"`
	}
	doGetJSON(t, h, "/dashboard/api/policy", &p)
	want := []bool{false, true, false, true}
	for i, e := range p.Allowlist {
		got, _ := e["scoped"].(bool)
		if got != want[i] {
			t.Errorf("allowlist[%d] scoped = %v, want %v (%v)", i, got, want[i], e)
		}
	}
	if len(p.Lint) != 1 || !strings.Contains(p.Lint[0], "api.github.com") {
		t.Errorf("lint = %v, want one warning naming the shadowed api.github.com entry", p.Lint)
	}
	if p.Lint == nil {
		t.Error("lint must be a (possibly empty) array")
	}

	var s struct {
		Settings struct {
			MCP struct {
				Tools struct {
					Allow       []string
					Constraints map[string]struct {
						Scoped    bool
						AllowWhen *config.MCPToolCondition
					}
				}
			}
		}
	}
	doGetJSON(t, h, "/dashboard/api/settings", &s)
	c := s.Settings.MCP.Tools.Constraints
	if !c["deploy"].Scoped || c["read"].Scoped {
		t.Errorf("tool scoped flags = deploy %v read %v, want true false", c["deploy"].Scoped, c["read"].Scoped)
	}
	if c["deploy"].AllowWhen == nil || c["deploy"].AllowWhen.Groups[0] != "sre" || len(s.Settings.MCP.Tools.Allow) != 2 {
		t.Errorf("settings body lost the condition: %+v", s.Settings.MCP.Tools)
	}
}

func TestPolicyGET_UnscopedHasNoLintOrBadge(t *testing.T) {
	h := newTestServer(&fakeDataSource{}, config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "a.example.com"}}}, &fakeSecretProvider{values: map[string]string{}})
	body := getRaw(t, h, "/dashboard/api/policy")
	if strings.Contains(body, `"scoped"`) || !strings.Contains(body, `"lint":[]`) {
		t.Errorf("unscoped body = %s", body)
	}
}

func TestPolicyGET_EscapesMarkup(t *testing.T) {
	const evil = "<script>alert(1)</script>"
	srv := NewServer(&fakeDataSource{}, config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "a.example.com", Groups: []string{evil}}}}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetLiveSettings(func() *config.SettingsWire {
		return &config.SettingsWire{MCP: &config.MCPSettings{Enabled: true, Tools: &config.MCPToolsSettings{
			Allow:       []string{"t"},
			Constraints: map[string]config.MCPToolConstraints{"t": {AllowWhen: &config.MCPToolCondition{Users: []string{evil}}}},
		}}}
	})
	for _, path := range []string{"/dashboard/api/policy", "/dashboard/api/settings"} {
		body := getRaw(t, srv.Handler(), path)
		if strings.Contains(body, "<script>") {
			t.Errorf("%s contains a literal <script>: %s", path, body)
		}
		if !strings.Contains(body, `\u003cscript\u003e`) {
			t.Errorf("%s did not carry the value back escaped: %s", path, body)
		}
	}
}

// TestIndexChipsAreEscaped: the chip renderers build their markup only from
// esc()-ed values, and no chip value is assigned to innerHTML raw.
func TestIndexChipsAreEscaped(t *testing.T) {
	html := string(indexHTML)
	for _, fn := range []string{"function chipsHTML(", "function scopedBadge(", "function renderPolicyLint("} {
		i := strings.Index(html, fn)
		if i < 0 {
			t.Fatalf("index.html has no %s", fn)
		}
		body := html[i:]
		if j := strings.Index(body[1:], "\nfunction "); j > 0 {
			body = body[:j+1]
		}
		if fn != "function scopedBadge(" && !strings.Contains(body, "esc(") {
			t.Errorf("%s does not escape through esc(", fn)
		}
		if regexp.MustCompile(`innerHTML\s*=\s*[a-zA-Z_]*(group|user|chip|val)[a-zA-Z_]*\s*[;\n]`).MatchString(body) {
			t.Errorf("%s assigns a raw value to innerHTML", fn)
		}
	}
	// Inside the chip renderer a value is only ever concatenated as esc(...).
	chips := html[strings.Index(html, "function chipsHTML("):]
	chips = chips[:strings.Index(chips, "\n}\n")]
	if regexp.MustCompile(`\+\s*(v|values|value)\s*[+)]`).MatchString(chips) {
		t.Error("a chip value is concatenated into HTML without esc()")
	}
}

func TestWorkerDashboardScopedReadOnly(t *testing.T) {
	srv := scopedServer(false) // no writer: a worker
	h := srv.Handler()
	rec := postJSON(t, h, "/dashboard/api/policy", `{"allowlist":[{"domain":"x.com","groups":["eng"]}]}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("worker policy write = %d, want 405", rec.Code)
	}
	var p struct {
		Editable  bool             `json:"editable"`
		Allowlist []map[string]any `json:"allowlist"`
		Lint      []string         `json:"lint"`
	}
	doGetJSON(t, h, "/dashboard/api/policy", &p)
	if p.Editable {
		t.Error("worker policy view is editable")
	}
	if s, _ := p.Allowlist[1]["scoped"].(bool); !s || len(p.Lint) != 1 {
		t.Errorf("worker view lost the badge or lint: %v lint=%v", p.Allowlist[1], p.Lint)
	}
	if !strings.Contains(string(indexHTML), "scopedBadge(") {
		t.Error("index.html does not render the scoped badge")
	}
}

// TestPolicyEdit_ScopedInvalid: a writer error for an empty group is a 400
// naming the validation error, and the served view is unchanged.
func TestPolicyEdit_ScopedInvalid(t *testing.T) {
	cur := scopedPolicy()
	srv := NewServer(&fakeDataSource{}, cur, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetPolicyWriter(func(_ context.Context, p config.Policy, _ WriteMeta) error {
		for _, e := range p.Allowlist {
			for _, g := range e.Groups {
				if strings.TrimSpace(g) == "" {
					return &InvalidPolicyError{Err: errors.New("config: policy.allowlist[1].groups[0]: value must not be empty")}
				}
			}
		}
		cur = p
		return nil
	})
	srv.SetLivePolicy(func() config.Policy { return cur })
	h := srv.Handler()
	before := getRaw(t, h, "/dashboard/api/policy")

	rec := postJSON(t, h, "/dashboard/api/policy", `{"allowlist":[{"domain":"a.example.com","groups":[" "]}]}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "must not be empty") {
		t.Fatalf("empty group = %d %s, want 400 with the validation error", rec.Code, rec.Body.String())
	}
	if after := getRaw(t, h, "/dashboard/api/policy"); after != before {
		t.Errorf("served policy changed after a rejected edit:\n%s\n%s", before, after)
	}

	// A valid scoped edit passes groups/users to the writer unchanged.
	rec = postJSON(t, h, "/dashboard/api/policy", `{"allowlist":[{"domain":"a.example.com","groups":["eng"],"users":["Bob@x.example"]}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid scoped edit = %d %s", rec.Code, rec.Body.String())
	}
	var got struct{ Allowlist []config.AllowlistEntry }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Allowlist[0].Users[0] != "Bob@x.example" || got.Allowlist[0].Groups[0] != "eng" {
		t.Errorf("echo = %s (%v)", rec.Body.String(), err)
	}
}
