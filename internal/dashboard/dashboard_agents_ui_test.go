package dashboard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// agentsBlock returns the Agents tab's script (agents:begin .. agents:end).
func agentsBlock(t *testing.T, html string) string {
	t.Helper()
	a, b := strings.Index(html, "/* agents:begin */"), strings.Index(html, "/* agents:end */")
	if a < 0 || b < a {
		t.Fatal("index.html has no agents:begin/agents:end script block")
	}
	return html[a:b]
}

// TestSetupAgentRegistry: agentRegistry is true only when the registry seam is
// set and can serve (a state dir). A worker dashboard (no seam) and a control
// plane without a state dir report false, and the key is always present.
func TestSetupAgentRegistry(t *testing.T) {
	for _, c := range []struct {
		name string
		reg  AgentRegistry
		want bool
	}{
		{"no seam (worker dashboard)", nil, false},
		{"seam without a state dir", &fakeAgents{ready: ErrAgentStateRequired}, false},
		{"seam ready", &fakeAgents{}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
			if c.reg != nil {
				srv.SetAgentRegistry(c.reg)
			}
			rr := doGet(t, srv.Handler(), "/dashboard/api/setup")
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(raw["agentRegistry"]) != map[bool]string{true: "true", false: "false"}[c.want] {
				t.Errorf("agentRegistry = %s, want %v (body %s)", raw["agentRegistry"], c.want, rr.Body.String())
			}
			if got := getSetup(t, srv).AgentRegistry; got != c.want {
				t.Errorf("setupResponse.AgentRegistry = %v, want %v", got, c.want)
			}
		})
	}
}

// TestIndexAgentsTab pins the Agents tab: the nav item is hidden until setup
// says agentRegistry, the page and form exist, every write control is admin
// only, writes go through api() with If-Match, a private JWK is refused
// client-side, and no coordinate or user-supplied value is rendered as markup.
func TestIndexAgentsTab(t *testing.T) {
	html := servedIndex(t)
	for _, want := range []string{
		`id="agentsNav" style="display:none"`,
		`id="page-agents"`,
		`id="ag-list"`,
		`id="ag-form"`,
		`an.style.display=s.agentRegistry===true?'':'none'`,
		`case 'agents':      loadAgents(); break;`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	for _, marker := range []string{`id="ag-new"`, `id="ag-save"`, `id="ag-reload"`, `id="ag-form"`} {
		i := strings.Index(html, marker)
		if i < 0 {
			t.Fatalf("no %s", marker)
		}
		if tag := tagAt(html, i); !strings.Contains(tag, `data-min-role="admin"`) {
			t.Errorf("%s must be admin only: %.160s", marker, tag)
		}
	}
	js := agentsBlock(t, html)
	for _, want := range []string{
		`api('GET','/dashboard/api/agents')`,
		`api('PUT','/dashboard/api/agents/'`,
		`api('POST','/dashboard/api/agents'`,
		`'If-Match':'"r'+e.revision+'"'`,
		`'If-Match':'"r'+a.revision+'"'`,
		`const AG_PRIVATE_MEMBERS=['d',`,
		`ag.canWrite=authMode==='oidc'&&roleAllows('admin')`,
		`window.confirm(`,
		`agent_conflict`,
		`String(k.jkt||'').slice(0,8)`,
		`workers.filter(w=>w.agentID===a.id&&w.online)`,
		`if(w.online&&w.agentID&&!known[w.agentID])`,
		`if(!ag.settings) return 'unknown'`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("agents script lacks %q", want)
		}
	}
	// Values from the server or the operator are text, never markup, and a key's
	// coordinates are never rendered (the stored key is only re-sent).
	for _, bad := range []string{"innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "fetch(", ".jwk.x", ".jwk.y", ".x)", "jwk.x"} {
		if strings.Contains(js, bad) {
			t.Errorf("agents script uses %q", bad)
		}
	}
	if !strings.Contains(js, "e.textContent=String(text)") {
		t.Error("agEl must set text with textContent")
	}
}
