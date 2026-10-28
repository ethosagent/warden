package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const scopedBody = `{
  "allowlist": [{"domain": "a.example.com"}, {"domain": "c.example.com"}],
  "scopedAllowlist": [
    {"domain": "b.example.com", "groups": ["eng", "Eng"]},
    {"domain": "d.example.com", "users": ["Bob@Example.com"]}
  ],
  "scopedAllowPos": [1, 3]
}`

func domains(p *Policy) []string {
	var out []string
	for _, e := range p.Allowlist {
		out = append(out, e.Domain)
	}
	return out
}

func TestParseRemotePolicy_Scoped(t *testing.T) {
	p, _, err := parseRemotePolicy([]byte(scopedBody))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := strings.Join(domains(p), ","), "a.example.com,b.example.com,c.example.com,d.example.com"; got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
	if g := p.Allowlist[1].Groups; len(g) != 2 || g[0] != "Eng" || g[1] != "eng" {
		t.Errorf("groups = %v, want normalized [Eng eng]", g)
	}
	if u := p.Allowlist[3].Users; len(u) != 1 || u[0] != "bob@example.com" {
		t.Errorf("users = %v, want [bob@example.com]", u)
	}
}

func TestParseRemotePolicy_ScopedAppendsWithoutPositions(t *testing.T) {
	body := `{"allowlist":[{"domain":"a.example.com"}],"scopedAllowlist":[{"domain":"b.example.com","groups":["eng"]}]}`
	p, _, err := parseRemotePolicy([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := strings.Join(domains(p), ","); got != "a.example.com,b.example.com" {
		t.Fatalf("order = %s", got)
	}
}

func TestParseRemotePolicy_ScopedOnly(t *testing.T) {
	body := `{"allowlist":[],"scopedAllowlist":[{"domain":"b.example.com","groups":["eng"]}],"scopedAllowPos":[0]}`
	p, _, err := parseRemotePolicy([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.Allowlist) != 1 || len(p.Allowlist[0].Groups) != 1 {
		t.Fatalf("allowlist = %+v", p.Allowlist)
	}
}

func TestParseRemotePolicy_ScopedRejects(t *testing.T) {
	cases := map[string]string{
		"entry without principals": `{"allowlist":[{"domain":"a.example.com"}],"scopedAllowlist":[{"domain":"b.example.com"}]}`,
		"positions length":         `{"allowlist":[{"domain":"a.example.com"}],"scopedAllowlist":[{"domain":"b.example.com","groups":["g"]}],"scopedAllowPos":[0,1]}`,
		"positions out of range":   `{"allowlist":[{"domain":"a.example.com"}],"scopedAllowlist":[{"domain":"b.example.com","groups":["g"]}],"scopedAllowPos":[5]}`,
		"positions descending":     `{"allowlist":[{"domain":"a.example.com"}],"scopedAllowlist":[{"domain":"b.example.com","groups":["g"]},{"domain":"c.example.com","groups":["g"]}],"scopedAllowPos":[2,1]}`,
		"positions without list":   `{"allowlist":[{"domain":"a.example.com"}],"scopedAllowPos":[0]}`,
		"empty group":              `{"allowlist":[{"domain":"a.example.com"}],"scopedAllowlist":[{"domain":"b.example.com","groups":[" "]}]}`,
		"scoped in plain list":     `{"allowlist":[{"domain":"a.example.com","groups":["g"]}]}`,
		"bad scoped domain":        `{"allowlist":[{"domain":"a.example.com"}],"scopedAllowlist":[{"domain":"b *.com","groups":["g"]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRemotePolicy([]byte(body)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func scopedMCPBody(tool string) string {
	return `{"allowlist":[{"domain":"a.example.com"}],"settings":{"mcp":{"enabled":true,"tools":{"allow":["deploy"],"constraints":{"deploy":` + tool + `}}}}}`
}

func TestParseRemotePolicy_ScopedMCP(t *testing.T) {
	body := scopedMCPBody(`{"AllowWhen":{"AgentID":"!identity-scoped"},"AllowWhenScoped":{"TimeWindow":"09-17","Groups":["eng"]}}`)
	_, s, err := parseRemotePolicy([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tc := s.MCP.Tools.Constraints["deploy"]
	if tc.AllowWhenScoped != nil {
		t.Error("AllowWhenScoped must be cleared after the merge")
	}
	if tc.AllowWhen == nil || tc.AllowWhen.AgentID != "" || tc.AllowWhen.TimeWindow != "09-17" || len(tc.AllowWhen.Groups) != 1 {
		t.Fatalf("AllowWhen = %+v, want the real scoped condition", tc.AllowWhen)
	}
	// Unscoped conditions pass through untouched.
	_, s, err = parseRemotePolicy([]byte(scopedMCPBody(`{"AllowWhen":{"AgentID":"ci"}}`)))
	if err != nil || s.MCP.Tools.Constraints["deploy"].AllowWhen.AgentID != "ci" {
		t.Fatalf("unscoped condition changed: %v", err)
	}
}

func TestParseRemotePolicy_DanglingSentinel(t *testing.T) {
	bodies := map[string]string{
		"sentinel alone":         scopedMCPBody(`{"AllowWhen":{"AgentID":"!identity-scoped"}}`),
		"scoped without marker":  scopedMCPBody(`{"AllowWhen":{"AgentID":"ci"},"AllowWhenScoped":{"Groups":["g"]}}`),
		"scoped without nothing": scopedMCPBody(`{"AllowWhenScoped":{"Groups":["g"]}}`),
		"scoped without groups":  scopedMCPBody(`{"AllowWhen":{"AgentID":"!identity-scoped"},"AllowWhenScoped":{"AgentID":"ci"}}`),
		"scoped is the sentinel": scopedMCPBody(`{"AllowWhen":{"AgentID":"!identity-scoped"},"AllowWhenScoped":{"AgentID":"!identity-scoped","Groups":["g"]}}`),
		"bad window":             scopedMCPBody(`{"AllowWhen":{"AgentID":"!identity-scoped"},"AllowWhenScoped":{"TimeWindow":"99","Groups":["g"]}}`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRemotePolicy([]byte(body)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

// A failed pull keeps the last good policy.
func TestPull_DanglingSentinelKeepsLastGood(t *testing.T) {
	good := `{"allowlist":[{"domain":"a.example.com"}]}`
	bad := scopedMCPBody(`{"AllowWhen":{"AgentID":"!identity-scoped"}}`)
	body := good
	rp, closeFn := newTestRemote(t, func() string { return body })
	defer closeFn()
	if err := rp.Pull(); err != nil {
		t.Fatal(err)
	}
	body = bad
	if err := rp.Pull(); err == nil {
		t.Fatal("dangling sentinel must fail the pull")
	}
	pol, err := rp.GetPolicy()
	if err != nil || len(pol.Allowlist) != 1 || pol.Allowlist[0].Domain != "a.example.com" {
		t.Fatalf("last good policy lost: %v %+v", err, pol.Allowlist)
	}
}

// previousRemoteWire is the worker decode shape before W-P1-GPOL-06, frozen.
type previousRemoteWire struct {
	Policy
	Settings *SettingsWire `json:"settings,omitempty"`
}

func TestOldWorkerDeniesScoped(t *testing.T) {
	body := `{"allowlist":[{"domain":"a.example.com"}],
	  "scopedAllowlist":[{"domain":"b.example.com","groups":["eng"]}],"scopedAllowPos":[1],
	  "settings":{"mcp":{"enabled":true,"tools":{"allow":["deploy"],"constraints":{"deploy":
	    {"AllowWhen":{"AgentID":"!identity-scoped"},"AllowWhenScoped":{"Groups":["eng"]}}}}}}}`
	var old previousRemoteWire
	if err := json.Unmarshal([]byte(body), &old); err != nil {
		t.Fatal(err)
	}
	for _, e := range old.Allowlist {
		if e.Domain == "b.example.com" {
			t.Fatal("old worker sees the scoped host in its allowlist")
		}
	}
	aw := old.Settings.MCP.Tools.Constraints["deploy"].AllowWhen
	if aw == nil || aw.AgentID != ReservedScopedAgentID {
		t.Fatalf("old worker AllowWhen = %+v, want the sentinel", aw)
	}
	// No agent id equals the reserved sentinel (config rejects it), so the
	// gateway's agent-id gate denies every agent; the gateway test
	// TestConditionAgentIDMismatchDenies covers that path.
	if err := validateAllowWhen("x", &MCPToolCondition{AgentID: ReservedScopedAgentID}, false); err == nil {
		t.Fatal("the sentinel must not be a valid configured agent id")
	}
}

func newTestRemote(t *testing.T, body func() string) (*RemoteProvider, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body()))
	}))
	rp, err := NewRemoteProvider(srv.URL, "test-token")
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	rp.client = srv.Client()
	return rp, srv.Close
}
