package scenarios

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// mcpSubjectOpts boots the worker with identity on and the MCP gateway in
// monitor mode.
func mcpSubjectOpts() []harness.Option {
	return append(identityOpts(), harness.WithMCP())
}

// mcpSubjectSeamUnchanged (W-P1-GPOL-04): the verified subject now travels to
// the MCP gateway through RequestMeta, and the gateway ignores it, so an MCP
// tools/call is forwarded exactly as before whether the caller presents a
// valid identity, an expired one or none, on HTTP/1.1 and on h2. The
// upstream receives every request and none is audited as a deny.
func mcpSubjectSeamUnchanged(t *testing.T, h *harness.H) {
	up := h.FakeMCP()
	host := h.Host("mcp")
	valid := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	expired := h.MintUserToken(fakes.Valid("erin", "erin@example.com"), fakes.Expired())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	post := func(cl *http.Client, token string) int {
		req, err := http.NewRequest(http.MethodPost, "https://"+host+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Warden-Identity", "Bearer "+token)
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", host, err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	want := 0
	for _, tc := range []struct {
		name string
		cl   func() *http.Client
	}{{"h1", h.Agent}, {"h2", h.AgentH2}} {
		for _, tok := range []string{valid, expired, ""} {
			if got := post(tc.cl(), tok); got != http.StatusOK {
				t.Fatalf("%s: MCP call = %d, want 200 (the subject must not change a verdict)", tc.name, got)
			}
			want++
		}
	}
	if n := len(up.Requests()); n != want {
		t.Errorf("MCP upstream saw %d requests, want %d", n, want)
	}
	for _, e := range h.Events() {
		if e.Decision == "deny" {
			t.Errorf("unexpected deny event: %+v", e)
		}
	}
}

// mcpGroupOpts boots the worker with identity on and an enforce-mode MCP
// gateway whose "pay" tool is allowed only for the finance group (W-P1-GPOL-11).
func mcpGroupOpts() []harness.Option {
	return append(identityOpts(), harness.WithMCPConfig(config.MCPConfig{
		Mode: "enforce",
		Tools: config.MCPToolsConfig{
			Allow: []string{"pay", "lookup"},
			Constraints: map[string]config.MCPToolConstraints{
				"pay": {AllowWhen: &config.MCPToolCondition{Groups: []string{"finance"}}},
			},
		},
	}))
}

// mcpGroupCondition (W-P1-GPOL-11): a tool gated by allowWhen.groups is
// forwarded for a finance member and denied (403, reason mcp_tool_condition)
// for an eng member, an anonymous caller and an expired token, on HTTP/1.1 and
// h2. An ungated tool is unaffected, and a denied call never reaches the
// upstream.
func mcpGroupCondition(t *testing.T, h *harness.H) {
	up := h.FakeMCP()
	host := h.Host("mcp")
	fin := h.MintUserToken(fakes.Valid("fran", "fran@example.com", "finance"))
	eng := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	expired := h.MintUserToken(fakes.Valid("erin", "erin@example.com", "finance"), fakes.Expired())

	call := func(cl *http.Client, tool, token string) (status int, closes bool) {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
		req, err := http.NewRequest(http.MethodPost, "https://"+host+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Warden-Identity", "Bearer "+token)
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", host, err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Close
	}

	allowed, denied := 0, 0
	for _, tc := range []struct {
		name string
		cl   func() *http.Client
	}{{"h1", h.Agent}, {"h2", h.AgentH2}} {
		for _, c := range []struct {
			who   string
			tool  string
			token string
			want  int
		}{
			{"finance", "pay", fin, http.StatusOK},
			{"eng", "pay", eng, http.StatusForbidden},
			{"anonymous", "pay", "", http.StatusForbidden},
			{"expired", "pay", expired, http.StatusForbidden},
			{"eng ungated", "lookup", eng, http.StatusOK},
		} {
			got, closes := call(tc.cl(), c.tool, c.token)
			if got != c.want {
				t.Errorf("%s %s: status = %d, want %d", tc.name, c.who, got, c.want)
			}
			// A deny ends the h1 session, so the response must say so or the
			// agent pools the dying conn and its next call fails with EOF (#602).
			if tc.name == "h1" && c.want == http.StatusForbidden && !closes {
				t.Errorf("%s %s: deny response lacks Connection: close", tc.name, c.who)
			}
			if c.want == http.StatusOK {
				allowed++
			} else {
				denied++
			}
		}
	}
	if n := len(up.Requests()); n != allowed {
		t.Errorf("MCP upstream saw %d requests, want %d (denied calls must not reach it)", n, allowed)
	}
	h.Eventually("an mcp_tool_condition deny event per denied call", func() bool {
		n := 0
		for _, e := range h.Events() {
			if e.Decision == "deny" && e.Reason == "mcp_tool_condition" {
				n++
			}
		}
		return n == denied
	})
}
