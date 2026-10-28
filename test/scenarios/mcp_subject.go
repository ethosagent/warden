package scenarios

import (
	"io"
	"net/http"
	"strings"
	"testing"

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
