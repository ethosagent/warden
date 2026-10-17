package harness

import (
	"github.com/ethosagent/warden/internal/mcp/poisoned"
)

// FakeMCP returns the fake MCP server on mcp.example.com: the poisoned MCP
// handler (internal/mcp/poisoned — the SAME package the mcp-wedge demo binary
// serves) as the whole server, so the demo and every harness scenario exercise
// byte-identical tooling. Every request is recorded by the underlying Upstream
// (what the tool client actually sent, swaps included).
func (h *H) FakeMCP() *Upstream {
	h.tb.Helper()
	h.mcpOnce.Do(func() {
		u := h.Upstream(h.Host("mcp"))
		u.route("/", poisoned.Handler())
		h.mcpU = u
	})
	return h.mcpU
}
