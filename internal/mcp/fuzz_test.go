package mcp_test

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/scan"
)

// FuzzMCPMessage feeds arbitrary bytes to the JSON-RPC parsing the MCP gateway
// relies on. Properties:
//   - parsing, argument/result scanning and the gateway never panic;
//   - parsing is deterministic and only reports a tool call for method tools/call;
//   - in enforce mode, a tools/call for any tool outside the allowlist is denied,
//     whatever shape the JSON takes (duplicate keys, odd ids, nested noise);
//   - the tool policy never allows a name that is not exactly on its allowlist.
func FuzzMCPMessage(f *testing.F) {
	// Seeds live in testdata/fuzz/FuzzMCPMessage: well-formed and malformed
	// JSON-RPC (duplicate keys, odd ids, batches, BOM, deep nesting) and the
	// injection payloads from the red-team playbook §4.
	cfg := config.MCPConfig{
		Enabled:              true,
		Mode:                 "enforce",
		MaxResponseScanBytes: 1 << 20,
		Tools:                config.MCPToolsConfig{Allow: []string{"read_file"}, Deny: []string{"exec_cmd"}},
		Scan:                 config.MCPScanConfig{ToolArgs: true, ToolResults: true, ProfileSchema: true},
		Chain:                config.MCPChainConfig{Enabled: true, WindowSize: 50},
	}
	scanner := scan.NewScanner()
	gw := gateway.New(cfg, scanner, nil)
	policy := mcp.NewToolPolicy(cfg.Tools.Allow, cfg.Tools.Deny, nil)

	f.Fuzz(func(t *testing.T, body []byte) {
		tc, err := mcp.ParseToolCall(body)
		tc2, err2 := mcp.ParseToolCall(body)
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(tc, tc2) {
			t.Fatalf("ParseToolCall is not deterministic for %q", body)
		}
		if err == nil && tc != nil {
			if tc.Method != "tools/call" {
				t.Fatalf("tool call reported for method %q: %q", tc.Method, body)
			}
			if policy.Evaluate(tc.Name) && tc.Name != "read_file" {
				t.Fatalf("tool policy allowed %q, which is not on the allowlist", tc.Name)
			}
		}

		_ = mcp.ScanToolArgs(body, scanner)
		_ = mcp.ScanToolResult(body, scanner)

		v := gw.OnRequest("fuzz:session", http.MethodPost, "https://mcp.test/mcp", http.Header{}, body)
		if err == nil && tc != nil && tc.Name != "read_file" && v.Action != gateway.Deny {
			t.Fatalf("enforce mode let tools/call %q through: %q", tc.Name, body)
		}
		_ = gw.OnResponse("fuzz:session", http.StatusOK, http.Header{"Content-Type": {"application/json"}}, body)
	})
}
