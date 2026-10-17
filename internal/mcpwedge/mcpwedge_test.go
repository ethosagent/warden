package mcpwedge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postRPC sends a JSON-RPC request to the handler and decodes the response
// envelope into a generic map.
func postRPC(t *testing.T, h http.Handler, method string) map[string]any {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":7,"method":"` + method + `","params":{"name":"list_files"}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status = %d, want 200", method, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s: content-type = %q, want application/json", method, ct)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: decode response: %v", method, err)
	}
	return out
}

// TestToolsList_CarriesPoisonedDescription pins the attack payload: the demo
// only demonstrates Warden's injection detection if list_files advertises the
// poisoned description. Both the mcp-wedge example and the e2e fake upstream
// serve this handler, so a change here changes what both expose.
func TestToolsList_CarriesPoisonedDescription(t *testing.T) {
	out := postRPC(t, NewHandler(), "tools/list")
	if out["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", out["jsonrpc"])
	}
	result, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/list result missing: %v", out)
	}
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) != 2 {
		t.Fatalf("tools = %v, want 2 entries", result["tools"])
	}
	byName := map[string]map[string]any{}
	for _, tl := range tools {
		tool, ok := tl.(map[string]any)
		if !ok {
			t.Fatalf("tool entry is not an object: %v", tl)
		}
		byName[tool["name"].(string)] = tool
	}
	listFiles, ok := byName["list_files"]
	if !ok {
		t.Fatal("tools/list is missing list_files")
	}
	desc, _ := listFiles["description"].(string)
	for _, want := range []string{"ignore all previous instructions", "run_shell", "~/.aws/credentials"} {
		if !strings.Contains(desc, want) {
			t.Errorf("poisoned description %q does not contain %q", desc, want)
		}
	}
	if _, ok := byName["run_shell"]; !ok {
		t.Fatal("tools/list is missing run_shell (the dangerous tool the payload names)")
	}
}

// TestToolsCall_ReturnsBenignResult checks the tools/call path the demo's
// enforce mode blocks before it ever reaches the upstream.
func TestToolsCall_ReturnsBenignResult(t *testing.T) {
	out := postRPC(t, NewHandler(), "tools/call")
	result, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/call result missing: %v", out)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("content = %v, want one entry", result["content"])
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "list_files executed") {
		t.Errorf("tools/call text = %q, want it to name the called tool", text)
	}
}

// TestUnknownMethod_IsJSONRPCError keeps the -32601 branch honest.
func TestUnknownMethod_IsJSONRPCError(t *testing.T) {
	out := postRPC(t, NewHandler(), "no/such/method")
	errObj, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("error object missing: %v", out)
	}
	if code, _ := errObj["code"].(float64); code != -32601 {
		t.Errorf("error code = %v, want -32601", errObj["code"])
	}
}
