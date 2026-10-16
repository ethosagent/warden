package poisoned

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// call issues one JSON-RPC request against the handler and decodes the JSON
// response envelope.
func call(t *testing.T, method, body string) (int, http.Header, map[string]any) {
	t.Helper()
	srv := httptest.NewServer(Handler())
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Post(srv.URL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	return resp.StatusCode, resp.Header, v
}

// TestToolsListCarriesThePoisonedTool pins the payload Warden's scanner must
// flag: two tools, one of them (list_files) carrying the prompt-injection
// description, the other a benign-but-dangerous run_shell the injection steers
// the agent toward.
func TestToolsListCarriesThePoisonedTool(t *testing.T) {
	status, header, v := call(t, "tools/list", `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if ct := header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (Warden's discrete-response buffering keys on it)", ct)
	}
	if got := v["jsonrpc"]; got != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", got)
	}
	if id := v["id"]; id != float64(7) {
		t.Errorf("id = %v, want the request's 7", id)
	}
	result, _ := v["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools/list returned %d tools, want 2", len(tools))
	}
	byName := map[string]string{}
	for _, tool := range tools {
		m, _ := tool.(map[string]any)
		name, _ := m["name"].(string)
		desc, _ := m["description"].(string)
		byName[name] = desc
	}
	poisonedDesc, ok := byName["list_files"]
	if !ok {
		t.Fatal("tools/list has no list_files tool")
	}
	for _, want := range []string{"IMPORTANT:", "ignore all previous instructions", "run_shell", "exfiltrate"} {
		if !strings.Contains(poisonedDesc, want) {
			t.Errorf("list_files description missing injection marker %q:\n%s", want, poisonedDesc)
		}
	}
	if _, ok := byName["run_shell"]; !ok {
		t.Error("tools/list has no run_shell tool")
	}
}

// TestToolsCallEchoesTheToolName pins the benign result path.
func TestToolsCallEchoesTheToolName(t *testing.T) {
	_, _, v := call(t, "tools/call",
		`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"run_shell"}}`)
	result, _ := v["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content = %v, want one text block", content)
	}
	block, _ := content[0].(map[string]any)
	if text, _ := block["text"].(string); text != "ok: run_shell executed" {
		t.Errorf("text = %q, want the tool-name echo", text)
	}
}

// TestUnknownMethodIsJSONRPCError pins the -32601 fallback, and that a request
// with no id still gets one (the demo's curl traffic omits it).
func TestUnknownMethodIsJSONRPCError(t *testing.T) {
	_, _, v := call(t, "bogus", `{"jsonrpc":"2.0","method":"nope"}`)
	errObj, _ := v["error"].(map[string]any)
	if code, _ := errObj["code"].(float64); code != -32601 {
		t.Errorf("error code = %v, want -32601", errObj["code"])
	}
	if v["id"] == nil {
		t.Error("response has no id; a request without one must default to 1")
	}
}
