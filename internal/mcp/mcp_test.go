package mcp

import "testing"

func TestParseToolCall_Valid(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_search","arguments":{"query":"hello"}}}`)
	tc, err := ParseToolCall(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
	}
	if tc.Method != "tools/call" {
		t.Errorf("Method = %q, want %q", tc.Method, "tools/call")
	}
	if tc.Name != "web_search" {
		t.Errorf("Name = %q, want %q", tc.Name, "web_search")
	}
	if tc.ID != "1" {
		t.Errorf("ID = %q, want %q", tc.ID, "1")
	}
}

func TestParseToolCall_StringID(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":"req-42","method":"tools/call","params":{"name":"read_file"}}`)
	tc, err := ParseToolCall(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
	}
	if tc.ID != "req-42" {
		t.Errorf("ID = %q, want %q", tc.ID, "req-42")
	}
}

func TestParseToolCall_NonToolCall(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tc, err := ParseToolCall(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc != nil {
		t.Errorf("expected nil for non-tool-call, got %+v", tc)
	}
}

func TestParseToolCall_InvalidJSON(t *testing.T) {
	body := []byte(`{not valid json`)
	_, err := ParseToolCall(body)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestToolPolicy_AllowedTool(t *testing.T) {
	p := NewToolPolicy([]string{"web_search", "read_file"}, nil)
	if !p.Evaluate("web_search") {
		t.Error("expected web_search to be allowed")
	}
	if p.Evaluate("exec_command") {
		t.Error("expected exec_command to be denied (not in allowed list)")
	}
}

func TestToolPolicy_DeniedPrecedence(t *testing.T) {
	p := NewToolPolicy([]string{"web_search", "exec_command"}, []string{"exec_command"})
	if !p.Evaluate("web_search") {
		t.Error("expected web_search to be allowed")
	}
	if p.Evaluate("exec_command") {
		t.Error("expected exec_command to be denied (in denied list, even though in allowed)")
	}
}

func TestToolPolicy_DefaultDeny(t *testing.T) {
	p := NewToolPolicy(nil, nil)
	if p.Evaluate("anything") {
		t.Error("expected all tools denied when both lists empty (default-deny)")
	}
	if p.Evaluate("web_search") {
		t.Error("expected all tools denied when both lists empty (default-deny)")
	}
}

func TestToolPolicy_DeniedOnly(t *testing.T) {
	p := NewToolPolicy(nil, []string{"dangerous_tool"})
	// No allowlist configured, so default-deny applies to all tools.
	if p.Evaluate("safe_tool") {
		t.Error("expected safe_tool to be denied (no allowlist, default-deny)")
	}
	if p.Evaluate("dangerous_tool") {
		t.Error("expected dangerous_tool to be denied")
	}
}

func TestParseToolCall_InvalidJSONRPCVersion(t *testing.T) {
	body := []byte(`{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"web_search"}}`)
	_, err := ParseToolCall(body)
	if err == nil {
		t.Error("expected error for invalid jsonrpc version")
	}
}

func TestParseToolCall_MissingJSONRPCVersion(t *testing.T) {
	body := []byte(`{"id":1,"method":"tools/call","params":{"name":"web_search"}}`)
	_, err := ParseToolCall(body)
	if err == nil {
		t.Error("expected error for missing jsonrpc version")
	}
}
