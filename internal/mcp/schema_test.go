package mcp

import (
	"encoding/json"
	"testing"
)

func TestSchemaStore_NoDrift(t *testing.T) {
	store := NewSchemaStore(false)
	tools := []ToolSchema{
		{Name: "web_search", Description: "Search the web", InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`)},
	}
	store.CaptureBaseline(tools)
	drifts := store.DetectDrift(tools)
	if len(drifts) != 0 {
		t.Errorf("expected no drift, got %d: %+v", len(drifts), drifts)
	}
}

func TestSchemaStore_ToolAdded(t *testing.T) {
	store := NewSchemaStore(false)
	baseline := []ToolSchema{
		{Name: "web_search", Description: "Search the web"},
	}
	store.CaptureBaseline(baseline)
	current := []ToolSchema{
		{Name: "web_search", Description: "Search the web"},
		{Name: "new_tool", Description: "A new tool"},
	}
	drifts := store.DetectDrift(current)
	found := false
	for _, d := range drifts {
		if d.ToolName == "new_tool" && d.Type == "added" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'added' drift for new_tool, got %+v", drifts)
	}
}

func TestSchemaStore_ToolRemoved(t *testing.T) {
	store := NewSchemaStore(false)
	baseline := []ToolSchema{
		{Name: "web_search", Description: "Search the web"},
		{Name: "old_tool", Description: "An old tool"},
	}
	store.CaptureBaseline(baseline)
	current := []ToolSchema{
		{Name: "web_search", Description: "Search the web"},
	}
	drifts := store.DetectDrift(current)
	found := false
	for _, d := range drifts {
		if d.ToolName == "old_tool" && d.Type == "removed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'removed' drift for old_tool, got %+v", drifts)
	}
}

func TestSchemaStore_DescriptionChanged(t *testing.T) {
	store := NewSchemaStore(false)
	baseline := []ToolSchema{
		{Name: "web_search", Description: "Search the web"},
	}
	store.CaptureBaseline(baseline)
	current := []ToolSchema{
		{Name: "web_search", Description: "Search the entire internet"},
	}
	drifts := store.DetectDrift(current)
	found := false
	for _, d := range drifts {
		if d.ToolName == "web_search" && d.Type == "description_changed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'description_changed' drift, got %+v", drifts)
	}
}

func TestSchemaStore_SchemaChanged(t *testing.T) {
	store := NewSchemaStore(false)
	baseline := []ToolSchema{
		{Name: "web_search", Description: "Search", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
	store.CaptureBaseline(baseline)
	current := []ToolSchema{
		{Name: "web_search", Description: "Search", InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`)},
	}
	drifts := store.DetectDrift(current)
	found := false
	for _, d := range drifts {
		if d.ToolName == "web_search" && d.Type == "schema_changed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'schema_changed' drift, got %+v", drifts)
	}
}

func TestSchemaStore_PinnedModeDrift(t *testing.T) {
	store := NewSchemaStore(true)
	baseline := []ToolSchema{
		{Name: "web_search", Description: "Search the web"},
	}
	store.CaptureBaseline(baseline)
	current := []ToolSchema{
		{Name: "web_search", Description: "Search the web"},
		{Name: "new_tool", Description: "Sneaky tool"},
	}
	drifts := store.DetectDrift(current)
	if len(drifts) == 0 {
		t.Error("expected drift detected even in pinned mode")
	}
	for _, d := range drifts {
		if !d.Blocked {
			t.Errorf("expected Blocked=true in pinned mode for drift %q, got false", d.ToolName)
		}
	}
}

func TestParseToolList_Valid(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"web_search","description":"Search","inputSchema":{"type":"object"}}]}}`)
	tools, err := ParseToolList(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "web_search" {
		t.Errorf("Name = %q, want %q", tools[0].Name, "web_search")
	}
}

func TestParseToolList_InvalidJSON(t *testing.T) {
	body := []byte(`{not valid}`)
	_, err := ParseToolList(body)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseToolList_InvalidVersion(t *testing.T) {
	body := []byte(`{"jsonrpc":"1.0","id":1,"result":{"tools":[]}}`)
	_, err := ParseToolList(body)
	if err == nil {
		t.Error("expected error for invalid jsonrpc version")
	}
}
