package controlplane

import (
	"testing"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
)

func snapWith(tool string) analytics.MCPSnapshot {
	return analytics.MCPSnapshot{
		Inventory: []gateway.InventoryItem{{Name: tool}},
		Schema: map[string]mcp.ToolProfileView{
			tool + "\x00request": {Fields: map[string]mcp.FieldProfileView{
				"path": {Types: []string{"string"}, SeenCount: 1},
			}},
		},
	}
}

func TestMCPStorePerWorker(t *testing.T) {
	s := newMCPStore()
	s.Update("w1", snapWith("read_file"))
	s.Update("w2", snapWith("write_file"))
	s.Update("", snapWith("ignored")) // blank id ignored

	// Specific worker.
	inv, schema := s.For("w1")
	if len(inv) != 1 || inv[0].Name != "read_file" {
		t.Fatalf("w1 inventory = %+v", inv)
	}
	if _, ok := schema["read_file\x00request"]; !ok {
		t.Errorf("w1 schema missing: %+v", schema)
	}

	// Empty proxyID -> most-recently-updated worker (w2 here).
	inv, _ = s.For("")
	if len(inv) != 1 || inv[0].Name != "write_file" {
		t.Errorf("default (most-recent) = %+v, want write_file", inv)
	}

	// Unknown worker -> nil.
	if inv, _ := s.For("nope"); inv != nil {
		t.Errorf("unknown worker should be nil, got %+v", inv)
	}
}
