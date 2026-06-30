package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// TestMCPFleetProxyAware verifies the control-plane MCP panel sources inventory +
// schema per worker via SetMCPFleet, selected by ?proxy=, and scopes the
// event-derived counts to that worker.
func TestMCPFleetProxyAware(t *testing.T) {
	now := time.Now()
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: now, Protocol: "mcp", Tool: "read_file", Decision: "allow", ProxyID: "w1"},
		{Timestamp: now, Protocol: "mcp", Tool: "read_file", Decision: "deny", ProxyID: "w1"},
		{Timestamp: now, Protocol: "mcp", Tool: "write_file", Decision: "allow", ProxyID: "w2"},
	}}
	fleet := map[string]analytics.MCPSnapshot{
		"w1": {
			Inventory: []gateway.InventoryItem{{Name: "read_file"}},
			Schema: map[string]mcp.ToolProfileView{
				"read_file\x00request": {Fields: map[string]mcp.FieldProfileView{
					"path": {Types: []string{"string"}, SeenCount: 2, Sensitivity: []string{"pii"}},
				}},
			},
		},
		"w2": {Inventory: []gateway.InventoryItem{{Name: "write_file"}}},
	}
	srv := NewServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetMCPFleet(func(proxyID string) ([]gateway.InventoryItem, map[string]mcp.ToolProfileView) {
		s := fleet[proxyID]
		return s.Inventory, s.Schema
	})
	h := srv.Handler()

	var resp struct {
		Enabled bool `json:"enabled"`
		Tools   []struct {
			Tool          string                            `json:"tool"`
			Calls         int                               `json:"calls"`
			Denied        int                               `json:"denied"`
			Sensitive     []string                          `json:"sensitive"`
			RequestSchema map[string]map[string]interface{} `json:"requestSchema"`
		} `json:"tools"`
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/mcp?proxy=w1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Enabled || len(resp.Tools) != 1 || resp.Tools[0].Tool != "read_file" {
		t.Fatalf("w1 MCP view = %+v", resp)
	}
	if resp.Tools[0].Calls != 2 || resp.Tools[0].Denied != 1 {
		t.Errorf("w1 counts scoped wrong: %+v", resp.Tools[0])
	}
	if _, ok := resp.Tools[0].RequestSchema["path"]; !ok {
		t.Errorf("w1 request schema missing path: %+v", resp.Tools[0].RequestSchema)
	}
}
