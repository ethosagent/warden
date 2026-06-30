package controlplane

import (
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// mcpStore holds the most recent MCP snapshot each worker has forwarded, so the
// control-plane dashboard can show per-worker MCP inventory + observed schema.
// In-memory and safe for concurrent use; snapshots are value-free (paths/types/
// sensitivity only), like the worker dashboard.
type mcpStore struct {
	mu   sync.Mutex
	byID map[string]mcpEntry
	now  func() time.Time
}

type mcpEntry struct {
	snap    analytics.MCPSnapshot
	updated time.Time
}

func newMCPStore() *mcpStore {
	return &mcpStore{byID: make(map[string]mcpEntry), now: time.Now}
}

// Update records a worker's latest MCP snapshot (ingest callback). A blank proxy
// id is ignored — it can't be attributed to a worker.
func (s *mcpStore) Update(proxyID string, snap analytics.MCPSnapshot) {
	if proxyID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[proxyID] = mcpEntry{snap: snap, updated: s.now()}
}

// For returns a worker's inventory + schema. An empty proxyID selects the
// most-recently-updated worker, so the panel shows something by default. An
// unknown id (or empty store) yields nil, nil.
func (s *mcpStore) For(proxyID string) ([]gateway.InventoryItem, map[string]mcp.ToolProfileView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if proxyID == "" {
		var bestT time.Time
		for id, e := range s.byID {
			if proxyID == "" || e.updated.After(bestT) {
				proxyID, bestT = id, e.updated
			}
		}
	}
	e, ok := s.byID[proxyID]
	if !ok {
		return nil, nil
	}
	return e.snap.Inventory, e.snap.Schema
}
