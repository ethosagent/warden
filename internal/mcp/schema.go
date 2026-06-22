package mcp

import (
	"encoding/json"
	"fmt"
	"sync"
)

// ToolSchema represents the schema of an MCP tool from a tools/list response.
type ToolSchema struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// SchemaStore tracks tool schemas and detects drift from a known-good baseline.
type SchemaStore struct {
	mu       sync.RWMutex
	baseline map[string]ToolSchema
	pinned   bool
}

// NewSchemaStore creates a SchemaStore. If pinned is true, the caller is
// expected to treat any drift as a hard block.
func NewSchemaStore(pinned bool) *SchemaStore {
	return &SchemaStore{
		baseline: make(map[string]ToolSchema),
		pinned:   pinned,
	}
}

// CaptureBaseline stores the initial tool list as the known-good baseline.
func (s *SchemaStore) CaptureBaseline(tools []ToolSchema) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseline = make(map[string]ToolSchema, len(tools))
	for _, t := range tools {
		s.baseline[t.Name] = t
	}
}

// SchemaDrift describes a single change between baseline and current tool list.
type SchemaDrift struct {
	ToolName string
	Type     string // "added", "removed", "description_changed", "schema_changed"
	Detail   string
}

// DetectDrift compares a new tool list against the baseline and returns changes.
func (s *SchemaStore) DetectDrift(tools []ToolSchema) []SchemaDrift {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var drifts []SchemaDrift

	current := make(map[string]ToolSchema, len(tools))
	for _, t := range tools {
		current[t.Name] = t
	}

	// Check for added tools
	for name := range current {
		if _, ok := s.baseline[name]; !ok {
			drifts = append(drifts, SchemaDrift{ToolName: name, Type: "added", Detail: "tool not in baseline"})
		}
	}

	// Check for removed tools
	for name := range s.baseline {
		if _, ok := current[name]; !ok {
			drifts = append(drifts, SchemaDrift{ToolName: name, Type: "removed", Detail: "tool missing from current list"})
		}
	}

	// Check for changes
	for name, curr := range current {
		base, ok := s.baseline[name]
		if !ok {
			continue // already reported as added
		}
		if curr.Description != base.Description {
			drifts = append(drifts, SchemaDrift{
				ToolName: name,
				Type:     "description_changed",
				Detail:   fmt.Sprintf("description changed from %q to %q", base.Description, curr.Description),
			})
		}
		if string(base.InputSchema) != string(curr.InputSchema) {
			drifts = append(drifts, SchemaDrift{
				ToolName: name,
				Type:     "schema_changed",
				Detail:   "input schema changed",
			})
		}
	}

	return drifts
}

// ParseToolList parses a tools/list JSON-RPC response and returns the tool schemas.
func ParseToolList(body []byte) ([]ToolSchema, error) {
	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		Result  struct {
			Tools []ToolSchema `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if resp.JSONRPC != "2.0" {
		return nil, fmt.Errorf("mcp: invalid jsonrpc version: %q", resp.JSONRPC)
	}
	return resp.Result.Tools, nil
}
