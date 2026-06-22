// Package mcp provides MCP (Model Context Protocol) message parsing and
// tool-call policy evaluation. MCP uses JSON-RPC 2.0 over HTTP; this package
// extracts tool invocation metadata and applies allow/deny decisions.
package mcp

import (
	"encoding/json"
	"fmt"
)

// ToolCall represents a parsed MCP tool invocation.
type ToolCall struct {
	ID     string
	Method string // e.g. "tools/call"
	Name   string // tool name from params
}

// jsonRPCRequest is the wire format of an MCP JSON-RPC request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  struct {
		Name string `json:"name"`
	} `json:"params"`
}

// ParseToolCall extracts tool call info from an MCP JSON-RPC request body.
// Returns nil (no error) when the message is valid JSON-RPC but not a
// tools/call method. Returns an error only for malformed input.
func ParseToolCall(body []byte) (*ToolCall, error) {
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.JSONRPC != "2.0" {
		return nil, fmt.Errorf("mcp: invalid jsonrpc version: %q", req.JSONRPC)
	}
	if req.Method != "tools/call" {
		return nil, nil
	}
	// Extract the ID as a string for logging/correlation.
	var id string
	if req.ID != nil {
		// ID can be string or number in JSON-RPC; stringify either way.
		var s string
		if err := json.Unmarshal(req.ID, &s); err != nil {
			// Not a string — use the raw representation (e.g. "1").
			id = string(req.ID)
		} else {
			id = s
		}
	}
	return &ToolCall{
		ID:     id,
		Method: req.Method,
		Name:   req.Params.Name,
	}, nil
}

// ToolPolicy evaluates whether a tool call is allowed.
type ToolPolicy struct {
	allowed map[string]struct{} // tool names explicitly allowed
	denied  map[string]struct{} // tool names denied; takes precedence over allowed
}

// NewToolPolicy creates a ToolPolicy. Empty allowed list means deny all
// (default-deny). Denied list takes precedence over allowed.
func NewToolPolicy(allowed, denied []string) *ToolPolicy {
	p := &ToolPolicy{
		allowed: make(map[string]struct{}, len(allowed)),
		denied:  make(map[string]struct{}, len(denied)),
	}
	for _, name := range allowed {
		p.allowed[name] = struct{}{}
	}
	for _, name := range denied {
		p.denied[name] = struct{}{}
	}
	return p
}

// Evaluate returns true if the tool name is allowed by this policy.
// Denied takes precedence over allowed. If no allowlist is configured,
// all tools are denied (default-deny).
func (p *ToolPolicy) Evaluate(toolName string) bool {
	// Denylist takes precedence.
	if _, ok := p.denied[toolName]; ok {
		return false
	}
	// If no allowlist is configured, deny by default (default-deny).
	if len(p.allowed) == 0 {
		return false
	}
	// Otherwise, must be in the allowed list.
	_, ok := p.allowed[toolName]
	return ok
}
