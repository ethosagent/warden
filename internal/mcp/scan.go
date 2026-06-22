package mcp

import (
	"encoding/json"
	"strings"

	"github.com/ethosagent/warden/internal/scan"
)

// extractStrings recursively walks a JSON value and collects all string values.
func extractStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var result []string

	// Try as string
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}

	// Try as array
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, item := range arr {
			result = append(result, extractStrings(item)...)
		}
		return result
	}

	// Try as object
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for _, v := range obj {
			result = append(result, extractStrings(v)...)
		}
		return result
	}

	return nil
}

// ScanToolArgs scans outbound tool call arguments for credential leakage
// and injection patterns using the provided scanner.
func ScanToolArgs(args json.RawMessage, scanner *scan.Scanner) []scan.Detection {
	if len(args) == 0 {
		return nil
	}
	strs := extractStrings(args)
	if len(strs) == 0 {
		return nil
	}
	concatenated := strings.Join(strs, "\n")
	return scanner.ScanResponse([]byte(concatenated))
}

// ScanToolResult scans inbound tool result content for injection patterns
// and credential leakage.
func ScanToolResult(result json.RawMessage, scanner *scan.Scanner) []scan.Detection {
	if len(result) == 0 {
		return nil
	}
	strs := extractStrings(result)
	if len(strs) == 0 {
		return nil
	}
	concatenated := strings.Join(strs, "\n")
	return scanner.ScanResponse([]byte(concatenated))
}
