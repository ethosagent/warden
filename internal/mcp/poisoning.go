package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ethosagent/warden/internal/scan"
)

// DescriptionLengthThreshold is the maximum description length before triggering
// a description_length_anomaly detection.
const DescriptionLengthThreshold = 500

// PoisoningDetection represents a tool poisoning finding.
type PoisoningDetection struct {
	ToolName string
	Pattern  string // "description_injection", "cross_tool_reference", "overly_broad_schema", "description_length_anomaly"
	Detail   string
}

var crossToolRe = regexp.MustCompile(`(?i)(always|must|should)\s+(call|use|invoke|run)\s+\w+`)

// DetectPoisoning analyzes tool schemas for signs of tool poisoning attacks.
func DetectPoisoning(tools []ToolSchema, scanner *scan.Scanner) []PoisoningDetection {
	var detections []PoisoningDetection
	for _, tool := range tools {
		// 1. description_injection - run description through scanner's injection detection
		scanResults := scanner.ScanResponse([]byte(tool.Description))
		for _, d := range scanResults {
			if d.Category == "injection" {
				detections = append(detections, PoisoningDetection{
					ToolName: tool.Name,
					Pattern:  "description_injection",
					Detail:   fmt.Sprintf("injection pattern %q found in description", d.Pattern),
				})
			}
		}

		// 2. cross_tool_reference
		if crossToolRe.MatchString(tool.Description) {
			detections = append(detections, PoisoningDetection{
				ToolName: tool.Name,
				Pattern:  "cross_tool_reference",
				Detail:   "description contains directive to call another tool",
			})
		}

		// 3. overly_broad_schema
		if isOverlyBroadSchema(tool.InputSchema) {
			detections = append(detections, PoisoningDetection{
				ToolName: tool.Name,
				Pattern:  "overly_broad_schema",
				Detail:   "input schema is overly broad",
			})
		}

		// 4. description_length_anomaly
		if len(tool.Description) > DescriptionLengthThreshold {
			detections = append(detections, PoisoningDetection{
				ToolName: tool.Name,
				Pattern:  "description_length_anomaly",
				Detail:   fmt.Sprintf("description length %d exceeds threshold %d", len(tool.Description), DescriptionLengthThreshold),
			})
		}
	}
	return detections
}

func isOverlyBroadSchema(schema json.RawMessage) bool {
	if len(schema) == 0 {
		return false
	}
	var s map[string]json.RawMessage
	if err := json.Unmarshal(schema, &s); err != nil {
		return false
	}
	// Check additionalProperties: true
	if ap, ok := s["additionalProperties"]; ok {
		var b bool
		if json.Unmarshal(ap, &b) == nil && b {
			return true
		}
	}
	// Check type: "object" with no properties key
	if tp, ok := s["type"]; ok {
		var t string
		if json.Unmarshal(tp, &t) == nil && t == "object" {
			if _, hasProp := s["properties"]; !hasProp {
				return true
			}
		}
	}
	return false
}
