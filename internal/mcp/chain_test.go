package mcp

import (
	"testing"
	"time"
)

func TestCallChain_RapidRepeat(t *testing.T) {
	analyzer := NewCallChainAnalyzer(20)
	now := time.Now()
	var lastDetections []ChainDetection
	for i := 0; i < 11; i++ {
		lastDetections = analyzer.Record(CallRecord{
			ToolName:  "web_search",
			Timestamp: now.Add(time.Duration(i) * time.Millisecond * 100),
			Allowed:   true,
		})
	}
	found := false
	for _, d := range lastDetections {
		if d.Pattern == "rapid_repeat" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected rapid_repeat detection, got %+v", lastDetections)
	}
}

func TestCallChain_PermissionProbing(t *testing.T) {
	analyzer := NewCallChainAnalyzer(20)
	now := time.Now()
	var lastDetections []ChainDetection
	deniedTools := []string{"exec_cmd", "write_file", "delete_file"}
	for i, tool := range deniedTools {
		lastDetections = analyzer.Record(CallRecord{
			ToolName:  tool,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Allowed:   false,
		})
	}
	found := false
	for _, d := range lastDetections {
		if d.Pattern == "permission_probing" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected permission_probing detection, got %+v", lastDetections)
	}
}

func TestCallChain_ReadThenSend(t *testing.T) {
	analyzer := NewCallChainAnalyzer(20)
	now := time.Now()
	analyzer.Record(CallRecord{
		ToolName:  "read_file",
		Timestamp: now,
		Allowed:   true,
	})
	detections := analyzer.Record(CallRecord{
		ToolName:  "send_email",
		Timestamp: now.Add(time.Second),
		Allowed:   true,
	})
	found := false
	for _, d := range detections {
		if d.Pattern == "read_then_send" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected read_then_send detection, got %+v", detections)
	}
}

func TestCallChain_NormalUsage(t *testing.T) {
	analyzer := NewCallChainAnalyzer(20)
	now := time.Now()
	tools := []string{"web_search", "format_output", "analyze_data"}
	var lastDetections []ChainDetection
	for i, tool := range tools {
		lastDetections = analyzer.Record(CallRecord{
			ToolName:  tool,
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Allowed:   true,
		})
	}
	if len(lastDetections) != 0 {
		t.Errorf("expected no detections for normal usage, got %+v", lastDetections)
	}
}

func TestCallChain_WindowSlides(t *testing.T) {
	analyzer := NewCallChainAnalyzer(5)
	now := time.Now()
	// Fill window with denied calls
	for i := 0; i < 3; i++ {
		analyzer.Record(CallRecord{
			ToolName:  "denied_" + string(rune('a'+i)),
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Allowed:   false,
		})
	}
	// Now add 5 allowed calls to push the denied ones out
	var lastDetections []ChainDetection
	for i := 0; i < 5; i++ {
		lastDetections = analyzer.Record(CallRecord{
			ToolName:  "allowed_tool",
			Timestamp: now.Add(time.Duration(10+i) * time.Second),
			Allowed:   true,
		})
	}
	// The denied calls should have been pushed out of the window
	for _, d := range lastDetections {
		if d.Pattern == "permission_probing" {
			t.Error("expected permission_probing to be gone after window slides")
		}
	}
}
