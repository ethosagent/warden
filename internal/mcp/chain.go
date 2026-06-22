package mcp

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CallRecord represents a single tool call in the chain.
type CallRecord struct {
	ToolName  string
	Timestamp time.Time
	ArgsHash  string
	Allowed   bool
}

// ChainDetection represents a suspicious pattern detected in the call chain.
type ChainDetection struct {
	Pattern string
	Detail  string
	Tools   []string
}

// ChainPattern defines a named detection function for call chain analysis.
type ChainPattern struct {
	Name   string
	Detect func(window []CallRecord) []ChainDetection
}

// CallChainAnalyzer maintains a sliding window of tool calls and detects
// suspicious patterns.
type CallChainAnalyzer struct {
	mu         sync.Mutex
	windowSize int
	window     []CallRecord
	patterns   []ChainPattern
}

// NewCallChainAnalyzer creates a CallChainAnalyzer with the given window size.
func NewCallChainAnalyzer(windowSize int) *CallChainAnalyzer {
	a := &CallChainAnalyzer{
		windowSize: windowSize,
		patterns: []ChainPattern{
			{Name: "rapid_repeat", Detect: detectRapidRepeat},
			{Name: "permission_probing", Detect: detectPermissionProbing},
			{Name: "read_then_send", Detect: detectReadThenSend},
		},
	}
	return a
}

// Record adds a tool call to the sliding window and returns any detections.
func (a *CallChainAnalyzer) Record(call CallRecord) []ChainDetection {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.window = append(a.window, call)
	if len(a.window) > a.windowSize {
		a.window = a.window[len(a.window)-a.windowSize:]
	}

	var detections []ChainDetection
	for _, p := range a.patterns {
		detections = append(detections, p.Detect(a.window)...)
	}
	return detections
}

// detectRapidRepeat detects same tool called >10 times within 10 seconds.
func detectRapidRepeat(window []CallRecord) []ChainDetection {
	if len(window) == 0 {
		return nil
	}

	latest := window[len(window)-1]
	counts := make(map[string]int)
	for _, r := range window {
		if latest.Timestamp.Sub(r.Timestamp) <= 10*time.Second {
			counts[r.ToolName]++
		}
	}

	var detections []ChainDetection
	for tool, count := range counts {
		if count > 10 {
			detections = append(detections, ChainDetection{
				Pattern: "rapid_repeat",
				Detail:  fmt.Sprintf("tool %q called %d times in 10s", tool, count),
				Tools:   []string{tool},
			})
		}
	}
	return detections
}

// detectPermissionProbing detects 3+ distinct denied tool calls within window.
func detectPermissionProbing(window []CallRecord) []ChainDetection {
	denied := make(map[string]struct{})
	for _, r := range window {
		if !r.Allowed {
			denied[r.ToolName] = struct{}{}
		}
	}
	if len(denied) >= 3 {
		tools := make([]string, 0, len(denied))
		for t := range denied {
			tools = append(tools, t)
		}
		return []ChainDetection{{
			Pattern: "permission_probing",
			Detail:  fmt.Sprintf("%d distinct denied tools in window", len(denied)),
			Tools:   tools,
		}}
	}
	return nil
}

// detectReadThenSend detects a read-type tool followed by a send-type tool.
func detectReadThenSend(window []CallRecord) []ChainDetection {
	isRead := func(name string) bool {
		return name == "read_file" || strings.HasPrefix(name, "get_") || strings.HasPrefix(name, "fetch_") || strings.HasPrefix(name, "list_")
	}
	isSend := func(name string) bool {
		return strings.HasPrefix(name, "send_") || strings.HasPrefix(name, "post_") || strings.HasPrefix(name, "write_") || strings.HasPrefix(name, "upload_")
	}

	for i := 0; i < len(window)-1; i++ {
		if isRead(window[i].ToolName) {
			for j := i + 1; j < len(window); j++ {
				if isSend(window[j].ToolName) {
					return []ChainDetection{{
						Pattern: "read_then_send",
						Detail:  fmt.Sprintf("read tool %q followed by send tool %q", window[i].ToolName, window[j].ToolName),
						Tools:   []string{window[i].ToolName, window[j].ToolName},
					}}
				}
			}
		}
	}
	return nil
}
