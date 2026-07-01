package proxy

import (
	"strings"

	"github.com/ethosagent/warden/internal/scan"
)

// responseScan modes (mirror the gateway's off/monitor/enforce).
const (
	responseScanOff     = "off"
	responseScanMonitor = "monitor"
	responseScanEnforce = "enforce"
)

// ResponseScanner scans ordinary (non-MCP) HTTP response bodies for credential
// leakage, prompt injection, and PII, applying an off/monitor/enforce mode that
// mirrors the MCP gateway. It is safe for concurrent use (the underlying
// scan.Scanner is immutable after construction). Nil = disabled.
type ResponseScanner struct {
	scanner  scan.Scanner
	mode     string
	maxBytes int
}

// NewResponseScanner builds a scanner from the mode + cap + PII/evidence opts.
// A cap <= 0 defaults to 1 MiB so the proxy never buffers an unbounded body.
func NewResponseScanner(mode string, maxBytes int, phonePII, evidence bool) *ResponseScanner {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	if mode == "" {
		mode = responseScanMonitor
	}
	return &ResponseScanner{
		scanner:  scan.NewScanner(scan.WithPhonePII(phonePII), scan.WithEvidence(evidence)),
		mode:     mode,
		maxBytes: maxBytes,
	}
}

// MaxBytes returns the buffered-body cap.
func (r *ResponseScanner) MaxBytes() int { return r.maxBytes }

// enforcing reports whether the scanner may replace a flagged body.
func (r *ResponseScanner) enforcing() bool { return r.mode == responseScanEnforce }

// scannable reports whether a response with this content-type and content-length
// can be safely buffered and scanned. Streaming (text/event-stream), unknown or
// negative length, and over-cap bodies are NOT scannable — the caller forwards
// them unchanged and logs a skip. Only textual/JSON-ish bodies are worth scanning.
func (r *ResponseScanner) scannable(contentType string, contentLength int64) bool {
	if contentLength < 0 || contentLength > int64(r.maxBytes) {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(ct, "text/event-stream") {
		return false
	}
	// scan textual and JSON/form/xml bodies; skip binary (images, octet-stream, etc.)
	if ct == "" {
		return true // no content-type: err toward scanning a small buffered body
	}
	return strings.HasPrefix(ct, "text/") ||
		strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/xml") ||
		strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "application/javascript")
}

// Scan runs the detectors over body and returns the detections plus whether the
// response should be blocked. Blocking is true only in enforce mode AND when a
// high-severity detection is present (mirrors the gateway's applyScanSeverity:
// only "high" severity blocks). reason is a bounded kind for the deny event:
// "http_response_leak" or "http_response_injection" (leak wins if both present;
// PII alone never blocks). Detections are always returned (for logging) even when
// not blocking.
func (r *ResponseScanner) Scan(body []byte) (dets []scan.Detection, block bool, reason string) {
	dets = r.scanner.ScanResponse(body)
	if !r.enforcing() {
		return dets, false, ""
	}
	highLeak, highInjection := false, false
	for _, d := range dets {
		if d.Severity != "high" {
			continue
		}
		switch d.Category {
		case "credential_leak":
			highLeak = true
		case "injection":
			highInjection = true
		}
	}
	switch {
	case highLeak:
		return dets, true, "http_response_leak"
	case highInjection:
		return dets, true, "http_response_injection"
	default:
		return dets, false, ""
	}
}
