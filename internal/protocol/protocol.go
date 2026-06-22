// Package protocol detects the wire protocol from the first decrypted bytes of
// a connection and routes to the appropriate handler. Phase 1 implements HTTP
// detection; gRPC and MCP arrive in later milestones. Unsupported protocols are
// reported as Unknown and (per the architecture) are still gated by the TCP and
// TLS layers — gated, not blocked.
package protocol

import (
	"encoding/json"
	"strings"
)

// Protocol identifies a detected wire protocol.
type Protocol int

const (
	// Unknown is an unrecognized protocol; it is forwarded as raw bytes after
	// the TCP/TLS gates (gated pass-through), not blocked.
	Unknown Protocol = iota
	// HTTP is HTTP/1.x detected from the request line.
	HTTP
	// HTTP2 is HTTP/2, detected from the connection preface. gRPC runs over HTTP/2 but is distinguished at the handler level (content-type), not here.
	HTTP2
	// MCP is the Model Context Protocol, detected post-HTTP from Content-Type
	// and JSON-RPC method inspection (see IsMCP).
	MCP
)

// String renders the protocol for logging.
func (p Protocol) String() string {
	switch p {
	case HTTP:
		return "http"
	case HTTP2:
		return "http2"
	case MCP:
		return "mcp"
	default:
		return "unknown"
	}
}

// httpMethods are the HTTP/1.x request-line tokens used for cheap detection
// from the leading bytes of a connection.
var httpMethods = []string{
	"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
	"OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
}

// Detect inspects the first bytes of a (decrypted) stream and returns the
// protocol. It only needs the leading bytes; callers should peek, not consume.
func Detect(peek []byte) Protocol {
	s := string(peek)
	if strings.HasPrefix(s, "PRI ") {
		return HTTP2
	}
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) {
			return HTTP
		}
	}
	return Unknown
}

// Handler is the minimal contract a protocol handler satisfies. Phase 1 ships a
// no-op HTTP handler skeleton; M1 fills in inspection, policy, and secret swap.
type Handler interface {
	Protocol() Protocol
}

// HTTPHandler is the phase-1 HTTP handler skeleton.
type HTTPHandler struct{}

// NewHTTPHandler constructs the HTTP handler skeleton.
func NewHTTPHandler() *HTTPHandler { return &HTTPHandler{} }

// Protocol reports HTTP.
func (h *HTTPHandler) Protocol() Protocol { return HTTP }

// mcpMethods are the JSON-RPC method names defined by the Model Context
// Protocol. A request whose Content-Type is application/json and whose body
// contains one of these methods is classified as MCP-over-HTTP.
var mcpMethods = []string{
	"tools/call",
	"tools/list",
	"resources/read",
	"resources/list",
	"prompts/get",
	"prompts/list",
	"completion/complete",
	"initialize",
	"ping",
	"notifications/",
	"logging/",
}

// IsMCP checks HTTP headers for MCP indicators. MCP-over-HTTP uses
// Content-Type: application/json with specific JSON-RPC method patterns.
// Call this after HTTP detection, not from Detect().
func IsMCP(contentType string, body []byte) bool {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "application/json") {
		return false
	}
	if len(body) == 0 {
		return false
	}
	var msg struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return false
	}
	if msg.JSONRPC != "2.0" || msg.Method == "" {
		return false
	}
	for _, m := range mcpMethods {
		if strings.HasPrefix(msg.Method, m) {
			return true
		}
	}
	return false
}
