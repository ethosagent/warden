package proxy

// Path names one protocol path through the proxy: a place where dispatch
// commits an allowed connection to a specific handler. The registry below is the
// single list of them. The dispatch code announces each path it takes with
// p.reach, and the invariant suite (invariants_test.go) has to carry a row for
// every registered path — so a new path cannot ship without leak and deny
// coverage. Adding a path means: add the constant, add it to protocolPaths, call
// p.reach(PathX) at the dispatch site, and add a row to the suite.
type Path string

const (
	// PathTunnel is the opaque byte tunnel: a statically allowed CONNECT with no
	// TLS termination, or plaintext inside a terminated CONNECT.
	PathTunnel Path = "tunnel"
	// PathRawTLS is an unrecognized protocol inside terminated TLS, forwarded raw.
	PathRawTLS Path = "raw-tls"
	// PathHTTP1 is HTTP/1.x inside terminated TLS: the full request stage chain.
	PathHTTP1 Path = "http1"
	// PathH2 is a plain (non-gRPC) HTTP/2 stream.
	PathH2 Path = "h2"
	// PathGRPC is an HTTP/2 stream with an application/grpc content type.
	PathGRPC Path = "grpc"
	// PathWebSocket is a 101 WebSocket upgrade handed to the MCP frame pump.
	PathWebSocket Path = "websocket"
	// PathSSE is an MCP server-sent-events response teed through the SSE scanner.
	PathSSE Path = "sse"
	// PathMCP is an MCP JSON-RPC request classified by the gateway.
	PathMCP Path = "mcp"
)

// protocolPaths is the registry of every path above. Keep it in step with the
// constants; TestPaths_RegistryMatchesDispatch fails when a p.reach call names a
// path that is missing here, or a registered path has no dispatch site.
var protocolPaths = []Path{
	PathTunnel, PathRawTLS, PathHTTP1, PathH2, PathGRPC, PathWebSocket, PathSSE, PathMCP,
}

// ProtocolPaths returns the registered protocol paths, in a stable order.
func ProtocolPaths() []Path { return append([]Path(nil), protocolPaths...) }

// reach announces that dispatch took path. It is a nil check on the hot path;
// only in-package tests install a hook.
func (p *Proxy) reach(path Path) {
	if p.pathHook != nil {
		p.pathHook(path)
	}
}
