// Package denyreason declares Warden's single closed set of deny reasons
// (rule X6 in #349: deny reasons are declared exactly once, here).
//
// Every deny analytics event (analytics.Event.Reason) and every blocked metric
// label (MetricsRecorder.RecordBlocked) carries a value from this set — the SAME
// value for both, so the dashboard, the alert bridge and warden_blocked_total
// agree on why a request was denied. No other file may declare or write a
// reason value as a literal; TestNoReasonLiteralsOutsideTheDeclaredSet enforces
// that by scanning the tree.
//
// A reason is a bounded enum identifier — metadata, never content — so it is
// safe as a metric label and inside alerts. It never carries a secret value, a
// request/response body, or a raw domain.
package denyreason

// Reason is one bounded deny reason from the declared set.
type Reason string

// The declared set. Grouped by the ticket that introduced the paths, with the
// CONNECT-floor and mediation-shape reasons last. MCP gateway verdict reasons
// (mcp_tool_denied, mcp_poisoning, …) are deliberately NOT redeclared here:
// they are produced (and declared) by internal/mcp/gateway and only pass
// through the proxy.
const (
	// PolicyNoMatch: the destination matched no allowlist entry and no judge
	// could decide it — the default-deny floor (#409).
	PolicyNoMatch Reason = "policy_no_match"
	// PolicyDenylist: the destination matched an explicit denylist entry (#409).
	PolicyDenylist Reason = "policy_denylist"
	// RateLimited: the matched allowlist entry's rate limit was exhausted (#409).
	RateLimited Reason = "rate_limited"
	// TimeWindow: the request fell outside the matched entry's time window (#409).
	TimeWindow Reason = "time_window"

	// PathNotCanonical: the raw request path carries a dot segment, an encoded
	// separator or a matrix parameter, so the matched bytes and the served
	// resource could differ (#371).
	PathNotCanonical Reason = "path_not_canonical"
	// MethodNotAllowed: the method is not in the matched entry's `methods` (#371).
	MethodNotAllowed Reason = "method_not_allowed"
	// PathNotAllowed: the path matches no pattern in the matched entry's
	// `paths` (#371).
	PathNotAllowed Reason = "path_not_allowed"

	// IdentityRequired: the destination is only reachable with a verified
	// identity and the request carries none (W-P1-GPOL-02).
	IdentityRequired Reason = "identity_required"
	// GroupNotAllowed: a verified subject matched the destination only through
	// scoped allow entries that do not name it (W-P1-GPOL-02).
	GroupNotAllowed Reason = "group_not_allowed"
	// IdentityGroupsTruncated: like GroupNotAllowed, but the subject's group
	// list was cut at the cap, so the miss may be an artifact of the cut; it
	// fails closed under its own name (W-P1-GPOL-02).
	IdentityGroupsTruncated Reason = "identity_groups_truncated"

	// H2RequestTrailersUnsupported: an h2 stream declared request trailers,
	// which the h2 forward path does not relay (#388).
	H2RequestTrailersUnsupported Reason = "h2_request_trailers_unsupported"
	// H2ExtendedConnectUnsupported: an RFC 8441 extended CONNECT (WebSocket
	// over h2) the stream path cannot relay faithfully (#388).
	H2ExtendedConnectUnsupported Reason = "h2_extended_connect_unsupported"
	// TransformNeedsBufferedBody: an auth transform needed the body but it
	// could not be buffered (streaming/unknown length) (#388).
	TransformNeedsBufferedBody Reason = "transform_needs_buffered_body"
	// HostMismatch: the Host/:authority disagrees with the CONNECT-time host
	// (defense in depth) (#388).
	HostMismatch Reason = "host_mismatch"
	// RequestTrailersUnsupported: an HTTP/1.1 request declared trailers (#396).
	RequestTrailersUnsupported Reason = "request_trailers_unsupported"

	// GRPCBodyPlaceholder: a gRPC message frame carried a secret placeholder
	// configured for the destination. Placeholders are swapped in metadata only;
	// the frame is refused, never forwarded (#418).
	GRPCBodyPlaceholder Reason = "grpc_body_placeholder"
	// GRPCFrameTooLarge: a gRPC message frame declared a length over the
	// inspection bound, so it cannot be checked and fails closed (#418).
	GRPCFrameTooLarge Reason = "grpc_frame_too_large"
	// GRPCFrameMalformed: the gRPC request body was not valid length-prefixed
	// framing (bad flag byte, or the stream ended inside a frame) (#418).
	GRPCFrameMalformed Reason = "grpc_frame_malformed"
	// GRPCFrameCompressed: a gRPC message frame set the compressed flag, so its
	// payload cannot be inspected and it fails closed (#418).
	GRPCFrameCompressed Reason = "grpc_frame_compressed"

	// SecretEcho: the response echoed a swapped secret value back toward the
	// agent (#389).
	SecretEcho Reason = "secret_echo"
	// SecretEchoUnscannable: the response body could not be scanned for
	// swapped values, so it fails closed (#389).
	SecretEchoUnscannable Reason = "secret_echo_unscannable"

	// SSRFBlocked and SSRFDeniedHostname are written by the SSRF dial guard
	// (#391): proxy.SSRFError carries them and every refusal is audited as a deny.
	// SSRFBlocked: the dial target was refused by the SSRF guard.
	SSRFBlocked Reason = "ssrf_blocked"
	// SSRFDeniedHostname: the dial target's hostname is not allowed by the
	// SSRF guard.
	SSRFDeniedHostname Reason = "ssrf_denied_hostname"

	// UnsupportedProtocol: the CONNECT-floor saw bytes that are not an HTTP
	// CONNECT request line — the "cannot bypass by not being HTTP" audit.
	UnsupportedProtocol Reason = "unsupported_protocol"
	// MalformedConnect: the CONNECT request line could not be parsed into a
	// host:port target.
	MalformedConnect Reason = "malformed_connect"
	// NoTLS: egress that required judge inspection could not be TLS-terminated
	// (no ClientHello / not HTTP inside TLS), so it fails closed.
	NoTLS Reason = "no_tls"

	// TransparentNoSNI: a TLS ClientHello on a transparent :443 listener carried
	// no readable server_name — including an ECH-encrypted hello, whose real
	// SNI Warden cannot read — so the destination is unknown and the handshake
	// is refused (fail closed) (#376).
	TransparentNoSNI Reason = "transparent_no_sni"
	// TransparentBadClientHello: the bytes on a transparent :443 listener were
	// not a parseable TLS ClientHello (truncated, over-limit or malformed)
	// (#376).
	TransparentBadClientHello Reason = "transparent_bad_client_hello"
	// TransparentH2PriorKnowledge: plaintext HTTP/2 prior-knowledge bytes
	// arrived on a transparent :443 listener, where no TLS ClientHello — and so
	// no SNI to gate on — can exist (#376).
	TransparentH2PriorKnowledge Reason = "transparent_h2_prior_knowledge"
	// TransparentLoopGuard: an upstream dial resolved to one of Warden's OWN
	// transparent listener addresses, so serving it would re-enter the proxy
	// (an interception loop); the dial is refused (#376).
	TransparentLoopGuard Reason = "transparent_loop_guard"
	// MalformedRequest: the plain-HTTP transparent floor refused a request that
	// is not parseable enough to gate — no Host header, or a header block over
	// the byte budget (#376).
	MalformedRequest Reason = "malformed_request"

	// Judge: the inline LLM judge denied (or was disabled mid-flight for a
	// NoMatch request). The free-text rationale rides JudgeReason, never here.
	Judge Reason = "judge"

	// DLPBlock: the outbound request body hit a DLP rule in enforce mode with
	// action=block.
	DLPBlock Reason = "dlp_block"
	// DLPRedact: a decoded-layer DLP redact could not be located inline, so
	// the request was escalated to a fail-closed block.
	DLPRedact Reason = "dlp_redact"

	// MCPWS: the WebSocket frame pump reported a blocked (denied) message.
	MCPWS Reason = "mcp_ws"
	// MCPWSUnscannable: MCP enforce mode could not scan a WebSocket upgrade,
	// so it is refused.
	MCPWSUnscannable Reason = "mcp_ws_unscannable"
	// MCPSSEEventTooLarge: an MCP SSE event exceeded the scan cap in enforce
	// mode, so it was held back rather than forwarded unscanned (#400).
	MCPSSEEventTooLarge Reason = "mcp_sse_event_too_large"
	// MCPGatewayDeny: an MCP gateway verdict denied without naming a reason.
	// Gateway reasons (mcp_tool_denied, mcp_poisoning, …) are declared in
	// internal/mcp/gateway and pass through the proxy; this is the fallback so
	// a gateway deny is never anonymous (#409).
	MCPGatewayDeny Reason = "mcp_gateway_deny"

	// HTTPResponseLeak: the non-MCP response scan found a high-severity
	// credential leak in enforce mode.
	HTTPResponseLeak Reason = "http_response_leak"
	// HTTPResponseInjection: the non-MCP response scan found a high-severity
	// injection in enforce mode.
	HTTPResponseInjection Reason = "http_response_injection"

	// Unspecified: the never-in-practice fallback the proxy's emitDeny
	// substitutes when a deny reaches it without a reason. The deny path is one
	// chokepoint (internal/proxy emitDeny/emitDenyEvent), so this label on a
	// metric or event means a code path bypassed the helper — it is logged
	// loudly there, and the proxy test fakes fail the run outright (rule X6,
	// #349; #409 review).
	Unspecified Reason = "unspecified"
)

// declared is the whole set, used by Declared and the self-checks. Keep in sync
// with the block above; TestDeclaredSetIsComplete pins it.
var declared = []Reason{
	PolicyNoMatch, PolicyDenylist, RateLimited, TimeWindow,
	PathNotCanonical, MethodNotAllowed, PathNotAllowed,
	IdentityRequired, GroupNotAllowed, IdentityGroupsTruncated,
	H2RequestTrailersUnsupported, H2ExtendedConnectUnsupported,
	TransformNeedsBufferedBody, HostMismatch, RequestTrailersUnsupported,
	GRPCBodyPlaceholder, GRPCFrameTooLarge, GRPCFrameMalformed, GRPCFrameCompressed,
	SecretEcho, SecretEchoUnscannable,
	SSRFBlocked, SSRFDeniedHostname,
	UnsupportedProtocol, MalformedConnect, NoTLS,
	TransparentNoSNI, TransparentBadClientHello,
	TransparentH2PriorKnowledge, TransparentLoopGuard,
	MalformedRequest,
	Judge,
	DLPBlock, DLPRedact,
	MCPWS, MCPWSUnscannable, MCPSSEEventTooLarge, MCPGatewayDeny,
	HTTPResponseLeak, HTTPResponseInjection,
	Unspecified,
}

// Declared returns every reason in the set, for tests and tooling. The order
// is not significant.
func Declared() []Reason {
	out := make([]Reason, len(declared))
	copy(out, declared)
	return out
}

// Declared reports whether r is part of the declared set.
func (r Reason) Declared() bool {
	for _, d := range declared {
		if r == d {
			return true
		}
	}
	return false
}
