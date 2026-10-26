package proxy

import (
	"bufio"
	"bytes"

	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/mcp/sse"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/protocol"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/internal/secrets"
)

const maxBodySwapSize = 10 << 20 // 10 MB

// requestScope owns one HTTP request's mutable state and its three closables
// (request body, response body, upstream conn) for the duration of a single
// keep-alive iteration. Every stage of handleHTTP takes/mutates the scope, and a
// single deferred scope.cleanup() releases the closables on every exit path —
// replacing the old hand-rolled close triplets that each terminal branch
// repeated. See cleanup for the exact per-path close semantics.
type requestScope struct {
	// Per-connection context (constant across the keep-alive session, copied in
	// per request so stages read one value). clientConn is the client-facing
	// conn — the terminated TLS conn on both CONNECT and transparent :443, or
	// the raw TCP conn on the transparent plain-HTTP listener (#376).
	clientConn net.Conn
	br         *bufio.Reader
	domain     string
	port       int
	needsJudge bool
	// scheme is this connection's UPSTREAM scheme: https on every terminated
	// tunnel, http only on the transparent plain-HTTP listener. It selects the
	// constraint-gate evaluation, the event URL prefix and the upstream dial
	// (TLS vs plain); the zero value is SchemeHTTPS, so the h2 paths — which
	// never ride plain HTTP — need not set it.
	scheme policy.Scheme

	// out frames every client-bound response (see responseSink). rt is non-nil
	// only on HTTP/2: forward then round-trips over it instead of dialing an
	// HTTP/1.1 conn, and the stages that assume an h1 conn (readRequest's
	// mismatch handling, the WebSocket upgrade) branch on it. proto is the
	// protocol label of this request's events: "https" on h1, "http" on the
	// transparent plain-HTTP listener, "http2" or "grpc" on h2 (an MCP request
	// is always "mcp").
	out   responseSink
	rt    http.RoundTripper
	proto string
	// streamBody marks a gRPC request: its (protobuf, possibly unbounded
	// bidirectional-stream) body is never buffered whole or swapped — it is
	// relayed verbatim message by message (inspected by grpcGuard), and DLP
	// records it as partial like any non-text body.
	streamBody bool
	// grpcGuard inspects a gRPC request body frame by frame (nil when no
	// placeholder is in scope for the destination, or for non-gRPC requests).
	grpcGuard *grpcFrameGuard

	// Per-request atomic-pointer snapshots, taken ONCE at the top of the request
	// so a concurrent control-plane swap can't change them mid-request.
	gw        MCPGateway
	liveJudge Judge

	// req and resp are per-request closables cleanup closes exactly once. The
	// upstream conn (upstream + its upstreamBR) is owned by the SESSION, not the
	// request: handleHTTP carries it across keep-alive iterations for reuse and
	// closes it exactly once when the session ends, so cleanup never touches it.
	req        *http.Request
	resp       *http.Response
	upstream   net.Conn
	upstreamBR *bufio.Reader
	// reused is true when upstream was carried over from a prior keep-alive
	// response (an already-connected conn), so forward writes to it and, on a
	// stale half-closed conn, redials ONCE. A fresh (reused==false) dial never
	// retries. The SAME upstreamBR is carried so buffered next-response bytes are
	// preserved.
	reused bool
	// handoff is set when the connection lifecycle is handed to the WebSocket
	// pump, which owns and closes the upstream (and the response) itself. cleanup
	// must NOT touch resp in that case, and the session must NOT close the
	// upstream (the pump does), to avoid a double close.
	handoff bool

	// inflightDone, non-nil only when an assembly-only quiescence tracker is
	// installed (worker.Overrides.Inflight; production nil = one nil check),
	// leaves the tracker for this request scope. It runs on every terminal path
	// AFTER the scope's bookkeeping (audit event, metric, decision log) is
	// recorded — that ordering is what makes a drained tracker happen-after all
	// of the request's analytics — and is idempotent, so the streaming paths
	// (WS handoff, SSE) can step out early and re-enter without double-firing.
	inflightDone func()

	// reqBody is the request body read ONCE (bounded by maxBodySwapSize+1) and
	// shared by MCP inspection and the secret swap. bodyRead records that the
	// single read has happened so a second consumer reuses the buffer instead of
	// re-reading a spent body.
	reqBody  []byte
	bodyRead bool
	// trailerDenied is set by trailerGuard when the h1 request body ended with
	// trailer fields; denyTrailers (set by stripHopHeaders) answers the 400 deny.
	trailerDenied bool
	denyTrailers  func()

	// Identity (identity.go). ci is the connection's CONNECT identity; rawIdentity
	// and rawIdentityN are the X-Warden-Identity value and count captured before
	// stripHopHeaders deletes it, cleared again by identityStage. The id* fields
	// are the resolved result; subject is non-nil only for status valid. idClaims
	// may hold the unverified sub of an invalid or expired token: for the
	// block-list deny check only, never for a policy decision.
	ci           connIdentity
	rawIdentity  string
	rawIdentityN int
	idStatus     identity.Status
	idReason     identity.Reason
	idClaims     identity.Claims
	subject      *identity.Subject

	// Decision state threaded between stages.
	judgeReason string
	wasMCP      bool
	mcpTool     string
	mcpReason   string
	mcpSessKey  string
	closeAfter  bool

	// reqStart is the wall-clock instant this request was read off the wire
	// (captured in serveHTTPRequest right after http.ReadRequest). Every event the
	// request produces records LatencyMs = time.Since(reqStart) at write time, so
	// the whole mediation cost (request-read → response-relayed) is one number on
	// each event — always safe, always populated.
	reqStart time.Time

	// Secret-swap results, carried onto the single forwarding audit event.
	// swappedNames is the set of placeholder NAMES actually swapped (bounded,
	// log-safe tokens the agent already holds — never secret values); it also feeds
	// Event.SwappedRefs.
	refs         []secrets.Reference
	swappedNames []string

	// echoSecrets are the exact real values put into THIS request (swapped
	// placeholders and auth-transformer injections); the echo guard checks the
	// response for them. Empty — and the guard fully skipped — when nothing was
	// swapped. echoMonitorReason is set when monitor mode saw a hit (rides the allow
	// event); abortStream is set when a streaming response was cut for a hit.
	echoSecrets []echoSecret
	// origRawQuery is the query as the agent sent it, kept only when a swap rewrote
	// it, so an event never records the swapped (real) value.
	origRawQuery      string
	echoMonitorReason string
	abortStream       bool
	echoRdr           *echoReader // the streaming response guard, if one was installed

	// evidence collects bounded, MASKED evidence samples (the value-free
	// "••••<last4> (len N)" form) from scan/DLP findings on this request, capped at
	// maxEvidenceSamples. It rides Event.Evidence — never raw matched content.
	evidence []string

	// DLP results, carried onto the single forwarding audit event. All zero when
	// DLP is off, so the off-case event is identical to today. dlpClasses is the
	// deduplicated set of detection categories seen in the PRE-SWAP body;
	// dlpAction is "monitor" when DLP inspected the request (Phase 1 never blocks);
	// dlpPartial flags honest under-coverage (over-cap body or non-scannable type);
	// dlpEncoded flags a redact/block finding that lived only in a decoded/classifier
	// layer with no raw offset — set by dlpApplyRedact's fail-closed escalation.
	dlpClasses []string
	dlpAction  string
	dlpRule    string
	dlpPartial bool
	dlpEncoded bool
}

// cleanup releases the REQUEST's closables exactly once, on whatever exit path
// serveHTTPRequest returns through. The upstream conn is NOT a request closable —
// the session (handleHTTP) owns and closes it — so cleanup only handles bodies:
//   - req.Body is always closed (http.ReadRequest always leaves it non-nil).
//   - resp.Body is closed on non-handoff paths (harmless — a fully relayed
//     response was already drained by resp.Write; a terminal path may leave a
//     partial body that Close releases).
//   - When handoff is set (WebSocket upgrade) resp is left alone: the frame pump
//     owns the raw conn and the 101 response has no separate body to close.
func (s *requestScope) cleanup() {
	if s.req != nil && s.req.Body != nil {
		_ = s.req.Body.Close()
	}
	if s.handoff {
		return
	}
	if s.resp != nil && s.resp.Body != nil {
		_ = s.resp.Body.Close()
	}
}

// endInflight leaves the quiescence tracker for this scope (a no-op when no
// tracker is installed or the scope already stepped out — done is idempotent).
// It runs deferred in serveHTTPRequest, i.e. after every stage's bookkeeping.
func (s *requestScope) endInflight() { runInflight(s.inflightDone) }

// ensureBody reads req.Body exactly once (bounded by maxBodySwapSize+1), caches
// the bytes on the scope, and restores req.Body as a re-readable NopCloser so a
// later consumer and req.Write(upstream) still see the full payload. Repeat calls
// return the cached bytes without re-reading, so MCP inspection and the secret
// swap share a single read.
//
// A nil / http.NoBody request body reads as nil bytes without a read or a
// restore, preserving the old per-site "only touch the body when present" guard.
// On a read error it writes 502 and on an over-limit body 413 (the exact
// terminal responses the two old read sites produced), returning ok=false so the
// caller returns immediately and the deferred cleanup runs.
func (s *requestScope) ensureBody() (body []byte, ok bool) {
	if s.bodyRead {
		return s.reqBody, true
	}
	if s.req.Body == nil || s.req.Body == http.NoBody {
		s.bodyRead = true
		s.reqBody = nil
		return nil, true
	}
	b, err := io.ReadAll(io.LimitReader(s.req.Body, maxBodySwapSize+1))
	if err != nil {
		if s.trailerDenied {
			s.denyTrailers()
			return nil, false
		}
		s.out.errorResponse(502, "Bad Gateway")
		return nil, false
	}
	if int64(len(b)) > maxBodySwapSize {
		s.out.errorResponse(413, "Request body too large for secret substitution")
		return nil, false
	}
	s.reqBody = b
	s.bodyRead = true
	// Restore the body so the downstream secret-swap re-read and
	// req.Write(upstream) still see the full payload.
	s.req.Body = io.NopCloser(bytes.NewReader(b))
	return b, true
}

// maxEvidenceSamples caps how many masked evidence samples ride one event, so a
// pathological body full of findings cannot bloat the record. Each sample is
// already length-bounded by scan's masker.
const maxEvidenceSamples = 8

// latencyMs returns the mediation latency so far in whole milliseconds, from the
// request-read instant (reqStart) to now. Cheap (one time.Now) and always safe —
// it is a plain number recorded on every event the request produces.
func (s *requestScope) latencyMs() int64 {
	return time.Since(s.reqStart).Milliseconds()
}

// addEvidence appends the MASKED evidence samples carried by dets (the value-free
// "••••<last4> (len N)" form; empty when a scanner was built without evidence) onto
// the scope, skipping empties and stopping at maxEvidenceSamples. It never sees raw
// matched content — only the masked sample the scanner already produced.
func (s *requestScope) addEvidence(dets []scan.Detection) {
	for _, d := range dets {
		if d.Evidence == "" {
			continue
		}
		if len(s.evidence) >= maxEvidenceSamples {
			return
		}
		s.evidence = append(s.evidence, d.Evidence)
	}
}

// handleHTTP serves the keep-alive loop for one client conn whose requests all
// target the same fixed domain:port. It is the shared h1 path for BOTH arrivals
// of an allowed TLS destination — the CONNECT tunnel and the transparent :443
// listener (scheme https, clientConn the terminated TLS conn) — and the
// transparent plain-HTTP listener (#376: scheme http, clientConn the raw TCP
// conn). firstReq, when non-nil, is the request the transparent floor already
// read and gated while admitting the connection; the loop serves it instead of
// reading another.
//
// The SESSION owns the upstream conn: one upstream (+ its bufio.Reader) is
// carried across iterations so N keep-alive requests to this single fixed host
// pay ONE upstream dial instead of N. A CONNECT tunnel targets exactly one
// domain:port, so intra-session reuse never crosses hosts.
//
// serveHTTPRequest returns the upstream to carry (nil after a WebSocket handoff,
// which hands ownership to the frame pump). The deferred close fires ONCE for
// whatever upstream is current when the loop exits — for any reason: a clean
// Connection: close, a deny/502 terminal, an SSE stream, a client EOF, or a
// stale-conn redial's fresh conn. It is nil (nothing to close) before the first
// forward and after a handoff, so there is no double close and no leak.
func (p *Proxy) handleHTTP(clientConn net.Conn, br *bufio.Reader, domain string, port int, needsJudge bool, scheme policy.Scheme, firstReq *http.Request, ci connIdentity) {
	if scheme == policy.SchemeHTTPS {
		p.reach(PathHTTP1)
	} else {
		p.reach(PathTransparentHTTP)
	}
	var upstream net.Conn
	var upstreamBR *bufio.Reader
	defer func() {
		if upstream != nil {
			_ = upstream.Close()
		}
	}()
	for {
		end, up, upBR := p.serveHTTPRequest(clientConn, br, domain, port, needsJudge, scheme, firstReq, upstream, upstreamBR, ci)
		// The pre-read first request is served exactly once; later iterations
		// read from the wire like every keep-alive request.
		firstReq = nil
		upstream, upstreamBR = up, upBR
		if end {
			return
		}
	}
}

// serveHTTPRequest reads and serves one request end-to-end as the named stage
// sequence, with a single deferred cleanup releasing the request's body closables
// on every exit. The carried-in upstream (nil on the session's first request, or
// the reusable conn from a prior clean keep-alive response) is threaded onto the
// scope so forward reuses it. firstReq, when non-nil, was already read (and
// policy-gated) by the transparent plain-HTTP floor; it is served as-is. It
// returns whether the session should end plus the upstream to carry forward: the
// scope's upstream on every non-handoff path (the session closes it on exit or
// reuses it next iteration), or nil after a WebSocket handoff so the session does
// not double-close the pump-owned conn.
func (p *Proxy) serveHTTPRequest(clientConn net.Conn, br *bufio.Reader, domain string, port int, needsJudge bool, scheme policy.Scheme, firstReq *http.Request, upstream net.Conn, upstreamBR *bufio.Reader, ci connIdentity) (endSession bool, carryUpstream net.Conn, carryBR *bufio.Reader) {
	req := firstReq
	if req == nil {
		var err error
		req, err = http.ReadRequest(br)
		if err != nil {
			// Client gone / EOF between keep-alive requests: end the session and let it
			// close whatever upstream was carried in (nil if none was ever dialed).
			return true, upstream, upstreamBR
		}
	}
	// Mediation-latency clock starts at the request-read point and stops where each
	// event is written (see requestScope.latencyMs). time.Now (not the injectable
	// leaf-cert clock) so latency is real wall time on every event.
	reqStart := time.Now()

	// Snapshot the live MCP gateway and judge once per request through their
	// atomic pointers, so a concurrent control-plane swap can't change them
	// mid-request. A nil gw/judge means the feature is disabled — identical to a
	// nil cfg.MCP / cfg.Judge before.
	s := &requestScope{
		clientConn: clientConn,
		out:        connSink{w: clientConn},
		proto:      schemeProto(scheme),
		scheme:     scheme,
		br:         br,
		domain:     domain,
		port:       port,
		needsJudge: needsJudge,
		req:        req,
		reqStart:   reqStart,
		gw:         p.mcpGateway(),
		liveJudge:  p.judge(),
		upstream:   upstream,
		upstreamBR: upstreamBR,
		reused:     upstream != nil,
		ci:         ci,
	}
	// The quiescence tracker is entered by runRequestStages — the ONE pipeline
	// both h1 requests and h2/gRPC streams run — so this h1 path and serveGRPCStream
	// share a single entry/exit point. Deferred here: the request's closables are
	// released on every exit path after the stages (and their bookkeeping) ran.
	defer s.cleanup()

	end := p.runRequestStages(s)
	if s.handoff {
		// The frame pump owns and closes s.upstream; the session must not.
		return true, nil, nil
	}
	// The session owns s.upstream: it closes it on end==true and reuses it on the
	// clean end==false path. On a stale-conn redial s.upstream is the fresh conn.
	return end, s.upstream, s.upstreamBR
}

// runRequestStages runs the named stage chain for one request and returns whether
// the keep-alive session should end.
//
// It is also the ONE quiescence-tracker entry/exit for both protocols (#363):
// every h1 request (serveHTTPRequest) and every h2/gRPC stream (serveGRPCStream)
// runs this pipeline, so one tracked unit per request scope starts here and the
// deferred endInflight leaves it on every exit path AFTER the scope's terminal
// bookkeeping is recorded — the allow path records its event only after the
// response is already in the agent's hands, so "the response arrived" does not
// imply "the analytics are readable"; a drained tracker does. The entry sits
// after the request-read point (an idle keep-alive conn parked in ReadRequest
// stays OUT of the tracker, so pooled-but-idle agent connections never block a
// waiter), and the streaming paths step out at delivery and re-enter before
// their terminal event (relayMCPSSE, handleWSUpgrade). Every terminal branch the
// stages reach — echo-guard denies and stream aborts, readRequest's h2
// refusals, badGateway — leaves exactly once through that defer, after its
// bookkeeping. Production (no tracker) pays one nil check and builds no
// description string (the guard keeps the concatenation off the hot path — see
// the allocation note on inflightStart).
func (p *Proxy) runRequestStages(s *requestScope) (endSession bool) {
	if p.cfg.Inflight != nil {
		s.inflightDone = p.inflightStart(s.proto + " " + s.req.Method + " " + s.eventURL())
	}
	defer s.endInflight()

	if p.readRequest(s) {
		return true
	}
	p.captureIdentityHeader(s)
	if p.stripHopHeaders(s) {
		return true
	}
	if p.identityStage(s) {
		return true
	}
	if p.constraintGate(s) {
		return true
	}
	if p.judgeGate(s) {
		return true
	}
	if p.mcpRequestScan(s) {
		return true
	}
	if p.dlpScan(s) {
		return true
	}
	if p.swapSecrets(s) {
		return true
	}
	if p.applyTransforms(s) {
		return true
	}
	if p.forward(s) {
		return true
	}
	return p.relayResponse(s)
}

// readRequest validates that the just-read request belongs on this connection:
// a host-header recheck (defense in depth) against the CONNECT-time domain, plus
// the HTTP/2 shapes the proxy cannot mediate faithfully. Every refusal records a
// deny event so it is never silent. A refusal ends the session on h1 (cleanup
// closes req.Body); an h2 stream is refused alone, the connection's others go on.
// Both sides of the host recheck go through policy.NormalizeHost (#397), so case
// and any number of trailing dots cannot make the recheck disagree with the
// CONNECT admission it belongs to — while a different host, or a Host header
// that is only dots (normalised to ""), is still refused (fail closed).
func (p *Proxy) readRequest(s *requestScope) (endSession bool) {
	hostOnly := s.req.Host
	if h, _, err := net.SplitHostPort(s.req.Host); err == nil {
		hostOnly = h
	}
	if policy.NormalizeHost(hostOnly) != policy.NormalizeHost(s.domain) {
		p.emitDeny(s, denyreason.HostMismatch, denyExtra{LatencyMs: s.latencyMs()})
		if s.rt != nil {
			s.out.errorResponse(http.StatusMisdirectedRequest, "Misdirected Request")
		}
		return true
	}
	if s.rt == nil {
		return false
	}
	// RFC 8441 extended CONNECT (WebSocket over h2) cannot be relayed by the stream
	// path. x/net does not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL by default (only
	// with GODEBUG=http2xconnect=1); refuse explicitly if a client sends it anyway, so
	// it falls back to the h1 WebSocket path.
	if s.req.Header.Get(":protocol") != "" {
		p.emitDeny(s, denyreason.H2ExtendedConnectUnsupported, denyExtra{LatencyMs: s.latencyMs()})
		s.out.errorResponse(http.StatusNotImplemented, "Not Implemented")
		return true
	}
	// Request trailers are not forwarded by forwardH2; dropping them silently would
	// change the request, so a stream that declares them is refused.
	if len(s.req.Trailer) > 0 {
		p.emitDeny(s, denyreason.H2RequestTrailersUnsupported, denyExtra{LatencyMs: s.latencyMs()})
		s.out.errorResponse(http.StatusBadRequest, "Bad Request")
		return true
	}
	return false
}

// recordSSRFDeny is the deny path for a dial the SSRF-safe dialer refused
// (#391): one deny through the emitDeny chokepoint with the bounded ssrf_*
// reason and the address class. It is a no-op for any other error, so ordinary
// dial failures (DNS failure, timeout, connection refused) keep their
// long-standing treatment — a 502 with no analytics event, never an ssrf_* deny.
func (p *Proxy) recordSSRFDeny(s *requestScope, err error) {
	se, ok := AsSSRFError(err)
	if !ok {
		return
	}
	p.emitDeny(s, ssrfDenyReason(se), denyExtra{AddrClass: se.AddrClass, LatencyMs: s.latencyMs()})
}

// constraintGate enforces the #371 method/path constraints on EVERY request of
// a keep-alive tunnel. CONNECT admission only could-matched them (domain+port,
// rate limit peeked); this per-request evaluation is authoritative and counts
// the request exactly once. It runs before the judge, before any secret swap,
// and before any upstream write, so a denied request never reaches the origin
// and never carries a real secret. The path matched is the RAW request target
// component — req.URL.EscapedPath() — which is byte-for-byte the path req.Write
// sends upstream (RequestURI renders EscapedPath); URL.Path (decoded) would not
// be what the origin sees. A NoMatch falls through unchanged (judge-eligible
// exactly as before); an explicit Deny is terminal — a constraint violation is
// never judge-eligible, by construction of the evaluator.
func (p *Proxy) constraintGate(s *requestScope) (endSession bool) {
	verdict := p.cfg.Policy.EvaluateRequest(s.domain, s.port, s.scheme, s.req.Method, s.req.URL.EscapedPath())
	if verdict.Decision != policy.Deny {
		return false
	}
	// Every explicit Deny names itself from the declared set (#409): a
	// constraint violation (method_not_allowed / path_not_allowed /
	// path_not_canonical), a denylist hit, or an exhausted guard.
	p.emitDeny(s, verdict.Reason, denyExtra{LatencyMs: s.latencyMs()})
	s.out.errorResponse(403, "Forbidden")
	return true
}

// judgeGate runs the inline judge for requests that matched no static rule. The
// judge receives auth *presence* only, never the auth value, and fails closed
// (deny) on any error or when it was disabled between CONNECT and now. On allow
// the reason is carried onto the single forwarding event so there is exactly one
// audit event per request; on deny the request terminates here with its own
// event.
func (p *Proxy) judgeGate(s *requestScope) (endSession bool) {
	if !s.needsJudge {
		return false
	}
	fullURL := s.eventURL()
	_, hasAuth := s.req.Header["Authorization"]
	// needsJudge was decided at CONNECT time. If a concurrent control-plane swap
	// disabled the judge between then and now, liveJudge is nil: this request
	// matched no static rule and there is no judge to allow it, so it must fail
	// closed (deny) — the exact default-deny semantics a NoMatch request gets
	// when no judge is configured.
	var verdict Verdict
	if s.liveJudge != nil {
		verdict = s.liveJudge.Evaluate(
			p.cfg.AgentID, s.req.Method, fullURL, s.domain,
			s.req.Header.Get("Content-Type"), hasAuth,
		)
	} else {
		verdict = Verdict{Decision: "deny", Reason: "judge disabled"}
	}
	if verdict.Decision != "allow" {
		p.emitDeny(s, denyreason.Judge, denyExtra{
			JudgeReason: verdict.Reason,
			LatencyMs:   s.latencyMs(),
			SwappedRefs: s.swappedNames,
			Evidence:    s.evidence,
		})
		p.cfg.Metrics.RecordJudge("deny")
		s.out.errorResponse(403, "Forbidden")
		return true
	}
	s.judgeReason = verdict.Reason
	p.cfg.Metrics.RecordJudge("allow")
	return false
}

// mcpRequestScan inspects an MCP JSON-RPC request through the gateway. When the
// gateway is nil the whole stage is skipped: no body read, no behavior change —
// byte-identical to before. When enabled it reads the body once (shared with the
// secret swap via the scope), classifies it, and on a Deny verdict terminates
// with its own audit event.
func (p *Proxy) mcpRequestScan(s *requestScope) (endSession bool) {
	if s.gw == nil || s.streamBody {
		return false
	}
	body, ok := s.ensureBody()
	if !ok {
		return true
	}
	ct := s.req.Header.Get("Content-Type")
	if !protocol.IsMCP(ct, body) {
		return false
	}
	s.wasMCP = true
	p.reach(PathMCP)
	fullURL := s.eventURL()
	s.mcpSessKey = p.cfg.AgentID + ":" + s.domain
	start := time.Now()
	v := s.gw.OnRequest(s.mcpSessKey, s.req.Method, fullURL, s.req.Header, body)
	p.cfg.Metrics.ObserveAddedLatency("mcp_scan", time.Since(start))
	p.recordMCPFindings(v)
	s.mcpTool = v.Tool
	s.mcpReason = v.Reason
	if v.Action == gateway.Deny {
		p.emitDeny(s, gatewayDenyReason(v.Reason), denyExtra{
			Protocol:    "mcp",
			Tool:        v.Tool,
			LatencyMs:   s.latencyMs(),
			SwappedRefs: s.swappedNames,
			Evidence:    s.evidence,
		})
		s.out.errorResponse(403, "Forbidden")
		return true
	}
	return false
}

// dlpScan runs the outbound REQUEST-body DLP scan as a named stage placed
// BETWEEN mcpRequestScan and swapSecrets. The ordering is load-bearing: it scans
// the PRE-SWAP body, so a Warden-managed secret VALUE (injected only later, in
// swapSecrets) never reaches the scanner, and a configured placeholder NAME in
// the body is an inert token — never classified as a credential, never mutated
// here, and still swapped normally downstream.
//
// It records findings on the scope (which ride the single audit event) + bounded
// metrics. With NO policy configured (no rules/class-defaults) or no data class
// detected it is pure observability: action="monitor", never blocks. When a policy
// IS configured and a class is detected it evaluates the per-class egress rules;
// in ENFORCE mode a block verdict terminates here with a 403 + deny event and a
// redact verdict scrubs the matched spans inline (dlpApplyRedact) before forwarding.
// MONITOR mode records the would-be action but NEVER blocks or mutates the body —
// the zero-risk wedge.
//
// DLP is FAIL-OPEN on unscannable bodies and never 413s. It only performs the
// shared buffered read when that read provably cannot 413 (a known Content-Length
// that fits maxBodySwapSize, or a body an earlier stage already buffered). An
// over-cap body (Content-Length > cap) or an unknown-length/chunked body
// (Content-Length < 0) is flagged dlp_partial and FORWARDED WITHOUT reading — the
// same honest coverage gap as an unscannable response stream; DLP does not
// stream-scan chunked bodies (a later phase can). This guarantees dlpScan never
// writes a 413 and never consumes a body it cannot restore, so the swap/MCP 413
// contract is theirs alone: when a swap IS configured and the body is over-cap,
// swapSecrets still 413s later exactly as it does today — DLP just does not
// pre-empt it. (Enforce blocking, above, is a 403 — distinct from the 413 caps.)
//
// mode: off (p.dlp() == nil) returns immediately with NO body read, NO event
// fields, and NO metric — byte-identical to before.
func (p *Proxy) dlpScan(s *requestScope) (endSession bool) {
	d := p.dlp()
	if d == nil {
		return false
	}
	// DLP inspected this request. Default the recorded action to "monitor" (DLP saw
	// it, nothing to police); the policy evaluation below overrides it with the
	// verdict when a policy is configured and a data class is detected. Every path
	// that forwards without evaluating (non-scannable, over-cap, chunked, empty)
	// keeps "monitor".
	s.dlpAction = dlpMonitor

	ct := s.req.Header.Get("Content-Type")
	if !scannableContentType(ct) {
		// Binary/octet-stream/SSE/multipart or otherwise non-textual: don't read
		// the body, flag honest under-coverage, and forward (monitor never blocks).
		s.dlpPartial = true
		return false
	}

	// Body acquisition — the fail-open gate. Read only when it is SAFE (the body
	// provably fits the buffer); otherwise flag partial and forward WITHOUT
	// reading, so dlpScan can never 413 and never strand an unrestorable body.
	var body []byte
	switch {
	case s.bodyRead:
		// An earlier stage (MCP scan / swap) already buffered the body; it is
		// ≤ maxBodySwapSize by construction (ensureBody 413s before caching an
		// over-cap body). Reuse it.
		body = s.reqBody
	case s.req.ContentLength >= 0 && s.req.ContentLength <= maxBodySwapSize:
		// Known length that fits the buffer (includes 0): ensureBody cannot 413.
		b, ok := s.ensureBody()
		if !ok {
			// A read error (502) — never a 413, since the length is ≤ cap — the
			// same terminal the MCP/swap sites produce on a broken body.
			return true
		}
		body = b
	default:
		// ContentLength > maxBodySwapSize (known too large) or < 0 (unknown /
		// chunked): don't read, flag the honest coverage gap, FORWARD (fail-open).
		s.dlpPartial = true
		return false
	}
	if len(body) == 0 {
		return false
	}

	scanBody := body
	if len(scanBody) > maxDLPScanSize {
		// Over cap: scan the first 1 MB only and flag the coverage gap.
		scanBody = scanBody[:maxDLPScanSize]
		s.dlpPartial = true
	}

	start := time.Now()
	dets := d.scan(scanBody)
	p.cfg.Metrics.ObserveAddedLatency("dlp_scan", time.Since(start))
	p.recordDLPFindings(dets)
	// Carry the bounded MASKED evidence samples (opt-in "••••<last4> (len N)"; empty
	// when evidence is disabled) onto the scope so they ride the event — never raw.
	s.addEvidence(dets)

	// Emit the real DataClass taxonomy: each detection carries zero or more dotted
	// data classes; dedup the union across all detections (preserving first-seen
	// order) into both the bounded event class list and the ordered class slice the
	// evaluator consumes. Injection findings carry no data class, so they add nothing.
	seen := make(map[scan.DataClass]struct{}, len(dets))
	var detected []scan.DataClass
	for _, det := range dets {
		for _, c := range det.Classes {
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			detected = append(detected, c)
		}
	}
	if len(detected) > 0 {
		classes := make([]string, len(detected))
		for i, c := range detected {
			classes[i] = string(c)
		}
		s.dlpClasses = classes
	}

	// Per-class egress rules. With NO policy configured (no rules, no class defaults)
	// DLP is pure observability — the action stays "monitor" and nothing is blocked or
	// mutated, byte-identical to the monitor-only phase. A body with no data class
	// likewise has nothing to police. Otherwise evaluate the precedence rules and map
	// the whole-body verdict onto behavior:
	//   - block  → ENFORCE terminates with a 403 + deny event; monitor records only.
	//   - redact → ENFORCE scrubs the matched spans inline and forwards (dlpApplyRedact);
	//              monitor records the would-be redact and forwards the ORIGINAL body.
	//   - allow/monitor → forward, record the action.
	// MONITOR MODE never blocks or mutates: the would-be action is recorded on the
	// single allow event and the request is forwarded unchanged.
	if d.hasPolicy() && len(detected) > 0 {
		action, rule := d.decide(detected, s.domain)
		s.dlpAction = action
		s.dlpRule = rule
		switch action {
		case config.DLPActionBlock:
			if d.mode == config.DLPModeEnforce {
				return p.dlpDeny(s)
			}
		case config.DLPActionRedact:
			return p.dlpApplyRedact(s, body)
		}
	}
	return false
}

// dlpDeny terminates a request the DLP policy blocked in enforce mode: a 403 to the
// agent plus a deny audit event carrying the bounded classes + action + rule, and a
// bounded "dlp" blocked metric. It mirrors the judge/MCP enforce-deny shape and is
// terminal (returns endSession=true so the deferred cleanup runs). The recorded
// DLPAction preserves the verdict intent — for a decoded-layer redact that could not
// be located it stays "redact" with DLPEncoded=true, so the event honestly reflects
// that policy asked for redaction but the request was escalated to a fail-closed block.
func (p *Proxy) dlpDeny(s *requestScope) (endSession bool) {
	// The reason names the action that blocked the request (dlp_block, or
	// dlp_redact for a decoded-layer redact escalated to fail-closed) — same
	// value on the event and the metric.
	reason := denyreason.DLPBlock
	if s.dlpAction == config.DLPActionRedact {
		reason = denyreason.DLPRedact
	}
	p.emitDeny(s, reason, denyExtra{
		DataClasses: s.dlpClasses,
		DLPAction:   s.dlpAction,
		DLPRule:     s.dlpRule,
		DLPPartial:  s.dlpPartial,
		DLPEncoded:  s.dlpEncoded,
		LatencyMs:   s.latencyMs(),
		SwappedRefs: s.swappedNames,
		Evidence:    s.evidence,
	})
	s.out.errorResponse(403, "Forbidden")
	return true
}

// swapSecrets substitutes each configured placeholder with its resolved secret
// in the request headers, query, and body. The body is swapped in a single
// left-to-right pass (swapBodySecrets), reading the body once via the shared
// scope buffer. A placeholder is recorded as swapped (for the by-reference audit
// and the swap metric) when it changed a header, the query, or was present in
// the body. A missing secret terminates with 503; the body read errors terminate
// with 502/413 exactly as before.
func (p *Proxy) swapSecrets(s *requestScope) (endSession bool) {
	if len(p.cfg.PlaceholderNames) == 0 {
		return false
	}
	// Snapshot the live secret provider once for this request so a concurrent
	// cache.ttl swap can't change it mid-substitution.
	secretsProvider := p.secrets()

	needBodySwap := !s.streamBody && s.req.Body != nil && s.req.Body != http.NoBody && s.req.ContentLength != 0
	var bodyStr string
	if needBodySwap {
		b, ok := s.ensureBody()
		if !ok {
			return true
		}
		bodyStr = string(b)
	}

	// Resolve each placeholder, swap it into headers + query (a per-placeholder
	// pass, since those are tiny), record which placeholders appear in the body,
	// and collect the placeholder→value pairs for one NewReplacer body pass.
	var bodyPairs []string
	var outOfScope []string
	for _, placeholder := range p.cfg.PlaceholderNames {
		// Destination scoping (#373): a placeholder is a swap candidate only for
		// its matchHosts. s.domain is the CONNECT/SNI host (what policy allowed and
		// what is dialed; readRequest rejects a mismatching Host header). Out of
		// scope: leave it untouched, never fetch its secret (so a missing secret
		// cannot 503 an unrelated destination), and record presence by name.
		if !p.placeholderInScope(placeholder, s.domain) {
			if headerCarriesPlaceholder(s.req.Header, placeholder) ||
				queryCarriesPlaceholder(s.req.URL, placeholder) ||
				(needBodySwap && strings.Contains(bodyStr, placeholder)) {
				outOfScope = append(outOfScope, placeholder)
			}
			continue
		}
		realValue, err := secretsProvider.GetSecret(placeholder)
		if err != nil {
			s.out.errorResponse(503, "Service Unavailable")
			return true
		}
		swapped := false

		// Header values
		for key, vals := range s.req.Header {
			for i, v := range vals {
				replaced := strings.ReplaceAll(v, placeholder, realValue)
				// HTTP Basic auth hides the placeholder inside base64, so the raw
				// match above cannot see it. Only the destination "Authorization"
				// header is decoded — NEVER "Proxy-Authorization", which is
				// addressed to Warden itself. URL-embedded credentials
				// (https://user:pass@host) are a conscious cut: out of scope.
				if replaced == v && key == "Authorization" {
					replaced, _ = swapBasicAuth(v, placeholder, realValue)
				}
				if replaced != v {
					s.req.Header[key][i] = replaced
					swapped = true
				}
			}
		}

		// URL query
		if s.req.URL.RawQuery != "" {
			params := s.req.URL.Query()
			changed := false
			for key, vals := range params {
				for i, v := range vals {
					replaced := strings.ReplaceAll(v, placeholder, realValue)
					if replaced != v {
						params[key][i] = replaced
						changed = true
					}
				}
			}
			if changed {
				if s.origRawQuery == "" {
					s.origRawQuery = s.req.URL.RawQuery // keep the agent's, across placeholders
				}
				s.req.URL.RawQuery = params.Encode()
				swapped = true
			}
		}

		// Body: presence in the (original) body marks the placeholder as swapped;
		// the actual rewrite is one NewReplacer pass after the loop. For distinct
		// non-overlapping placeholder tokens this matches the old per-placeholder
		// ReplaceAll's "replaced != body" detection.
		if needBodySwap && bodyStr != "" {
			bodyPairs = append(bodyPairs, placeholder, realValue)
			if strings.Contains(bodyStr, placeholder) {
				swapped = true
			}
		}

		if swapped {
			s.refs = append(s.refs, secrets.Ref(realValue))
			if !p.cfg.EchoGuard.Disabled {
				s.noteSecret(placeholder, realValue)
			}
			// placeholder is the configured NAME (bounded, log-safe),
			// never the secret value.
			s.swappedNames = append(s.swappedNames, placeholder)
		}
	}

	if len(outOfScope) > 0 {
		p.recordOutOfScope(s.resolved(), s.domain, s.port, s.proto, s.req.Method, s.eventURL(), outOfScope)
	}

	// Set swapped body back
	if needBodySwap && bodyStr != "" {
		bodyStr = swapBodySecrets(bodyStr, bodyPairs)
		s.req.Body = io.NopCloser(strings.NewReader(bodyStr))
		s.req.ContentLength = int64(len(bodyStr))
	}
	return false
}

// swapBasicAuth swaps placeholder for realValue inside the base64 payload of an
// "Authorization: Basic ..." value (scheme matched case-insensitively). The
// payload must decode and split as "user:password"; otherwise, or when the
// placeholder is absent, the value is returned unchanged (never guess). The
// decoded credentials are never logged. Reports whether a swap happened.
func swapBasicAuth(value, placeholder, realValue string) (string, bool) {
	scheme, payload, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return value, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return value, false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return value, false
	}
	newUser := strings.ReplaceAll(user, placeholder, realValue)
	newPass := strings.ReplaceAll(pass, placeholder, realValue)
	if newUser == user && newPass == pass {
		return value, false
	}
	return scheme + " " + base64.StdEncoding.EncodeToString([]byte(newUser+":"+newPass)), true
}

// swapBodySecrets replaces every placeholder with its resolved secret in a single
// left-to-right pass via strings.NewReplacer. pairs is the flat
// [placeholder1, value1, placeholder2, value2, ...] slice NewReplacer expects.
// Placeholders are distinct, non-overlapping tokens and secret values do not
// contain placeholder tokens, so the one non-overlapping pass yields the same
// bytes as the old sequential per-placeholder strings.ReplaceAll loop while
// scanning the body once instead of once per placeholder.
func swapBodySecrets(body string, pairs []string) string {
	if len(pairs) == 0 {
		return body
	}
	return strings.NewReplacer(pairs...).Replace(body)
}

// transformerReadsBody reports whether t consumes the request body (HMAC / SigV4
// sign it). A transformer that does not say so is header-only.
func transformerReadsBody(t auth.RequestTransformer) bool {
	b, ok := t.(interface{ ReadsBody() bool })
	return ok && b.ReadsBody()
}

// applyTransforms runs the configured auth transformers whose matcher matches the
// destination domain. A transform error terminates with 502.
func (p *Proxy) applyTransforms(s *requestScope) (endSession bool) {
	// A swapped value means the response must be checked for it, which needs a plain
	// body: ask for identity. Set before any transformer runs so a signer covers it.
	if len(s.echoSecrets) > 0 {
		s.req.Header.Set("Accept-Encoding", "identity")
		// A WebSocket upgrade that swapped a value must not negotiate
		// permessage-deflate (#399 review): compressed (RSV) frames cannot be
		// scanned, so the extension offer is dropped and the upstream answers
		// uncompressed. The frame guard refuses a compressed frame that arrives
		// anyway.
		if strings.EqualFold(s.req.Header.Get("Upgrade"), "websocket") {
			s.req.Header.Del("Sec-WebSocket-Extensions")
		}
	}
	for _, mt := range p.cfg.Transformers {
		if mt.Matches(s.domain) {
			// Only a transformer that really puts a value in the request needs the
			// response checked (so a plain body); one that injects nothing (SigV4
			// without a session token) leaves the client's Accept-Encoding alone.
			// A source that reports nothing until it has run (a cold OAuth2 token)
			// is caught by the recording after Transform below; its request keeps the
			// client's encoding, so a compressed answer is decoded or refused by the
			// guard, never passed.
			src, ok := mt.Transformer.(auth.SecretSource)
			injects := ok && len(src.InjectedSecrets()) > 0 && !p.cfg.EchoGuard.Disabled
			if injects {
				s.req.Header.Set("Accept-Encoding", "identity")
			}
			// A streamed (gRPC) body is never buffered, and a body-signing transformer
			// would read it whole and stall the stream: refuse rather than mis-sign.
			if s.streamBody && transformerReadsBody(mt.Transformer) && s.req.Body != nil && s.req.Body != http.NoBody {
				p.emitDeny(s, denyreason.TransformNeedsBufferedBody, denyExtra{LatencyMs: s.latencyMs()})
				s.out.errorResponse(http.StatusNotImplemented, "Not Implemented")
				return true
			}
			if err := mt.Transformer.Transform(s.req); err != nil {
				s.out.errorResponse(502, "Bad Gateway")
				return true
			}
			// Record after Transform, whatever was decided before: the value is
			// only known once the transformer has run.
			if ok && !p.cfg.EchoGuard.Disabled {
				s.noteTransformerSecrets(src)
			}
		}
	}
	return false
}

// forward sends s.req to the upstream and reads the response onto the scope,
// computing closeAfter from the request/response Connection semantics. It has two
// modes:
//
//   - Fresh (s.reused==false): the session's first request, or the leg after a
//     stale close. Dial s.domain:s.port, stream the request straight through, read
//     the response. Any dial/write/read failure is a real error → 502, NO retry.
//   - Reused (s.reused==true): a conn carried over from a prior clean keep-alive
//     response. The server may have closed it while idle, so serialize the request
//     once (req.Write consumes the body) and, if the write or read fails, close the
//     dead conn, REDIAL ONCE to the SAME host, and re-send the identical bytes. A
//     second failure → 502. Never more than one retry.
//
// On success s.upstream/s.upstreamBR are the live conn the session carries. On a
// stale redial they are the fresh conn; the dead one was already closed here.
func (p *Proxy) forward(s *requestScope) (endSession bool) {
	if s.rt != nil {
		return p.forwardH2(s)
	}
	if !s.reused {
		if err := p.dialUpstream(s); err != nil {
			return p.badGateway(s)
		}
		if err := s.req.Write(s.upstream); err != nil || !p.readUpstreamResponse(s) {
			return p.badGateway(s)
		}
		return false
	}

	// Reused conn: serialize once so a stale redial can re-send identical bytes.
	var buf bytes.Buffer
	if err := s.req.Write(&buf); err != nil {
		return p.badGateway(s)
	}
	raw := buf.Bytes()
	if _, err := s.upstream.Write(raw); err == nil && p.readUpstreamResponse(s) {
		return false
	}
	// Stale half-closed keep-alive conn: drop it and redial exactly once.
	_ = s.upstream.Close()
	s.upstream, s.upstreamBR, s.reused = nil, nil, false
	if err := p.dialUpstream(s); err != nil {
		return p.badGateway(s)
	}
	if _, err := s.upstream.Write(raw); err != nil || !p.readUpstreamResponse(s) {
		return p.badGateway(s)
	}
	return false
}

// dialUpstream dials a fresh upstream for this session's fixed host and
// installs it (plus a new buffered reader) on the scope. It always targets
// s.domain:s.port — reuse never crosses hosts. A plain-HTTP scope (#376) dials
// plaintext; everything else dials TLS with the config from upstreamTLSConfig,
// so the assembly-only root-CA override applies here too.
func (p *Proxy) dialUpstream(s *requestScope) error {
	var upstream net.Conn
	var err error
	if s.scheme == policy.SchemeHTTP {
		upstream, err = p.dialFunc("tcp", net.JoinHostPort(s.domain, fmt.Sprintf("%d", s.port)))
	} else {
		upstream, err = p.dialTLS("tcp", net.JoinHostPort(s.domain, fmt.Sprintf("%d", s.port)), p.upstreamTLSConfig(s.domain))
	}
	if err != nil {
		p.recordSSRFDeny(s, err)
		return err
	}
	s.upstream = upstream
	s.upstreamBR = bufio.NewReader(upstream)
	return nil
}

// readUpstreamResponse reads the response off s.upstreamBR onto the scope and
// computes closeAfter. It returns false on a read error so forward can treat a
// reused conn as stale (or a fresh conn as a 502).
func (p *Proxy) readUpstreamResponse(s *requestScope) (ok bool) {
	resp, err := http.ReadResponse(s.upstreamBR, s.req)
	if err != nil {
		return false
	}
	s.resp = resp
	s.closeAfter = s.req.Close || resp.Close
	return true
}

// badGateway writes a 502 to the client and signals the session should end.
func (p *Proxy) badGateway(s *requestScope) (endSession bool) {
	if s.trailerDenied {
		s.denyTrailers()
		return true
	}
	s.out.errorResponse(502, "Bad Gateway")
	return true
}

// relayResponse dispatches the upstream response to one of three terminal
// shapes: a WebSocket 101 upgrade (hands the conn to the frame pump), an MCP
// response scan (buffered JSON or SSE), or the plain forward path. It returns
// true when the session should end.
func (p *Proxy) relayResponse(s *requestScope) (endSession bool) {
	// WebSocket upgrade: an MCP server may speak JSON-RPC over a WebSocket, and
	// a plain upstream may speak its own. On a 101 the connection is consumed
	// for the lifetime of the socket, so this branch is terminal — it hands the
	// raw conn to the frame pump (which owns and closes the upstream), then
	// returns. EVERY 101 to a WebSocket upgrade is pumped (#399, #408): the MCP
	// gateway scans it when one is configured, the echo guard guards it when the
	// request swapped a value, and with neither the pump relays frames verbatim —
	// a plain upgrade must not lose its frames.
	if s.rt == nil && s.resp.StatusCode == 101 &&
		strings.EqualFold(s.req.Header.Get("Upgrade"), "websocket") {
		// The 101 headers are checked before the handoff writes them verbatim.
		if len(s.echoSecrets) > 0 && p.echoGuardHeaders(s) {
			return true
		}
		s.handoff = true
		p.handleWSUpgrade(s)
		return true
	}

	// Echo guard: nothing of the response may reach the agent if it carries a value
	// swapped into this request. One check here covers every protocol and path below.
	if len(s.echoSecrets) > 0 && p.echoGuard(s) {
		return true
	}

	// MCP response scan (buffered JSON deny, SSE stream, or unscanned). Returns
	// true when it fully handled the response (deny or SSE); false to fall through
	// to the shared forward path (buffered-allow restored the body, or the
	// response was left unscanned).
	if s.gw != nil && s.wasMCP {
		if p.mcpResponseScan(s) {
			return true
		}
	}

	return p.finishResponse(s)
}

// mcpResponseScan scans an MCP response. For a bufferable JSON body it buffers
// and scans, denying (terminal 502) on a Deny verdict or restoring the buffered
// body for the forward path. For an SSE stream it tees each event through the
// scanner (terminal). Anything else is forwarded unscanned. It returns true only
// when it fully handled the response (deny or SSE terminal).
func (p *Proxy) mcpResponseScan(s *requestScope) (terminal bool) {
	ct := s.resp.Header.Get("Content-Type")
	scanCap := int64(s.gw.MaxResponseScanBytes())
	bufferable := strings.HasPrefix(ct, "application/json") &&
		s.resp.ContentLength >= 0 && s.resp.ContentLength <= scanCap
	switch {
	case bufferable:
		body, readErr := io.ReadAll(s.resp.Body)
		if readErr != nil {
			// Read failed mid-body: fall through and forward whatever remains,
			// exactly as before (resp.Body is left as-is, not restored).
			return false
		}
		start := time.Now()
		v := s.gw.OnResponse(s.mcpSessKey, s.resp.StatusCode, s.resp.Header, body)
		p.cfg.Metrics.ObserveAddedLatency("mcp_scan", time.Since(start))
		p.recordMCPFindings(v)
		if v.Reason != "" {
			s.mcpReason = v.Reason
		}
		if v.Action == gateway.Deny {
			p.emitDeny(s, gatewayDenyReason(v.Reason), denyExtra{
				Protocol:    "mcp",
				Tool:        s.mcpTool,
				LatencyMs:   s.latencyMs(),
				SwappedRefs: s.swappedNames,
				Evidence:    s.evidence,
			})
			s.out.errorResponse(502, "Bad Gateway")
			return true
		}
		s.resp.Body = io.NopCloser(bytes.NewReader(body))
		return false
	case strings.HasPrefix(ct, "text/event-stream"):
		return p.relayMCPSSE(s)
	default:
		// chunked / unknown or over-cap length: stream unchanged, record that it
		// was not scanned.
		p.cfg.Metrics.RecordScanFinding("mcp_response_unscanned_stream")
		return false
	}
}

// relayMCPSSE forwards an MCP Streamable-HTTP / SSE response verbatim while
// scanning each event's JSON-RPC payload with bounded per-event memory. An SSE
// response is terminal for the connection, so this fully handles the request
// (writing the deny/allow audit event) and always returns true.
func (p *Proxy) relayMCPSSE(s *requestScope) (terminal bool) {
	p.reach(PathSSE)
	fullURL := s.eventURL()

	// Headers go out first; the body is then teed through the SSE scanner into the
	// sink's writer (resp.Write cannot be used for that).
	bodyOut, werr := s.out.stream(s.resp)
	if werr != nil {
		return true
	}

	// The SSE response is delivered: the agent now reads the stream directly, so
	// the scope steps OUT of the quiescence tracker — an open stream may run for
	// minutes and must never block a waiter. It steps back IN below, once the
	// stream ends and before the terminal event is recorded, so the stream's
	// bookkeeping is still happened-after by a drained tracker. The remaining
	// window is the same one the WS session documents below: from this step-out
	// until the re-entry the tracker is idle while the stream's terminal event
	// does not exist yet, so a test reading a stream's terminal event must use
	// EventuallyWithin (like the WS rule).
	s.endInflight()

	// Enforce mode holds each event until it is scanned and writes it to bodyOut
	// only on allow. bodyOut is unchanged and the echo guard sits on s.resp.Body
	// upstream of the scanner, so only bytes it cleared are ever held or released.
	scan := sse.Scan
	if p.holdMCP(s.gw) {
		scan = sse.ScanHeld
	}
	blocked := false
	scanErr := scan(s.resp.Body, bodyOut, func(data []byte) bool {
		start := time.Now()
		v := s.gw.OnResponse(s.mcpSessKey, s.resp.StatusCode, s.resp.Header, data)
		p.cfg.Metrics.ObserveAddedLatency("mcp_scan", time.Since(start))
		p.recordMCPFindings(v)
		if v.Reason != "" {
			s.mcpReason = v.Reason
		}
		if v.Action == gateway.Deny {
			blocked = true
			return true
		}
		return false
	})

	// Stream over: back in the quiescence tracker BEFORE the terminal bookkeeping
	// below — the echo guard's cut-stream deny or the stream's own allow/deny
	// event — so the scope's done (the deferred endInflight in runRequestStages)
	// runs after whichever record ends this stream. The guard keeps the
	// description concatenation off the production hot path (no tracker
	// installed).
	if p.cfg.Inflight != nil {
		s.inflightDone = p.inflightStart("sse " + s.req.Method + " " + fullURL)
	}
	p.beforeTerminal()

	if p.echoStreamDone(s) {
		return true // echo guard cut the stream; its deny is the only event
	}
	if errors.Is(scanErr, sse.ErrEventTooLarge) {
		// Enforce mode could not scan this event, so it was not forwarded.
		blocked = true
		s.mcpReason = string(denyreason.MCPSSEEventTooLarge)
	}
	if blocked {
		// A gateway (or held-event) deny names itself; an empty verdict reason
		// falls back to the declared mcp_gateway_deny (#409).
		p.emitDeny(s, gatewayDenyReason(preferEchoReason(s.mcpReason, s.echoMonitorReason)), denyExtra{
			Protocol:       "mcp",
			Tool:           s.mcpTool,
			ResponseStatus: s.resp.StatusCode,
			LatencyMs:      s.latencyMs(),
			SwappedRefs:    s.swappedNames,
			Evidence:       s.evidence,
		})
	} else {
		p.recordEvent(s.resolved(), analytics.Event{
			Timestamp:      time.Now(),
			Domain:         s.domain,
			Port:           s.port,
			Protocol:       "mcp",
			Method:         s.req.Method,
			URL:            fullURL,
			Decision:       "allow",
			ResponseStatus: s.resp.StatusCode,
			Tool:           s.mcpTool,
			Reason:         preferEchoReason(s.mcpReason, s.echoMonitorReason),
			LatencyMs:      s.latencyMs(),
			SwappedRefs:    s.swappedNames,
			Evidence:       s.evidence,
		})
		p.cfg.Metrics.RecordRequest("allow", "mcp")
		p.logDecision(decisionLog{
			Domain: s.domain, Port: s.port, Protocol: "mcp",
			Method: s.req.Method, URL: fullURL, Decision: "allow",
			ResponseStatus: s.resp.StatusCode,
			ID:             s.resolved(),
		})
	}

	_ = scanErr // ErrBlocked already handled via blocked; other errors
	// mean the stream ended early — nothing more to forward.
	return true
}

// finishResponse is the shared forward path: an optional non-MCP HTTP response
// scan (which may deny, terminal 502), then the verbatim response write and the
// single allow audit event. It returns true when the session should end (write
// error or Connection: close), false to serve another request on the conn.
func (p *Proxy) finishResponse(s *requestScope) (endSession bool) {
	if p.cfg.ResponseScan != nil && p.cfg.ResponseScan.mode != responseScanOff &&
		!s.wasMCP && s.resp.StatusCode != 101 {
		if p.httpResponseScan(s) {
			return true
		}
	}

	writeErr := s.out.relay(s.resp)
	if p.echoStreamDone(s) {
		// The echo guard cut the stream and already recorded the deny: end the
		// session (closing the conn) and record no allow.
		return true
	}
	if s.grpcGuard.Refused() {
		// A gRPC frame was refused after the response began: its deny is the only
		// event, and the client leg is finished with the refusal status.
		return true
	}
	p.recordAllowEvent(s)
	return writeErr != nil || s.closeAfter
}

// httpResponseScan runs the optional non-MCP HTTP response scanner. It runs only
// for non-MCP, non-101 responses when a scanner is configured in a non-off mode.
// Unscannable bodies are forwarded unchanged (recorded as skipped); a
// high-severity finding in enforce mode replaces the body with a 502 and records
// a deny (terminal). Otherwise the buffered body is restored for the write below.
// It returns true only on the terminal deny.
func (p *Proxy) httpResponseScan(s *requestScope) (blocked bool) {
	rs := p.cfg.ResponseScan
	ct := s.resp.Header.Get("Content-Type")
	if !rs.scannable(ct, s.resp.ContentLength) {
		// Streaming/SSE, unknown/negative length, over-cap, or non-textual:
		// forward unchanged and record a skip (never truncate, never block).
		p.cfg.Metrics.RecordScanFinding("http_response_unscanned_stream")
		p.cfg.Logger.Debug("http response not scanned (unscannable)",
			slog.String("domain", s.domain),
			slog.String("content_type", ct),
			slog.Int64("content_length", s.resp.ContentLength),
		)
		return false
	}
	// Buffer up to the cap + 1 so we can detect an upstream that lied about (or
	// grew past) its Content-Length and skip rather than block.
	body, readErr := io.ReadAll(io.LimitReader(s.resp.Body, int64(rs.MaxBytes())+1))
	if readErr != nil {
		// FAIL-OPEN: a read error never breaks egress. Forward what we have and
		// skip scanning. No body is logged.
		p.cfg.Logger.Warn("http response scan read error; forwarding unscanned",
			slog.String("domain", s.domain),
			slog.String("error", readErr.Error()),
		)
		s.resp.Body = io.NopCloser(bytes.NewReader(body))
		return false
	}
	if int64(len(body)) > int64(rs.MaxBytes()) {
		// Over cap (upstream under-reported Content-Length): skip + log.
		s.resp.Body = io.NopCloser(bytes.NewReader(body))
		p.cfg.Metrics.RecordScanFinding("http_response_unscanned_stream")
		p.cfg.Logger.Debug("http response not scanned (over cap)",
			slog.String("domain", s.domain),
			slog.Int("buffered_bytes", len(body)),
		)
		return false
	}
	start := time.Now()
	dets, block, reason := rs.Scan(body)
	p.cfg.Metrics.ObserveAddedLatency("http_response_scan", time.Since(start))
	p.recordResponseFindings(dets)
	// Carry the bounded MASKED evidence samples onto the scope so they ride the
	// event (allow or the deny below) — never raw response content.
	s.addEvidence(dets)
	if block {
		// enforce + high leak/injection: replace the body with an error, record a
		// deny, and return (terminal, mirrors the MCP enforce-deny branch).
		p.emitDeny(s, reason, denyExtra{
			ResponseStatus: s.resp.StatusCode,
			LatencyMs:      s.latencyMs(),
			SwappedRefs:    s.swappedNames,
			Evidence:       s.evidence,
		})
		s.out.errorResponse(502, "Bad Gateway")
		return true
	}
	// monitor, or enforce with no high finding: restore the buffered body so the
	// normal write forwards it intact.
	s.resp.Body = io.NopCloser(bytes.NewReader(body))
	return false
}

// recordAllowEvent writes the single allow audit event for a forwarded request:
// the by-reference secret list, optional cost estimate, MCP tool/reason, and any
// judge reason — exactly one StoreEvent per allowed request. It also emits the
// per-secret swap metric and the structured decision log.
func (p *Proxy) recordAllowEvent(s *requestScope) {
	// Test-only (worker.Overrides.BeforeTerminal; production nil): widen
	// exactly the post-response window whose bookkeeping race the quiescence
	// tracker closes, so a harness test can make the #363 race deterministic
	// instead of flaky-red.
	p.beforeTerminal()
	var refStrs []string
	for _, r := range s.refs {
		refStrs = append(refStrs, r.String())
	}
	fullURL := s.eventURL()
	secretRef := strings.Join(refStrs, ",")
	proto := s.proto
	if s.wasMCP {
		proto = "mcp"
	}
	reason := s.mcpReason // "" unless wasMCP
	if s.echoMonitorReason != "" {
		reason = s.echoMonitorReason // echo guard in monitor mode saw a hit
	}
	// Cost estimate (optional). Heuristic dollar figure from observed
	// request/response Content-Length and the destination provider's pricing;
	// zero when cost tracking is off or the domain is not a known provider.
	var costUSD float64
	var provider string
	if p.cfg.Cost != nil {
		reqBytes := s.req.ContentLength
		if reqBytes < 0 {
			reqBytes = 0
		}
		respBytes := s.resp.ContentLength
		if respBytes < 0 {
			respBytes = 0
		}
		if est := p.cfg.Cost.Estimate(s.domain, reqBytes, respBytes); est != nil {
			costUSD = est.TotalCost
			provider = est.Provider
		}
	}
	p.recordEvent(s.resolved(), analytics.Event{
		Timestamp:      time.Now(),
		Domain:         s.domain,
		Port:           s.port,
		Protocol:       proto,
		Method:         s.req.Method,
		URL:            fullURL,
		Decision:       "allow",
		ResponseStatus: s.resp.StatusCode,
		SecretRef:      secretRef,
		JudgeReason:    s.judgeReason, // empty unless a judge allowed this request
		Tool:           s.mcpTool,     // "" unless wasMCP
		Reason:         reason,
		CostUSD:        costUSD,
		Provider:       provider,
		// DLP fields ride this single allow event (no second event is emitted).
		// All zero/empty when DLP is off, so the off-case event is identical to
		// today. DLPRule is the bounded id of the winning rule (empty with no policy).
		DataClasses: s.dlpClasses,
		DLPAction:   s.dlpAction,
		DLPRule:     s.dlpRule,
		DLPPartial:  s.dlpPartial,
		DLPEncoded:  s.dlpEncoded,
		// Dashboard "Activity" metadata: total mediation latency, the placeholder
		// NAMES swapped on this request (never values), and bounded MASKED evidence
		// samples (never raw). All safe; SwappedRefs/Evidence empty when nothing
		// swapped / no findings.
		LatencyMs:   s.latencyMs(),
		SwappedRefs: s.swappedNames,
		Evidence:    s.evidence,
	})
	p.cfg.Metrics.RecordRequest("allow", proto)
	for _, name := range s.swappedNames {
		p.cfg.Metrics.RecordSecretSwap(name)
	}
	p.logDecision(decisionLog{
		Domain: s.domain, Port: s.port, Protocol: proto,
		Method: s.req.Method, URL: fullURL, Decision: "allow",
		ResponseStatus: s.resp.StatusCode, SecretRef: secretRef,
		JudgeReason: s.judgeReason, ID: s.resolved(),
	})
}

func writeErrorResponse(w io.Writer, statusCode int, statusText string) {
	resp := &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, statusText),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(statusText + "\n")),
		ContentLength: int64(len(statusText) + 1),
	}
	_ = resp.Write(w)
}
