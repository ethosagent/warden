package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/mcp/sse"
	"github.com/ethosagent/warden/internal/protocol"
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
	// per request so stages read one value).
	tlsConn    *tls.Conn
	br         *bufio.Reader
	domain     string
	port       int
	needsJudge bool

	// Per-request atomic-pointer snapshots, taken ONCE at the top of the request
	// so a concurrent control-plane swap can't change them mid-request.
	gw        MCPGateway
	liveJudge Judge

	// Closables owned by this request. cleanup closes each exactly once.
	req        *http.Request
	resp       *http.Response
	upstream   net.Conn
	upstreamBR *bufio.Reader
	// handoff is set when the connection lifecycle is handed to the WebSocket
	// pump, which owns and closes the upstream (and the response) itself. cleanup
	// must NOT touch upstream/resp in that case, to avoid a double close.
	handoff bool

	// reqBody is the request body read ONCE (bounded by maxBodySwapSize+1) and
	// shared by MCP inspection and the secret swap. bodyRead records that the
	// single read has happened so a second consumer reuses the buffer instead of
	// re-reading a spent body.
	reqBody  []byte
	bodyRead bool

	// Decision state threaded between stages.
	judgeReason string
	wasMCP      bool
	mcpTool     string
	mcpReason   string
	mcpSessKey  string
	closeAfter  bool

	// Secret-swap results, carried onto the single forwarding audit event.
	refs         []secrets.Reference
	swappedNames []string
}

// cleanup releases the request's closables exactly once, on whatever exit path
// serveHTTPRequest returns through. It reproduces the close semantics the old
// six hand-rolled exits had, per path:
//   - req.Body is always closed (http.ReadRequest always leaves it non-nil).
//   - resp/upstream are closed only when they were actually dialed/read (nil
//     before forward, so guarded), matching paths that returned before dialing.
//   - When handoff is set (WebSocket upgrade), upstream and resp are left alone:
//     handleWSUpgrade already owns and closes the upstream, and the response has
//     no separate body to close — so the generic cleanup skips both to avoid a
//     double close of the conn that was handed to the frame pump.
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
	if s.upstream != nil {
		_ = s.upstream.Close()
	}
}

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
		writeErrorResponse(s.tlsConn, 502, "Bad Gateway")
		return nil, false
	}
	if int64(len(b)) > maxBodySwapSize {
		writeErrorResponse(s.tlsConn, 413, "Request body too large for secret substitution")
		return nil, false
	}
	s.reqBody = b
	s.bodyRead = true
	// Restore the body so the downstream secret-swap re-read and
	// req.Write(upstream) still see the full payload.
	s.req.Body = io.NopCloser(bytes.NewReader(b))
	return b, true
}

// handleHTTP serves the keep-alive loop for one MITM-terminated client conn.
// Each iteration is one request served by serveHTTPRequest, which owns a
// requestScope and a single deferred cleanup; the loop ends when that request
// signals the session is over (a read error, a terminal decision, a write
// failure, or Connection: close).
func (p *Proxy) handleHTTP(tlsConn *tls.Conn, br *bufio.Reader, domain string, port int, needsJudge bool) {
	for {
		if p.serveHTTPRequest(tlsConn, br, domain, port, needsJudge) {
			return
		}
	}
}

// serveHTTPRequest reads and serves one request end-to-end as the named stage
// sequence, with a single deferred cleanup releasing the request's closables on
// every exit. It returns true when the keep-alive session should end.
func (p *Proxy) serveHTTPRequest(tlsConn *tls.Conn, br *bufio.Reader, domain string, port int, needsJudge bool) (endSession bool) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return true
	}

	// Snapshot the live MCP gateway and judge once per request through their
	// atomic pointers, so a concurrent control-plane swap can't change them
	// mid-request. A nil gw/judge means the feature is disabled — identical to a
	// nil cfg.MCP / cfg.Judge before.
	s := &requestScope{
		tlsConn:    tlsConn,
		br:         br,
		domain:     domain,
		port:       port,
		needsJudge: needsJudge,
		req:        req,
		gw:         p.mcpGateway(),
		liveJudge:  p.judge(),
	}
	defer s.cleanup()

	if p.readRequest(s) {
		return true
	}
	if p.judgeGate(s) {
		return true
	}
	if p.mcpRequestScan(s) {
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
// a host-header recheck (defense in depth) against the CONNECT-time domain. A
// mismatch ends the session (cleanup closes req.Body).
func (p *Proxy) readRequest(s *requestScope) (endSession bool) {
	hostOnly := s.req.Host
	if h, _, err := net.SplitHostPort(s.req.Host); err == nil {
		hostOnly = h
	}
	return !strings.EqualFold(hostOnly, s.domain)
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
	fullURL := "https://" + s.domain + s.req.URL.RequestURI()
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
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp:   time.Now(),
			Domain:      s.domain,
			Port:        s.port,
			Protocol:    "https",
			Method:      s.req.Method,
			URL:         fullURL,
			Decision:    "deny",
			JudgeReason: verdict.Reason,
		})
		p.cfg.Metrics.RecordRequest("deny", "https")
		p.cfg.Metrics.RecordBlocked("judge")
		p.cfg.Metrics.RecordJudge("deny")
		p.logDecision(decisionLog{
			Domain: s.domain, Port: s.port, Protocol: "https",
			Method: s.req.Method, URL: fullURL, Decision: "deny",
			JudgeReason: verdict.Reason,
		})
		writeErrorResponse(s.tlsConn, 403, "Forbidden")
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
	if s.gw == nil {
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
	fullURL := "https://" + s.domain + s.req.URL.RequestURI()
	s.mcpSessKey = p.cfg.AgentID + ":" + s.domain
	start := time.Now()
	v := s.gw.OnRequest(s.mcpSessKey, s.req.Method, fullURL, s.req.Header, body)
	p.cfg.Metrics.ObserveAddedLatency("mcp_scan", time.Since(start))
	p.recordMCPFindings(v)
	s.mcpTool = v.Tool
	s.mcpReason = v.Reason
	if v.Action == gateway.Deny {
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    s.domain,
			Port:      s.port,
			Protocol:  "mcp",
			Method:    s.req.Method,
			URL:       fullURL,
			Decision:  "deny",
			Tool:      v.Tool,
			Reason:    v.Reason,
		})
		p.cfg.Metrics.RecordRequest("deny", "mcp")
		p.cfg.Metrics.RecordBlocked(v.Reason)
		p.logDecision(decisionLog{
			Domain: s.domain, Port: s.port, Protocol: "mcp",
			Method: s.req.Method, URL: fullURL, Decision: "deny",
		})
		writeErrorResponse(s.tlsConn, 403, "Forbidden")
		return true
	}
	return false
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

	needBodySwap := s.req.Body != nil && s.req.Body != http.NoBody && s.req.ContentLength != 0
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
	for _, placeholder := range p.cfg.PlaceholderNames {
		realValue, err := secretsProvider.GetSecret(placeholder)
		if err != nil {
			writeErrorResponse(s.tlsConn, 503, "Service Unavailable")
			return true
		}
		swapped := false

		// Header values
		for key, vals := range s.req.Header {
			for i, v := range vals {
				replaced := strings.ReplaceAll(v, placeholder, realValue)
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
			// placeholder is the configured NAME (bounded, log-safe),
			// never the secret value.
			s.swappedNames = append(s.swappedNames, placeholder)
		}
	}

	// Set swapped body back
	if needBodySwap && bodyStr != "" {
		bodyStr = swapBodySecrets(bodyStr, bodyPairs)
		s.req.Body = io.NopCloser(strings.NewReader(bodyStr))
		s.req.ContentLength = int64(len(bodyStr))
	}
	return false
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

// applyTransforms runs the configured auth transformers whose matcher matches the
// destination domain. A transform error terminates with 502.
func (p *Proxy) applyTransforms(s *requestScope) (endSession bool) {
	for _, mt := range p.cfg.Transformers {
		if mt.Matches(s.domain) {
			if err := mt.Transformer.Transform(s.req); err != nil {
				writeErrorResponse(s.tlsConn, 502, "Bad Gateway")
				return true
			}
		}
	}
	return false
}

// forward dials a fresh TLS upstream, writes the request, and reads the response
// onto the scope. Dial/write/read failures terminate with 502; cleanup then
// closes exactly what was opened (upstream is nil before a successful dial, so a
// dial failure leaks nothing). closeAfter is computed here from the request and
// response Connection semantics.
func (p *Proxy) forward(s *requestScope) (endSession bool) {
	upstream, err := p.dialTLS("tcp", net.JoinHostPort(s.domain, fmt.Sprintf("%d", s.port)), &tls.Config{ServerName: s.domain})
	if err != nil {
		writeErrorResponse(s.tlsConn, 502, "Bad Gateway")
		return true
	}
	s.upstream = upstream

	if err := s.req.Write(upstream); err != nil {
		writeErrorResponse(s.tlsConn, 502, "Bad Gateway")
		return true
	}

	s.upstreamBR = bufio.NewReader(upstream)
	resp, err := http.ReadResponse(s.upstreamBR, s.req)
	if err != nil {
		writeErrorResponse(s.tlsConn, 502, "Bad Gateway")
		return true
	}
	s.resp = resp
	s.closeAfter = s.req.Close || resp.Close
	return false
}

// relayResponse dispatches the upstream response to one of three terminal
// shapes: a WebSocket 101 upgrade (hands the conn to the frame pump), an MCP
// response scan (buffered JSON or SSE), or the plain forward path. It returns
// true when the session should end.
func (p *Proxy) relayResponse(s *requestScope) (endSession bool) {
	// WebSocket upgrade: an MCP server may speak JSON-RPC over a WebSocket. On a
	// 101 the connection is consumed for the lifetime of the socket, so this
	// branch is terminal — it hands the raw conn to the frame pump (which owns and
	// closes the upstream), then returns. When the MCP gateway is disabled we
	// leave today's behavior untouched (a 101 was never special-cased before).
	if s.gw != nil && s.resp.StatusCode == 101 &&
		strings.EqualFold(s.req.Header.Get("Upgrade"), "websocket") {
		s.handoff = true
		p.handleWSUpgrade(s.tlsConn, s.br, s.upstream, s.upstreamBR, s.resp, s.req, s.domain, s.port, s.mcpSessKey, s.gw)
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
			fullURL := "https://" + s.domain + s.req.URL.RequestURI()
			_ = p.analyticsStore().StoreEvent(analytics.Event{
				Timestamp: time.Now(),
				Domain:    s.domain,
				Port:      s.port,
				Protocol:  "mcp",
				Method:    s.req.Method,
				URL:       fullURL,
				Decision:  "deny",
				Tool:      s.mcpTool,
				Reason:    v.Reason,
			})
			p.cfg.Metrics.RecordRequest("deny", "mcp")
			p.cfg.Metrics.RecordBlocked(v.Reason)
			p.logDecision(decisionLog{
				Domain: s.domain, Port: s.port, Protocol: "mcp",
				Method: s.req.Method, URL: fullURL, Decision: "deny",
				ResponseStatus: s.resp.StatusCode,
			})
			writeErrorResponse(s.tlsConn, 502, "Bad Gateway")
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
	fullURL := "https://" + s.domain + s.req.URL.RequestURI()

	// Write the status line + headers manually: resp.Write cannot be used because
	// we tee the body through the SSE scanner. This preserves Content-Type,
	// Transfer-Encoding, Cache-Control, etc.
	statusLine := fmt.Sprintf("HTTP/%d.%d %03d %s\r\n",
		s.resp.ProtoMajor, s.resp.ProtoMinor, s.resp.StatusCode,
		http.StatusText(s.resp.StatusCode))
	if _, werr := io.WriteString(s.tlsConn, statusLine); werr != nil {
		return true
	}
	if werr := s.resp.Header.Write(s.tlsConn); werr != nil {
		return true
	}
	if _, werr := io.WriteString(s.tlsConn, "\r\n"); werr != nil {
		return true
	}

	blocked := false
	scanErr := sse.Scan(s.resp.Body, s.tlsConn, func(data []byte) bool {
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

	if blocked {
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp:      time.Now(),
			Domain:         s.domain,
			Port:           s.port,
			Protocol:       "mcp",
			Method:         s.req.Method,
			URL:            fullURL,
			Decision:       "deny",
			ResponseStatus: s.resp.StatusCode,
			Tool:           s.mcpTool,
			Reason:         s.mcpReason,
		})
		p.cfg.Metrics.RecordRequest("deny", "mcp")
		p.cfg.Metrics.RecordBlocked(s.mcpReason)
		p.logDecision(decisionLog{
			Domain: s.domain, Port: s.port, Protocol: "mcp",
			Method: s.req.Method, URL: fullURL, Decision: "deny",
			ResponseStatus: s.resp.StatusCode,
		})
	} else {
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp:      time.Now(),
			Domain:         s.domain,
			Port:           s.port,
			Protocol:       "mcp",
			Method:         s.req.Method,
			URL:            fullURL,
			Decision:       "allow",
			ResponseStatus: s.resp.StatusCode,
			Tool:           s.mcpTool,
			Reason:         s.mcpReason,
		})
		p.cfg.Metrics.RecordRequest("allow", "mcp")
		p.logDecision(decisionLog{
			Domain: s.domain, Port: s.port, Protocol: "mcp",
			Method: s.req.Method, URL: fullURL, Decision: "allow",
			ResponseStatus: s.resp.StatusCode,
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

	writeErr := s.resp.Write(s.tlsConn)
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
	if block {
		// enforce + high leak/injection: replace the body with an error, record a
		// deny, and return (terminal, mirrors the MCP enforce-deny branch).
		fullURL := "https://" + s.domain + s.req.URL.RequestURI()
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp:      time.Now(),
			Domain:         s.domain,
			Port:           s.port,
			Protocol:       "https",
			Method:         s.req.Method,
			URL:            fullURL,
			Decision:       "deny",
			ResponseStatus: s.resp.StatusCode,
			Reason:         reason,
		})
		p.cfg.Metrics.RecordRequest("deny", "https")
		p.cfg.Metrics.RecordBlocked(reason)
		p.logDecision(decisionLog{
			Domain: s.domain, Port: s.port, Protocol: "https",
			Method: s.req.Method, URL: fullURL, Decision: "deny",
			ResponseStatus: s.resp.StatusCode,
		})
		writeErrorResponse(s.tlsConn, 502, "Bad Gateway")
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
	var refStrs []string
	for _, r := range s.refs {
		refStrs = append(refStrs, r.String())
	}
	fullURL := "https://" + s.domain + s.req.URL.RequestURI()
	secretRef := strings.Join(refStrs, ",")
	proto := "https"
	if s.wasMCP {
		proto = "mcp"
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
	_ = p.analyticsStore().StoreEvent(analytics.Event{
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
		Reason:         s.mcpReason,   // "" unless wasMCP
		CostUSD:        costUSD,
		Provider:       provider,
	})
	p.cfg.Metrics.RecordRequest("allow", proto)
	for _, name := range s.swappedNames {
		p.cfg.Metrics.RecordSecretSwap(name)
	}
	p.logDecision(decisionLog{
		Domain: s.domain, Port: s.port, Protocol: proto,
		Method: s.req.Method, URL: fullURL, Decision: "allow",
		ResponseStatus: s.resp.StatusCode, SecretRef: secretRef,
		JudgeReason: s.judgeReason,
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
