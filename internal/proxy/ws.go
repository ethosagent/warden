package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/mcp/ws"
)

// rwc adapts a buffered reader (which may already hold bytes read past the HTTP
// response) plus a net.Conn writer into a single io.ReadWriteCloser, so the
// WebSocket pump can treat the TLS-terminated client side uniformly. Reads come
// from br (preserving any buffered bytes); writes and Close go to the conn.
type rwc struct {
	br   *bufio.Reader
	conn net.Conn
}

func (c rwc) Read(p []byte) (int, error)  { return c.br.Read(p) }
func (c rwc) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c rwc) Close() error                { return c.conn.Close() }

// connRWC wraps a net.Conn whose reads should go through a buffered reader (so
// no bytes buffered during the HTTP handshake are lost). Used for the upstream
// side of the WebSocket pump.
type connRWC struct {
	r    io.Reader
	conn net.Conn
}

func (c connRWC) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c connRWC) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c connRWC) Close() error                { return c.conn.Close() }

// handleWSUpgrade completes a WebSocket handshake through Warden and runs the
// frame pump. It writes the upstream's 101 response verbatim to the client, then
// scans every JSON-RPC text message in both directions while forwarding frames
// transparently. A 101 is terminal for the connection: this method fully owns
// the client conn, the upstream, and the buffered readers, and the caller must
// return afterward.
//
// clientBR is the buffered reader over the client TLS conn (it may already hold
// frame bytes the client pipelined after the upgrade request). upstreamBR is the
// buffered reader used to read the 101 response (it may already hold frame bytes
// the server sent after its 101), so both readers are reused to avoid losing
// buffered payload.
//
// inflightDone is the request scope's quiescence-tracker slot (nil when no
// tracker is installed). It is fired once the 101 is DELIVERED — an open WS
// session must never block a waiter — and the session re-enters the tracker
// after the pump ends, before this session's terminal event is recorded.
// The deliberate trade-off: the tracker does not track the OPEN session, so
// from the 101 delivery until the re-entry below it is idle while the
// session's terminal event does not exist yet — and a session that has just
// ended is only re-tracked milliseconds before its event lands. "Tracker
// idle" therefore never implies a WebSocket session's terminal event is
// readable, and a test reading one must use EventuallyWithin (the drained-
// tracker guarantee covers every non-streaming request, never a session).
func (p *Proxy) handleWSUpgrade(
	tlsConn *tls.Conn,
	clientBR *bufio.Reader,
	upstream net.Conn,
	upstreamBR *bufio.Reader,
	resp *http.Response,
	req *http.Request,
	domain string,
	port int,
	sessionKey string,
	gw MCPGateway,
	inflightDone func(),
) {
	defer func() { _ = upstream.Close() }()

	// Resolve the WS-scan capability through the interface — never a concrete
	// type — so any MCPGateway (including a wrapper/decorator over the real
	// gateway) drives frame scanning. When the live gateway does NOT provide WS
	// scanning we fail closed in enforce mode and log-once + pass through in
	// monitor/off, instead of silently forwarding unscanned frames.
	scanner, canScan := gw.(WSScanner)
	if !canScan {
		if p.wsEnforcing(gw) {
			// Fail closed: refuse the 101, record the block, and let the deferred
			// upstream.Close() run. The pump never starts, so nothing else owns or
			// closes the upstream — no leak, no double close.
			p.refuseWSEnforce(tlsConn, req, domain, port)
			return
		}
		// monitor/off: preserve today's pass-through (nil scanner => pump forwards
		// frames unscanned) but log the degraded control exactly once.
		p.wsDowngradeOnce.Do(func() {
			p.cfg.Logger.Warn("mcp ws scanning unavailable; forwarding frames unscanned (monitor/off)",
				slog.String("domain", domain), slog.Int("port", port))
		})
	}

	// Write the 101 status line + headers verbatim (mirrors the SSE manual
	// write). resp.Write cannot be used: there is no body and the connection is
	// then handed to the raw frame pump.
	statusLine := fmt.Sprintf("HTTP/%d.%d %03d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode,
		http.StatusText(resp.StatusCode))
	if _, err := io.WriteString(tlsConn, statusLine); err != nil {
		return
	}
	if err := resp.Header.Write(tlsConn); err != nil {
		return
	}
	if _, err := io.WriteString(tlsConn, "\r\n"); err != nil {
		return
	}

	// The 101 is delivered: the session is open-ended from here, so the request
	// scope steps OUT of the quiescence tracker (firing the slot is idempotent —
	// the caller's deferred endInflight re-calls it harmlessly). On the
	// write-error returns above the scope was never stepped out and still ends
	// through the caller's defer.
	runInflight(inflightDone)

	// scanner is a nil ws.Scanner when the capability was absent (monitor/off
	// downgrade): the pump then forwards every frame verbatim without scanning.
	pump := &ws.Pump{GW: scanner, SessionKey: sessionKey, Log: p.cfg.Logger}
	client := rwc{br: clientBR, conn: tlsConn}
	server := connRWC{r: upstreamBR, conn: upstream}

	start := time.Now()
	blocked, _ := pump.Run(context.Background(), client, server)
	p.cfg.Metrics.ObserveAddedLatency("mcp_scan", time.Since(start))

	fullURL := "https://" + domain + req.URL.RequestURI()

	// Session over: back in the quiescence tracker BEFORE the terminal
	// bookkeeping below, so the tracker's drain happens-after the session's
	// audit event, metric and decision log. The guard keeps the description
	// concatenation off the production hot path (no tracker installed).
	if p.cfg.Inflight != nil {
		if done := p.inflightStart("ws " + req.Method + " " + fullURL); done != nil {
			defer done()
		}
	}
	p.beforeTerminal()

	decision := "allow"
	if blocked {
		decision = "deny"
		p.cfg.Metrics.RecordBlocked("mcp_ws")
	}
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp:      time.Now(),
		Domain:         domain,
		Port:           port,
		Protocol:       "mcp",
		Method:         req.Method,
		URL:            fullURL,
		Decision:       decision,
		ResponseStatus: resp.StatusCode,
	})
	p.cfg.Metrics.RecordRequest(decision, "mcp")
	p.logDecision(decisionLog{
		Domain: domain, Port: port, Protocol: "mcp",
		Method: req.Method, URL: fullURL, Decision: decision,
		ResponseStatus: resp.StatusCode,
	})
}

// wsEnforcing reads the CURRENT gateway's enforce state live (hot-swap safe: gw
// is the per-request snapshot). A gateway that does not expose mcpModeReader is
// treated as non-enforcing, so the WS path falls through to the pass-through
// downgrade rather than fabricating a refusal.
func (p *Proxy) wsEnforcing(gw MCPGateway) bool {
	mr, ok := gw.(mcpModeReader)
	return ok && mr.Enforcing()
}

// refuseWSEnforce fails a WebSocket upgrade closed: the live gateway cannot scan
// WS frames and MCP mode is enforce, so Warden refuses the 101 rather than
// forwarding frames unscanned. It writes a 502 (consistent with other MCP enforce
// denials), records a blocked decision (analytics event + metric + decisionLog)
// with the bounded reason mcp_ws_unscannable, and logs why at WARN. The caller's
// deferred upstream.Close() closes the upstream; the pump is never started.
func (p *Proxy) refuseWSEnforce(tlsConn *tls.Conn, req *http.Request, domain string, port int) {
	const reason = "mcp_ws_unscannable"
	fullURL := "https://" + domain + req.URL.RequestURI()
	writeErrorResponse(tlsConn, 502, "Bad Gateway")
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp:      time.Now(),
		Domain:         domain,
		Port:           port,
		Protocol:       "mcp",
		Method:         req.Method,
		URL:            fullURL,
		Decision:       "deny",
		Reason:         reason,
		ResponseStatus: 502,
	})
	p.cfg.Metrics.RecordRequest("deny", "mcp")
	p.cfg.Metrics.RecordBlocked(reason)
	p.logDecision(decisionLog{
		Domain: domain, Port: port, Protocol: "mcp",
		Method: req.Method, URL: fullURL, Decision: "deny",
		ResponseStatus: 502,
	})
	p.cfg.Logger.Warn("mcp ws scanning unavailable in enforce mode; refusing upgrade",
		slog.String("domain", domain), slog.Int("port", port), slog.String("reason", reason))
}
