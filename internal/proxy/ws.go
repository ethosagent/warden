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
// transparently, and guards every server->agent frame for swapped values when
// the upgrade request carried any (#399). A 101 is terminal for the connection:
// this method fully owns the client conn, the upstream, and the buffered
// readers, and the caller must return afterward.
//
// The scope's buffered readers are reused so no bytes are lost: s.br may already
// hold frame bytes the client pipelined after the upgrade request, and
// s.upstreamBR frame bytes the server sent after its 101.
func (p *Proxy) handleWSUpgrade(s *requestScope) {
	tlsConn, clientBR := s.tlsConn, s.br
	upstream, upstreamBR := s.upstream, s.upstreamBR
	resp, req, gw := s.resp, s.req, s.gw
	fullURL := s.eventURL() // the agent's original query, never a swapped one
	defer func() { _ = upstream.Close() }()

	// Resolve the WS-scan capability through the interface — never a concrete
	// type — so any MCPGateway (including a wrapper/decorator over the real
	// gateway) drives frame scanning. When the live gateway does NOT provide WS
	// scanning we fail closed in enforce mode and log-once + pass through in
	// monitor/off, instead of silently forwarding unscanned frames. A nil gw is
	// no downgrade: a plain WebSocket upgrade has no gateway to scan with and is
	// guarded for echo only.
	scanner, canScan := gw.(WSScanner)
	if !canScan && gw != nil {
		if p.wsEnforcing(gw) {
			// Fail closed: refuse the 101, record the block, and let the deferred
			// upstream.Close() run. The pump never starts, so nothing else owns or
			// closes the upstream — no leak, no double close.
			p.refuseWSEnforce(tlsConn, req, fullURL, s.domain, s.port)
			return
		}
		// monitor/off: preserve today's pass-through (nil scanner => pump forwards
		// frames unscanned) but log the degraded control exactly once.
		p.wsDowngradeOnce.Do(func() {
			p.cfg.Logger.Warn("mcp ws scanning unavailable; forwarding frames unscanned (monitor/off)",
				slog.String("domain", s.domain), slog.Int("port", s.port))
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

	// scanner is a nil ws.Scanner when the capability was absent (monitor/off
	// downgrade, or no gateway at all): the pump then forwards every frame
	// verbatim without scanning. Enforce mode holds each text message until it
	// is scanned, so a denied message never reaches its peer; monitor/off keep
	// forward-then-scan.
	hold := false
	if gw != nil {
		hold = p.holdMCP(gw)
	}
	pump := &ws.Pump{GW: scanner, SessionKey: s.mcpSessKey, Log: p.cfg.Logger, Hold: hold}
	// The frame guard arms only on a swap (#399): no swapped value in the
	// upgrade request means no needle set and no per-frame work — the frames are
	// forwarded exactly as before.
	var echo *wsEchoGuard
	if len(s.echoSecrets) > 0 {
		echo = p.newWSEchoGuard(s)
		pump.Echo = echo
	}
	client := rwc{br: clientBR, conn: tlsConn}
	server := connRWC{r: upstreamBR, conn: upstream}

	start := time.Now()
	blocked, _ := pump.Run(context.Background(), client, server)
	p.cfg.Metrics.ObserveAddedLatency("mcp_scan", time.Since(start))

	// An echo hit owns the session's one decision event: block mode wrote the
	// deny (reason secret_echo, the secret by reference) and nothing else is
	// recorded; in monitor mode the hit rides the allow event below, like every
	// other echo monitor hit. An RSV (compressed) frame on the armed connection
	// is the exception: the guard cannot scan those bytes, so it fails closed in
	// every mode with reason secret_echo_unscannable.
	if echo != nil {
		if secret, hit := echo.hitSecret(); hit {
			if r := echo.hitReason(); r == reasonSecretEchoUnscannable {
				p.echoDeny(s, secret, r)
				return
			}
			if !p.cfg.EchoGuard.Monitor {
				p.echoDeny(s, secret, reasonSecretEcho)
				return
			}
			s.echoMonitorReason = reasonSecretEcho
		}
	}

	proto := "mcp"
	if gw == nil {
		proto = s.proto // a plain WebSocket upgrade: no MCP gateway is involved
	}
	decision := "allow"
	if blocked {
		decision = "deny"
		p.cfg.Metrics.RecordBlocked("mcp_ws")
	}
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp:      time.Now(),
		Domain:         s.domain,
		Port:           s.port,
		Protocol:       proto,
		Method:         req.Method,
		URL:            fullURL,
		Decision:       decision,
		Reason:         s.echoMonitorReason,
		ResponseStatus: resp.StatusCode,
	})
	p.cfg.Metrics.RecordRequest(decision, proto)
	p.logDecision(decisionLog{
		Domain: s.domain, Port: s.port, Protocol: proto,
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

// holdMCP reports whether scanned MCP traffic must be held until the verdict. It
// follows the live mode, but FAILS SAFE: a gateway that scans yet does not report
// its mode is held as if enforcing (logged once) rather than silently falling
// back to forward-then-scan.
func (p *Proxy) holdMCP(gw MCPGateway) bool {
	if mr, ok := gw.(mcpModeReader); ok {
		return mr.Enforcing()
	}
	p.mcpModeUnknownOnce.Do(func() {
		p.cfg.Logger.Warn("mcp gateway does not report its mode; holding messages until scanned (fail safe)")
	})
	return true
}

// refuseWSEnforce fails a WebSocket upgrade closed: the live gateway cannot scan
// WS frames and MCP mode is enforce, so Warden refuses the 101 rather than
// forwarding frames unscanned. It writes a 502 (consistent with other MCP enforce
// denials), records a blocked decision (analytics event + metric + decisionLog)
// with the bounded reason mcp_ws_unscannable, and logs why at WARN. The caller's
// deferred upstream.Close() closes the upstream; the pump is never started.
func (p *Proxy) refuseWSEnforce(tlsConn *tls.Conn, req *http.Request, fullURL, domain string, port int) {
	const reason = "mcp_ws_unscannable"
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
