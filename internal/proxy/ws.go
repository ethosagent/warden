package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/mcp/gateway"
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
) {
	defer func() { _ = upstream.Close() }()

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

	// The WS frame pump scans through the concrete *gateway.Gateway. gw is always
	// a *gateway.Gateway in production (built by gateway.New); the type assertion
	// recovers it. A non-gateway MCPGateway (e.g. a test fake) leaves the pump's GW
	// nil, so frames forward verbatim without WS scanning — the request/response
	// HTTP paths still went through the interface.
	concreteGW, _ := gw.(*gateway.Gateway)
	pump := &ws.Pump{GW: concreteGW, SessionKey: sessionKey, Log: p.cfg.Logger}
	client := rwc{br: clientBR, conn: tlsConn}
	server := connRWC{r: upstreamBR, conn: upstream}

	start := time.Now()
	blocked, _ := pump.Run(context.Background(), client, server)
	p.cfg.Metrics.ObserveAddedLatency("mcp_scan", time.Since(start))

	fullURL := "https://" + domain + req.URL.RequestURI()
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
