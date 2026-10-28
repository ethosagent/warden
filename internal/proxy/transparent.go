package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/policy"
)

// The transparent listeners (#376). The ports are the INTERCEPTED destination
// ports, not the local binds: DNS/redirect moves the agent's :443/:80 packets
// to whatever address proxy.transparent.* binds, so policy is evaluated on
// 443/https and 80/http regardless of the bind port. The listeners are
// opt-in (proxy.mode transparent|both); in forward mode none of this runs.
const (
	transparentHTTPSPort = 443
	transparentHTTPPort  = 80
	// maxPlainHeaderBytes caps the plain-HTTP header block, in the same order
	// as maxConnectHeaderBytes: the agent controls every byte, so the first
	// header block is bounded before it is parsed.
	maxPlainHeaderBytes = 64 << 10 // 64 KiB
)

// handleTransparentTLS serves one connection on the transparent :443 listener:
// the ClientHello is sniffed BEFORE any handshake (its server_name is the only
// destination signal there is), policy is evaluated on (SNI, 443, https) with
// the same admission gate as the CONNECT floor, and only then does TLS
// termination begin — via terminateAndDispatch, the ONE post-ClientHello path
// shared with forward mode, so h1 and h2 (ALPN) enter the same pipeline. Fail
// closed everywhere: no readable SNI (including ECH), a malformed or over-limit
// hello, and plaintext h2 prior knowledge on this port are all denied with
// their declared reasons; a truncated hello mirrors the CONNECT floor's silent
// drop (the client vanished before anything was gated).
func (p *Proxy) handleTransparentTLS(conn net.Conn) {
	p.reach(PathTransparentTLS)
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)

	// Slowloris floor, mirroring the CONNECT preamble: the whole ClientHello
	// must arrive within one deadline, which is lifted before the (much
	// longer) TLS handshake.
	if !p.setPreambleDeadline(conn) {
		return
	}
	sni, helloWire, err := sniffClientHello(br, maxClientHelloBytes)
	if err != nil {
		switch {
		case errors.Is(err, errH2PriorKnowledge):
			p.storeDeny(connIdentity{}, "", transparentHTTPSPort, "tcp", denyreason.TransparentH2PriorKnowledge, "")
		case errors.Is(err, errHelloTruncated):
			// Client gone / stalled mid-hello: nothing was gated, drop silently
			// (CONNECT-floor parity).
		case errors.Is(err, errNotTLSRecord):
			p.storeDeny(connIdentity{}, "", transparentHTTPSPort, "tcp", denyreason.TransparentBadClientHello, "not_tls")
		case errors.Is(err, errHelloTooLarge):
			p.storeDeny(connIdentity{}, "", transparentHTTPSPort, "tcp", denyreason.TransparentBadClientHello, "hello_too_large")
		default:
			p.storeDeny(connIdentity{}, "", transparentHTTPSPort, "tcp", denyreason.TransparentBadClientHello, "malformed")
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	domain := policy.NormalizeHost(sni)
	if domain == "" {
		// A readable hello that names no server — the ECH case included: the
		// real SNI is encrypted, so the destination is unknown. Refuse.
		p.storeDeny(connIdentity{}, "", transparentHTTPSPort, "tcp", denyreason.TransparentNoSNI, "")
		return
	}

	// The name is client-chosen bytes on an unauthenticated port: it must be a
	// plain LDH DNS name before policy evaluates it and before any certificate
	// is minted for it (validateSNI's normalisation matches NormalizeHost's).
	// A refused name is audited only in its safe rendering — never the raw
	// bytes the client picked.
	domain, ok := validateSNI(sni)
	if !ok {
		p.storeDeny(connIdentity{}, safeSNI(sni), transparentHTTPSPort, "tcp", denyreason.TransparentBadClientHello, "bad_sni")
		return
	}

	// Policy on the SNI before any handshake, through the same gate as the
	// CONNECT floor (admit): Deny (or NoMatch with no judge) is refused with the
	// declared reason; NoMatch with a judge, and a Conditional destination (no
	// Proxy-Authorization exists here), proceed to termination so the judge or
	// the per-request subject can decide the real request.
	g := p.admit(policy.RequestContext{Domain: domain, Port: transparentHTTPSPort, Scheme: policy.SchemeHTTPS})
	if g.deny {
		p.emitDenyEvent(connIdentity{}, analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      transparentHTTPSPort,
			Protocol:  "tcp",
			Reason:    string(g.reason),
		})
		return
	}

	// The sniff consumed the hello off the socket, so the TLS handshake must be
	// handed it back: re-serve the sniffed bytes, then whatever stayed buffered
	// in br, then the conn itself — into the same post-ClientHello path forward
	// mode uses.
	replay := io.MultiReader(bytes.NewReader(helloWire), br, conn)
	p.terminateAndDispatch(conn, replay, domain, transparentHTTPSPort, g.defers, connIdentity{})
}

// handleTransparentHTTP serves one connection on the transparent :80 listener:
// plain HTTP, gated on the Host header (no Host → deny). The first request is
// read under a bounded header budget, admitted through the same tri-state
// policy gate as the CONNECT floor, then handed — request included — to the
// shared h1 pipeline (handleHTTP) with an upstream scheme of http, so every
// later stage (swap, scan, MCP, judge, analytics) is the ONE pipeline.
func (p *Proxy) handleTransparentHTTP(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if !p.setPreambleDeadline(conn) {
		return
	}
	// Bound the header block while it is parsed; the cap is lifted before any
	// body streams (single goroutine owns the conn: parse, then serve). ONE
	// bufio over the bounded conn feeds the parse AND the pipeline below, so
	// buffered bytes are never stranded in a second reader.
	bc := &boundedHeaderConn{Conn: conn, budget: maxPlainHeaderBytes}
	br := bufio.NewReader(bc)
	req, err := http.ReadRequest(br)
	if err != nil {
		if bc.exceeded {
			p.rejectPlainHTTP(conn, br, connectHeadersTooLargeResponse, "header_block_too_large")
			return
		}
		if isConnDrop(err) {
			// Client gone / stalled / garbage truncated by a close: nothing was
			// gated, drop silently (CONNECT-floor parity).
			return
		}
		p.rejectPlainHTTP(conn, br, plainHTTPBadRequestResponse, "unparseable")
		return
	}
	// The request parsed — lift the deadline so it cannot cut off the upstream
	// round trip, and unbind the header budget so a body streams uncapped.
	_ = conn.SetReadDeadline(time.Time{})
	bc.unbound()

	// The port is stripped exactly as readRequest strips it: the default-deny
	// gate decides on the HOST, so "Host: x:80" and "Host: x" cannot decide
	// differently, and a deny records the bare host.
	host := req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		host = h
	}
	host = policy.NormalizeHost(host)
	if host == "" {
		// HTTP/1.1 requires Host; without it the destination is unknown and the
		// request cannot be gated. (A full URL-form target sets req.URL.Host,
		// which net/http mirrors into req.Host; an empty one is absolute-form
		// garbage or a bare HTTP/1.0 request.)
		p.rejectPlainHTTP(conn, br, plainHTTPBadRequestResponse, "no_host")
		return
	}

	g := p.admit(policy.RequestContext{Domain: host, Port: transparentHTTPPort, Scheme: policy.SchemeHTTP})
	if g.deny {
		p.emitDenyEvent(connIdentity{}, analytics.Event{
			Timestamp: time.Now(),
			Domain:    host,
			Port:      transparentHTTPPort,
			Protocol:  "http",
			Reason:    string(g.reason),
		})
		_, _ = fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	// Admitted: the SAME h1 pipeline a CONNECT tunnel runs, over http.
	p.handleHTTP(conn, br, host, transparentHTTPPort, g.defers, policy.SchemeHTTP, req, connIdentity{})
}

// rejectPlainHTTP is the plain-HTTP floor's bounded rejection: ONE deny with a
// declared reason, the error response, then the lingering close (drain + drop)
// the CONNECT floor uses — the client is often still mid-send when the limit
// trips, and closing unread would reset before it can read the response.
func (p *Proxy) rejectPlainHTTP(conn net.Conn, br *bufio.Reader, resp, detail string) {
	p.storeDeny(connIdentity{}, "", transparentHTTPPort, "http", denyreason.MalformedRequest, detail)
	_, _ = fmt.Fprint(conn, resp)
	_, _ = io.Copy(io.Discard, br)
}

// plainHTTPBadRequestResponse is the floor's 400 (unparseable request line /
// headers, missing Host). Connection: close + Content-Length: 0 delimit it
// exactly, like the CONNECT preamble rejections.
const plainHTTPBadRequestResponse = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"

// setPreambleDeadline applies the shared slowloris floor (the CONNECT
// preamble timeout) to conn. It reports false when the deadline cannot be set,
// in which case the conn is unusable.
func (p *Proxy) setPreambleDeadline(conn net.Conn) bool {
	timeout := p.preambleTimeout
	if timeout <= 0 {
		timeout = connectPreambleTimeout
	}
	return conn.SetReadDeadline(time.Now().Add(timeout)) == nil
}

// isConnDrop reports whether err is a connection drop (EOF, reset, deadline)
// rather than bytes the client actually sent that failed to parse. A drop
// before anything was gated is dropped silently, like the CONNECT floor; real
// bytes that do not parse are denied.
func isConnDrop(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// errPlainHeaderBudget reports a plain-HTTP header block that crossed its byte
// budget (see boundedHeaderConn).
var errPlainHeaderBudget = errors.New("proxy: plain-HTTP header block over budget")

// boundedHeaderConn caps the TOTAL bytes read from the underlying conn while
// the plain-HTTP header block is parsed (#376). unbound lifts the cap before
// the request body streams. One goroutine owns the conn at a time — the
// handler parses, then serves — so the flip needs no locking; the exceeded
// flag lets the handler tell an over-budget parse from an ordinary drop.
type boundedHeaderConn struct {
	net.Conn
	budget   int64
	exceeded bool
}

func (c *boundedHeaderConn) Read(p []byte) (int, error) {
	if c.budget <= 0 {
		// The budget is spent. A parse already holding a complete request
		// never reads again; one that needs more header bytes fails here, and
		// the exceeded flag tells the handler it was the budget (not a drop).
		c.exceeded = true
		return 0, errPlainHeaderBudget
	}
	if int64(len(p)) > c.budget {
		p = p[:c.budget]
	}
	n, err := c.Conn.Read(p)
	c.budget -= int64(n)
	return n, err
}

// unbound lifts the byte cap entirely (a body streams uncapped afterwards; the
// 10 MB swap cap still applies to buffering, as on every path).
func (c *boundedHeaderConn) unbound() { c.budget = math.MaxInt64 }
