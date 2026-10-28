package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
)

// CONNECT preamble limits. An agent controls every byte it sends to the proxy
// port, so the request line and the whole header block are bounded before they
// are parsed (#390, found by the red-team playbook dry run #356). They are
// constants on purpose — the same order common proxies use — not config keys:
// a knob would let a misconfiguration weaken the floor.
const (
	// maxConnectLineBytes caps the CONNECT request line, CRLF included.
	maxConnectLineBytes = 8 << 10 // 8 KiB
	// maxConnectHeaderBytes caps the whole preamble: the request line, every
	// header line, and the terminating blank line.
	maxConnectHeaderBytes = 64 << 10 // 64 KiB
	// connectPreambleTimeout is how long a client may take to deliver the whole
	// preamble. A slowloris agent dribbling one byte per minute must not hold a
	// handleConn goroutine forever.
	connectPreambleTimeout = 10 * time.Second
)

func (p *Proxy) Serve(ctx context.Context) error {
	// served is one listener plus the handler its connections go to.
	type served struct {
		ln     net.Listener
		handle func(net.Conn)
		name   string
	}
	var listeners []served
	// closeAll releases every listener on a late bind failure, so a boot that
	// fails mid-way leaves no socket behind.
	closeAll := func() {
		for _, l := range listeners {
			_ = l.ln.Close()
		}
	}

	// The CONNECT listener binds in forward and both mode — byte-identical to
	// before #376 (same bind, same seam precedence, same ctx-done close). In
	// transparent-only mode it must NOT exist: the agent-facing proxy port is
	// the point of the mode.
	if p.cfg.Mode != config.ProxyModeTransparent {
		ln := p.cfg.Listener
		if ln == nil {
			var err error
			ln, err = net.Listen("tcp", p.cfg.ListenAddr)
			if err != nil {
				return fmt.Errorf("proxy: listen: %w", err)
			}
		}
		p.listenerMu.Lock()
		p.listener = ln
		p.listenerMu.Unlock()
		listeners = append(listeners, served{ln: ln, handle: p.handleConn, name: "listen"})
	}

	// The transparent listeners (#376) bind only in transparent/both mode.
	// Either listener may come from the assembly seam instead of a bind.
	if p.cfg.Mode == config.ProxyModeTransparent || p.cfg.Mode == config.ProxyModeBoth {
		tlsLn := p.cfg.TransparentHTTPSListener
		if tlsLn == nil {
			var err error
			tlsLn, err = net.Listen("tcp", p.cfg.TransparentHTTPSListen)
			if err != nil {
				closeAll()
				return fmt.Errorf("proxy: transparent https listen: %w", err)
			}
		}
		listeners = append(listeners, served{ln: tlsLn, handle: p.handleTransparentTLS, name: "transparent_https"})
		httpLn := p.cfg.TransparentHTTPListener
		if httpLn == nil && p.cfg.TransparentHTTPListen != "" {
			var err error
			httpLn, err = net.Listen("tcp", p.cfg.TransparentHTTPListen)
			if err != nil {
				closeAll()
				return fmt.Errorf("proxy: transparent http listen: %w", err)
			}
		}
		if httpLn != nil {
			listeners = append(listeners, served{ln: httpLn, handle: p.handleTransparentHTTP, name: "transparent_http"})
		}
		p.setTransparentAddrs(tlsLn.Addr(), httpAddr(httpLn))
		// Loop guard (#376): the guard set must be installed before the first
		// connection is served, so no upstream dial can pre-date it.
		p.installLoopGuard()
		if p.cfg.OnTransparentReady != nil {
			p.cfg.OnTransparentReady(tlsLn.Addr().String(), listenerAddrString(httpLn))
		}
	}

	// ctx done closes every listener — injected and self-bound alike.
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		closeAll()
		close(done)
	}()

	// One accept loop per listener; the first failure that is not the ctx-done
	// close ends Serve with it.
	errCh := make(chan error, len(listeners))
	for _, l := range listeners {
		go func(l served) {
			for {
				conn, err := l.ln.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						errCh <- nil
					default:
						errCh <- fmt.Errorf("proxy: accept (%s): %w", l.name, err)
					}
					return
				}
				go l.handle(conn)
			}
		}(l)
	}
	select {
	case <-done:
		return nil
	case err := <-errCh:
		return err
	}
}

// httpAddr is nil-safe so setTransparentAddrs can record "plain HTTP not
// served" as a nil address.
func httpAddr(ln net.Listener) net.Addr {
	if ln == nil {
		return nil
	}
	return ln.Addr()
}

// listenerAddrString formats a listener's bound address, "" when there is none
// (the plain-HTTP listener may be absent) — the OnTransparentReady shape.
func listenerAddrString(ln net.Listener) string {
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

// errLineTooLong reports a preamble line that crossed its byte cap before the
// terminating newline arrived (see readBoundedLine).
var errLineTooLong = errors.New("proxy: connect preamble line too long")

// Preamble rejections, answered before the drain-and-close. Connection: close
// announces that nothing follows the response, and Content-Length: 0 delimits
// it exactly, so a client never waits on a body of unknown length.
const (
	// connectLineTooLongResponse is the 414 for a request line past
	// maxConnectLineBytes.
	connectLineTooLongResponse = "HTTP/1.1 414 URI Too Long\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
	// connectHeadersTooLargeResponse is the 431 for a preamble past
	// maxConnectHeaderBytes.
	connectHeadersTooLargeResponse = "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
)

// readBoundedLine reads one '\n'-terminated line from br — newline included,
// the same shape bufio.Reader.ReadString returns. Unlike ReadString it refuses
// (with errLineTooLong, without reading or buffering a single byte past limit)
// any longer line, so a multi-megabyte request line can never reach memory
// whole. The accumulated line itself never occupies more than limit bytes.
func readBoundedLine(br *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			return "", errLineTooLong
		}
		line = append(line, chunk...)
		if err == nil {
			return string(line), nil
		}
		if err != bufio.ErrBufferFull {
			return "", err
		}
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)

	// Slowloris floor: the whole preamble (line + headers) must arrive within
	// one deadline; a client still dribbling bytes past it is dropped silently
	// (nothing was gated). The deadline is lifted below once the preamble
	// completes, so it never bounds the tunnel/TLS traffic that follows.
	preambleTimeout := p.preambleTimeout
	if preambleTimeout <= 0 {
		preambleTimeout = connectPreambleTimeout
	}
	if err := conn.SetReadDeadline(time.Now().Add(preambleTimeout)); err != nil {
		return
	}

	line, err := readBoundedLine(br, maxConnectLineBytes)
	if err != nil {
		if errors.Is(err, errLineTooLong) {
			p.rejectPreamble(conn, br, connectLineTooLongResponse, "request_line_too_long")
			return
		}
		// The client closed (or errored/timed out) before sending a request line —
		// no egress was attempted, so there is nothing to gate or audit. Drop
		// silently.
		return
	}

	// TCP default-deny floor. This proxy speaks only HTTP CONNECT; every egress
	// path an agent has (including tunnels for non-HTTP protocols) arrives as a
	// CONNECT request and is gated on host:port below. Anything that is NOT a
	// well-formed CONNECT is dropped AND audited here, so an agent cannot bypass
	// policy simply by not speaking HTTP CONNECT ("cannot bypass by not being
	// HTTP"). No domain is known at this pre-protocol stage, so the deny is
	// recorded without one.
	if !strings.HasPrefix(line, "CONNECT ") || !strings.Contains(line, "HTTP/") {
		p.storeDeny(connIdentity{}, "", 0, "tcp", denyreason.UnsupportedProtocol, "")
		return
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		p.storeDeny(connIdentity{}, "", 0, "tcp", denyreason.MalformedConnect, "")
		return
	}
	target := fields[1]

	domain, port, err := SplitHostPort(target)
	if err != nil {
		p.storeDeny(connIdentity{}, "", 0, "tcp", denyreason.MalformedConnect, "")
		return
	}

	// Bounded header block: line + every header line + the terminating blank
	// line must fit maxConnectHeaderBytes. Each line is capped at what is left
	// of the budget, so one huge header trips the same 431 as many small ones.
	total := len(line)
	// Proxy-Authorization carries the user token (identity.go). Only the first
	// line's value is kept; a second line makes the identity malformed.
	var proxyAuth string
	proxyAuthLines := 0
	for {
		hdr, err := readBoundedLine(br, maxConnectHeaderBytes-total)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				p.rejectPreamble(conn, br, connectHeadersTooLargeResponse, "headers_too_large")
				return
			}
			return
		}
		total += len(hdr)
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
		if isHeaderLine(hdr, proxyAuthorizationHeader) {
			if proxyAuthLines == 0 {
				proxyAuth = hdr[len(proxyAuthorizationHeader)+1:]
			}
			proxyAuthLines++
		}
	}
	// Preamble complete — lift the deadline so it cannot cut off the tunnel or
	// the TLS handshake, either of which may idle far longer than the preamble
	// budget.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	// Resolve who is asking before the policy check, so a CONNECT deny is
	// attributable too. A CONNECT with no token (the common case) does no work
	// here; one with a token is bounded by identityVerifyTimeout.
	ci := p.resolveConnIdentity(proxyAuthLines, proxyAuth)

	// A blocked user is refused before the policy check, any dial and the 200,
	// on both the TLS-terminating and the raw-tunnel path.
	if p.connectBlocked(conn, ci, domain, port) {
		return
	}

	// Destination-only evaluation (#371): no method/path exists yet at CONNECT,
	// so constraints could-match here and the rate limit is peeked, not
	// consumed. The per-request check on the terminated tunnel is authoritative
	// and counts each request exactly once. The subject is the connection's
	// verified identity (nil unless the token was valid), so a scoped entry can
	// admit a member here; everything it leaves open is deferred (see admit).
	g := p.admit(policy.RequestContext{
		Domain:  domain,
		Port:    port,
		Scheme:  policy.SchemeHTTPS,
		Subject: p.connSubject(ci),
	})
	if g.deny {
		// Deny (denylist hit, or an allowlisted destination rejected by a
		// constraint / rate-limit / time-window guard) names its reason (#409);
		// a NoMatch with no judge is the policy_no_match default-deny.
		p.emitDenyEvent(ci, analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Reason:    string(g.reason),
		})
		_, _ = fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	if p.caCert != nil {
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		p.handleTLS(conn, br, domain, port, g.defers, ci)
		return
	}

	// No TLS termination: neither the judge nor a per-request subject check can
	// inspect an opaque tunnel, so a deferred request must fail closed here —
	// only statically Allowed destinations may be raw-tunneled, with one
	// exception: a scoped Allow for a verified member, tunneled only until the
	// token expires.
	var tunnelUntil time.Time
	switch g.defers {
	case deferNone:
	case deferIdentity:
		if g.verdict.Decision != policy.Allow || ci.Expiry.IsZero() {
			p.denyConnect(conn, ci, domain, port, denyreason.IdentityRequired)
			return
		}
		d := ci.Expiry.Sub(p.clock())
		if d <= 0 {
			p.denyConnect(conn, ci, domain, port, denyreason.IdentityRequired)
			return
		}
		tunnelUntil = time.Now().Add(d)
	default:
		p.denyConnect(conn, ci, domain, port, denyreason.PolicyNoMatch)
		return
	}

	_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	p.tunnel(conn, br, domain, port, ci, tunnelUntil)
}

// connSubject is the policy subject of the connection's verified identity: nil
// unless the CONNECT token verified (status valid), so a missing, invalid,
// expired or unverified token never counts as a member.
func (p *Proxy) connSubject(ci connIdentity) *identity.Subject {
	s := identity.SubjectFrom(ci.Claims, ci.status())
	if s != nil {
		s.AgentID = p.cfg.AgentID
	}
	return s
}

// denyConnect refuses a CONNECT with a 403 and one deny event.
func (p *Proxy) denyConnect(conn net.Conn, ci connIdentity, domain string, port int, reason denyreason.Reason) {
	p.emitDenyEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  "tcp",
		Reason:    string(reason),
	})
	_, _ = fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
}

// isHeaderLine reports whether the raw header line starts with "<name>:",
// case-insensitively. It allocates nothing, so the CONNECT loop pays one
// length check and a compare per header line.
func isHeaderLine(line, name string) bool {
	return len(line) > len(name) && line[len(name)] == ':' && strings.EqualFold(line[:len(name)], name)
}

// rejectPreamble answers an over-limit CONNECT preamble with an HTTP error and
// records exactly ONE deny decision — bounded reason plus detail, never the
// oversized bytes themselves — then drops the connection. Before dropping, the
// rest of the request is drained to the bit bucket, bounded by the preamble
// deadline and io.Copy's fixed buffer (never accumulated): the client is still
// mid-send when the limit trips, and closing on it unread would reset the
// connection before it can read the rejection. This is the standard error
// close (nginx/HAProxy lingering close).
func (p *Proxy) rejectPreamble(conn net.Conn, br *bufio.Reader, resp, detail string) {
	p.storeDeny(connIdentity{}, "", 0, "tcp", denyreason.MalformedConnect, detail)
	_, _ = fmt.Fprint(conn, resp)
	_, _ = io.Copy(io.Discard, br)
}

// storeDeny records a pre-tunnel CONNECT-floor deny (headers/metadata only —
// never bodies; there is no requestScope yet, so it builds the event directly
// and hands it to the shared deny chokepoint). The reason is from the one
// declared set (internal/denyreason) and rides BOTH the event and the
// warden.blocked.total{reason} metric. detail, when non-empty, is a bounded
// refinement of the reason (e.g. "request_line_too_long") for the decision log
// only; it never carries request content.
func (p *Proxy) storeDeny(ci connIdentity, domain string, port int, protocol string, reason denyreason.Reason, detail string) {
	p.emitDenyEventDetail(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  protocol,
		Reason:    string(reason),
	}, detail)
}

// storeSSRFDeny records the deny decision for a dial the SSRF-safe dialer
// refused (#391): the event carries the bounded ssrf_* reason and the address
// class, never the resolved address list. It is a no-op — returning false — for
// any other error, so ordinary dial failures (DNS failure, timeout, connection
// refused) are never mis-audited as ssrf_*.
func (p *Proxy) storeSSRFDeny(ci connIdentity, domain string, port int, protocol string, err error) bool {
	se, ok := AsSSRFError(err)
	if !ok {
		return false
	}
	p.emitDenyEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  protocol,
		Reason:    string(ssrfDenyReason(se)),
		AddrClass: se.AddrClass,
	})
	return true
}

// storeAllow records the single allow decision for an admitted CONNECT
// (event + metric + log line), the raw-tunnel counterpart of storeDeny.
func (p *Proxy) storeAllow(ci connIdentity, domain string, port int, protocol string) {
	p.recordEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  protocol,
		Decision:  "allow",
	})
	p.cfg.Metrics.RecordRequest("allow", protocol)
	p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: protocol, Decision: "allow", ID: ci})
}

// tunnel completes a raw (non-TLS-terminating) CONNECT: dial the destination
// through the SSRF-safe dialer, audit ONE decision event, then pipe both ways.
// The allow audit is written only once the dial succeeds (#391), so a refused
// dial records the deny instead and the dashboard shows the final decision —
// never an allow followed by a deny for the same CONNECT. The client, which
// already has its 200, sees the tunnel close either way. An ordinary dial
// failure is not a policy decision: it keeps the allow audit the CONNECT has
// always gotten, unchanged from before #391.
//
// A raw tunnel is opaque and records no per-request identity (stamping events
// is W-P1-VRFY-09); the CONNECT identity only registers it for a block-list cut.
func (p *Proxy) tunnel(client net.Conn, br *bufio.Reader, domain string, port int, ci connIdentity, until time.Time) {
	p.reach(PathTunnel)
	// Only an attributed tunnel registers: an anonymous one costs nothing here.
	var sess *session
	if ci.Claims.Sub != "" || ci.Claims.Email != "" {
		sess = p.sessions.newSession("tcp", domain, port, true, client)
		sess.bind(ci)
		defer sess.release()
	}
	remote, err := p.dialFunc("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)))
	if err != nil {
		if !p.storeSSRFDeny(ci, domain, port, "tcp", err) {
			p.storeAllow(ci, domain, port, "tcp")
		}
		return
	}
	p.storeAllow(ci, domain, port, "tcp")
	sess.addCloser(remote)

	// A tunnel admitted through a scoped entry cannot be re-checked per request,
	// so it lives only as long as the token: both ends are cut at until. A
	// policy swap does not cut it (documented limitation).
	if !until.IsZero() {
		_ = client.SetDeadline(until)
		t := time.AfterFunc(time.Until(until), func() {
			_ = client.Close()
			_ = remote.Close()
		})
		defer t.Stop()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, br)
		if tc, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, remote)
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}
