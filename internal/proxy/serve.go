package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/policy"
)

func (p *Proxy) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("proxy: listen: %w", err)
	}
	p.listenerMu.Lock()
	p.listener = ln
	p.listenerMu.Unlock()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("proxy: accept: %w", err)
			}
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		// The client closed (or errored) before sending a request line — no egress
		// was attempted, so there is nothing to gate or audit. Drop silently.
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
		p.storeDeny("", 0, "tcp", "unsupported_protocol")
		return
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		p.storeDeny("", 0, "tcp", "malformed_connect")
		return
	}
	target := fields[1]

	domain, port, err := SplitHostPort(target)
	if err != nil {
		p.storeDeny("", 0, "tcp", "malformed_connect")
		return
	}

	for {
		hdr, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
	}

	// Destination-only evaluation (#371): no method/path exists yet at CONNECT,
	// so constraints could-match here and the rate limit is peeked, not
	// consumed. The per-request check on the terminated tunnel is authoritative
	// and counts each request exactly once.
	decision := p.cfg.Policy.EvaluateRequest(domain, port, policy.SchemeHTTPS, "", "").Decision
	// Tri-state gate:
	//   Allow   -> proceed.
	//   Deny    -> 403 (explicit denylist / throttled allow entry).
	//   NoMatch -> if the judge is enabled, let CONNECT proceed to TLS
	//              termination so the judge can inspect the full request;
	//              otherwise default-deny exactly as before (403).
	judgeEnabled := p.judge() != nil
	if decision == policy.Deny || (decision == policy.NoMatch && !judgeEnabled) {
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Decision:  "deny",
		})
		p.cfg.Metrics.RecordRequest("deny", "tcp")
		p.cfg.Metrics.RecordBlocked("policy")
		p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: "tcp", Decision: "deny"})
		_, _ = fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	if p.caCert != nil {
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		p.handleTLS(conn, br, domain, port, decision == policy.NoMatch)
		return
	}

	// No TLS termination: the judge cannot inspect an opaque tunnel, so a
	// NoMatch request must fail closed here — only statically Allowed
	// destinations may be raw-tunneled.
	if decision == policy.NoMatch {
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Decision:  "deny",
		})
		p.cfg.Metrics.RecordRequest("deny", "tcp")
		p.cfg.Metrics.RecordBlocked("no_tls")
		p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: "tcp", Decision: "deny"})
		_, _ = fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	p.tunnel(conn, br, domain, port)
}

// storeDeny records a deny decision (headers/metadata only — never bodies). The
// reason is a bounded enum used for the warden.blocked.total{reason} metric.
func (p *Proxy) storeDeny(domain string, port int, protocol, reason string) {
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  protocol,
		Decision:  "deny",
	})
	p.cfg.Metrics.RecordRequest("deny", protocol)
	p.cfg.Metrics.RecordBlocked(reason)
	p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: protocol, Decision: "deny"})
}

// storeSSRFDeny records the deny decision for a dial the SSRF-safe dialer
// refused (#391): the event carries the bounded ssrf_* reason and the address
// class, never the resolved address list. It is a no-op — returning false — for
// any other error, so ordinary dial failures (DNS failure, timeout, connection
// refused) are never mis-audited as ssrf_*.
func (p *Proxy) storeSSRFDeny(domain string, port int, protocol string, err error) bool {
	se, ok := AsSSRFError(err)
	if !ok {
		return false
	}
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  protocol,
		Decision:  "deny",
		Reason:    se.Reason,
		AddrClass: se.AddrClass,
	})
	p.cfg.Metrics.RecordRequest("deny", protocol)
	p.cfg.Metrics.RecordBlocked(se.Reason)
	p.logDecision(decisionLog{
		Domain: domain, Port: port, Protocol: protocol,
		Decision: "deny", Reason: se.Reason, AddrClass: se.AddrClass,
	})
	return true
}

// storeAllow records the single allow decision for an admitted CONNECT
// (event + metric + log line), the raw-tunnel counterpart of storeDeny.
func (p *Proxy) storeAllow(domain string, port int, protocol string) {
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  protocol,
		Decision:  "allow",
	})
	p.cfg.Metrics.RecordRequest("allow", protocol)
	p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: protocol, Decision: "allow"})
}

// tunnel completes a raw (non-TLS-terminating) CONNECT: dial the destination
// through the SSRF-safe dialer, audit ONE decision event, then pipe both ways.
// The allow audit is written only once the dial succeeds (#391), so a refused
// dial records the deny instead and the dashboard shows the final decision —
// never an allow followed by a deny for the same CONNECT. The client, which
// already has its 200, sees the tunnel close either way. An ordinary dial
// failure is not a policy decision: it keeps the allow audit the CONNECT has
// always gotten, unchanged from before #391.
func (p *Proxy) tunnel(client net.Conn, br *bufio.Reader, domain string, port int) {
	remote, err := p.dialFunc("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)))
	if err != nil {
		if !p.storeSSRFDeny(domain, port, "tcp", err) {
			p.storeAllow(domain, port, "tcp")
		}
		return
	}
	p.storeAllow(domain, port, "tcp")

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
