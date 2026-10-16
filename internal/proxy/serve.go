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
	"github.com/ethosagent/warden/internal/denyreason"
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
		p.storeDeny("", 0, "tcp", denyreason.UnsupportedProtocol)
		return
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		p.storeDeny("", 0, "tcp", denyreason.MalformedConnect)
		return
	}
	target := fields[1]

	domain, port, err := SplitHostPort(target)
	if err != nil {
		p.storeDeny("", 0, "tcp", denyreason.MalformedConnect)
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
	verdict := p.cfg.Policy.EvaluateRequest(domain, port, policy.SchemeHTTPS, "", "")
	// Tri-state gate:
	//   Allow   -> proceed.
	//   Deny    -> 403 (denylist hit, or an allowlisted destination rejected by
	//              a constraint / rate-limit / time-window guard). The verdict
	//              names WHY (#409): policy_denylist, rate_limited, time_window.
	//   NoMatch -> if the judge is enabled, let CONNECT proceed to TLS
	//              termination so the judge can inspect the full request;
	//              otherwise default-deny exactly as before (403) as
	//              policy_no_match.
	judgeEnabled := p.judge() != nil
	if verdict.Decision == policy.Deny || (verdict.Decision == policy.NoMatch && !judgeEnabled) {
		// A NoMatch default-deny is named here, at the gate: policy itself does
		// not consider NoMatch a deny (it is judge-eligible).
		reason := verdict.Reason
		if verdict.Decision == policy.NoMatch {
			reason = denyreason.PolicyNoMatch
		}
		p.emitDenyEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Reason:    string(reason),
		})
		_, _ = fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	if p.caCert != nil {
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		p.handleTLS(conn, br, domain, port, verdict.Decision == policy.NoMatch)
		return
	}

	// No TLS termination: the judge cannot inspect an opaque tunnel, so a
	// NoMatch request must fail closed here — only statically Allowed
	// destinations may be raw-tunneled.
	if verdict.Decision == policy.NoMatch {
		p.emitDenyEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Reason:    string(denyreason.PolicyNoMatch),
		})
		_, _ = fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  "tcp",
		Decision:  "allow",
	})
	p.cfg.Metrics.RecordRequest("allow", "tcp")
	p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: "tcp", Decision: "allow"})
	p.tunnel(conn, br, net.JoinHostPort(domain, fmt.Sprintf("%d", port)))
}

// storeDeny records a pre-tunnel CONNECT-floor deny (headers/metadata only —
// never bodies; there is no requestScope yet, so it builds the event directly
// and hands it to the shared emitDenyEvent chokepoint). The reason is from the
// one declared set (internal/denyreason) and rides BOTH the event and the
// warden.blocked.total{reason} metric.
func (p *Proxy) storeDeny(domain string, port int, protocol string, reason denyreason.Reason) {
	p.emitDenyEvent(analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  protocol,
		Reason:    string(reason),
	})
}

func (p *Proxy) tunnel(client net.Conn, br *bufio.Reader, targetAddr string) {
	remote, err := p.dialFunc("tcp", targetAddr)
	if err != nil {
		return
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
