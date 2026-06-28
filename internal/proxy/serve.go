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
		return
	}

	if !strings.HasPrefix(line, "CONNECT ") || !strings.Contains(line, "HTTP/") {
		return
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	target := fields[1]

	domain, port, err := SplitHostPort(target)
	if err != nil {
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

	decision := p.cfg.Policy.Evaluate(domain, port, policy.SchemeHTTPS)
	// Tri-state gate:
	//   Allow   -> proceed.
	//   Deny    -> 403 (explicit denylist / throttled allow entry).
	//   NoMatch -> if the judge is enabled, let CONNECT proceed to TLS
	//              termination so the judge can inspect the full request;
	//              otherwise default-deny exactly as before (403).
	judgeEnabled := p.cfg.Judge != nil
	if decision == policy.Deny || (decision == policy.NoMatch && !judgeEnabled) {
		_ = p.cfg.Analytics.StoreEvent(analytics.Event{
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
		_ = p.cfg.Analytics.StoreEvent(analytics.Event{
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
	_ = p.cfg.Analytics.StoreEvent(analytics.Event{
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

// storeDeny records a deny decision (headers/metadata only — never bodies). The
// reason is a bounded enum used for the warden.blocked.total{reason} metric.
func (p *Proxy) storeDeny(domain string, port int, protocol, reason string) {
	_ = p.cfg.Analytics.StoreEvent(analytics.Event{
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
