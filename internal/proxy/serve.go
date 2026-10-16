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
		p.storeDeny("", 0, "tcp", "unsupported_protocol", "")
		return
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		p.storeDeny("", 0, "tcp", "malformed_connect", "")
		return
	}
	target := fields[1]

	domain, port, err := SplitHostPort(target)
	if err != nil {
		p.storeDeny("", 0, "tcp", "malformed_connect", "")
		return
	}

	// Bounded header block: line + every header line + the terminating blank
	// line must fit maxConnectHeaderBytes. Each line is capped at what is left
	// of the budget, so one huge header trips the same 431 as many small ones.
	total := len(line)
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
	}
	// Preamble complete — lift the deadline so it cannot cut off the tunnel or
	// the TLS handshake, either of which may idle far longer than the preamble
	// budget.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	decision := p.cfg.Policy.Evaluate(domain, port, policy.SchemeHTTPS)
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

// rejectPreamble answers an over-limit CONNECT preamble with an HTTP error and
// records exactly ONE deny decision — bounded reason plus detail, never the
// oversized bytes themselves — then drops the connection. Before dropping, the
// rest of the request is drained to the bit bucket, bounded by the preamble
// deadline and io.Copy's fixed buffer (never accumulated): the client is still
// mid-send when the limit trips, and closing on it unread would reset the
// connection before it can read the rejection. This is the standard error
// close (nginx/HAProxy lingering close).
func (p *Proxy) rejectPreamble(conn net.Conn, br *bufio.Reader, resp, detail string) {
	p.storeDeny("", 0, "tcp", "malformed_connect", detail)
	_, _ = fmt.Fprint(conn, resp)
	_, _ = io.Copy(io.Discard, br)
}

// storeDeny records a deny decision (headers/metadata only — never bodies). The
// reason is a bounded enum used for the warden.blocked.total{reason} metric and
// the decision record; detail, when non-empty, is a bounded refinement of the
// reason (e.g. "request_line_too_long"). Neither ever carries request content.
func (p *Proxy) storeDeny(domain string, port int, protocol, reason, detail string) {
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  protocol,
		Decision:  "deny",
	})
	p.cfg.Metrics.RecordRequest("deny", protocol)
	p.cfg.Metrics.RecordBlocked(reason)
	p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: protocol, Decision: "deny", Reason: reason, Detail: detail})
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
