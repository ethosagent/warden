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
	if decision != policy.Allow {
		_ = p.cfg.Analytics.StoreEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Decision:  "deny",
		})
		_, _ = fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}

	if p.caCert != nil {
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		p.handleTLS(conn, br, domain, port)
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
	p.tunnel(conn, br, net.JoinHostPort(domain, fmt.Sprintf("%d", port)))
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
