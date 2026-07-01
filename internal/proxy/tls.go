package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/protocol"
)

type bufferedConn struct {
	io.Reader
	net.Conn
}

func (c bufferedConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

// handleTLS terminates TLS and dispatches by protocol. needsJudge is true when
// the destination matched no static rule (policy.NoMatch) and the judge is
// enabled: such requests are only allowed to proceed via the HTTP path, where
// the judge can inspect method/URL/headers. Every other path (opaque TLS
// passthrough, raw/HTTP2 forwarding) cannot be judged, so a needsJudge request
// there fails closed — preserving the default-deny invariant.
func (p *Proxy) handleTLS(clientConn net.Conn, br *bufio.Reader, domain string, port int, needsJudge bool) {
	firstByte, err := br.Peek(1)
	if err != nil || firstByte[0] != 0x16 {
		if needsJudge {
			// Not a TLS ClientHello: cannot terminate and inspect, so the judge
			// cannot run. Fail closed.
			p.storeDeny(domain, port, "tcp", "no_tls")
			return
		}
		remote, dialErr := p.dialFunc("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)))
		if dialErr != nil {
			return
		}
		_ = p.analyticsStore().StoreEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Decision:  "allow",
		})
		p.cfg.Metrics.RecordRequest("allow", "tcp")
		p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: "tcp", Decision: "allow"})
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
			_, _ = io.Copy(clientConn, remote)
			if tc, ok := clientConn.(interface{ CloseWrite() error }); ok {
				_ = tc.CloseWrite()
			}
		}()
		wg.Wait()
		return
	}

	leaf, err := p.getOrCreateCert(domain)
	if err != nil {
		return
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	bc := bufferedConn{Reader: br, Conn: clientConn}
	tlsConn := tls.Server(bc, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	plainReader := bufio.NewReader(tlsConn)

	// ALPN fast-path: a real gRPC client over TLS requires ALPN "h2", so when the
	// handshake negotiated h2 we terminate HTTP/2 directly rather than peeking for
	// a preface (the h2 preface would be sent inside the negotiated protocol
	// anyway). Existing tests build client conns with no NextProtos, so
	// NegotiatedProtocol stays "" and this branch is skipped — the peek path below
	// is unchanged for them.
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		if needsJudge {
			// HTTP/2 cannot be judged (no HTTP/1 request to inspect); fail closed,
			// preserving the default-deny invariant for NoMatch destinations.
			p.storeDeny(domain, port, "tcp", "no_tls")
			return
		}
		p.handleGRPC(bufferedConn{Reader: plainReader, Conn: tlsConn}, domain, port)
		return
	}

	peekBytes, err := plainReader.Peek(8)
	if err != nil {
		return
	}

	detected := protocol.Detect(peekBytes)
	switch detected {
	case protocol.HTTP:
		p.handleHTTP(tlsConn, plainReader, domain, port, needsJudge)
		return
	case protocol.HTTP2:
		if !needsJudge {
			// Prior-knowledge h2 client (no ALPN): the peek saw the HTTP/2
			// connection preface. Terminate HTTP/2 directly.
			p.handleGRPC(bufferedConn{Reader: plainReader, Conn: tlsConn}, domain, port)
			return
		}
		// needsJudge: HTTP/2 is unjudgeable — fall through to the fail-closed
		// `if needsJudge { ... }` block below (unchanged).
	}

	// Non-HTTP traffic inside TLS cannot be judged (no request to inspect):
	// fail closed when the judge was required.
	if needsJudge {
		p.storeDeny(domain, port, "tcp", "no_tls")
		return
	}

	// Unrecognized protocol inside TLS: raw forwarding.
	remote, dialErr := p.dialTLS("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)), &tls.Config{ServerName: domain})
	if dialErr != nil {
		return
	}
	defer remote.Close()
	proto := detected.String()
	if detected == protocol.Unknown {
		proto = "raw"
	}
	_ = p.analyticsStore().StoreEvent(analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  proto,
		Decision:  "allow",
	})
	p.cfg.Metrics.RecordRequest("allow", proto)
	p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: proto, Decision: "allow"})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, plainReader)
		_ = remote.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(tlsConn, remote)
		_ = tlsConn.CloseWrite()
	}()
	wg.Wait()
}

func (p *Proxy) getOrCreateCert(domain string) (*tls.Certificate, error) {
	if cached, ok := p.certCache.Load(domain); ok {
		return cached.(*tls.Certificate), nil
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("proxy: generate leaf key: %w", err)
	}

	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, fmt.Errorf("proxy: generate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, p.caCert, &leafKey.PublicKey, p.caKey)
	if err != nil {
		return nil, fmt.Errorf("proxy: sign leaf cert: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  leafKey,
	}

	actual, _ := p.certCache.LoadOrStore(domain, &cert)
	return actual.(*tls.Certificate), nil
}
