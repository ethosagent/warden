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

func (p *Proxy) handleTLS(clientConn net.Conn, br *bufio.Reader, domain string, port int) {
	firstByte, err := br.Peek(1)
	if err != nil || firstByte[0] != 0x16 {
		remote, dialErr := p.dialFunc("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)))
		if dialErr != nil {
			return
		}
		_ = p.cfg.Analytics.StoreEvent(analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Decision:  "allow",
		})
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

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{*leaf}}
	bc := bufferedConn{Reader: br, Conn: clientConn}
	tlsConn := tls.Server(bc, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	plainReader := bufio.NewReader(tlsConn)
	peekBytes, err := plainReader.Peek(8)
	if err != nil {
		return
	}

	if protocol.Detect(peekBytes) == protocol.HTTP {
		p.handleHTTP(tlsConn, plainReader, domain, port)
		return
	}

	// Unrecognized protocol inside TLS: raw forwarding.
	remote, dialErr := p.dialTLS("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)), &tls.Config{ServerName: domain})
	if dialErr != nil {
		return
	}
	defer remote.Close()
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
