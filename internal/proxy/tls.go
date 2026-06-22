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
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
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
	requestLine, err := plainReader.ReadString('\n')
	if err != nil {
		return
	}

	var reqBuf strings.Builder
	reqBuf.WriteString(requestLine)

	parts := strings.Fields(requestLine)
	method := ""
	path := ""
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	}

	var hostHeader string
	for {
		hdr, err := plainReader.ReadString('\n')
		if err != nil {
			return
		}
		reqBuf.WriteString(hdr)
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(hdr), "host:") {
			hostHeader = strings.TrimSpace(hdr[len("host:"):])
		}
	}

	hostOnly := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		hostOnly = h
	}
	if !strings.EqualFold(hostOnly, domain) {
		return
	}

	upstream, err := p.dialTLS("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)), &tls.Config{ServerName: domain})
	if err != nil {
		return
	}
	defer upstream.Close()

	_, err = fmt.Fprint(upstream, reqBuf.String())
	if err != nil {
		return
	}

	url := "https://" + domain + path
	_ = p.cfg.Analytics.StoreEvent(analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  "https",
		Method:    method,
		URL:       url,
		Decision:  "allow",
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, plainReader)
		_ = upstream.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(tlsConn, upstream)
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
