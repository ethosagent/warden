package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// defaultLeafTTL is the validity window minted for MITM leaf certificates. It is
// a field default (p.leafTTL) rather than a hard constant so expiry tests can
// shrink it via a white-box override.
const defaultLeafTTL = 24 * time.Hour

// leafRenewSkew is how long before a cached leaf's NotAfter getOrCreateCert
// re-mints it. Re-minting early absorbs clock skew and avoids handing out a cert
// that expires mid-handshake. Kept a const because tests exercise expiry by
// using a short leafTTL and advancing the injected clock past NotAfter-skew.
const leafRenewSkew = time.Hour

// cachedCert is the certCache value. It carries the leaf's NotAfter alongside
// the certificate so the hot cache-hit path is a cheap time comparison instead
// of re-parsing the DER on every connection. notAfter is set at mint time from
// the signing template.
type cachedCert struct {
	cert     *tls.Certificate
	notAfter time.Time
}

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

// getOrCreateCert returns a MITM leaf certificate for domain, minting one on a
// cache miss and re-minting one that is within leafRenewSkew of expiry. Control
// flow: cache hit still inside its window → return it; otherwise a per-domain
// singleflight collapses concurrent misses so exactly one goroutine mints. The
// flight re-checks the cache first (a sibling flight may have just filled it),
// then generates an ECDSA P-256 leaf, signs it with the CA, and stores it.
func (p *Proxy) getOrCreateCert(domain string) (*tls.Certificate, error) {
	if cached, ok := p.certCache.Load(domain); ok {
		cc := cached.(*cachedCert)
		if p.clock().Before(cc.notAfter.Add(-leafRenewSkew)) {
			return cc.cert, nil
		}
	}

	result, err, _ := p.certFlight.Do(domain, func() (any, error) {
		// Another flight for this domain may have already minted a fresh cert
		// while we waited to enter; re-check before spending a keygen.
		if cached, ok := p.certCache.Load(domain); ok {
			cc := cached.(*cachedCert)
			if p.clock().Before(cc.notAfter.Add(-leafRenewSkew)) {
				return cc.cert, nil
			}
		}
		return p.mintLeaf(domain)
	})
	if err != nil {
		return nil, err
	}
	return result.(*tls.Certificate), nil
}

// mintLeaf generates an ECDSA P-256 leaf key, signs a short-lived certificate
// for domain with the CA, and stores it (with its NotAfter) in the cache. The CA
// key/cert are untouched: x509.CreateCertificate signs an ECDSA leaf public key
// with the existing (RSA) CA key regardless of the CA key type.
func (p *Proxy) mintLeaf(domain string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxy: generate leaf key: %w", err)
	}

	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, fmt.Errorf("proxy: generate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	now := p.clock()
	notAfter := now.Add(p.leafValidity())
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, p.caCert, &leafKey.PublicKey, p.caKey)
	if err != nil {
		return nil, fmt.Errorf("proxy: sign leaf cert: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  leafKey,
	}

	p.certCache.Store(domain, &cachedCert{cert: cert, notAfter: notAfter})
	return cert, nil
}

// clock returns the proxy's time source, defaulting to time.Now when the
// injectable now field is unset (production). Tests set p.now to a controllable
// clock to exercise leaf expiry deterministically.
func (p *Proxy) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// leafValidity returns the leaf-cert TTL, defaulting to defaultLeafTTL when the
// injectable leafTTL field is unset (production). Tests shrink it to force
// expiry within the test's lifetime.
func (p *Proxy) leafValidity() time.Duration {
	if p.leafTTL > 0 {
		return p.leafTTL
	}
	return defaultLeafTTL
}
