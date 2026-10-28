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
	"sort"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/policy"
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

// handshakeTimeout bounds the TLS handshake in terminateAndDispatch: a client
// that delivers a hello (or a CONNECT tunnel) and then stalls would otherwise
// hold its connection goroutine forever. It is the slowloris floor for the
// termination step, one order above the preamble budgets.
const handshakeTimeout = 10 * time.Second

// cachedCert is the certCache value. It carries the leaf's NotAfter alongside
// the certificate so the hot cache-hit path is a cheap time comparison instead
// of re-parsing the DER on every connection. notAfter is set at mint time from
// the signing template.
type cachedCert struct {
	cert     *tls.Certificate
	notAfter time.Time
}

// maxCertCacheEntries bounds the leaf cache. Its keys include client-chosen
// names (transparent mode mints for every allowed SNI), so without a cap any
// agent able to reach many names grows it without bound. Held as a constant on
// purpose like the hello/preamble budgets: a knob would let a misconfiguration
// re-open the unbounded-growth hole. The cap is large enough that a deployment
// never evicts names it actually serves, and eviction prefers the entries
// closest to NotAfter (see storeLeafCert).
const maxCertCacheEntries = 10_000

type bufferedConn struct {
	io.Reader
	net.Conn
}

func (c bufferedConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

// handleTLS terminates TLS and dispatches by protocol. d says what the CONNECT
// gate left undecided: deferJudge when the destination matched no static rule
// (policy.NoMatch) and the judge is enabled, deferIdentity when it is reachable
// only for some identities. Such requests are only allowed to proceed via the
// HTTP path, where the judge or the per-request subject can decide on
// method/URL/headers: HTTP/1.1 and HTTP/2 (both run the shared stage
// pipeline). Every other path (opaque TLS passthrough, raw forwarding) cannot
// be decided per request, so a deferred request there fails closed —
// preserving the default-deny invariant.
// handleTLS is the CONNECT-tunnel entry to TLS termination: it classifies the
// first bytes (a CONNECT tunnel may carry anything) and fails closed for
// deferred traffic that is not TLS, then hands the TLS case to
// terminateAndDispatch — the SAME termination/dispatch path the transparent
// :443 listener uses after its ClientHello gate (#376). Forward-mode behavior
// is unchanged byte for byte.
func (p *Proxy) handleTLS(clientConn net.Conn, br *bufio.Reader, domain string, port int, d deferred, ci connIdentity) {
	firstByte, err := br.Peek(1)
	if err != nil || firstByte[0] != 0x16 {
		if d != deferNone {
			// Not a TLS ClientHello: cannot terminate and inspect, so neither the
			// judge nor the per-request subject check can run. Fail closed.
			p.storeDeny(ci, domain, port, "tcp", failClosedReason(d), "")
			return
		}
		p.reach(PathTunnel)
		// Only an attributed tunnel registers (see tunnel): a block-list cut must
		// reach this opaque passthrough, the form a CONNECT takes on a worker
		// with TLS termination, as well as the CA-less one.
		var sess *session
		if ci.Claims.Sub != "" || ci.Claims.Email != "" {
			sess = p.sessions.newSession("tcp", domain, port, true, clientConn)
			sess.bind(ci)
			defer sess.release()
		}
		remote, dialErr := p.dialFunc("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)))
		if dialErr != nil {
			// A dial the SSRF-safe dialer refused is a policy decision: audit it
			// (silent before #391). Ordinary dial failures stay silent — this
			// passthrough never wrote an event for them either.
			p.storeSSRFDeny(ci, domain, port, "tcp", dialErr)
			return
		}
		sess.addCloser(remote)
		p.recordEvent(ci, analytics.Event{
			Timestamp: time.Now(),
			Domain:    domain,
			Port:      port,
			Protocol:  "tcp",
			Decision:  "allow",
		})
		p.cfg.Metrics.RecordRequest("allow", "tcp")
		p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: "tcp", Decision: "allow", ID: ci})
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

	p.terminateAndDispatch(clientConn, br, domain, port, d, ci)
}

// terminateAndDispatch terminates TLS for domain with the MITM leaf cert and
// dispatches by what the decrypted stream turns out to be: an ALPN-negotiated
// or prior-knowledge h2 connection goes to handleGRPC, HTTP to handleHTTP,
// everything else to a deferred fail-closed deny or the raw-TLS forward.
// This is the ONE post-ClientHello path for both arrivals of an allowed TLS
// destination — the CONNECT tunnel (handleTLS) and the transparent :443
// listener (handleTransparentTLS, #376) — so policy, swap, scan, MCP and
// analytics CANNOT diverge between the two modes.
func (p *Proxy) terminateAndDispatch(clientConn net.Conn, firstBytes io.Reader, domain string, port int, d deferred, ci connIdentity) {
	leaf, err := p.getOrCreateCert(domain)
	if err != nil {
		return
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	bc := bufferedConn{Reader: firstBytes, Conn: clientConn}
	tlsConn := tls.Server(bc, tlsCfg)
	// Bound the handshake: after the hello a client may stall mid-negotiation,
	// and without a deadline that goroutine never returns. Both deadlines are
	// lifted once the handshake completes — the tunnel's own lifetime is not
	// governed by this budget.
	deadline := time.Now().Add(p.handshakeDeadline())
	_ = clientConn.SetDeadline(deadline)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = clientConn.SetDeadline(time.Time{})
	defer tlsConn.Close()

	plainReader := bufio.NewReader(tlsConn)

	// ALPN fast-path: a real gRPC client over TLS requires ALPN "h2", so when the
	// handshake negotiated h2 we terminate HTTP/2 directly rather than peeking for
	// a preface (the h2 preface would be sent inside the negotiated protocol
	// anyway). Existing tests build client conns with no NextProtos, so
	// NegotiatedProtocol stays "" and this branch is skipped — the peek path below
	// is unchanged for them.
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		p.handleGRPC(bufferedConn{Reader: plainReader, Conn: tlsConn}, domain, port, d, ci)
		return
	}

	peekBytes, err := plainReader.Peek(8)
	if err != nil {
		return
	}

	detected := protocol.Detect(peekBytes)
	switch detected {
	case protocol.HTTP:
		p.handleHTTP(tlsConn, plainReader, domain, port, d, policy.SchemeHTTPS, nil, ci)
		return
	case protocol.HTTP2:
		// Prior-knowledge h2 client (no ALPN): the peek saw the HTTP/2
		// connection preface. Terminate HTTP/2 directly; each stream runs the
		// shared stage pipeline, judge included.
		p.handleGRPC(bufferedConn{Reader: plainReader, Conn: tlsConn}, domain, port, d, ci)
		return
	}

	// Non-HTTP traffic inside TLS cannot be judged or checked against a subject
	// (no request to inspect): fail closed when a per-request decision was
	// required.
	if d != deferNone {
		p.storeDeny(ci, domain, port, "tcp", failClosedReason(d), "")
		return
	}

	// Unrecognized protocol inside TLS: raw forwarding.
	proto := detected.String()
	if detected == protocol.Unknown {
		proto = "raw"
	}
	p.reach(PathRawTLS)
	remote, dialErr := p.dialTLS("tcp", net.JoinHostPort(domain, fmt.Sprintf("%d", port)), p.upstreamTLSConfig(domain))
	if dialErr != nil {
		// A dial the SSRF-safe dialer refused is a policy decision: audit it
		// under the same protocol label the allow would have used (silent
		// before #391). Ordinary dial failures stay silent, as before.
		p.storeSSRFDeny(ci, domain, port, proto, dialErr)
		return
	}
	defer remote.Close()
	p.recordEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  proto,
		Decision:  "allow",
	})
	p.cfg.Metrics.RecordRequest("allow", proto)
	p.logDecision(decisionLog{Domain: domain, Port: port, Protocol: proto, Decision: "allow", ID: ci})
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

	p.storeLeafCert(domain, &cachedCert{cert: cert, notAfter: notAfter})
	return cert, nil
}

// storeLeafCert inserts a freshly minted leaf, keeping the cache at or under
// certCap() entries: when the cap is reached, entries closest to NotAfter are
// evicted first — expired or in-renew-window ones outright, then the soonest
// expiring — so a bound never forces a live, long-lived leaf out ahead of a
// dying one. The hot getOrCreateCert hit path stays the lock-free Load it was
// before; the whole insert path sits under certStoreMu (mints are rare next to
// hits).
func (p *Proxy) storeLeafCert(domain string, cc *cachedCert) {
	if _, cached := p.certCache.Load(domain); cached {
		// Replace in place: no growth, no eviction needed.
		p.certCache.Store(domain, cc)
		return
	}
	p.certStoreMu.Lock()
	defer p.certStoreMu.Unlock()
	limit := p.certCap()
	if size := cacheSize(&p.certCache); size >= limit {
		p.evictLeafCerts(size - limit + 1)
	}
	p.certCache.Store(domain, cc)
}

// evictLeafCerts removes n entries: every leaf already expired or inside its
// renew window goes first (it is dead weight), and the rest by soonest
// NotAfter. Called with certStoreMu held.
func (p *Proxy) evictLeafCerts(n int) {
	now := p.clock()
	type entry struct {
		domain   string
		notAfter time.Time
	}
	var (
		expired []entry
		live    []entry
	)
	p.certCache.Range(func(key, value any) bool {
		cc := value.(*cachedCert)
		e := entry{domain: key.(string), notAfter: cc.notAfter}
		if cc.notAfter.Add(-leafRenewSkew).Before(now) {
			expired = append(expired, e)
		} else {
			live = append(live, e)
		}
		return true
	})
	sort.Slice(expired, func(i, j int) bool { return expired[i].notAfter.Before(expired[j].notAfter) })
	sort.Slice(live, func(i, j int) bool { return live[i].notAfter.Before(live[j].notAfter) })
	victims := append(expired, live...)
	for _, v := range victims {
		if n <= 0 {
			return
		}
		p.certCache.Delete(v.domain)
		n--
	}
}

// certCap returns the leaf-cache entry cap, defaulting to maxCertCacheEntries
// when the injectable certCacheCap field is unset (production). Tests shrink it
// to drive the eviction path without minting thousands of certificates.
func (p *Proxy) certCap() int {
	if p.certCacheCap > 0 {
		return p.certCacheCap
	}
	return maxCertCacheEntries
}

// cacheSize counts a sync.Map the only way it allows; called only on the
// bounded insert path, never on a hit.
func cacheSize(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
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

// handshakeDeadline returns the terminateAndDispatch handshake deadline,
// defaulting to the handshakeTimeout const when the injectable handshakeTimeout
// field is unset (production). Tests shrink it to drive the stalled-handshake
// cutoff within the test's lifetime.
func (p *Proxy) handshakeDeadline() time.Duration {
	if p.handshakeTimeout > 0 {
		return p.handshakeTimeout
	}
	return handshakeTimeout
}
