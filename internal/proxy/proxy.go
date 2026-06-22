// Package proxy is the listener / TCP-accept / TLS-termination skeleton. Phase 1
// (M1) fills in real connection handling: TCP accept with default-deny, TLS
// termination with a cert the agent trusts, protocol detection, secret swap,
// and forwarding. This file provides the constructor and small pure helpers so
// the wiring is testable without raw networking in the skeleton.
package proxy

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/secrets"
)

// Config holds the proxy's listen address and collaborators. All external
// dependencies are interfaces, honoring the day-zero interface rule.
type Config struct {
	// ListenAddr is the loopback / pod-internal address the agent connects to
	// (e.g. "127.0.0.1:8080").
	ListenAddr       string
	Policy           *policy.Evaluator
	Secrets          secrets.SecretProvider
	Analytics        analytics.AnalyticsStore
	CACertPath       string
	CAKeyPath        string
	PlaceholderNames []string
}

// Proxy is the egress guardrail front door. M1 adds Serve()/accept loops; the
// skeleton constructs it and validates its configuration.
type Proxy struct {
	cfg        Config
	listenerMu sync.Mutex
	listener   net.Listener
	caCert     *x509.Certificate
	caKey      crypto.PrivateKey
	certCache  sync.Map
	dialFunc   func(network, addr string) (net.Conn, error)
	dialTLS    func(network, addr string, cfg *tls.Config) (*tls.Conn, error)
}

// New constructs a Proxy, validating that the required collaborators are
// present. It does not bind a socket; Serve (M1) does.
func New(cfg Config) (*Proxy, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("proxy: ListenAddr is required")
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("proxy: Policy evaluator is required")
	}
	if cfg.Secrets == nil {
		return nil, fmt.Errorf("proxy: Secrets provider is required")
	}
	if cfg.Analytics == nil {
		return nil, fmt.Errorf("proxy: Analytics store is required")
	}
	p := &Proxy{cfg: cfg}

	haveCert := cfg.CACertPath != ""
	haveKey := cfg.CAKeyPath != ""
	if haveCert != haveKey {
		return nil, fmt.Errorf("proxy: both CACertPath and CAKeyPath must be set")
	}
	if haveCert {
		certPEM, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("proxy: read CA cert: %w", err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("proxy: no PEM block in CA cert")
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("proxy: parse CA cert: %w", err)
		}
		p.caCert = caCert

		keyPEM, err := os.ReadFile(cfg.CAKeyPath)
		if err != nil {
			return nil, fmt.Errorf("proxy: read CA key: %w", err)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, fmt.Errorf("proxy: no PEM block in CA key")
		}
		caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			// Fall back to PKCS#1 RSA key format
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if rsaErr != nil {
				return nil, fmt.Errorf("proxy: parse CA key (tried PKCS#8 and PKCS#1): %w", err)
			}
			caKey = rsaKey
		}
		p.caKey = caKey

		// Validate that the certificate is actually a CA.
		if !caCert.IsCA || caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("proxy: CA cert is not a certificate authority")
		}

		// Verify key matches cert (RSA-only; gen-certs.sh only produces RSA keys).
		rsaPub, ok := caCert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("proxy: only RSA CA keys are supported")
		}
		rsaPriv, ok := caKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("proxy: only RSA CA keys are supported")
		}
		if rsaPub.N.Cmp(rsaPriv.N) != 0 {
			return nil, fmt.Errorf("proxy: CA key does not match CA cert")
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	p.dialFunc = dialer.Dial
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		return tls.DialWithDialer(dialer, network, addr, cfg)
	}

	return p, nil
}

// ListenAddr returns the configured listen address.
func (p *Proxy) ListenAddr() string { return p.cfg.ListenAddr }

// Addr returns the listener's address, or nil if the proxy has not started.
func (p *Proxy) Addr() net.Addr {
	p.listenerMu.Lock()
	ln := p.listener
	p.listenerMu.Unlock()
	if ln != nil {
		return ln.Addr()
	}
	return nil
}

// SplitHostPort parses a "host:port" destination into its host and numeric
// port. It is a thin, pure helper used on the accept path to feed the policy
// evaluator.
func SplitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("proxy: split %q: %w", addr, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("proxy: bad port in %q: %w", addr, err)
	}
	return h, port, nil
}
