package harness

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ca is a throwaway certificate authority minted per harness instance. Warden's
// trust is always file-or-pool based per connection (the worker's MITM CA path,
// the control-plane caCert path, the assembly-only UpstreamRootCAs pool), so a
// per-test CA needs no distribution story: everything the harness boots trusts
// exactly the CAs this file creates, nothing else.
type ca struct {
	name    string
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	keyPEM  []byte
}

// newCA generates a throwaway RSA CA. RSA because the worker's proxy CA loader
// (and controlplane.MintServerTLS) parse PKCS#1/PKCS#8 RSA keys only — the same
// constraint production deployments live with, mirrored here so the harness
// exercises the real code paths.
func newCA(t testing.TB, name string) *ca {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("harness: generate CA key for %s: %v", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Warden L1 Harness"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("harness: create CA cert for %s: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("harness: parse CA cert for %s: %v", name, err)
	}
	return &ca{
		name:    name,
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}
}

// pool returns the CA as a verify pool (the UpstreamRootCAs / agent RootCAs form).
func (c *ca) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// write persists the CA as PEM so the components that read PATHS (the worker's
// proxy ca-cert/ca-key, the control plane's --ca-cert/--ca-key, the worker's
// controlPlane.caCert) can load it. base names the pair: <base>.crt / <base>.key.
func (c *ca) write(t testing.TB, dir, base string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	if err := os.WriteFile(certPath, c.certPEM, 0o600); err != nil {
		t.Fatalf("harness: write %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, c.keyPEM, 0o600); err != nil {
		t.Fatalf("harness: write %s: %v", keyPath, err)
	}
	return certPath, keyPath
}

// leaf signs a short-lived server certificate for host (SANs: the host name and
// 127.0.0.1, so a dialer that keeps SNI at the fake hostname and one that
// rewrites it to loopback both verify). The leaf key is ECDSA P-256 — instant to
// generate, and the upstream TLS client verifies by chain, not key type.
func (c *ca) leaf(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("harness: generate leaf key for %s: %w", host, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("harness: leaf serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Warden L1 Harness"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("harness: sign leaf for %s: %w", host, err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}, nil
}
