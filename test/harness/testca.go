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
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCA is a throwaway certificate authority for security and L1 tests. Every
// key is generated at run time and lives in memory (or a t.TempDir file the
// caller asked for), so nothing secret is ever committed. It signs the leaf
// shapes an mTLS attack case needs: a foreign CA's leaf, an expired leaf, a
// wrong-EKU leaf, a multi-SAN leaf and a plain server leaf.
//
// The key is RSA because the worker's MITM CA loader and the control plane's
// server-TLS minting parse PKCS#1/PKCS#8 RSA keys only; leaf keys are P-256.
type TestCA struct {
	// Cert is the CA certificate.
	Cert *x509.Certificate
	// CertPEM is Cert in PEM form (the form a controlPlane.caCert file holds).
	CertPEM []byte

	tb     testing.TB
	key    crypto.Signer
	keyPEM []byte
}

// NewTestCA creates a self-signed CA named name, valid from an hour ago for a
// day (real time: crypto/tls verifies against the wall clock).
func NewTestCA(tb testing.TB, name string) *TestCA {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("test CA %s: generate key: %v", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Warden test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("test CA %s: create certificate: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("test CA %s: parse certificate: %v", name, err)
	}
	return &TestCA{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		tb:      tb,
		key:     key,
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}
}

// Pool is the CA as a verify pool.
func (c *TestCA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	return pool
}

// WriteFiles writes <base>.crt and <base>.key (mode 0600) into dir and returns
// their paths, for components that read a CA from paths.
func (c *TestCA) WriteFiles(dir, base string) (certPath, keyPath string) {
	c.tb.Helper()
	certPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	if err := os.WriteFile(certPath, c.CertPEM, 0o600); err != nil {
		c.tb.Fatalf("test CA: write %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, c.keyPEM, 0o600); err != nil {
		c.tb.Fatalf("test CA: write %s: %v", keyPath, err)
	}
	return certPath, keyPath
}

// KeyPEM is the CA's private key in PEM form. Tests use it only to plant it as
// a canary the leak invariant must never find.
func (c *TestCA) KeyPEM() []byte { return append([]byte(nil), c.keyPEM...) }

// LeafSpec describes a leaf certificate. The zero value is a valid client
// certificate with no SAN: set what the case attacks.
type LeafSpec struct {
	// CommonName is the subject CN (default "leaf").
	CommonName string
	// DNS, IPs and URIs are the SANs.
	DNS  []string
	IPs  []net.IP
	URIs []string
	// EKU defaults to client auth. A non-nil empty slice means no EKU at all.
	EKU []x509.ExtKeyUsage
	// NotBefore and NotAfter default to an hour ago and a day ahead (wall clock).
	NotBefore, NotAfter time.Time
	// PublicKey, when set, is certified instead of a fresh key (a renewal that
	// reuses its key). Key is then nil on the result.
	PublicKey *ecdsa.PublicKey
}

// Leaf is an issued leaf certificate and its key.
type Leaf struct {
	Cert *x509.Certificate
	// Key is nil when the spec supplied its own PublicKey.
	Key *ecdsa.PrivateKey
}

// TLS is the leaf as a tls.Certificate (client or server credential).
func (l Leaf) TLS() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{l.Cert.Raw}, PrivateKey: l.Key, Leaf: l.Cert}
}

// Serial is the certificate serial in lowercase hex (the form the control
// plane prints).
func (l Leaf) Serial() string { return l.Cert.SerialNumber.Text(16) }

// Leaf issues a leaf certificate under this CA.
func (c *TestCA) Leaf(spec LeafSpec) Leaf {
	c.tb.Helper()
	var key *ecdsa.PrivateKey
	pub := spec.PublicKey
	if pub == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			c.tb.Fatalf("test CA: generate leaf key: %v", err)
		}
		pub = &key.PublicKey
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		c.tb.Fatalf("test CA: serial: %v", err)
	}
	cn := spec.CommonName
	if cn == "" {
		cn = "leaf"
	}
	nb, na := spec.NotBefore, spec.NotAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(24 * time.Hour)
	}
	eku := spec.EKU
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Warden test CA"}},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		DNSNames:     spec.DNS,
		IPAddresses:  spec.IPs,
	}
	for _, raw := range spec.URIs {
		u, err := url.Parse(raw)
		if err != nil {
			c.tb.Fatalf("test CA: bad URI SAN %q: %v", raw, err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, pub, c.key)
	if err != nil {
		c.tb.Fatalf("test CA: sign leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		c.tb.Fatalf("test CA: parse leaf: %v", err)
	}
	return Leaf{Cert: cert, Key: key}
}

// ServerCert issues a server certificate for host (SANs: host and 127.0.0.1) as
// a tls.Certificate chained to this CA.
func (c *TestCA) ServerCert(host string) tls.Certificate {
	c.tb.Helper()
	l := c.Leaf(LeafSpec{
		CommonName: host,
		DNS:        []string{host},
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
		EKU:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return tls.Certificate{Certificate: [][]byte{l.Cert.Raw, c.Cert.Raw}, PrivateKey: l.Key}
}

// SPIFFEURI is the worker SPIFFE id a worker certificate carries as its one URI
// SAN: spiffe://<trustDomain>/warden/worker/<workerID>.
func SPIFFEURI(trustDomain, workerID string) string {
	return "spiffe://" + trustDomain + "/warden/worker/" + workerID
}
