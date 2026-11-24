// Package signer is the private-key adapter of the worker CA: the only place
// that signs certificates (rule X1). It creates worker certificates for
// workerca.CA (CreateCertificate), and the root, intermediate and CSR that
// `warden control-plane ca init|csr` produce. It never reads the proxy CA.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// Lifetimes of the CA certificates `ca init` creates.
const (
	RootValidity         = 10 * 365 * 24 * time.Hour
	IntermediateValidity = 365 * 24 * time.Hour
	backdate             = 5 * time.Minute

	rootCommonName         = "Warden Worker Root CA"
	intermediateCommonName = "Warden Worker Intermediate CA"
)

// CreateCertificate signs template under parent with priv and returns the DER
// certificate for pub. It satisfies workerca.CertCreator.
func CreateCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
}

// GenerateKey returns a fresh ECDSA P-256 key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("workerca: generate p-256 key: %w", err)
	}
	return k, nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewRoot creates a self-signed P-256 root valid for ten years from now.
func NewRoot(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, fmt.Errorf("workerca: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: rootCommonName},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("workerca: create root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("workerca: parse root: %w", err)
	}
	return cert, key, nil
}

// NewIntermediate signs the worker intermediate for pub under root: CA:true,
// MaxPathLen 0, certSign, valid one year, and permitted to issue only URI
// names in trustDomain.
func NewIntermediate(root *x509.Certificate, rootKey crypto.Signer, pub crypto.PublicKey, trustDomain string, now time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, fmt.Errorf("workerca: serial: %w", err)
	}
	notAfter := now.Add(IntermediateValidity)
	if notAfter.After(root.NotAfter) {
		notAfter = root.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:                sn,
		Subject:                     pkix.Name{CommonName: intermediateCommonName},
		NotBefore:                   now.Add(-backdate),
		NotAfter:                    notAfter,
		KeyUsage:                    x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedURIDomains:         []string{trustDomain},
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, pub, rootKey)
	if err != nil {
		return nil, fmt.Errorf("workerca: create intermediate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// NewCSR returns the DER certificate request of key, for an offline root to
// sign into an intermediate. The subject is a label only.
func NewCSR(key crypto.Signer) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: intermediateCommonName},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("workerca: create csr: %w", err)
	}
	return der, nil
}
