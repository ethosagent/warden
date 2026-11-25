package workerca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCertsPEM decodes every CERTIFICATE block of data, in order. A document
// with no certificate, or a block that does not parse, is an error that names
// the problem and never echoes the bytes.
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("workerca: certificate %d does not parse", len(out)+1)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("workerca: no CERTIFICATE block")
	}
	return out, nil
}

// EncodeCertsPEM encodes certs as concatenated CERTIFICATE blocks.
func EncodeCertsPEM(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.Bytes()
}

// ParseCSRPEM decodes the first CERTIFICATE REQUEST block of data. It does not
// check the signature; Issue does.
func ParseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, fmt.Errorf("%w: no CERTIFICATE REQUEST block", ErrBadCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: does not parse", ErrBadCSR)
	}
	return csr, nil
}

// SameSPKI reports whether a and b carry the same public key (compared as
// SubjectPublicKeyInfo bytes).
func SameSPKI(a, b *x509.Certificate) bool {
	return a != nil && b != nil && bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo)
}

// publicKeyMatches reports whether pub marshals to the same SPKI as cert.
func publicKeyMatches(cert *x509.Certificate, pub crypto.PublicKey) bool {
	der, err := x509.MarshalPKIXPublicKey(pub)
	return err == nil && bytes.Equal(der, cert.RawSubjectPublicKeyInfo)
}

// CheckSeparateRoot fails with ErrSharedTrustRoot when any of certs has the
// same public key as, or is signed by, any of proxyCAs. The worker CA must be
// its own trust root: compose workers hold the proxy CA key, so a worker
// intermediate under it would let any worker mint certs for any other.
func CheckSeparateRoot(certs, proxyCAs []*x509.Certificate) error {
	for _, c := range certs {
		for _, p := range proxyCAs {
			if SameSPKI(c, p) {
				return fmt.Errorf("%w: same public key as the proxy CA", ErrSharedTrustRoot)
			}
			if p.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
				return fmt.Errorf("%w: signed by the proxy CA", ErrSharedTrustRoot)
			}
		}
	}
	return nil
}
