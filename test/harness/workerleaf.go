package harness

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

// WorkerLeafSpec describes a hostile worker certificate signed by a worker CA
// the caller holds (a security stack's own intermediate): everything but the
// field under attack is valid. The zero value is a certificate the control
// plane accepts, except that NotBefore and NotAfter must be set.
type WorkerLeafSpec struct {
	// URIs are the URI SANs; empty means the one SPIFFE id of WorkerID in
	// TrustDomain.
	URIs []string
	// WorkerID and TrustDomain build the default SPIFFE URI.
	WorkerID, TrustDomain string
	// EKU defaults to clientAuth. A non-nil empty slice means no EKU.
	EKU []x509.ExtKeyUsage
	// NotBefore and NotAfter are the validity window (required, so a case
	// states the clock it attacks).
	NotBefore, NotAfter time.Time
}

// MintWorkerLeaf signs spec with the worker CA intermediate (parent, key): the
// way a cert the real CA would not have issued (expired, wrong EKU, two SANs)
// still chains to the pinned CA, so each reaches its own rejection reason.
func MintWorkerLeaf(tb testing.TB, parent *x509.Certificate, key crypto.Signer, spec WorkerLeafSpec) WorkerCert {
	tb.Helper()
	uris := spec.URIs
	if len(uris) == 0 {
		uris = []string{SPIFFEURI(spec.TrustDomain, spec.WorkerID)}
	}
	eku := spec.EKU
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	sn, err := wcasigner.NewSerial()
	if err != nil {
		tb.Fatalf("harness: serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, NotBefore: spec.NotBefore, NotAfter: spec.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku, BasicConstraintsValid: true,
	}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			tb.Fatalf("harness: bad URI SAN %q: %v", raw, err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	leafKey, err := wcasigner.GenerateKey()
	if err != nil {
		tb.Fatalf("harness: generate a worker key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &leafKey.PublicKey, key)
	if err != nil {
		tb.Fatalf("harness: mint a worker leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("harness: parse the worker leaf: %v", err)
	}
	return WorkerCert{Cert: cert, Key: leafKey}
}
