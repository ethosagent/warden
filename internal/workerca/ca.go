// Package workerca issues short-lived mTLS client certificates to workers from
// a control-plane-held intermediate CA (W-P2-WCA-01). The worker CA is its own
// trust root, separate from the proxy MITM CA: compose workers hold
// proxy-ca.key and could otherwise mint certificates for any worker.
//
// The package is pure domain: it parses and checks certificates and builds the
// certificate template. The private-key operation (X1) is injected as a
// CertCreator, built by internal/workerca/adapters/signer, and the key itself
// arrives as a crypto.Signer from the key manager or a dev key file.
package workerca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"time"
)

// notBeforeSkew backdates NotBefore so a worker with a slow clock still
// accepts a fresh certificate.
const notBeforeSkew = 5 * time.Minute

// CertCreator signs template under parent with signer and returns the DER
// certificate for pub. It is the one place a private key signs a certificate;
// the implementation is internal/workerca/adapters/signer.CreateCertificate.
type CertCreator func(template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) ([]byte, error)

// Options builds a CA.
type Options struct {
	// Chain is the signing intermediate first, then anything above it. Only
	// Chain[0] is trusted and used to sign.
	Chain []*x509.Certificate
	// Previous is the previous intermediate chain, trusted for verification
	// only while the intermediate is being rotated. It never signs.
	Previous []*x509.Certificate
	// Signer holds the private key of Chain[0].
	Signer crypto.Signer
	// Create performs the certificate signing (the adapter).
	Create CertCreator
	// TrustDomain is the SPIFFE trust domain of issued identities.
	TrustDomain string
	// Clock returns the current time; nil means time.Now.
	Clock func() time.Time
}

// CA issues worker client certificates. It is safe for concurrent use.
type CA struct {
	*Verifier
	chain  []*x509.Certificate
	signer crypto.Signer
	create CertCreator
}

// Verifier checks worker client certificates against the pinned intermediates.
// It holds no private key, so it exists as soon as the chain is known and keeps
// working while the signing key is unavailable (degraded CA).
type Verifier struct {
	chain       []*x509.Certificate
	trustDomain string
	clock       func() time.Time
	roots       *x509.CertPool
}

// NewVerifier pins Chain[0] (and Previous[0]) after the structural checks of
// New, without needing a key. The previous intermediate's validity is not
// checked here: an expired one simply never verifies a live certificate.
func NewVerifier(o Options) (*Verifier, error) {
	if !ValidTrustDomain(o.TrustDomain) {
		return nil, ErrInvalidTrustDomain
	}
	if len(o.Chain) == 0 {
		return nil, fmt.Errorf("%w: empty chain", ErrIntermediate)
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	if err := CheckIntermediate(o.Chain[0], clock()); err != nil {
		return nil, err
	}
	if len(o.Chain) > 1 {
		inter := o.Chain[0]
		if err := o.Chain[1].CheckSignature(inter.SignatureAlgorithm, inter.RawTBSCertificate, inter.Signature); err != nil {
			return nil, fmt.Errorf("%w: the intermediate is not signed by the next certificate of the chain", ErrIntermediate)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(o.Chain[0])
	if len(o.Previous) > 0 {
		if err := checkStructure(o.Previous[0]); err != nil {
			return nil, fmt.Errorf("previous: %w", err)
		}
		roots.AddCert(o.Previous[0])
	}
	return &Verifier{chain: o.Chain, trustDomain: o.TrustDomain, clock: clock, roots: roots}, nil
}

// String, GoString and LogValue keep a CA's printable forms to the trust
// domain and expiry: the signer inside may be a bare Ed25519 key whose bytes
// fmt would otherwise print.
func (ca *CA) String() string   { return "workerca.CA{" + ca.Verifier.describe() + "}" }
func (ca *CA) GoString() string { return ca.String() }
func (ca *CA) LogValue() slog.Value {
	return slog.GroupValue(slog.String("trust_domain", ca.trustDomain),
		slog.String("not_after", ca.NotAfter().UTC().Format(time.RFC3339)))
}

func (v *Verifier) describe() string {
	return "trust_domain=" + v.trustDomain + " not_after=" + v.NotAfter().UTC().Format(time.RFC3339)
}

// String and GoString describe a Verifier without certificate bytes.
func (v *Verifier) String() string   { return "workerca.Verifier{" + v.describe() + "}" }
func (v *Verifier) GoString() string { return v.String() }

// New validates the intermediate and returns the CA. The intermediate must be
// CA:true with MaxPathLen 0 and certSign, its public key must be the signer's,
// and it must be valid now. It does not compare against the proxy CA: that is
// CheckSeparateRoot, which needs the --ca-cert the control plane was given.
func New(o Options) (*CA, error) {
	if o.Signer == nil || o.Create == nil {
		return nil, fmt.Errorf("%w: a signer and a certificate creator are required", ErrIntermediate)
	}
	v, err := NewVerifier(o)
	if err != nil {
		return nil, err
	}
	if !publicKeyMatches(o.Chain[0], o.Signer.Public()) {
		return nil, fmt.Errorf("%w: the signing key does not match the intermediate certificate", ErrIntermediate)
	}
	return &CA{Verifier: v, chain: o.Chain, signer: o.Signer, create: o.Create}, nil
}

// CheckIntermediate enforces what a worker intermediate must be, at now.
func CheckIntermediate(c *x509.Certificate, now time.Time) error {
	if err := checkStructure(c); err != nil {
		return err
	}
	switch {
	case now.After(c.NotAfter):
		return fmt.Errorf("%w: expired at %s", ErrIntermediateExpired, c.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(c.NotBefore):
		return fmt.Errorf("%w: not valid before %s", ErrIntermediateExpired, c.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// checkStructure is CheckIntermediate without the validity window.
func checkStructure(c *x509.Certificate) error {
	switch {
	case !c.BasicConstraintsValid || !c.IsCA:
		return fmt.Errorf("%w: not a CA certificate", ErrIntermediate)
	case c.MaxPathLen != 0 || !c.MaxPathLenZero:
		return fmt.Errorf("%w: pathLen must be 0", ErrIntermediate)
	case c.KeyUsage&x509.KeyUsageCertSign == 0:
		return fmt.Errorf("%w: missing certSign key usage", ErrIntermediate)
	}
	return nil
}

// TrustDomain returns the SPIFFE trust domain.
func (v *Verifier) TrustDomain() string { return v.trustDomain }

// Intermediate returns the signing intermediate certificate.
func (v *Verifier) Intermediate() *x509.Certificate { return v.chain[0] }

// NotAfter returns the signing intermediate's expiry.
func (v *Verifier) NotAfter() time.Time { return v.chain[0].NotAfter }

// Roots returns the pool of pinned worker intermediates (current and previous).
// Client certificates are verified against it and nothing else.
func (v *Verifier) Roots() *x509.CertPool { return v.roots }

// Issue signs a client certificate for csr's public key and workerID. Every
// CSR subject, SAN and extension is ignored: the certificate carries exactly
// one URI SAN spiffe://<trustDomain>/warden/worker/<workerID>, EKU clientAuth,
// KeyUsage digitalSignature, IsCA false, a random 128-bit serial, NotBefore
// now-5m and NotAfter min(now+ttl, intermediate NotAfter).
func (ca *CA) Issue(csr *x509.CertificateRequest, workerID string, ttl time.Duration) (*x509.Certificate, error) {
	if !ValidWorkerID(workerID) {
		return nil, ErrInvalidWorkerID
	}
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}
	if csr == nil {
		return nil, fmt.Errorf("%w: missing", ErrBadCSR)
	}
	if err := checkCSRKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: self-signature does not verify", ErrBadCSR)
	}
	id, err := SPIFFEID(ca.trustDomain, workerID)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("workerca: serial: %w", err)
	}
	serial.Add(serial, big.NewInt(1)) // never 0 (RFC 5280 wants a positive serial)
	now := ca.clock()
	notAfter := now.Add(ttl)
	if inter := ca.chain[0].NotAfter; notAfter.After(inter) {
		notAfter = inter
	}
	if !notAfter.After(now) {
		return nil, ErrIntermediateExpired
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-notBeforeSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{id},
	}
	der, err := ca.create(tmpl, ca.chain[0], csr.PublicKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("workerca: sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("workerca: issued certificate does not parse: %w", err)
	}
	return cert, nil
}

// Verify checks that cert chains to a pinned worker intermediate for client
// authentication at the CA's clock, and returns the worker id it carries.
func (v *Verifier) Verify(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrNotWorkerCert
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       v.roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: v.clock(),
	}); err != nil {
		return "", fmt.Errorf("workerca: certificate does not verify: %w", err)
	}
	return WorkerIDFromCert(cert, v.trustDomain)
}

// checkCSRKey accepts only ECDSA P-256 and Ed25519 public keys.
func checkCSRKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return nil
		}
	case ed25519.PublicKey:
		return nil
	}
	return ErrUnsupportedKey
}
