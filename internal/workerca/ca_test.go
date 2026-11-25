package workerca_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/workerca"
	"github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

const trustDomain = "warden.local"

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type pki struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
}

func newPKI(t *testing.T, now time.Time) pki {
	t.Helper()
	root, rootKey, err := signer.NewRoot(now)
	if err != nil {
		t.Fatal(err)
	}
	ik, err := signer.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	inter, err := signer.NewIntermediate(root, rootKey, &ik.PublicKey, trustDomain, now)
	if err != nil {
		t.Fatal(err)
	}
	return pki{root, rootKey, inter, ik}
}

func (p pki) ca(t *testing.T, now time.Time) *workerca.CA {
	t.Helper()
	ca, err := workerca.New(workerca.Options{
		Chain: []*x509.Certificate{p.inter, p.root}, Signer: p.interKey, Create: signer.CreateCertificate, Serial: signer.NewSerial,
		TrustDomain: trustDomain, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func csrFor(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestIssueIgnoresCSRContentAndVerifies(t *testing.T) {
	p := newPKI(t, t0)
	ca := p.ca(t, t0)
	evil, _ := url.Parse("spiffe://other/x")
	csr := csrFor(t, p256(t), &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "admin"},
		DNSNames:       []string{"evil.example"},
		URIs:           []*url.URL{evil},
		EmailAddresses: []string{"a@evil.example"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
	})
	cert, err := ca.Issue(csr, "worker-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 {
		t.Fatalf("copied CSR SANs: %v %v %v", cert.DNSNames, cert.EmailAddresses, cert.IPAddresses)
	}
	if cert.Subject.CommonName != "" {
		t.Fatalf("copied CSR subject %q", cert.Subject.CommonName)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://warden.local/warden/worker/worker-1" {
		t.Fatalf("uris = %v", cert.URIs)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("eku = %v", cert.ExtKeyUsage)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature || cert.IsCA {
		t.Fatalf("keyUsage=%v isCA=%v", cert.KeyUsage, cert.IsCA)
	}
	if !cert.NotBefore.Equal(t0.Add(-5*time.Minute)) || !cert.NotAfter.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("validity %s .. %s", cert.NotBefore, cert.NotAfter)
	}
	if cert.SerialNumber.BitLen() < 100 {
		t.Fatalf("serial too small: %d bits", cert.SerialNumber.BitLen())
	}
	// Verifies against a pool holding only the intermediate.
	pool := x509.NewCertPool()
	pool.AddCert(p.inter)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: t0}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id, err := ca.Verify(cert); err != nil || id != "worker-1" {
		t.Fatalf("CA.Verify = %q, %v", id, err)
	}
	if id, err := workerca.WorkerIDFromCert(cert, trustDomain); err != nil || id != "worker-1" {
		t.Fatalf("WorkerIDFromCert = %q, %v", id, err)
	}
	// A certificate of another trust domain is not a worker certificate here.
	if _, err := workerca.WorkerIDFromCert(cert, "other.local"); !errors.Is(err, workerca.ErrNotWorkerCert) {
		t.Fatalf("other trust domain: %v", err)
	}
}

func TestIssueAcceptsEd25519(t *testing.T) {
	p := newPKI(t, t0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cert, err := p.ca(t, t0).Issue(csrFor(t, priv, &x509.CertificateRequest{}), "w", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("key = %T", cert.PublicKey)
	}
}

func TestIssueCapsAtIntermediateNotAfter(t *testing.T) {
	p := newPKI(t, t0)
	// The intermediate lives 1y from t0; issue from a clock 2h before its end.
	late := p.inter.NotAfter.Add(-2 * time.Hour)
	cert, err := p.ca(t, late).Issue(csrFor(t, p256(t), &x509.CertificateRequest{}), "w", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(p.inter.NotAfter) {
		t.Fatalf("NotAfter %s, want intermediate's %s", cert.NotAfter, p.inter.NotAfter)
	}
}

func TestCSRValidation(t *testing.T) {
	p := newPKI(t, t0)
	ca := p.ca(t, t0)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, key := range map[string]crypto.Signer{"rsa2048": rsa2048, "rsa1024": rsa1024, "p384": p384} {
		_, err := ca.Issue(csrFor(t, key, &x509.CertificateRequest{}), "w", time.Hour)
		if !errors.Is(err, workerca.ErrUnsupportedKey) {
			t.Errorf("%s: err = %v, want ErrUnsupportedKey", name, err)
		}
	}
	// Broken self-signature: swap in another key's signature.
	good := csrFor(t, p256(t), &x509.CertificateRequest{})
	other := csrFor(t, p256(t), &x509.CertificateRequest{})
	good.Signature = other.Signature
	if _, err := ca.Issue(good, "w", time.Hour); !errors.Is(err, workerca.ErrBadCSR) {
		t.Errorf("broken signature: %v", err)
	}
	if _, err := ca.Issue(nil, "w", time.Hour); !errors.Is(err, workerca.ErrBadCSR) {
		t.Errorf("nil csr: %v", err)
	}
	ok := csrFor(t, p256(t), &x509.CertificateRequest{})
	for _, id := range []string{"../x", "", "a b", strings.Repeat("a", 129), "a/b"} {
		if _, err := ca.Issue(ok, id, time.Hour); !errors.Is(err, workerca.ErrInvalidWorkerID) {
			t.Errorf("worker id %q: %v", id, err)
		}
	}
	if _, err := ca.Issue(ok, "w", 0); !errors.Is(err, workerca.ErrInvalidTTL) {
		t.Errorf("zero ttl: %v", err)
	}
	if _, err := ca.Issue(ok, strings.Repeat("a", 128), time.Hour); err != nil {
		t.Errorf("128-char id: %v", err)
	}
}

func TestIntermediateChecks(t *testing.T) {
	p := newPKI(t, t0)
	opts := func() workerca.Options {
		return workerca.Options{
			Chain: []*x509.Certificate{p.inter}, Signer: p.interKey, Create: signer.CreateCertificate, Serial: signer.NewSerial,
			TrustDomain: trustDomain, Clock: func() time.Time { return t0 },
		}
	}
	// A leaf-like cert (the root has MaxPathLen 1) is rejected as an intermediate.
	o := opts()
	o.Chain = []*x509.Certificate{p.root}
	o.Signer = p.rootKey
	if _, err := workerca.New(o); !errors.Is(err, workerca.ErrIntermediate) {
		t.Errorf("root as intermediate: %v", err)
	}
	// Key mismatch.
	o = opts()
	o.Signer = p256(t)
	if _, err := workerca.New(o); !errors.Is(err, workerca.ErrIntermediate) {
		t.Errorf("key mismatch: %v", err)
	}
	// Expired.
	o = opts()
	o.Clock = func() time.Time { return p.inter.NotAfter.Add(time.Second) }
	if _, err := workerca.New(o); !errors.Is(err, workerca.ErrIntermediateExpired) {
		t.Errorf("expired: %v", err)
	}
	// Bad trust domain, empty chain, missing creator.
	o = opts()
	o.TrustDomain = "Bad Domain"
	if _, err := workerca.New(o); !errors.Is(err, workerca.ErrInvalidTrustDomain) {
		t.Errorf("trust domain: %v", err)
	}
	o = opts()
	o.Chain = nil
	if _, err := workerca.New(o); !errors.Is(err, workerca.ErrIntermediate) {
		t.Errorf("empty chain: %v", err)
	}
	o = opts()
	o.Create = nil
	if _, err := workerca.New(o); !errors.Is(err, workerca.ErrIntermediate) {
		t.Errorf("no creator: %v", err)
	}
	o = opts()
	o.Serial = nil
	if _, err := workerca.New(o); !errors.Is(err, workerca.ErrIntermediate) {
		t.Errorf("no serial source: %v", err)
	}
	// Previous intermediate is pinned for verification.
	prev := newPKI(t, t0)
	o = opts()
	o.Previous = []*x509.Certificate{prev.inter}
	ca, err := workerca.New(o)
	if err != nil {
		t.Fatal(err)
	}
	old, err := prev.ca(t, t0).Issue(csrFor(t, p256(t), &x509.CertificateRequest{}), "old", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := ca.Verify(old); err != nil || id != "old" {
		t.Errorf("previous-issued cert: %q %v", id, err)
	}
	// A cert from an unpinned intermediate does not verify.
	stranger := newPKI(t, t0)
	cert, _ := stranger.ca(t, t0).Issue(csrFor(t, p256(t), &x509.CertificateRequest{}), "x", time.Hour)
	if _, err := ca.Verify(cert); err == nil {
		t.Error("cert from an unpinned intermediate verified")
	}
}

func TestIntermediateChecksSeparateRoot(t *testing.T) {
	p := newPKI(t, t0)
	proxy := newPKI(t, t0)
	if err := workerca.CheckSeparateRoot(p.chain(), proxy.chain()); err != nil {
		t.Fatalf("independent roots: %v", err)
	}
	// Same public key as the proxy CA.
	if err := workerca.CheckSeparateRoot([]*x509.Certificate{proxy.root}, []*x509.Certificate{proxy.root}); !errors.Is(err, workerca.ErrSharedTrustRoot) {
		t.Errorf("same SPKI: %v", err)
	}
	// Signed by the proxy CA.
	if err := workerca.CheckSeparateRoot([]*x509.Certificate{proxy.inter}, []*x509.Certificate{proxy.root}); !errors.Is(err, workerca.ErrSharedTrustRoot) {
		t.Errorf("chains to proxy CA: %v", err)
	}
}

func (p pki) chain() []*x509.Certificate { return []*x509.Certificate{p.inter, p.root} }

func TestWorkerIDFromCert(t *testing.T) {
	mk := func(uris ...string) *x509.Certificate {
		c := &x509.Certificate{}
		for _, s := range uris {
			u, _ := url.Parse(s)
			c.URIs = append(c.URIs, u)
		}
		return c
	}
	for name, c := range map[string]*x509.Certificate{
		"none":      mk(),
		"two":       mk("spiffe://warden.local/warden/worker/a", "spiffe://warden.local/warden/worker/b"),
		"scheme":    mk("https://warden.local/warden/worker/a"),
		"host":      mk("spiffe://evil/warden/worker/a"),
		"prefix":    mk("spiffe://warden.local/other/a"),
		"empty id":  mk("spiffe://warden.local/warden/worker/"),
		"nested id": mk("spiffe://warden.local/warden/worker/a/b"),
		"query":     mk("spiffe://warden.local/warden/worker/a?x=1"),
		"port":      mk("spiffe://warden.local:8080/warden/worker/a"),
		"extra dnsSAN": func() *x509.Certificate {
			c := mk("spiffe://warden.local/warden/worker/a")
			c.DNSNames = []string{"x"}
			return c
		}(),
	} {
		if _, err := workerca.WorkerIDFromCert(c, trustDomain); !errors.Is(err, workerca.ErrNotWorkerCert) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := workerca.WorkerIDFromCert(nil, trustDomain); !errors.Is(err, workerca.ErrNotWorkerCert) {
		t.Errorf("nil: %v", err)
	}
}

func TestPEMHelpers(t *testing.T) {
	p := newPKI(t, t0)
	certs, err := workerca.ParseCertsPEM(workerca.EncodeCertsPEM(p.inter, p.root))
	if err != nil || len(certs) != 2 || !certs[0].Equal(p.inter) {
		t.Fatalf("round trip: %d %v", len(certs), err)
	}
	if _, err := workerca.ParseCertsPEM([]byte("not pem")); err == nil {
		t.Error("garbage parsed")
	}
	if _, err := workerca.ParseCertsPEM([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")); err == nil {
		t.Error("bad DER parsed")
	}
	der, err := signer.NewCSR(p.interKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workerca.ParseCSRPEM([]byte("junk")); !errors.Is(err, workerca.ErrBadCSR) {
		t.Errorf("junk csr: %v", err)
	}
	_ = der
	if !workerca.SameSPKI(p.inter, p.inter) || workerca.SameSPKI(p.inter, p.root) || workerca.SameSPKI(nil, p.root) {
		t.Error("SameSPKI")
	}
	if workerca.ValidTrustDomain("a..b") || !workerca.ValidTrustDomain("a.b-c") {
		t.Error("ValidTrustDomain")
	}
}

func TestCAAccessors(t *testing.T) {
	p := newPKI(t, t0)
	ca := p.ca(t, t0)
	if ca.TrustDomain() != trustDomain || !ca.NotAfter().Equal(p.inter.NotAfter) || !ca.Intermediate().Equal(p.inter) || ca.Roots() == nil {
		t.Fatal("accessors")
	}
	if _, err := ca.Verify(nil); !errors.Is(err, workerca.ErrNotWorkerCert) {
		t.Errorf("nil verify: %v", err)
	}
	if _, err := workerca.SPIFFEID("bad domain", "w"); !errors.Is(err, workerca.ErrInvalidTrustDomain) {
		t.Errorf("spiffe td: %v", err)
	}
}

func TestWorkerIDRejectsDotSegments(t *testing.T) {
	for _, id := range []string{".", ".."} {
		if workerca.ValidWorkerID(id) {
			t.Errorf("ValidWorkerID(%q) = true", id)
		}
		if _, err := workerca.SPIFFEID(trustDomain, id); !errors.Is(err, workerca.ErrInvalidWorkerID) {
			t.Errorf("SPIFFEID(%q): %v", id, err)
		}
	}
	for _, id := range []string{"a.b", "...", ".a", "a..b"} {
		if !workerca.ValidWorkerID(id) {
			t.Errorf("ValidWorkerID(%q) = false", id)
		}
	}
}

// TestIssueIgnoresCSRExtensions: a CSR asking for CA:true and serverAuth via
// extension requests gets neither.
func TestIssueIgnoresCSRExtensions(t *testing.T) {
	p := newPKI(t, t0)
	bc, _ := asn1.Marshal(struct{ IsCA bool }{true})
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})
	csr := csrFor(t, p256(t), &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc},
		{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku},
	}})
	cert, err := p.ca(t, t0).Issue(csr, "w", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("isCA=%v eku=%v", cert.IsCA, cert.ExtKeyUsage)
	}
}

// TestIntermediateChecksChainAndVerifier: the next certificate of the chain
// must have signed the intermediate, an expired previous is pinned harmlessly,
// and a Verifier needs no key.
func TestIntermediateChecksChainAndVerifier(t *testing.T) {
	p := newPKI(t, t0)
	stranger := newPKI(t, t0)
	_, err := workerca.NewVerifier(workerca.Options{Chain: []*x509.Certificate{p.inter, stranger.root}, TrustDomain: trustDomain, Clock: func() time.Time { return t0 }})
	if !errors.Is(err, workerca.ErrIntermediate) {
		t.Errorf("wrong next certificate: %v", err)
	}
	old := newPKI(t, t0.AddDate(-3, 0, 0))
	v, err := workerca.NewVerifier(workerca.Options{
		Chain: p.chain(), Previous: []*x509.Certificate{old.inter}, TrustDomain: trustDomain, Clock: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := p.ca(t, t0).Issue(csrFor(t, p256(t), &x509.CertificateRequest{}), "w", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := v.Verify(cert); err != nil || id != "w" {
		t.Fatalf("verifier: %q %v", id, err)
	}
	if _, err := workerca.NewVerifier(workerca.Options{Chain: p.chain(), Previous: []*x509.Certificate{p.root}, TrustDomain: trustDomain}); !errors.Is(err, workerca.ErrIntermediate) {
		t.Errorf("structurally wrong previous: %v", err)
	}
}

// TestCAPrintableFormsCarryNoKey: %v, %+v, %#v and %s of a CA built on a bare
// Ed25519 key show the trust domain and expiry, never key bytes.
func TestCAPrintableFormsCarryNoKey(t *testing.T) {
	root, rootKey, err := signer.NewRoot(t0)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	inter, err := signer.NewIntermediate(root, rootKey, pub, trustDomain, t0)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := workerca.New(workerca.Options{
		Chain: []*x509.Certificate{inter}, Signer: priv, Create: signer.CreateCertificate, Serial: signer.NewSerial,
		TrustDomain: trustDomain, Clock: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	seed, seedOnly := fmt.Sprintf("%v", []byte(priv)), fmt.Sprintf("%v", []byte(priv.Seed()))
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(f, ca)
		if strings.Contains(out, seed[1:20]) || strings.Contains(out, seedOnly[1:20]) {
			t.Errorf("%s of a CA prints key bytes: %s", f, out)
		}
		if !strings.Contains(out, trustDomain) {
			t.Errorf("%s of a CA lacks the trust domain: %s", f, out)
		}
	}
}

// TestIssueRefusesNonPositiveSerial: a serial source that returns 0 (or
// nothing) never yields a certificate; the adapter's source is never 0.
func TestIssueRefusesNonPositiveSerial(t *testing.T) {
	p := newPKI(t, t0)
	for name, src := range map[string]func() (*big.Int, error){
		"zero": func() (*big.Int, error) { return new(big.Int), nil },
		"nil":  func() (*big.Int, error) { return nil, nil },
		"err":  func() (*big.Int, error) { return nil, errors.New("no entropy") },
	} {
		ca, err := workerca.New(workerca.Options{
			Chain: p.chain(), Signer: p.interKey, Create: signer.CreateCertificate, Serial: src,
			TrustDomain: trustDomain, Clock: func() time.Time { return t0 },
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Issue(csrFor(t, p256(t), &x509.CertificateRequest{}), "w", time.Hour); err == nil {
			t.Errorf("%s serial issued a certificate", name)
		}
	}
	for i := 0; i < 200; i++ {
		n, err := signer.NewSerial()
		if err != nil || n.Sign() <= 0 || n.BitLen() > 129 {
			t.Fatalf("NewSerial = %v, %v", n, err)
		}
	}
}
