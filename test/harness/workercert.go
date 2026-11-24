package harness

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

// Worker certificate helpers (W-P2-WCA-04): enroll a worker the way its
// enroller does, present the certificate on the control plane client, renew it,
// and mint the hostile certificates the authenticator must refuse.

// WithRequireWorkerCerts boots the control plane with --require-worker-certs
// (strict-certs): worker certificates only. It implies WithWorkerCA. The
// harness's own workers keep presenting the shared worker token and so are
// refused; a scenario drives the control plane with CPClient.WithClientCert.
// In-process only.
func WithRequireWorkerCerts() Option {
	return func(h *H) {
		h.wantKeys, h.wantWorkerCA, h.wantStrictCerts = true, true, true
	}
}

func (h *H) applyStrictCerts(p *controlplane.Params) {
	if !h.wantStrictCerts {
		return
	}
	p.TokenEnv, p.LegacyTokenEnv = "", ""
	p.RequireWorkerCerts = true
}

// WorkerCert is a worker certificate with its private key.
type WorkerCert struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Serial is the certificate's serial as the control plane prints it (lowercase hex).
func (w WorkerCert) Serial() string { return w.Cert.SerialNumber.Text(16) }

// TLS is the certificate as a client credential.
func (w WorkerCert) TLS() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{w.Cert.Raw}, PrivateKey: w.Key}
}

// NewKeyCSR returns a fresh P-256 key and its PEM certificate request.
func NewKeyCSR(h *H) (*ecdsa.PrivateKey, string) {
	h.tb.Helper()
	key, err := wcasigner.GenerateKey()
	if err != nil {
		h.tb.Fatalf("harness: generate a worker key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		h.tb.Fatalf("harness: create a CSR: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

type certResponse struct {
	Certificate string `json:"certificate"`
	PrevSerial  string `json:"prevSerial"`
}

func (h *H) parseCertResponse(body string, key *ecdsa.PrivateKey) (WorkerCert, certResponse) {
	h.tb.Helper()
	var r certResponse
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		h.tb.Fatalf("harness: decode the certificate response: %v", err)
	}
	certs, err := workerca.ParseCertsPEM([]byte(r.Certificate))
	if err != nil || len(certs) != 1 {
		h.tb.Fatalf("harness: parse the certificate: %v", err)
	}
	return WorkerCert{Cert: certs[0], Key: key}, r
}

// EnrollWorker enrolls with token (and suffix) over the control plane and
// returns the issued certificate; anything but a 201 fails the test.
func (h *H) EnrollWorker(token, suffix string) WorkerCert {
	h.tb.Helper()
	key, csr := NewKeyCSR(h)
	status, body := h.CP().Enroll(token, csr, suffix)
	if status != http.StatusCreated {
		h.tb.Fatalf("harness: POST /control/enroll = %d %s", status, body)
	}
	w, _ := h.parseCertResponse(body, key)
	return w
}

// WithClientCert returns a control plane client that presents cert in the TLS
// handshake (and sends no bearer unless the call gives one).
func (c *CPClient) WithClientCert(cert WorkerCert) *CPClient {
	c.h.tb.Helper()
	base := c.cl.Transport.(*http.Transport).Clone()
	base.TLSClientConfig = base.TLSClientConfig.Clone()
	base.TLSClientConfig.Certificates = []tls.Certificate{cert.TLS()}
	cp := &CPClient{h: c.h, addr: c.addr, token: c.token, cl: &http.Client{Transport: base}}
	c.h.tb.Cleanup(cp.CloseIdleConnections)
	return cp
}

// Renew posts a CSR for a fresh key to /control/renew over a client that
// presents cert, and returns the status, the body and, on a 201, the new
// certificate and the serial it names as prev_serial.
func (c *CPClient) Renew(cert WorkerCert) (status int, body string, renewed WorkerCert, prev string) {
	c.h.tb.Helper()
	key, csr := NewKeyCSR(c.h)
	return c.RenewWithCSR(cert, key, csr)
}

// RenewWithCSR is Renew with a caller-chosen CSR (and the key behind it).
func (c *CPClient) RenewWithCSR(cert WorkerCert, key *ecdsa.PrivateKey, csr string) (int, string, WorkerCert, string) {
	c.h.tb.Helper()
	raw, err := json.Marshal(map[string]string{"csr": csr})
	if err != nil {
		c.h.tb.Fatal(err)
	}
	status, body, err := c.WithClientCert(cert).Do(http.MethodPost, "/control/renew", "", raw)
	if err != nil {
		c.h.tb.Fatalf("harness: POST /control/renew: %v", err)
	}
	if status != http.StatusCreated {
		return status, body, WorkerCert{}, ""
	}
	w, r := c.h.parseCertResponse(body, key)
	return status, body, w, r.PrevSerial
}

// CertMint describes a certificate to mint for an attack scenario.
type CertMint struct {
	WorkerID    string
	TrustDomain string // default WorkerCATrustDomain
	// EKU defaults to clientAuth.
	EKU []x509.ExtKeyUsage
	// Issuer is "worker-ca" (the real intermediate's key; default), "proxy-ca"
	// (the harness's MITM CA) or "other-ca" (a fresh worker CA of the same trust
	// domain the control plane does not pin).
	Issuer string
}

// MintWorkerCert signs a short-lived client certificate with a worker SPIFFE
// SAN, valid at the harness clock, that the control plane's authenticator must
// refuse unless it is exactly what the worker CA would have issued.
func (h *H) MintWorkerCert(m CertMint) WorkerCert {
	h.tb.Helper()
	td := m.TrustDomain
	if td == "" {
		td = WorkerCATrustDomain
	}
	eku := m.EKU
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	now := h.fake.Now()
	sn, err := wcasigner.NewSerial()
	if err != nil {
		h.tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku, BasicConstraintsValid: true,
		URIs: []*url.URL{{Scheme: "spiffe", Host: td, Path: "/warden/worker/" + m.WorkerID}},
	}
	var (
		parent *x509.Certificate
		signer any
	)
	switch m.Issuer {
	case "", "worker-ca":
		fx := h.workerCAFixture()
		parent, signer = fx.inter, fx.key
	case "proxy-ca":
		parent, signer = h.proxyCA.cert, h.proxyCA.key
	case "other-ca":
		root, rootKey, err := wcasigner.NewRoot(now)
		if err != nil {
			h.tb.Fatal(err)
		}
		ikey, err := wcasigner.GenerateKey()
		if err != nil {
			h.tb.Fatal(err)
		}
		inter, err := wcasigner.NewIntermediate(root, rootKey, &ikey.PublicKey, td, now)
		if err != nil {
			h.tb.Fatal(err)
		}
		parent, signer = inter, ikey
	default:
		h.tb.Fatalf("harness: unknown certificate issuer %q", m.Issuer)
	}
	key, err := wcasigner.GenerateKey()
	if err != nil {
		h.tb.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		h.tb.Fatalf("harness: mint a worker certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		h.tb.Fatal(err)
	}
	return WorkerCert{Cert: cert, Key: key}
}

// EnrollWorkerWhenLoaded enrolls with a token minted offline (CreateEnrollToken):
// the control plane loads it on its 2 s data_version poll, which runs on the
// harness clock, so each try advances the clock until the 401 turns into a 201.
func (h *H) EnrollWorkerWhenLoaded(token, suffix string) WorkerCert {
	h.tb.Helper()
	var out WorkerCert
	h.Eventually("the control plane to load the offline-created enrollment token", func() bool {
		key, csr := NewKeyCSR(h)
		status, body := h.CP().Enroll(token, csr, suffix)
		switch status {
		case http.StatusCreated:
			out, _ = h.parseCertResponse(body, key)
			return true
		case http.StatusUnauthorized:
			h.Clock().Advance(6 * time.Second)
			return false
		}
		h.tb.Fatalf("harness: POST /control/enroll = %d %s while waiting for the token", status, body)
		return false
	})
	return out
}

// CSRFor returns the PEM certificate request of key (so a scenario can ask for
// a certificate over a key it already holds).
func CSRFor(tb testing.TB, key *ecdsa.PrivateKey) string {
	tb.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		tb.Fatalf("harness: create a CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// ParkedWorkerPolls is how many held /policy long-polls the in-process control
// plane has parked for the certificate serial. A scenario waits on it before it
// revokes, so the revoke provably cuts a parked request.
func (c *CPClient) ParkedWorkerPolls(serial string) int {
	c.h.tb.Helper()
	s := c.h.cpSrv.Load()
	if s == nil {
		c.h.tb.Fatal("harness: ParkedWorkerPolls needs the in-process control plane")
	}
	return s.ParkedWorkerPolls(serial)
}

// CertPruneRuns is how many times the in-process control plane's expired
// certificate pruner has run.
func (c *CPClient) CertPruneRuns() int64 {
	c.h.tb.Helper()
	s := c.h.cpSrv.Load()
	if s == nil {
		c.h.tb.Fatal("harness: CertPruneRuns needs the in-process control plane")
	}
	return s.CertPruneRuns()
}
