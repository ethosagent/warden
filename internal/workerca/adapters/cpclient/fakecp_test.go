package cpclient_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/workerca"
)

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

const testTrustDomain = "warden.test"

// fakeCA is a worker CA good enough for the control plane fake: a root, an
// intermediate and an issue function that mirrors workerca.CA.Issue's template.
type fakeCA struct {
	root, inter *x509.Certificate
	interKey    *ecdsa.PrivateKey
	rootKey     *ecdsa.PrivateKey
	mu          sync.Mutex
	next        int64
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootT := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(1000 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	interT := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "inter"}, NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(900 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interT, root, &ik.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	return &fakeCA{root: root, inter: inter, interKey: ik, rootKey: rk, next: 100}
}

// issue signs a client certificate for pub with the worker SPIFFE id.
func (ca *fakeCA) issue(t testing.TB, pub any, td, id string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	ca.mu.Lock()
	ca.next++
	serial := ca.next
	ca.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
		URIs: []*url.URL{{Scheme: "spiffe", Host: td, Path: "/warden/worker/" + id}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.inter, pub, ca.interKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (ca *fakeCA) response(id string, leaf *x509.Certificate) map[string]any {
	return map[string]any{
		"workerId": id, "spiffeId": leaf.URIs[0].String(),
		"certificate": string(workerca.EncodeCertsPEM(leaf)),
		"chain":       []string{string(workerca.EncodeCertsPEM(ca.inter)), string(workerca.EncodeCertsPEM(ca.root))},
		"serial":      leaf.SerialNumber.Text(16), "notAfter": leaf.NotAfter.UTC().Format(time.RFC3339),
	}
}

// fakeCP serves /control/enroll and /control/renew over plain HTTP: the TLS
// handshake is the worker package's concern, this checks what is posted.
type fakeCP struct {
	t   *testing.T
	ca  *fakeCA
	srv *httptest.Server
	now func() time.Time
	ttl time.Duration

	enrolls, renews atomic.Int64
	// failRenew is how many renewals answer 503 before one succeeds.
	failRenew atomic.Int64
	// tamper, when set, edits the response before it is sent.
	tamper func(resp map[string]any, csr *x509.CertificateRequest)
	// lastToken is the token the last enrollment carried.
	lastToken atomic.Value
	// renewTimes records the clock at each renew request.
	mu         sync.Mutex
	renewTimes []time.Time
}

func newFakeCP(t *testing.T, now func() time.Time) *fakeCP {
	t.Helper()
	cp := &fakeCP{t: t, ca: newFakeCA(t), now: now, ttl: 24 * time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("/control/enroll", cp.handle(true))
	mux.HandleFunc("/control/renew", cp.handle(false))
	cp.srv = httptest.NewServer(mux)
	t.Cleanup(cp.srv.Close)
	return cp
}

func (cp *fakeCP) handle(enroll bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token, CSR, WorkerIDSuffix string
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if enroll {
			cp.enrolls.Add(1)
			cp.lastToken.Store(req.Token)
			if req.Token != "wet_good" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		} else {
			cp.renews.Add(1)
			cp.mu.Lock()
			cp.renewTimes = append(cp.renewTimes, cp.now())
			cp.mu.Unlock()
			if cp.failRenew.Add(-1) >= 0 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "ca_unavailable"})
				return
			}
		}
		csr, err := workerca.ParseCSRPEM([]byte(req.CSR))
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		now := cp.now()
		leaf := cp.ca.issue(cp.t, csr.PublicKey, testTrustDomain, "worker-1", now.Add(-5*time.Minute), now.Add(cp.ttl))
		resp := cp.ca.response("worker-1", leaf)
		if cp.tamper != nil {
			cp.tamper(resp, csr)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (cp *fakeCP) url(path string) string { return cp.srv.URL + path }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
