package cpclient_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/workerca"
	"github.com/ethosagent/warden/internal/workerca/adapters/cpclient"
)

func fixedNow() time.Time { return t0 }

func newEnroller(cp *fakeCP, dir, token string, logger *slog.Logger) *cpclient.Enroller {
	return &cpclient.Enroller{
		Endpoint: cp.url("/control/enroll"), HTTP: http.DefaultClient, StateDir: dir, Token: token, Suffix: "a", Now: cp.now, Logger: logger,
	}
}

func TestEnrollerEnrollsAndPersists(t *testing.T) {
	cp := newFakeCP(t, fixedNow)
	dir := filepath.Join(t.TempDir(), "state")
	var logs bytes.Buffer
	cred, err := newEnroller(cp, dir, "wet_good", slog.New(slog.NewTextHandler(&logs, nil))).LoadOrEnroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.WorkerID() != "worker-1" || cp.enrolls.Load() != 1 {
		t.Fatalf("worker %q, %d enrollments", cred.WorkerID(), cp.enrolls.Load())
	}
	// The files exist with the promised modes.
	for path, want := range map[string]os.FileMode{
		dir: 0o700, filepath.Join(dir, "cert"): 0o700,
		filepath.Join(dir, "cert", "worker-key.pem"): 0o600, filepath.Join(dir, "cert", "worker-cert.pem"): 0o600,
	} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", path, st.Mode().Perm(), want)
		}
	}
	key, _ := os.ReadFile(filepath.Join(dir, "cert", "worker-key.pem"))
	if !strings.HasPrefix(string(key), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("the key is not PKCS#8 PEM")
	}
	// Nothing secret in any printable form or log.
	for _, s := range []string{logs.String(), cred.String()} {
		if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "wet_good") {
			t.Errorf("secret in %q", s)
		}
	}
}

func TestEnrollerReusesPersistedCertWithoutContactingTheControlPlane(t *testing.T) {
	cp := newFakeCP(t, fixedNow)
	dir := t.TempDir()
	first, err := newEnroller(cp, dir, "wet_good", nil).LoadOrEnroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A restart: no token at all, still no request.
	again, err := newEnroller(cp, dir, "", nil).LoadOrEnroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cp.enrolls.Load() != 1 || again.Serial() != first.Serial() {
		t.Fatalf("enrollments = %d, serial %s vs %s", cp.enrolls.Load(), again.Serial(), first.Serial())
	}
	if len(again.Chain) != 2 {
		t.Errorf("chain = %d certificates, want the 2 the control plane sent", len(again.Chain))
	}
}

func TestEnrollerExpiredCertReenrolls(t *testing.T) {
	cp := newFakeCP(t, fixedNow)
	dir := t.TempDir()
	if _, err := newEnroller(cp, dir, "wet_good", nil).LoadOrEnroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(25 * time.Hour)
	e := newEnroller(cp, dir, "", nil)
	e.Now = func() time.Time { return later }
	if _, err := e.LoadOrEnroll(context.Background()); err != cpclient.ErrNoToken {
		t.Fatalf("expired and no token: err = %v, want ErrNoToken", err)
	}
	cp.now = func() time.Time { return later }
	e = newEnroller(cp, dir, "wet_good", nil)
	e.Now = cp.now
	cred, err := e.LoadOrEnroll(context.Background())
	if err != nil || cp.enrolls.Load() != 2 || cred.Expired(later) {
		t.Fatalf("re-enroll: %v, %d enrollments", err, cp.enrolls.Load())
	}
}

func TestEnrollerNoTokenNoCert(t *testing.T) {
	cp := newFakeCP(t, fixedNow)
	if _, err := newEnroller(cp, t.TempDir(), "", nil).LoadOrEnroll(context.Background()); err != cpclient.ErrNoToken {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
	if cp.enrolls.Load() != 0 {
		t.Error("contacted the control plane without a token")
	}
}

func TestEnrollerRejectedTokenIsPermanent(t *testing.T) {
	cp := newFakeCP(t, fixedNow)
	_, err := newEnroller(cp, t.TempDir(), "wet_bad", nil).LoadOrEnroll(context.Background())
	if err == nil || !cpclient.IsPermanent(err) {
		t.Fatalf("err = %v, want a permanent control plane refusal", err)
	}
	if strings.Contains(err.Error(), "wet_bad") {
		t.Errorf("the error echoes the token: %v", err)
	}
}

func TestEnrollerUnreachableControlPlaneIsTransient(t *testing.T) {
	cp := newFakeCP(t, fixedNow)
	e := newEnroller(cp, t.TempDir(), "wet_good", nil)
	cp.srv.Close()
	_, err := e.LoadOrEnroll(context.Background())
	if err == nil || cpclient.IsPermanent(err) {
		t.Fatalf("err = %v, want a transient failure", err)
	}
}

// TestEnrollerRefusesAForgedResponse: the worker verifies the chain before it
// trusts or writes anything.
func TestEnrollerRefusesAForgedResponse(t *testing.T) {
	stranger := newFakeCA(t)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]func(cp *fakeCP, resp map[string]any, csr *x509.CertificateRequest){
		"leaf not signed by Chain[0]": func(cp *fakeCP, resp map[string]any, csr *x509.CertificateRequest) {
			leaf := stranger.issue(t, csr.PublicKey, testTrustDomain, "worker-1", t0.Add(-time.Minute), t0.Add(time.Hour))
			resp["certificate"] = string(workerca.EncodeCertsPEM(leaf))
		},
		"Chain[1] did not sign Chain[0]": func(cp *fakeCP, resp map[string]any, _ *x509.CertificateRequest) {
			resp["chain"] = []string{string(workerca.EncodeCertsPEM(cp.ca.inter)), string(workerca.EncodeCertsPEM(stranger.root))}
		},
		"empty chain": func(cp *fakeCP, resp map[string]any, _ *x509.CertificateRequest) { resp["chain"] = []string{} },
		"key is not the CSR's": func(cp *fakeCP, resp map[string]any, _ *x509.CertificateRequest) {
			leaf := cp.ca.issue(t, &otherKey.PublicKey, testTrustDomain, "worker-1", t0.Add(-time.Minute), t0.Add(time.Hour))
			resp["certificate"] = string(workerca.EncodeCertsPEM(leaf))
		},
		"response worker id differs from the certificate": func(cp *fakeCP, resp map[string]any, _ *x509.CertificateRequest) {
			resp["workerId"] = "someone-else"
		},
		"response spiffe id differs from the certificate": func(cp *fakeCP, resp map[string]any, _ *x509.CertificateRequest) {
			resp["spiffeId"] = "spiffe://warden.test/warden/worker/other"
		},
		"already expired": func(cp *fakeCP, resp map[string]any, csr *x509.CertificateRequest) {
			leaf := cp.ca.issue(t, csr.PublicKey, testTrustDomain, "worker-1", t0.Add(-2*time.Hour), t0.Add(-time.Hour))
			resp["certificate"] = string(workerca.EncodeCertsPEM(leaf))
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			cp := newFakeCP(t, fixedNow)
			cp.tamper = func(resp map[string]any, csr *x509.CertificateRequest) { tamper(cp, resp, csr) }
			dir := t.TempDir()
			if _, err := newEnroller(cp, dir, "wet_good", nil).LoadOrEnroll(context.Background()); err == nil {
				t.Fatal("accepted a forged response")
			}
			if _, err := os.Stat(filepath.Join(dir, "cert", "worker-cert.pem")); err == nil {
				t.Error("wrote a certificate it did not trust")
			}
		})
	}
}

func TestLoadPersistedRecoversInterruptedRenewal(t *testing.T) {
	cp := newFakeCP(t, fixedNow)
	dir := t.TempDir()
	old, err := newEnroller(cp, dir, "wet_good", nil).LoadOrEnroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between installing the new certificate and its key: the
	// new key sits under the pending name, the old key is still in place.
	keyPath := filepath.Join(dir, "cert", "worker-key.pem")
	renewedKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	renewed := cp.ca.issue(t, &renewedKey.PublicKey, testTrustDomain, "worker-1", t0, t0.Add(24*time.Hour))
	der, _ := x509.MarshalPKCS8PrivateKey(renewedKey)
	pemKey := append([]byte("-----BEGIN PRIVATE KEY-----\n"), []byte(b64(der))...)
	pemKey = append(pemKey, []byte("\n-----END PRIVATE KEY-----\n")...)
	if err := os.WriteFile(keyPath+".next", pemKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert", "worker-cert.pem"), workerca.EncodeCertsPEM(renewed, cp.ca.inter), 0o600); err != nil {
		t.Fatal(err)
	}
	cred, err := newEnroller(cp, dir, "", nil).LoadOrEnroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.Serial() == old.Serial() || cred.Serial() != renewed.SerialNumber.Text(16) {
		t.Errorf("serial = %s, want the renewed one", cred.Serial())
	}
	if _, err := os.Stat(keyPath + ".next"); err == nil {
		t.Error("the pending key was not promoted")
	}
}

func TestLoadStatic(t *testing.T) {
	ca := newFakeCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.issue(t, &key.PublicKey, testTrustDomain, "static-1", t0.Add(-time.Minute), t0.Add(time.Hour))
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	_ = os.WriteFile(certPath, workerca.EncodeCertsPEM(leaf, ca.inter), 0o600)
	_ = os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\n"+b64(der)+"\n-----END PRIVATE KEY-----\n"), 0o600)
	cred, err := cpclient.LoadStatic(certPath, keyPath, t0)
	if err != nil || cred.WorkerID() != "static-1" {
		t.Fatalf("LoadStatic = %v, %v", cred, err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oder, _ := x509.MarshalPKCS8PrivateKey(other)
	_ = os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\n"+b64(oder)+"\n-----END PRIVATE KEY-----\n"), 0o600)
	if _, err := cpclient.LoadStatic(certPath, keyPath, t0); err == nil {
		t.Error("accepted a key that is not the certificate's")
	}
}

func TestRenewerRenewsAtHalfLifeThenBacksOff(t *testing.T) {
	clk := clocktest.NewFake(t0)
	cp := newFakeCP(t, clk.Now)
	dir := t.TempDir()
	cred, err := newEnroller(cp, dir, "wet_good", nil).LoadOrEnroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cred.ReceivedAt = clk.Now()
	src := cpclient.NewSource(cred)
	cp.failRenew.Store(3)
	var (
		omu      sync.Mutex
		outcomes []string
	)
	got := func() string {
		omu.Lock()
		defer omu.Unlock()
		return strings.Join(outcomes, ",")
	}
	var closed atomic.Int64
	r := &cpclient.Renewer{
		Endpoint: cp.url("/control/renew"), HTTP: http.DefaultClient, Source: src, StateDir: dir, Clock: clk,
		Jitter: func() float64 { return 0 }, CloseIdle: func() { closed.Add(1) }, OnRenew: func(o string) { omu.Lock(); outcomes = append(outcomes, o); omu.Unlock() },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, "the renewer to arm its 12h timer", func() bool { return clk.PendingTimers() == 1 })
	clk.Advance(12*time.Hour - time.Second)
	if cp.renews.Load() != 0 {
		t.Fatal("renewed before half of the lifetime")
	}
	clk.Advance(time.Second)
	// Three 503s, retried after 5s, 10s and 20s, with the old certificate in use.
	for i, wait := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second} {
		want := int64(i + 1)
		waitFor(t, "a failed renewal", func() bool { return cp.renews.Load() == want && clk.PendingTimers() == 1 })
		if src.Current().Serial() != cred.Serial() {
			t.Fatal("the certificate changed after a failed renewal")
		}
		clk.Advance(wait - time.Second)
		if cp.renews.Load() != want {
			t.Fatalf("retry %d came before its %s backoff", i+1, wait)
		}
		clk.Advance(time.Second)
	}
	// The swap, the idle-connection drop and the outcome report follow one another.
	waitFor(t, "the renewal to succeed", func() bool { return got() == "error,error,error,ok" && closed.Load() == 1 })
	if src.Current().Serial() == cred.Serial() {
		t.Error("the certificate was not swapped")
	}
	if cp.renews.Load() != 4 || closed.Load() != 1 {
		t.Errorf("renewals = %d, CloseIdle = %d", cp.renews.Load(), closed.Load())
	}
	// worker-cert.pem on disk is the new certificate.
	onDisk, err := newEnroller(cp, dir, "", nil).LoadOrEnroll(context.Background())
	if err != nil || onDisk.Serial() != src.Current().Serial() {
		t.Errorf("persisted serial %v (%v), want %s", onDisk, err, src.Current().Serial())
	}
	// And the next renewal is armed 12h after the new certificate arrived.
	waitFor(t, "the next timer", func() bool { return clk.PendingTimers() == 1 })
}

func TestRenewerKeepsTheCertWhenTheResponseIsForged(t *testing.T) {
	clk := clocktest.NewFake(t0)
	cp := newFakeCP(t, clk.Now)
	dir := t.TempDir()
	cred, _ := newEnroller(cp, dir, "wet_good", nil).LoadOrEnroll(context.Background())
	cred.ReceivedAt = clk.Now()
	src := cpclient.NewSource(cred)
	// The renewal names another worker.
	cp.tamper = func(resp map[string]any, csr *x509.CertificateRequest) {
		leaf := cp.ca.issue(t, csr.PublicKey, testTrustDomain, "worker-2", t0, t0.Add(time.Hour))
		resp["certificate"], resp["workerId"], resp["spiffeId"] = string(workerca.EncodeCertsPEM(leaf)), "worker-2", leaf.URIs[0].String()
	}
	var outcome atomic.Value
	r := &cpclient.Renewer{Endpoint: cp.url("/control/renew"), HTTP: http.DefaultClient, Source: src, StateDir: dir, Clock: clk,
		Jitter: func() float64 { return 0 }, OnRenew: func(o string) { outcome.Store(o) }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "the timer", func() bool { return clk.PendingTimers() == 1 })
	clk.Advance(12 * time.Hour)
	waitFor(t, "the forged renewal to be refused", func() bool { return outcome.Load() == cpclient.OutcomeRejected })
	if src.Current().Serial() != cred.Serial() {
		t.Error("installed a certificate for a different worker")
	}
}
