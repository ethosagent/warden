package worker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/workerca"
)

var certT0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// certCP is a control plane fake that, like the real one, authenticates by the
// client certificate: it serves /policy, /control/heartbeat, /central/ingest,
// /control/enroll and /control/renew over TLS and answers 401 to a request with
// no valid worker certificate.
type certCP struct {
	t          *testing.T
	clk        *clocktest.Fake
	srv        *httptest.Server
	caPath     string
	root       *x509.Certificate
	inter      *x509.Certificate
	interKey   *ecdsa.PrivateKey
	rootKey    *ecdsa.PrivateKey
	pool       *x509.CertPool
	serial     atomic.Int64
	workerID   string
	ttl        time.Duration
	enrolls    atomic.Int64
	renews     atomic.Int64
	down       atomic.Bool
	forge      atomic.Bool // answer enrollments with a response that names another worker
	mu         sync.Mutex
	bearers    []string // Authorization header of every request
	heartbeats []map[string]any
	ingestIDs  []string
	// rejectAuth makes the fake answer 400 to any request carrying an
	// Authorization header, the way a control plane in require mode must.
	rejectAuth atomic.Bool
	// pollHook, when set, runs inside GET /policy?wait=... after the client
	// certificate was identified (serial) and before the answer: a held long-poll.
	pollHook func(serial string)
	// frozen, when set, is the time the fake verifies certificates at: a control
	// plane whose clock the worker's does not drive.
	frozen atomic.Pointer[time.Time]
	// noCert counts requests that arrived without any client certificate.
	noCert atomic.Int64
}

func newCertCP(t *testing.T, clk *clocktest.Fake) *certCP {
	t.Helper()
	cp := &certCP{t: t, clk: clk, workerID: "worker-1", ttl: 24 * time.Hour}
	cp.rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cp.interKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: clk.Now().Add(-time.Hour),
		NotAfter: clk.Now().Add(1000 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, rootT, rootT, &cp.rootKey.PublicKey, cp.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cp.root, _ = x509.ParseCertificate(der)
	interT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "inter"}, NotBefore: clk.Now().Add(-time.Hour),
		NotAfter: clk.Now().Add(900 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	der, err = x509.CreateCertificate(rand.Reader, interT, cp.root, &cp.interKey.PublicKey, cp.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cp.inter, _ = x509.ParseCertificate(der)
	cp.pool = x509.NewCertPool()
	cp.pool.AddCert(cp.inter)

	cp.srv = httptest.NewUnstartedServer(http.HandlerFunc(cp.serve))
	cp.srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	cp.srv.EnableHTTP2 = true // like production: one connection carries concurrent requests
	cp.srv.StartTLS()
	t.Cleanup(cp.srv.Close)
	cp.caPath = filepath.Join(t.TempDir(), "cp-ca.pem")
	if err := os.WriteFile(cp.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cp
}

func (cp *certCP) endpoint() string { return cp.srv.URL + "/policy" }

func (cp *certCP) issue(pub any, id string, notAfter time.Time) *x509.Certificate {
	cp.t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1000 + cp.serial.Add(1)), NotBefore: cp.clk.Now().Add(-5 * time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
		URIs: []*url.URL{{Scheme: "spiffe", Host: "warden.test", Path: "/warden/worker/" + id}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, cp.inter, pub, cp.interKey)
	if err != nil {
		cp.t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// presented returns the worker id of a verified client certificate, or "".
func (cp *certCP) presented(r *http.Request) (id, serial string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ""
	}
	leaf := r.TLS.PeerCertificates[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: cp.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: cp.verifyTime()}); err != nil {
		return "", ""
	}
	id, err := workerca.WorkerIDFromCert(leaf, "warden.test")
	if err != nil {
		return "", ""
	}
	return id, leaf.SerialNumber.Text(16)
}

func (cp *certCP) verifyTime() time.Time {
	if f := cp.frozen.Load(); f != nil {
		return *f
	}
	return cp.clk.Now()
}

func (cp *certCP) serve(w http.ResponseWriter, r *http.Request) {
	cp.mu.Lock()
	cp.bearers = append(cp.bearers, r.Header.Get("Authorization"))
	cp.mu.Unlock()
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		cp.noCert.Add(1)
	}
	if cp.rejectAuth.Load() && r.Header.Get("Authorization") != "" {
		http.Error(w, "bearer not accepted", http.StatusBadRequest)
		return
	}
	if cp.down.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/control/enroll":
		cp.enrolls.Add(1)
		var req struct{ Token, CSR string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "wet_good" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		cp.issueTo(w, req.CSR)
		return
	case "/control/renew":
		cp.renews.Add(1)
		if id, _ := cp.presented(r); id == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct{ CSR string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		cp.issueTo(w, req.CSR)
		return
	}
	id, serial := cp.presented(r)
	if id == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/policy":
		if r.URL.Query().Get("wait") != "" && cp.pollHook != nil {
			cp.pollHook(serial)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"allowlist":[{"domain":"api.allowed.example"}],"denylist":[{"domain":"evil.example"}]}`)
	case "/control/heartbeat":
		var hb map[string]any
		_ = json.NewDecoder(r.Body).Decode(&hb)
		hb["_serial"], hb["_id"] = serial, id
		cp.mu.Lock()
		cp.heartbeats = append(cp.heartbeats, hb)
		cp.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "/central/ingest":
		cp.mu.Lock()
		cp.ingestIDs = append(cp.ingestIDs, id+"/"+r.Header.Get(analytics.ProxyIDHeader))
		cp.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (cp *certCP) issueTo(w http.ResponseWriter, csrPEM string) {
	csr, err := workerca.ParseCSRPEM([]byte(csrPEM))
	if err != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	leaf := cp.issue(csr.PublicKey, cp.workerID, cp.clk.Now().Add(cp.ttl))
	if cp.forge.Load() {
		leaf = cp.issue(csr.PublicKey, "forged-id", cp.clk.Now().Add(cp.ttl))
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"workerId": cp.workerID, "spiffeId": leaf.URIs[0].String(), "certificate": string(workerca.EncodeCertsPEM(leaf)),
		"chain":  []string{string(workerca.EncodeCertsPEM(cp.inter)), string(workerca.EncodeCertsPEM(cp.root))},
		"serial": leaf.SerialNumber.Text(16), "notAfter": leaf.NotAfter.UTC().Format(time.RFC3339),
	})
}

func (cp *certCP) sawBearer() bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, b := range cp.bearers {
		if b != "" {
			return true
		}
	}
	return false
}

func (cp *certCP) config(stateDir string) config.ControlPlaneConfig {
	return config.ControlPlaneConfig{
		Endpoint: cp.endpoint(), CACert: cp.caPath, StateDir: stateDir,
		Enrollment: config.EnrollmentConfig{TokenEnv: "WARDEN_TEST_ENROLL_TOKEN"},
	}
}

// syncBuf is a log sink the watcher goroutines and the test can share.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func certLogger() (*slog.Logger, *syncBuf) {
	buf := &syncBuf{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func pollPolicy(t *testing.T, wc *workerCert, ep string) (*config.RemoteProvider, error) {
	t.Helper()
	rp, err := config.NewRemoteProvider(ep, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	rp.SetHTTPClient(wc.Client(cpClientTimeout))
	rp.SetProxyIDFunc(wc.WorkerID)
	rp.SetCertInfo(wc.certInfo)
	return rp, rp.Pull()
}

func TestCertClientEnrollsOnceAndRestartMakesNoEnrollRequest(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	dir := filepath.Join(t.TempDir(), "state")
	logger, logs := certLogger()

	wc, err := newWorkerCert(context.Background(), cp.config(dir), config.CentralConfig{}, clk, logger)
	if err != nil || wc == nil {
		t.Fatalf("first start: %v", err)
	}
	first := wc.source.Current()
	if first == nil || cp.enrolls.Load() != 1 {
		t.Fatalf("enrollments = %d, cert = %v", cp.enrolls.Load(), first)
	}

	// Restart: the persisted certificate is reused, even with no token at all.
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "")
	wc2, err := newWorkerCert(context.Background(), cp.config(dir), config.CentralConfig{}, clk, logger)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if cp.enrolls.Load() != 1 {
		t.Fatalf("a restart made %d enroll requests, want 0 more", cp.enrolls.Load()-1)
	}
	got, err := wc2.getClientCertificate(nil)
	if err != nil || len(got.Certificate) == 0 || got.Leaf.SerialNumber.Text(16) != first.Serial() {
		t.Fatalf("GetClientCertificate = %+v, %v, want the persisted serial %s", got, err, first.Serial())
	}
	for _, s := range []string{logs.String()} {
		if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "wet_good") {
			t.Errorf("a secret reached the log: %q", s)
		}
	}
	st, err := os.Stat(filepath.Join(dir, "cert", "worker-key.pem"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v, want mode 0600", st, err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("stateDir mode = %v, want 0700", st.Mode().Perm())
	}
}

func TestCertClientPresentsTheCertificateAndNoBearer(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	logger, _ := certLogger()
	wc, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger)
	if err != nil {
		t.Fatal(err)
	}

	rp, err := pollPolicy(t, wc, cp.endpoint())
	if err != nil {
		t.Fatalf("policy pull with the certificate: %v", err)
	}
	if err := rp.Heartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	remote, err := analytics.NewHTTPRemoteStore(cp.srv.URL+"/central/ingest", "", wc.WorkerID(), wc.Client(cpClientTimeout))
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.SendBatch([]analytics.Event{{Timestamp: certT0, Domain: "api.allowed.example", Port: 443, Decision: "allow"}}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if cp.sawBearer() {
		t.Error("an Authorization header was sent although the worker holds a certificate")
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cur := wc.source.Current()
	if len(cp.heartbeats) != 1 || cp.heartbeats[0]["certSerial"] != cur.Serial() ||
		cp.heartbeats[0]["certNotAfter"] != cur.NotAfter().UTC().Format(time.RFC3339) || cp.heartbeats[0]["_id"] != "worker-1" {
		t.Errorf("heartbeat = %v, want the cert's serial and notAfter", cp.heartbeats)
	}
	if len(cp.ingestIDs) != 1 || cp.ingestIDs[0] != "worker-1/worker-1" {
		t.Errorf("ingest saw %v, want id worker-1 from both the cert and the header", cp.ingestIDs)
	}
}

func TestCertClientExpiredCertIsNotPresentedAndPolicyKeepsLastKnownGood(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	logger, logs := certLogger()
	wc, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := pollPolicy(t, wc, cp.endpoint())
	if err != nil {
		t.Fatal(err)
	}
	pol, err := rp.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	ev := policy.NewEvaluator(pol)

	// The ERROR line is logged once, however many checks pass, until an hour later.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go wc.watchExpiry(ctx)
	waitFor(t, "the expiry watcher to arm", func() bool { return clk.PendingTimers() == 1 })

	// The control plane's clock does not move: it would still accept the expired
	// certificate, so a pull can only fail because none was presented.
	frozen := clk.Now()
	cp.frozen.Store(&frozen)
	noCertBefore := cp.noCert.Load()
	clk.Advance(25 * time.Hour) // past NotAfter (24h)
	got, err := wc.getClientCertificate(nil)
	if err != nil || len(got.Certificate) != 0 {
		t.Fatalf("GetClientCertificate after expiry = %+v, %v, want an empty certificate", got, err)
	}
	waitFor(t, "the expiry error", func() bool { return strings.Count(logs.String(), "worker cert expired") >= 1 })
	if err := rp.Pull(); err == nil {
		t.Fatal("the control plane accepted a pull after the certificate expired: a pooled connection still presented it")
	}
	if cp.noCert.Load() == noCertBefore {
		t.Fatal("the control plane never saw a request without a certificate after expiry")
	}
	// The last-known-good policy still decides: allowed stays allowed, denied denied, unlisted default-denied.
	for host, want := range map[string]policy.Decision{"api.allowed.example": policy.Allow, "evil.example": policy.Deny, "other.example": policy.NoMatch} {
		if got := ev.Evaluate(host, 443, policy.SchemeHTTPS); got != want {
			t.Errorf("%s = %v, want %v", host, got, want)
		}
	}
	if kept, err := rp.GetPolicy(); err != nil || len(kept.Allowlist) != 1 {
		t.Errorf("the provider dropped its last-known-good policy: %v, %v", kept, err)
	}
	for i := 0; i < 30; i++ {
		clk.Advance(time.Minute)
		waitFor(t, "a check", func() bool { return clk.PendingTimers() == 1 })
	}
	if n := strings.Count(logs.String(), "worker cert expired"); n != 1 {
		t.Errorf("worker cert expired logged %d times in 30 minutes, want 1", n)
	}
	clk.Advance(time.Hour)
	waitFor(t, "the hourly repeat", func() bool { return strings.Count(logs.String(), "worker cert expired") == 2 })
}

func TestCertClientProxyIDMustMatchTheCertificate(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	logger, _ := certLogger()
	_, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{ProxyID: "someone-else"}, clk, logger)
	if err == nil || !strings.Contains(err.Error(), "central.proxyID") || !strings.Contains(err.Error(), "someone-else") || !strings.Contains(err.Error(), "worker-1") {
		t.Fatalf("err = %v, want one naming central.proxyID and both ids", err)
	}
	// The same id is fine.
	if _, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{ProxyID: "worker-1"}, clk, logger); err != nil {
		t.Fatalf("matching id: %v", err)
	}
}

func TestCertClientUnsetConfigBuildsNothingAndStillSendsTheBearer(t *testing.T) {
	logger, _ := certLogger()
	wc, err := newWorkerCert(context.Background(), config.ControlPlaneConfig{Endpoint: "https://cp.example/policy", TokenEnv: "X"}, config.CentralConfig{}, clocktest.NewFake(certT0), logger)
	if wc != nil || err != nil {
		t.Fatalf("newWorkerCert(no enrollment) = %v, %v, want nil, nil", wc, err)
	}
	var seen atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"allowlist":[{"domain":"a.example"}]}`)
	}))
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// What the worker builds when nothing is enrolled: a provider with no cert client.
	rp, err := config.NewRemoteProvider(srv.URL, "shared-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.SetCACert(caPath); err != nil {
		t.Fatal(err)
	}
	if err := rp.Pull(); err != nil {
		t.Fatal(err)
	}
	if seen.Load() != "Bearer shared-token" {
		t.Errorf("Authorization = %q, want the bearer", seen.Load())
	}
	rp.CloseIdleConnections()
}

func TestCertClientRejectedTokenStopsStartupUnreachableDoesNot(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	logger, _ := certLogger()
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_bad")
	if _, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger); err == nil {
		t.Fatal("a rejected token let the worker start")
	}
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "")
	if _, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger); err == nil || strings.Contains(err.Error(), "wet_") {
		t.Fatalf("no token and no cert: err = %v, want a startup error", err)
	}

	// Unreachable at boot: the worker starts without a certificate (fail-closed)
	// and enrolls in the background once the control plane answers.
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	cp.down.Store(true)
	wc, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger)
	if err != nil || wc == nil || wc.source.Current() != nil {
		t.Fatalf("unreachable at boot: %v, %v", wc, err)
	}
	got, _ := wc.getClientCertificate(nil)
	if len(got.Certificate) != 0 {
		t.Fatal("presented a certificate it does not have")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wc.start(ctx, nil)
	waitFor(t, "the expiry watcher and the enrollment retry timer", func() bool { return clk.PendingTimers() == 2 })
	attempts := len(cp.bearersCopy())
	clk.Advance(5 * time.Second) // retried, still down
	waitFor(t, "the retry", func() bool { return len(cp.bearersCopy()) > attempts })
	cp.down.Store(false)
	waitFor(t, "enrollment once the control plane is back", func() bool {
		clk.Advance(5 * time.Minute)
		return wc.source.Current() != nil
	})
}

func (cp *certCP) bearersCopy() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]string(nil), cp.bearers...)
}

func TestCertClientRenewsOnTheFakeClock(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	logger, _ := certLogger()
	dir := t.TempDir()
	wc, err := newWorkerCert(context.Background(), cp.config(dir), config.CentralConfig{}, clk, logger)
	if err != nil {
		t.Fatal(err)
	}
	before := wc.source.Current()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wc.jitter = func() float64 { return 0 } // otherwise the renewal lands anywhere in 10.8h to 13.2h
	wc.start(ctx, nil)
	waitFor(t, "the renewer to arm", func() bool { return clk.PendingTimers() >= 2 })

	clk.Advance(12 * time.Hour) // exactly half of the 24h lifetime
	waitFor(t, "the renewed certificate", func() bool { return wc.source.Current().Serial() != before.Serial() })
	if cp.renews.Load() < 1 {
		t.Error("no /control/renew request was made")
	}
	rp, err := pollPolicy(t, wc, cp.endpoint())
	if err != nil {
		t.Fatalf("pull with the renewed certificate: %v", err)
	}
	if err := rp.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	cp.mu.Lock()
	last := cp.heartbeats[len(cp.heartbeats)-1]
	cp.mu.Unlock()
	if last["_serial"] != wc.source.Current().Serial() {
		t.Errorf("the heartbeat was sent with serial %v, want the renewed %s", last["_serial"], wc.source.Current().Serial())
	}
	// worker-cert.pem on disk is the renewed certificate.
	disk, err := os.ReadFile(filepath.Join(dir, "cert", "worker-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := workerca.ParseCertsPEM(disk)
	if err != nil || certs[0].SerialNumber.Text(16) != wc.source.Current().Serial() {
		t.Errorf("persisted serial %v (%v), want %s", certs, err, wc.source.Current().Serial())
	}
}

func TestCertClientStaticCertificateIsNotRenewed(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := cp.issue(&key.PublicKey, "static-1", certT0.Add(time.Hour))
	dir := t.TempDir()
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(certPath, workerca.EncodeCertsPEM(leaf, cp.inter), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	logger, _ := certLogger()
	wc, err := newWorkerCert(context.Background(), config.ControlPlaneConfig{Endpoint: cp.endpoint(), CACert: cp.caPath, ClientCert: certPath, ClientKey: keyPath},
		config.CentralConfig{}, clk, logger)
	if err != nil || wc.enroller != nil || wc.WorkerID() != "static-1" {
		t.Fatalf("static cert: %v, %v", wc, err)
	}
	if _, err := pollPolicy(t, wc, cp.endpoint()); err != nil {
		t.Fatalf("pull with an externally issued certificate: %v", err)
	}
}

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

func TestCertClientLocalAndVerificationFailuresStopStartup(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	logger, _ := certLogger()
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")

	// A state dir that cannot be created is not "the control plane is down".
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if wc, err := newWorkerCert(context.Background(), cp.config(filepath.Join(file, "state")), config.CentralConfig{}, clk, logger); err == nil {
		t.Fatalf("an uncreatable stateDir let the worker start: %v", wc)
	}
	// A response that fails verification neither.
	cp.forge.Store(true)
	if _, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger); err == nil {
		t.Fatal("a response for another worker id let the worker start")
	}
}

func TestCertClientBackgroundEnrollmentRefusesAnotherWorkerID(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	logger, logs := certLogger()
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	cp.down.Store(true)
	// central.proxyID names a worker the certificate will not be for.
	wc, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{ProxyID: "expected-id"}, clk, logger)
	if err != nil || wc.source.Current() != nil {
		t.Fatalf("boot with the control plane down: %v", err)
	}
	cp.down.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wc.start(ctx, nil)
	waitFor(t, "the enrollment retry timer", func() bool { return clk.PendingTimers() == 2 })
	waitFor(t, "the refusal", func() bool {
		clk.Advance(5 * time.Second)
		return strings.Contains(logs.String(), "worker certificate refused")
	})
	if wc.source.Current() != nil {
		t.Error("installed a certificate for another id than central.proxyID")
	}
}

func TestCertClientCentralSameOriginGate(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	logger, _ := certLogger()
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	missing := filepath.Join(t.TempDir(), "nope.pem")

	// Same origin: the ingest forwarder presents the certificate and central.caCert
	// joins the shared pool (so an unreadable one is an error).
	same := config.CentralConfig{Mode: "worker", Endpoint: cp.srv.URL + "/central/ingest", CACert: missing}
	if _, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), same, clk, logger); err == nil {
		t.Error("central.caCert was not folded into the shared pool for the same origin")
	}
	same.CACert = cp.caPath
	wc, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), same, clk, logger)
	if err != nil || !wc.centralShared {
		t.Fatalf("same origin: %v, shared %v", err, wc != nil && wc.centralShared)
	}

	// A separate aggregator keeps its bearer client and its own trust.
	other := config.CentralConfig{Mode: "worker", Endpoint: "https://aggregator.example:9443/central/ingest", CACert: missing}
	wc, err = newWorkerCert(context.Background(), cp.config(t.TempDir()), other, clk, logger)
	if err != nil {
		t.Fatalf("a separate aggregator's CA leaked into the control plane trust pool: %v", err)
	}
	if wc.centralShared {
		t.Error("a different origin shares the certificate client")
	}
	// Scheme and port are part of the origin.
	for _, ep := range []string{"http://" + strings.TrimPrefix(cp.srv.URL, "https://") + "/x", strings.Replace(cp.srv.URL, "127.0.0.1:", "127.0.0.1:1", 1) + "/x"} {
		if sameOrigin(cp.endpoint(), ep) {
			t.Errorf("sameOrigin(%s) = true", ep)
		}
	}
}

func TestCertClientLateEnrollmentLabelsIngestWithTheCertificateID(t *testing.T) {
	clk := clocktest.NewFake(certT0)
	cp := newCertCP(t, clk)
	logger, _ := certLogger()
	t.Setenv("WARDEN_TEST_ENROLL_TOKEN", "wet_good")
	cp.down.Store(true)
	wc, err := newWorkerCert(context.Background(), cp.config(t.TempDir()), config.CentralConfig{}, clk, logger)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := analytics.NewHTTPRemoteStore(cp.srv.URL+"/central/ingest", "", wc.WorkerID(), wc.Client(cpClientTimeout))
	if err != nil {
		t.Fatal(err)
	}
	remote.SetProxyIDFunc(wc.WorkerID)
	if wc.WorkerID() != "" {
		t.Fatalf("id before enrollment = %q", wc.WorkerID())
	}
	cp.down.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wc.start(ctx, nil)
	waitFor(t, "the enrollment retry timer", func() bool { return clk.PendingTimers() == 2 })
	waitFor(t, "late enrollment", func() bool {
		clk.Advance(5 * time.Second)
		return wc.source.Current() != nil
	})
	if err := remote.SendBatch([]analytics.Event{{Timestamp: certT0, Domain: "a.example", Port: 443, Decision: "allow"}}); err != nil {
		t.Fatal(err)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.ingestIDs) != 1 || cp.ingestIDs[0] != "worker-1/worker-1" {
		t.Errorf("ingest saw %v, want the late certificate's id in the header", cp.ingestIDs)
	}
}
