package controlplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

const certTestBearer = "legacy-shared-token"

// certEnv is a control plane with worker certificate authentication on top of
// an enrollEnv (CA, store, fake clock).
type certEnv struct {
	*enrollEnv
	srv  *Server
	h    http.Handler
	rec  *fakeRecorder
	logs *syncBuf
}

type certOpt func(*Config)

func newCertEnv(t testing.TB, opts ...certOpt) *certEnv {
	t.Helper()
	e := newEnrollEnv(t)
	c := &certEnv{enrollEnv: e, rec: &fakeRecorder{}, logs: &syncBuf{}}
	cfg := Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), Clock: e.clk, Logger: slog.New(slog.NewTextHandler(c.logs, nil)),
		WorkerCAEnabled: true, WorkerCA: e.ca, WorkerCAVerifier: e.ca.Verifier, WorkerCertTTL: 24 * time.Hour,
		Enrollment: e.store, WorkerCerts: e.store, Store: analytics.NewCentralStore(100), TLS: true,
	}
	for _, o := range opts {
		o(&cfg)
	}
	c.srv = New(cfg)
	c.srv.auditRec = c.rec
	c.h = c.srv.Handler()
	return c
}

// workerCert is an issued certificate with its key.
type workerCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (w workerCert) serial() string { return w.cert.SerialNumber.Text(16) }

func newKeyCSR(t testing.TB) (*ecdsa.PrivateKey, *x509.CertificateRequest, string) {
	t.Helper()
	k, err := wcasigner.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return k, csr, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// issue enrolls workerID the way /control/enroll does: a certificate from the
// CA and its worker_certs row, then waits for nothing (the index only holds
// revocations).
func (c *certEnv) issue(t testing.TB, workerID string) workerCert {
	t.Helper()
	k, csr, _ := newKeyCSR(t)
	cert, err := c.ca.Issue(csr, workerID, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.RecordCert(context.Background(), RecordFor(cert, c.ca.Intermediate(), workerID, CertIssuedViaEnroll, c.clk.Now())); err != nil {
		t.Fatal(err)
	}
	return workerCert{cert: cert, key: k}
}

// revoke revokes one serial and reloads the index.
func (c *certEnv) revoke(t testing.TB, serial string) {
	t.Helper()
	if err := c.store.RevokeCert(context.Background(), serial, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if err := c.srv.certIdx.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// do sends a request that presents leaf (nil: no client certificate) and the
// bearer and proxy id header given, straight to the handler.
func (c *certEnv) do(method, path string, leaf *x509.Certificate, bearer, proxyID string) *httptest.ResponseRecorder {
	body := ""
	switch path {
	case "/central/ingest":
		body = `{"events":[{"type":"allow","host":"api.openai.com"}]}`
	case "/control/heartbeat":
		body = `{"policyETag":"x"}`
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if leaf != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if proxyID != "" {
		r.Header.Set(analytics.ProxyIDHeader, proxyID)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, r)
	return rec
}

// signed mints a certificate from tmpl under parent/parentKey for a fresh key.
func signed(t testing.TB, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) workerCert {
	t.Helper()
	k, err := wcasigner.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return workerCert{cert: c, key: k}
}

func leafTemplate(c *certEnv, id string, usage x509.ExtKeyUsage, td string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: c.clk.Now().Add(-time.Minute), NotAfter: c.clk.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, BasicConstraintsValid: true,
		URIs: []*url.URL{{Scheme: "spiffe", Host: td, Path: "/warden/worker/" + id}},
	}
}

var certRoutes = []struct {
	method, path string
	ok           int
}{
	{http.MethodGet, "/policy", http.StatusOK},
	{http.MethodPost, "/control/heartbeat", http.StatusNoContent},
	{http.MethodPost, "/central/ingest", http.StatusNoContent},
}

func TestWorkerCertAuthAcceptsOnThreeRoutes(t *testing.T) {
	c := newCertEnv(t)
	w := c.issue(t, "worker-1")
	for _, rt := range certRoutes {
		if rec := c.do(rt.method, rt.path, w.cert, "", ""); rec.Code != rt.ok {
			t.Errorf("%s with a valid cert = %d %s, want %d", rt.path, rec.Code, rec.Body.String(), rt.ok)
		}
	}
	// The identity is the SAN's: the registry, the ingest store and the fleet
	// view all say worker-1, authenticated as cert.
	evs, err := c.srv.central.GetEvents(analytics.EventFilter{})
	if err != nil || len(evs) != 1 || evs[0].ProxyID != "worker-1" {
		t.Fatalf("ingested events %v, %v", evs, err)
	}
	views := c.srv.registry.Views()
	if len(views) != 1 || views[0].ProxyID != "worker-1" || views[0].AuthKind != "cert" ||
		views[0].CertSerial != w.serial() || views[0].CertNotAfter != w.cert.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("fleet view %+v", views)
	}
	if got := c.srv.workerAuth.Count(KindCert, "ok"); got != int64(len(certRoutes)) {
		t.Errorf("auth counter kind=cert outcome=ok = %d, want %d", got, len(certRoutes))
	}
}

func TestWorkerCertAuthRejectsBadCerts(t *testing.T) {
	c := newCertEnv(t, func(cfg *Config) { cfg.Token = certTestBearer })
	good := c.issue(t, "worker-1")

	other := newWCAFixture(t, c.clk.Now())
	otherCA, err := workerca.New(workerca.Options{Chain: []*x509.Certificate{other.inter, other.root}, Signer: other.interKey,
		Create: wcasigner.CreateCertificate, Serial: wcasigner.NewSerial, TrustDomain: wcaTrustDomain, Clock: c.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	_, csr, _ := newKeyCSR(t)
	fromOtherCA, err := otherCA.Issue(csr, "worker-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// A certificate from the proxy MITM CA carrying a perfect worker SAN.
	proxyRoot, proxyKey, err := wcasigner.NewRoot(c.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	fromProxyCA := signed(t, leafTemplate(c, "worker-1", x509.ExtKeyUsageClientAuth, wcaTrustDomain), proxyRoot, proxyKey)
	serverAuthOnly := signed(t, leafTemplate(c, "worker-1", x509.ExtKeyUsageServerAuth, wcaTrustDomain), c.fix.inter, c.fix.interKey)
	otherDomain := signed(t, leafTemplate(c, "worker-1", x509.ExtKeyUsageClientAuth, "evil.example"), c.fix.inter, c.fix.interKey)
	noSAN := leafTemplate(c, "worker-1", x509.ExtKeyUsageClientAuth, wcaTrustDomain)
	noSAN.URIs, noSAN.DNSNames = nil, []string{"worker-1.example"}
	dnsOnly := signed(t, noSAN, c.fix.inter, c.fix.interKey)
	twoSANs := leafTemplate(c, "worker-1", x509.ExtKeyUsageClientAuth, wcaTrustDomain)
	twoSANs.URIs = append(twoSANs.URIs, &url.URL{Scheme: "spiffe", Host: wcaTrustDomain, Path: "/warden/worker/worker-2"})
	multi := signed(t, twoSANs, c.fix.inter, c.fix.interKey)

	cases := []struct {
		name   string
		cert   *x509.Certificate
		reason string
	}{
		{"another worker CA", fromOtherCA, "bad_chain"},
		{"the proxy CA", fromProxyCA.cert, "bad_chain"},
		{"serverAuth only", serverAuthOnly.cert, "bad_eku"},
		{"another trust domain", otherDomain.cert, "bad_chain"},
		{"a DNS SAN and no worker URI", dnsOnly.cert, "bad_san"},
		{"two URI SANs", multi.cert, "bad_san"},
	}
	for _, tc := range cases {
		for _, rt := range certRoutes {
			// A valid bearer rides along: it must never rescue a bad certificate.
			if rec := c.do(rt.method, rt.path, tc.cert, certTestBearer, ""); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s: %s = %d, want 401 (no fallback to the bearer)", tc.name, rt.path, rec.Code)
			}
		}
		if !strings.Contains(c.logs.String(), "reason="+tc.reason) {
			t.Errorf("%s: no rejection log with reason=%s in %s", tc.name, tc.reason, c.logs.String())
		}
		c.clk.Advance(2 * time.Minute) // past the per-(reason,host) log quiet period
	}
	if got := c.srv.workerAuth.Count(KindCert, "unauthorized"); got != int64(len(cases)*len(certRoutes)) {
		t.Errorf("unauthorized counter = %d", got)
	}
	if ids := c.srv.registry.Views(); len(ids) != 0 {
		t.Fatalf("a rejected certificate registered workers %+v", ids)
	}

	// Expired: the same good certificate, after its day.
	c.clk.Advance(25 * time.Hour)
	for _, rt := range certRoutes {
		if rec := c.do(rt.method, rt.path, good.cert, certTestBearer, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("expired cert: %s = %d, want 401", rt.path, rec.Code)
		}
	}
	if !strings.Contains(c.logs.String(), "reason=expired") {
		t.Errorf("no reason=expired rejection logged")
	}
	if strings.Contains(c.logs.String(), certTestBearer) {
		t.Errorf("the log carries the bearer")
	}
}

func TestWorkerCertAuthProxyIDBinding(t *testing.T) {
	c := newCertEnv(t)
	w := c.issue(t, "worker-1")
	for _, rt := range certRoutes {
		rec := c.do(rt.method, rt.path, w.cert, "", "worker-2")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "proxy id mismatch") {
			t.Errorf("%s with header worker-2 = %d %q, want 403 proxy id mismatch", rt.path, rec.Code, rec.Body.String())
		}
	}
	if got := c.srv.registry.Views(); len(got) != 0 {
		t.Fatalf("a mismatched request registered workers %+v", got)
	}
	for _, rt := range certRoutes {
		if rec := c.do(rt.method, rt.path, w.cert, "", "worker-1"); rec.Code != rt.ok {
			t.Errorf("%s with the matching header = %d", rt.path, rec.Code)
		}
	}
	// A second header value that names another worker is refused too.
	r := httptest.NewRequest(http.MethodGet, "/policy", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{w.cert}}
	r.Header.Add(analytics.ProxyIDHeader, "worker-1")
	r.Header.Add(analytics.ProxyIDHeader, "worker-2")
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("two header values = %d, want 403", rec.Code)
	}
	if got := c.srv.workerAuth.Count(KindCert, "forbidden"); got != int64(len(certRoutes)+1) {
		t.Errorf("forbidden counter = %d", got)
	}
}

func TestWorkerCertAuthRevocationIsPerRequest(t *testing.T) {
	c := newCertEnv(t)
	w1, w2 := c.issue(t, "worker-1"), c.issue(t, "worker-2")
	for _, w := range []workerCert{w1, w2} {
		if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusOK {
			t.Fatalf("before revoke = %d", rec.Code)
		}
	}
	c.revoke(t, w1.serial())
	for _, rt := range certRoutes {
		if rec := c.do(rt.method, rt.path, w1.cert, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("revoked: %s = %d, want 401", rt.path, rec.Code)
		}
		if rec := c.do(rt.method, rt.path, w2.cert, "", ""); rec.Code != rt.ok {
			t.Errorf("unrelated worker: %s = %d, want %d", rt.path, rec.Code, rt.ok)
		}
	}
	if !strings.Contains(c.logs.String(), "reason=revoked") || !strings.Contains(c.logs.String(), "serial="+w1.serial()) {
		t.Errorf("revoked rejection not logged with the serial: %s", c.logs.String())
	}
}

// failingCerts wraps a WorkerCertStore so its index queries can fail.
type failingCerts struct {
	WorkerCertStore
	mu   sync.Mutex
	fail bool
}

func (f *failingCerts) setFail(v bool) { f.mu.Lock(); f.fail = v; f.mu.Unlock() }
func (f *failingCerts) failing() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.fail }
func (f *failingCerts) RevokedCerts(ctx context.Context, t time.Time) ([]RevokedCert, error) {
	if f.failing() {
		return nil, errors.New("disk on fire")
	}
	return f.WorkerCertStore.RevokedCerts(ctx, t)
}

func TestWorkerCertAuthIndexFailsClosedThenKeepsLastGood(t *testing.T) {
	var fc *failingCerts
	c := newCertEnv(t, func(cfg *Config) {
		fc = &failingCerts{WorkerCertStore: cfg.WorkerCerts, fail: true}
		cfg.WorkerCerts = fc
	})
	// Not loaded at startup: revocation is unknowable, so no certificate is good.
	w := c.issue(t, "worker-1")
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("with no revocation index = %d, want 401", rec.Code)
	}
	if !strings.Contains(c.logs.String(), "revocation_unavailable") {
		t.Errorf("no revocation_unavailable reason logged")
	}
	fc.setFail(false)
	if err := c.srv.certIdx.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("with the index loaded = %d", rec.Code)
	}
	// A later failed reload keeps the last good index, revocations included.
	c.revoke(t, w.serial())
	fc.setFail(true)
	if err := c.srv.certIdx.Rebuild(context.Background()); err == nil {
		t.Fatal("rebuild did not fail")
	}
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked cert after a failed reload = %d, want 401", rec.Code)
	}
}

func TestWorkerCertAuthIndexPollsDataVersion(t *testing.T) {
	c := newCertEnv(t)
	w := c.issue(t, "worker-1")
	// Another process (the offline CLI) revokes through its own connection.
	other, err := openStateForTest(t, c.path, c.clk)
	if err != nil {
		t.Fatal(err)
	}
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("before = %d", rec.Code)
	}
	if err := other.RevokeCert(context.Background(), w.serial(), "cli", "test"); err != nil {
		t.Fatal(err)
	}
	c.srv.certIdx.tick(context.Background())
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after another process revoked = %d, want 401", rec.Code)
	}
}

func TestWorkerCertAuthSwapsPinnedIntermediate(t *testing.T) {
	c := newCertEnv(t)
	w := c.issue(t, "worker-1")
	other := newWCAFixture(t, c.clk.Now())
	v, err := workerca.NewVerifier(workerca.Options{Chain: []*x509.Certificate{other.inter, other.root}, TrustDomain: wcaTrustDomain, Clock: c.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("before the swap = %d", rec.Code)
	}
	c.srv.workerAuth.SetVerifier(v) // the cached verification must not outlive the pool
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after pinning another intermediate = %d, want 401", rec.Code)
	}
	c.srv.workerAuth.SetVerifier(c.ca.Verifier)
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("after pinning it back = %d", rec.Code)
	}
}

// TestWorkerCertAuthDegradedCAStillAuthenticates: certificate authentication
// uses the startup verifier, so a CA whose key has not loaded (no issuing CA)
// still authenticates workers it already certified.
func TestWorkerCertAuthDegradedCAStillAuthenticates(t *testing.T) {
	c := newCertEnv(t, func(cfg *Config) { cfg.WorkerCA = nil })
	if !c.srv.WorkerCADegraded() {
		t.Fatal("the CA is not degraded")
	}
	w := c.issue(t, "worker-1")
	for _, rt := range certRoutes {
		if rec := c.do(rt.method, rt.path, w.cert, "", ""); rec.Code != rt.ok {
			t.Errorf("degraded CA: %s = %d, want %d", rt.path, rec.Code, rt.ok)
		}
	}
}

func TestWorkerCertAuthWithoutStoreRefusesCerts(t *testing.T) {
	c := newCertEnv(t, func(cfg *Config) { cfg.WorkerCerts, cfg.Enrollment = nil, nil })
	w := c.issue(t, "worker-1")
	if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a cert with no certificate store = %d, want 401", rec.Code)
	}
}

// TestWorkerCertAuthHandshakeAcceptsAnyCert proves the listener only requests
// a client certificate: an expired and a foreign certificate complete the TLS
// handshake and are answered with a uniform HTTP 401.
func TestWorkerCertAuthHandshakeAcceptsAnyCert(t *testing.T) {
	c := newCertEnv(t)
	good := c.issue(t, "worker-1")
	ts := httptest.NewUnstartedServer(c.h)
	ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	get := func(cert *tls.Certificate) (int, error) {
		tr := ts.Client().Transport.(*http.Transport).Clone()
		if cert != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr}).Get(ts.URL + "/policy")
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}
	pair := func(w workerCert) *tls.Certificate {
		return &tls.Certificate{Certificate: [][]byte{w.cert.Raw}, PrivateKey: w.key}
	}
	if st, err := get(pair(good)); err != nil || st != http.StatusOK {
		t.Fatalf("valid cert over TLS = %d, %v", st, err)
	}
	root, rootKey, err := wcasigner.NewRoot(c.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	foreign := signed(t, leafTemplate(c, "worker-1", x509.ExtKeyUsageClientAuth, wcaTrustDomain), root, rootKey)
	if st, err := get(pair(foreign)); err != nil || st != http.StatusUnauthorized {
		t.Fatalf("a certificate from another CA over TLS = %d, %v; want a 401, not a handshake failure", st, err)
	}
	// A client with no certificate at all connects too (bearer workers, humans).
	if st, err := get(nil); err != nil || st != http.StatusOK { // open mode, no token configured
		t.Fatalf("no cert over TLS = %d, %v", st, err)
	}
	c.clk.Advance(48 * time.Hour)
	if st, err := get(pair(good)); err != nil || st != http.StatusUnauthorized {
		t.Fatalf("expired cert over TLS = %d, %v; want a 401, not a handshake failure", st, err)
	}
}

func TestWorkerAuthModesWithCerts(t *testing.T) {
	modes := []struct {
		name string
		cfg  func(*Config)
		// want is the status of GET /policy per credential.
		cert, token, legacy, none int
	}{
		{"open", func(*Config) {}, 200, 200, 200, 200},
		{"mixed", func(c *Config) { c.Token = certTestBearer }, 200, 200, 200, 401},
		{"strict tokens", func(c *Config) { c.RequireWorkerTokens = true }, 200, 200, 401, 401},
		{"strict certs", func(c *Config) { c.RequireWorkerCerts = true }, 200, 401, 401, 401},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			e := newWT(t)
			c := newCertEnv(t, m.cfg, func(cfg *Config) { cfg.WorkerTokens = e.store })
			w := c.issue(t, "worker-1")
			tok, _ := e.create(t, "tok", "worker-1")
			check := func(name string, leaf *x509.Certificate, bearer string, want int) {
				t.Helper()
				// An open control plane takes the unauthenticated request; the
				// wwt_ token is "unknown" to a mode that has no token store.
				if rec := c.do(http.MethodGet, "/policy", leaf, bearer, ""); rec.Code != want {
					t.Errorf("%s = %d, want %d", name, rec.Code, want)
				}
			}
			check("cert", w.cert, "", m.cert)
			check("wwt_ token", nil, tok, m.token)
			check("shared token", nil, certTestBearer, m.legacy)
			check("no credential", nil, "", m.none)
		})
	}
}

func TestWorkerAuthStrictCertsLogsMode(t *testing.T) {
	c := newCertEnv(t, func(cfg *Config) { cfg.RequireWorkerCerts = true })
	if !strings.Contains(c.logs.String(), "auth_mode=strict-certs") {
		t.Fatalf("startup log has no auth_mode=strict-certs: %s", c.logs.String())
	}
}

func TestWorkerAuthStrictCertsRejectsEveryBearerEvenWithValidCertAbsent(t *testing.T) {
	c := newCertEnv(t, func(cfg *Config) { cfg.RequireWorkerCerts = true })
	for _, rt := range certRoutes {
		if rec := c.do(rt.method, rt.path, nil, "wwt_"+strings.Repeat("a", 52), ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with a token in strict-certs = %d, want 401", rt.path, rec.Code)
		}
	}
	if !strings.Contains(c.logs.String(), "worker_cert_required") {
		t.Errorf("no worker_cert_required reason logged")
	}
}

func TestCentralSecretsRejectsWorkerCert(t *testing.T) {
	c := newCertEnv(t, func(cfg *Config) {
		cfg.SecretStore = secrets.NewEchoStore()
		cfg.AdminToken, cfg.RequireAdminToken = "admin-secret", true
	})
	w := c.issue(t, "worker-1")
	for _, m := range []struct{ method, path string }{
		{http.MethodGet, "/central/secrets"},
		{http.MethodPost, "/central/secrets"},
		{http.MethodDelete, "/central/secrets/some-key"},
	} {
		if rec := c.do(m.method, m.path, w.cert, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with only a worker cert = %d, want 401", m.method, m.path, rec.Code)
		}
	}
	// The cert never substitutes for the admin credential, nor adds to it.
	if rec := c.do(http.MethodGet, "/central/secrets", nil, "admin-secret", ""); rec.Code != http.StatusOK {
		t.Errorf("admin bearer = %d, want 200", rec.Code)
	}
	if rec := c.do(http.MethodGet, "/central/secrets", w.cert, "wrong", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("worker cert plus a wrong bearer = %d, want 401", rec.Code)
	}
	// The dashboard never consults the client certificate: the admin bearer
	// works without one and a cert alone is no write credential.
	if rec := c.do(http.MethodPost, "/dashboard/api/policy", w.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("dashboard write with only a cert = %d, want 401", rec.Code)
	}
}

// openDevSecrets: even a development control plane with no admin token at all
// (everything on /central/secrets passes) refuses a request that carries only
// a worker certificate.
func TestCentralSecretsOpenDevRefusesBareWorkerCert(t *testing.T) {
	c := newCertEnv(t, func(cfg *Config) { cfg.SecretStore = secrets.NewEchoStore() })
	w := c.issue(t, "worker-1")
	if rec := c.do(http.MethodGet, "/central/secrets", w.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET with only a worker cert on an open dev control plane = %d, want 401", rec.Code)
	}
}

func TestWorkerCertAuthHeldPolicyCancelledOnRevoke(t *testing.T) {
	c := newCertEnv(t)
	w := c.issue(t, "worker-1")
	rec := c.do(http.MethodGet, "/policy", w.cert, "", "")
	etag := strings.Trim(rec.Header().Get("ETag"), `"`)
	out := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/policy?wait=30s", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{w.cert}}
		r.Header.Set("If-None-Match", `"`+etag+`"`)
		rr := httptest.NewRecorder()
		c.h.ServeHTTP(rr, r)
		out <- rr
	}()
	key := certCancelKey(w.serial())
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.srv.workerAuth.cancelMu.Lock()
		parked := c.srv.workerAuth.cancels[key] != nil
		c.srv.workerAuth.cancelMu.Unlock()
		if parked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the long-poll never parked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.revoke(t, w.serial())
	select {
	case rr := <-out:
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("held poll after revoke = %d, want 401", rr.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("the held long-poll was not cancelled by the revocation")
	}
}

func TestWorkerCertReauthenticateExpiry(t *testing.T) {
	c := newCertEnv(t)
	w := c.issue(t, "worker-1")
	p := WorkerPrincipal{Kind: KindCert, ProxyID: "worker-1", CertSerial: w.serial(), NotAfter: w.cert.NotAfter}
	if err := c.srv.workerAuth.Reauthenticate(p); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	c.clk.Advance(25 * time.Hour)
	if err := c.srv.workerAuth.Reauthenticate(p); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestWorkerCertAuthMetricsAndLogsHaveNoCertificateBytes(t *testing.T) {
	c := newCertEnv(t)
	w := c.issue(t, "worker-1")
	c.revoke(t, w.serial())
	c.do(http.MethodGet, "/policy", w.cert, "", "")
	logs := c.logs.String()
	for _, bad := range []string{"BEGIN CERTIFICATE", "PRIVATE KEY"} {
		if strings.Contains(logs, bad) {
			t.Errorf("log carries %q", bad)
		}
	}
	if !bytes.Contains([]byte(logs), []byte("worker auth rejected")) {
		t.Errorf("no rejection line")
	}
}

// BenchmarkWorkerCertAuthenticate is the hot path: a cached certificate
// verification plus the revoked-index read, with no database access.
func BenchmarkWorkerCertAuthenticate(b *testing.B) {
	c := newCertEnv(b)
	w := c.issue(b, "worker-1")
	r := httptest.NewRequest(http.MethodGet, "/policy", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{w.cert}}
	a := c.srv.workerAuth
	if _, err := a.Authenticate(r); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Authenticate(r); err != nil {
			b.Fatal(err)
		}
	}
}

// openStateForTest opens a second store on the same database file, the way the
// offline CLI would in another process.
func openStateForTest(t testing.TB, path string, clk clock.Clock) (*EnrollmentStore, error) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), path, StateMigrations())
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewEnrollmentStore(db, EnrollmentOptions{Clock: clk})
}
