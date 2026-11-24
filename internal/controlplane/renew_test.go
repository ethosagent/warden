package controlplane

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/workerca"
)

// renewReply is a /control/renew response.
type renewReply struct {
	status int
	body   string
	header http.Header
	out    renewResponse
	cert   *x509.Certificate
	key    workerCert
}

// renew posts a CSR for a fresh key to /control/renew presenting leaf, and, on
// a 201, parses the new certificate.
func (c *certEnv) renew(t *testing.T, leaf *x509.Certificate) renewReply {
	t.Helper()
	k, _, csr := newKeyCSR(t)
	rep := c.renewCSR(t, leaf, csr, "")
	if rep.status == http.StatusCreated {
		rep.key = workerCert{cert: rep.cert, key: k}
	}
	return rep
}

func (c *certEnv) renewCSR(t *testing.T, leaf *x509.Certificate, csrPEM, bearer string) renewReply {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	r := httptest.NewRequest(http.MethodPost, renewPath, strings.NewReader(string(body)))
	if leaf != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, r)
	rep := renewReply{status: rec.Code, body: rec.Body.String(), header: rec.Header()}
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &rep.out); err != nil {
			t.Fatal(err)
		}
		certs, err := workerca.ParseCertsPEM([]byte(rep.out.Certificate))
		if err != nil || len(certs) != 1 {
			t.Fatalf("renewed certificate: %v", err)
		}
		rep.cert = certs[0]
	}
	return rep
}

func (c *certEnv) auditActions() []string {
	var out []string
	for _, in := range c.rec.inputs() {
		out = append(out, in.Action)
	}
	return out
}

func TestRenewIssuesNewCertificate(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	c.clk.Advance(time.Hour)
	got := c.renew(t, a.cert)
	if got.status != http.StatusCreated {
		t.Fatalf("renew = %d %s", got.status, got.body)
	}
	if got.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", got.header.Get("Cache-Control"))
	}
	if got.out.PrevSerial != a.serial() || got.out.Serial == a.serial() || got.out.Serial != got.cert.SerialNumber.Text(16) {
		t.Fatalf("serials: prev %q new %q (old %q)", got.out.PrevSerial, got.out.Serial, a.serial())
	}
	if id, err := c.ca.Verify(got.cert); err != nil || id != "worker-1" {
		t.Fatalf("the renewed cert does not verify for worker-1: %q %v", id, err)
	}
	if string(got.cert.RawSubjectPublicKeyInfo) == string(a.cert.RawSubjectPublicKeyInfo) {
		t.Fatal("the renewed certificate kept the key")
	}
	if len(got.out.Chain) != 2 || got.out.SpiffeID != got.cert.URIs[0].String() {
		t.Errorf("response %+v", got.out)
	}
	row, err := c.store.Cert(context.Background(), got.out.Serial)
	if err != nil || row.IssuedVia != CertIssuedViaRenew || row.PrevSerial != a.serial() || row.WorkerID != "worker-1" || row.IssuerKID == "" {
		t.Fatalf("worker_certs row %+v, %v", row, err)
	}
	rows := c.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	if r := rows[0]; r.Action != "worker.renewed" || r.Target != "worker_certs" || r.TargetRef != "worker:worker-1" ||
		r.Details["serial"] != got.out.Serial || r.Details["prev_serial"] != a.serial() || r.Outcome != adminaudit.OutcomeOK {
		t.Fatalf("audit row %+v", r)
	}
	// The new cert authenticates and the old one keeps working until it expires.
	for _, w := range []workerCert{got.key, a} {
		if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusOK {
			t.Errorf("/policy = %d", rec.Code)
		}
	}
	if c.srv.RenewCount(RenewOutcomeOK) != 1 {
		t.Errorf("renew ok counter = %d", c.srv.RenewCount(RenewOutcomeOK))
	}
}

func TestRenewNeedsACertificatePrincipal(t *testing.T) {
	e := newWT(t)
	c := newCertEnv(t, func(cfg *Config) {
		cfg.Token = certTestBearer
		cfg.WorkerTokens = e.store
	})
	tok, _ := e.create(t, "tok", "worker-1")
	_, _, csr := newKeyCSR(t)
	for name, bearer := range map[string]string{"no credential": "", "shared token": certTestBearer, "wwt_ token": tok} {
		if got := c.renewCSR(t, nil, csr, bearer); got.status != http.StatusUnauthorized {
			t.Errorf("%s: renew = %d, want 401", name, got.status)
		}
	}
	// An invalid certificate is a 401 whatever else rides along.
	w := c.issue(t, "worker-1")
	c.clk.Advance(48 * time.Hour)
	if got := c.renewCSR(t, w.cert, csr, certTestBearer); got.status != http.StatusUnauthorized {
		t.Errorf("expired cert + valid bearer: renew = %d, want 401", got.status)
	}
	if c.srv.RenewCount(RenewOutcomeUnauthorized) != 4 {
		t.Errorf("unauthorized renew counter = %d", c.srv.RenewCount(RenewOutcomeUnauthorized))
	}
	if n := len(c.rec.inputs()); n != 0 {
		t.Errorf("%d audit rows for refused renewals", n)
	}
}

func TestRenewRefusesRevokedCert(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	c.revoke(t, a.serial())
	if got := c.renew(t, a.cert); got.status != http.StatusUnauthorized {
		t.Fatalf("renew with a revoked cert = %d, want 401", got.status)
	}
	// Revoked in the database but not yet in this process's index: the renewal
	// transaction still refuses it.
	b := c.issue(t, "worker-2")
	if err := c.store.RevokeCert(context.Background(), b.serial(), "cli", "test"); err != nil {
		t.Fatal(err)
	}
	if got := c.renew(t, b.cert); got.status != http.StatusUnauthorized {
		t.Fatalf("renew with a cert revoked behind the index = %d, want 401", got.status)
	}
	if !strings.Contains(c.logs.String(), "reason=revoked") {
		t.Errorf("no revoked reason logged")
	}
}

func TestRenewUnknownSerialIsRefused(t *testing.T) {
	c := newCertEnv(t)
	_, csr, _ := newKeyCSR(t)
	cert, err := c.ca.Issue(csr, "worker-1", time.Hour) // signed by the CA, never recorded
	if err != nil {
		t.Fatal(err)
	}
	if got := c.renew(t, cert); got.status != http.StatusUnauthorized {
		t.Fatalf("renew of a certificate this database never issued = %d, want 401", got.status)
	}
	if !strings.Contains(c.logs.String(), "unknown_serial") {
		t.Errorf("no unknown_serial reason logged")
	}
}

func TestRenewCSRChecks(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	// The CSR carries the certificate's own key.
	der, err := x509.CreateCertificateRequest(crand.Reader, &x509.CertificateRequest{}, a.key)
	if err != nil {
		t.Fatal(err)
	}
	same := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if got := c.renewCSR(t, a.cert, same, ""); got.status != http.StatusBadRequest || !strings.Contains(got.body, "same_key") {
		t.Fatalf("same-SPKI CSR = %d %s, want 400 same_key", got.status, got.body)
	}
	rsaKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rder, err := x509.CreateCertificateRequest(crand.Reader, &x509.CertificateRequest{}, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaCSR := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: rder}))
	for name, csr := range map[string]string{"garbage": "not a csr", "empty": "", "rsa": rsaCSR} {
		if got := c.renewCSR(t, a.cert, csr, ""); got.status != http.StatusBadRequest {
			t.Errorf("%s CSR = %d, want 400", name, got.status)
		}
	}
	// Refusals issue nothing: the lineage is still just the first certificate.
	if latest, err := c.store.LatestCert(context.Background(), "worker-1"); err != nil || latest.Serial != a.serial() {
		t.Fatalf("latest after refused renewals = %+v, %v", latest, err)
	}
	if len(c.rec.inputs()) != 0 {
		t.Errorf("audit rows for refused renewals")
	}
}

func TestRenewDegradedCAIs503(t *testing.T) {
	c := newCertEnv(t, func(cfg *Config) { cfg.WorkerCA = nil })
	a := c.issue(t, "worker-1")
	got := c.renew(t, a.cert)
	if got.status != http.StatusServiceUnavailable || !strings.Contains(got.body, "ca_unavailable") {
		t.Fatalf("renew with the CA degraded = %d %s, want 503 ca_unavailable", got.status, got.body)
	}
	// Nothing was consumed: once the CA loads, the same cert renews.
	c.srv.SetWorkerCA(c.ca)
	if got := c.renew(t, a.cert); got.status != http.StatusCreated {
		t.Fatalf("renew once the CA loaded = %d %s", got.status, got.body)
	}
}

func TestRenewRateLimitPerWorker(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	first := c.renew(t, a.cert)
	if first.status != http.StatusCreated {
		t.Fatalf("first renew = %d %s", first.status, first.body)
	}
	second := c.renew(t, first.cert)
	if second.status != http.StatusTooManyRequests || second.header.Get("Retry-After") == "" {
		t.Fatalf("second renew inside 10 minutes = %d (Retry-After %q), want 429", second.status, second.header.Get("Retry-After"))
	}
	// Another worker has its own budget.
	if got := c.renew(t, c.issue(t, "worker-2").cert); got.status != http.StatusCreated {
		t.Fatalf("worker-2 renew = %d", got.status)
	}
	c.clk.Advance(renewMinInterval)
	if got := c.renew(t, first.cert); got.status != http.StatusCreated {
		t.Fatalf("renew after the interval = %d %s", got.status, got.body)
	}
	if c.srv.RenewCount(RenewOutcomeRateLimited) != 1 {
		t.Errorf("rate_limited counter = %d", c.srv.RenewCount(RenewOutcomeRateLimited))
	}
}

func TestRenewLineageConflictRevokesWorker(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	other := c.issue(t, "worker-2")
	b := c.renew(t, a.cert)
	if b.status != http.StatusCreated {
		t.Fatalf("renew = %d", b.status)
	}
	// The worker moved on to B (the CP saw it); A is now a copied, superseded key.
	if rec := c.do(http.MethodGet, "/policy", b.cert, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("B /policy = %d", rec.Code)
	}
	c.clk.Advance(time.Minute)
	if got := c.renew(t, a.cert); got.status != http.StatusUnauthorized {
		t.Fatalf("renew from the superseded serial = %d %s, want 401", got.status, got.body)
	}
	for _, w := range []workerCert{a, b.key} {
		if rec := c.do(http.MethodGet, "/policy", w.cert, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("after the conflict, /policy with %s = %d, want 401", w.serial()[:6], rec.Code)
		}
	}
	if rec := c.do(http.MethodGet, "/policy", other.cert, "", ""); rec.Code != http.StatusOK {
		t.Errorf("an unrelated worker = %d, want 200", rec.Code)
	}
	var found bool
	for _, in := range c.rec.inputs() {
		if in.Action == "worker.cert_lineage_conflict" {
			found = true
			if in.TargetRef != "worker:worker-1" || in.Details["serial"] != a.serial() || in.Outcome != adminaudit.OutcomeDenied {
				t.Errorf("conflict audit row %+v", in)
			}
		}
	}
	if !found {
		t.Fatalf("no worker.cert_lineage_conflict audit row among %v", c.auditActions())
	}
	row, err := c.store.Cert(context.Background(), b.out.Serial)
	if err != nil || row.RevokedAt.IsZero() || row.RevokeReason != RevokeReasonLineage {
		t.Fatalf("the successor was not revoked as a lineage conflict: %+v, %v", row, err)
	}
	if c.srv.RenewCount(RenewOutcomeLineageConflict) != 1 {
		t.Errorf("lineage_conflict counter = %d", c.srv.RenewCount(RenewOutcomeLineageConflict))
	}
}

// TestRenewGraceForALostResponse: the worker renewed but never received the
// answer, so the successor was never used; the predecessor may retry, briefly.
func TestRenewGraceForALostResponse(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	b := c.renew(t, a.cert) // B is never used: the response was lost
	if b.status != http.StatusCreated {
		t.Fatalf("renew = %d", b.status)
	}
	c.clk.Advance(time.Minute)
	retry := c.renew(t, a.cert)
	if retry.status != http.StatusCreated || retry.out.PrevSerial != a.serial() {
		t.Fatalf("retry from the predecessor = %d %s, want 201", retry.status, retry.body)
	}
	// Once the successor is seen, the predecessor is a fork.
	if rec := c.do(http.MethodGet, "/policy", retry.cert, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("successor /policy = %d", rec.Code)
	}
	c.clk.Advance(time.Minute)
	if got := c.renew(t, a.cert); got.status != http.StatusUnauthorized {
		t.Fatalf("renew from the predecessor after its successor was seen = %d, want 401", got.status)
	}
	if rec := c.do(http.MethodGet, "/policy", retry.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the worker survived a lineage conflict: %d", rec.Code)
	}
}

func TestRenewGraceIsBounded(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	if got := c.renew(t, a.cert); got.status != http.StatusCreated {
		t.Fatalf("renew = %d", got.status)
	}
	var last int
	for i := 0; i < renewGraceMax+1; i++ {
		last = c.renew(t, a.cert).status // every response lost: the predecessor keeps retrying
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("unbounded grace: last status %d, want 429", last)
	}
}

func TestRenewGraceExpiresAfterTenMinutes(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	if got := c.renew(t, a.cert); got.status != http.StatusCreated {
		t.Fatalf("renew = %d", got.status)
	}
	c.clk.Advance(renewGrace + time.Second)
	if got := c.renew(t, a.cert); got.status != http.StatusUnauthorized {
		t.Fatalf("renew from the predecessor after the grace = %d, want 401", got.status)
	}
}

// TestRenewLineageSkipsFailedIssuances: a certificate revoked as a failed
// issuance never reached the worker, so it is not "the latest serial".
func TestRenewLineageSkipsFailedIssuances(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	ctx := context.Background()
	for _, reason := range []string{RevokeReasonEnrollFailed, RevokeReasonRenewFailed} {
		failed := c.issue(t, "worker-1") // newer than a, but its issuance failed
		if err := c.store.RevokeCert(ctx, failed.serial(), "enroll:et_x", reason); err != nil {
			t.Fatal(err)
		}
		latest, err := c.store.LatestCert(ctx, "worker-1")
		if err != nil || latest.Serial != a.serial() {
			t.Fatalf("latest with a %s row = %+v, %v; want %s", reason, latest, err, a.serial())
		}
	}
	if got := c.renew(t, a.cert); got.status != http.StatusCreated {
		t.Fatalf("renew over failed issuances = %d %s", got.status, got.body)
	}
	// An admin revocation, by contrast, is real history: it stays the latest.
	rev := c.issue(t, "worker-9")
	if err := c.store.RevokeCert(ctx, rev.serial(), "admin", "compromised"); err != nil {
		t.Fatal(err)
	}
	if latest, err := c.store.LatestCert(ctx, "worker-9"); err != nil || latest.Serial != rev.serial() {
		t.Fatalf("an admin-revoked row must stay the latest: %+v, %v", latest, err)
	}
}

func TestRenewAuditFailureRevokesTheNewCertificate(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	c.rec.set(errors.New("audit down"), nil)
	if got := c.renew(t, a.cert); got.status != http.StatusInternalServerError {
		t.Fatalf("renew with the audit log down = %d, want 500", got.status)
	}
	latest, err := c.store.LatestCert(context.Background(), "worker-1")
	if err != nil || latest.Serial != a.serial() {
		t.Fatalf("the unrecorded certificate counts as the latest: %+v, %v", latest, err)
	}
	c.rec.set(nil, nil)
	c.clk.Advance(renewMinInterval)
	if got := c.renew(t, a.cert); got.status != http.StatusCreated {
		t.Fatalf("renew once the audit log is back = %d %s", got.status, got.body)
	}
}

func TestRenewMethodAndBody(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	r := httptest.NewRequest(http.MethodGet, renewPath, nil)
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", rec.Code)
	}
	for name, body := range map[string]string{"not json": "{", "too big": `{"csr":"` + strings.Repeat("a", enrollBodyMax) + `"}`} {
		r := httptest.NewRequest(http.MethodPost, renewPath, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{a.cert}}
		rec := httptest.NewRecorder()
		c.h.ServeHTTP(rec, r)
		want := http.StatusBadRequest
		if name == "too big" {
			want = http.StatusRequestEntityTooLarge
		}
		if rec.Code != want {
			t.Errorf("%s = %d, want %d", name, rec.Code, want)
		}
	}
}

func TestRenewNotMountedWithoutWorkerCA(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com")})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, renewPath, strings.NewReader("{}")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /control/renew without workerCA = %d, want 404", rec.Code)
	}
}

func TestRenewStoreRenewCertDirect(t *testing.T) {
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	ctx := context.Background()
	issue := func(id string) (*x509.Certificate, *x509.Certificate, error) {
		_, csr, _ := newKeyCSR(t)
		cert, err := c.ca.Issue(csr, id, time.Hour)
		return cert, c.ca.Intermediate(), err
	}
	always, never := func(bool) bool { return true }, func(bool) bool { return false }
	unseen := func(string) bool { return false }
	if _, _, err := c.store.RenewCert(ctx, "worker-1", a.serial(), unseen, never, issue); !errors.Is(err, ErrRenewRateLimited) {
		t.Fatalf("admit=false: %v", err)
	}
	if _, _, err := c.store.RenewCert(ctx, "worker-2", a.serial(), unseen, always, issue); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("a serial of another worker: %v", err)
	}
	if _, _, err := c.store.RenewCert(ctx, "worker-1", "ff", unseen, always, issue); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("an unknown serial: %v", err)
	}
	failing := func(string) (*x509.Certificate, *x509.Certificate, error) { return nil, nil, errors.New("sign failed") }
	if _, _, err := c.store.RenewCert(ctx, "worker-1", a.serial(), unseen, always, failing); err == nil {
		t.Fatal("an issue error was swallowed")
	}
	// A failed issue leaves nothing behind.
	if latest, _ := c.store.LatestCert(ctx, "worker-1"); latest.Serial != a.serial() {
		t.Fatalf("latest after a failed issue = %s", latest.Serial)
	}
	// A renewal with no issuer id is refused, not recorded blank.
	noIssuer := func(id string) (*x509.Certificate, *x509.Certificate, error) {
		cert, _, err := issue(id)
		cert.AuthorityKeyId = nil
		return cert, nil, err
	}
	if _, _, err := c.store.RenewCert(ctx, "worker-1", a.serial(), unseen, always, noIssuer); !errors.Is(err, ErrCertNoIssuer) {
		t.Fatalf("no issuer: %v", err)
	}
}
