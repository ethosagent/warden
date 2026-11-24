package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/workerca"
)

// enrollRig is a control plane Server with the enrollment route mounted on an
// enrollEnv, a recording admin audit and captured logs.
type enrollRig struct {
	*enrollEnv
	srv  *Server
	ts   *httptest.Server
	rec  *fakeRecorder
	slog *syncBuf
}

func newEnrollRig(t *testing.T) *enrollRig {
	t.Helper()
	e := newEnrollEnv(t)
	r := &enrollRig{enrollEnv: e, rec: &fakeRecorder{}, slog: &syncBuf{}}
	r.srv = New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), Clock: e.clk, Logger: slog.New(slog.NewJSONHandler(r.slog, nil)),
		WorkerCAEnabled: true, WorkerCA: e.ca, WorkerCAVerifier: e.ca.Verifier, WorkerCertTTL: 24 * time.Hour,
		Enrollment: e.store, WorkerCerts: e.store,
	})
	r.srv.auditRec = r.rec
	r.ts = httptest.NewServer(r.srv.Handler())
	t.Cleanup(r.ts.Close)
	return r
}

type enrollReply struct {
	status int
	body   string
	header http.Header
}

func (r *enrollRig) post(t *testing.T, body any) enrollReply {
	t.Helper()
	var raw []byte
	switch v := body.(type) {
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	default:
		raw, _ = json.Marshal(v)
	}
	resp, err := http.Post(r.ts.URL+enrollPath, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return enrollReply{resp.StatusCode, string(b), resp.Header}
}

func (r *enrollRig) enroll(t *testing.T, token, suffix string) enrollReply {
	t.Helper()
	return r.post(t, map[string]string{"token": token, "csr": csrPEM(t), "workerIdSuffix": suffix})
}

func TestEnrollIssuesCertificate(t *testing.T) {
	r := newEnrollRig(t)
	pt, tok := r.create(t, EnrollCreateOpts{Name: "n", WorkerID: "worker-1"})
	got := r.enroll(t, pt, "")
	if got.status != http.StatusCreated {
		t.Fatalf("status %d: %s", got.status, got.body)
	}
	if got.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", got.header.Get("Cache-Control"))
	}
	var out enrollResponse
	if err := json.Unmarshal([]byte(got.body), &out); err != nil {
		t.Fatal(err)
	}
	certs, err := workerca.ParseCertsPEM([]byte(out.Certificate))
	if err != nil || len(certs) != 1 {
		t.Fatalf("certificate: %v", err)
	}
	cert := certs[0]
	if out.WorkerID != "worker-1" || out.SpiffeID != "spiffe://"+wcaTrustDomain+"/warden/worker/worker-1" ||
		len(cert.URIs) != 1 || cert.URIs[0].String() != out.SpiffeID || out.Serial != cert.SerialNumber.Text(16) {
		t.Fatalf("response %+v, cert SAN %v", out, cert.URIs)
	}
	if id, err := r.ca.Verify(cert); err != nil || id != "worker-1" {
		t.Fatalf("issued cert does not verify: %q %v", id, err)
	}
	if want := cert.NotAfter.UTC().Format(time.RFC3339); out.NotAfter != want {
		t.Errorf("notAfter %q, want %q", out.NotAfter, want)
	}
	// The chain is the intermediate then the root, and each signed the previous.
	if len(out.Chain) != 2 {
		t.Fatalf("chain has %d certificates", len(out.Chain))
	}
	var chain []*x509.Certificate
	for _, p := range out.Chain {
		cs, err := workerca.ParseCertsPEM([]byte(p))
		if err != nil || len(cs) != 1 {
			t.Fatalf("chain entry: %v", err)
		}
		chain = append(chain, cs[0])
	}
	if !chain[0].Equal(r.fix.inter) || chain[1].CheckSignatureFrom(chain[1]) != nil || chain[0].CheckSignatureFrom(chain[1]) != nil || cert.CheckSignatureFrom(chain[0]) != nil {
		t.Fatal("chain[1] did not sign chain[0], or chain[0] did not sign the certificate")
	}
	rec, err := r.store.Cert(context.Background(), out.Serial)
	if err != nil || rec.IssuedVia != CertIssuedViaEnroll || rec.WorkerID != "worker-1" || rec.EnrollTokenID != tok.ID {
		t.Fatalf("worker_certs row %+v, %v", rec, err)
	}
	rows := r.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	a := rows[0]
	if a.Action != "worker.enrolled" || a.Actor.Sub != "enroll:"+tok.ID || a.TargetRef != "worker:worker-1" || a.Target != "worker_certs" ||
		a.Details["token_id"] != tok.ID || a.Details["serial"] != out.Serial || a.AuthMethod != adminaudit.AuthMethodSystem || a.Outcome != adminaudit.OutcomeOK {
		t.Fatalf("audit row %+v", a)
	}
	if r.srv.EnrollCount(EnrollOutcomeOK) != 1 {
		t.Errorf("ok counter = %d", r.srv.EnrollCount(EnrollOutcomeOK))
	}
	// The worker's cert lives at least a day and is issued for the token's id only.
	if cert.NotAfter.Sub(r.clk.Now()) < 23*time.Hour {
		t.Errorf("cert lifetime %v", cert.NotAfter.Sub(r.clk.Now()))
	}
}

func TestEnrollUniform401(t *testing.T) {
	r := newEnrollRig(t)
	used, _ := r.create(t, EnrollCreateOpts{Name: "used", WorkerID: "w-used"})
	revoked, revTok := r.create(t, EnrollCreateOpts{Name: "rev", WorkerID: "w-rev"})
	expired, _ := r.create(t, EnrollCreateOpts{Name: "exp", WorkerID: "w-exp", TTL: time.Minute})
	if got := r.enroll(t, used, ""); got.status != http.StatusCreated {
		t.Fatalf("first use: %d %s", got.status, got.body)
	}
	if err := r.store.Revoke(context.Background(), revTok.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(time.Hour) // expires the 1m token (and refills the limiters)
	unknown, _ := generateEnrollToken()
	var first enrollReply
	for i, tok := range []string{used, revoked, expired, unknown, "garbage", ""} {
		got := r.enroll(t, tok, "")
		if got.status != http.StatusUnauthorized || got.body != "unauthorized\n" {
			t.Errorf("token #%d: %d %q", i, got.status, got.body)
		}
		if i == 0 {
			first = got
		}
		if got.header.Get("Content-Type") != first.header.Get("Content-Type") || got.header.Get("WWW-Authenticate") != first.header.Get("WWW-Authenticate") {
			t.Errorf("token #%d: headers differ", i)
		}
	}
	if r.srv.EnrollCount(EnrollOutcomeBadToken) != 6 {
		t.Errorf("bad_token counter = %d", r.srv.EnrollCount(EnrollOutcomeBadToken))
	}
	if len(r.rec.inputs()) != 1 {
		t.Errorf("audit rows = %d, want only the one enrollment", len(r.rec.inputs()))
	}
}

func TestEnrollConcurrentSingleUse(t *testing.T) {
	r := newEnrollRig(t)
	pt, _ := r.create(t, EnrollCreateOpts{Name: "once", WorkerID: "worker-1"})
	body := map[string]string{"token": pt, "csr": csrPEM(t)}
	var created, other atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := r.post(t, body)
			switch got.status {
			case http.StatusCreated:
				created.Add(1)
			case http.StatusUnauthorized, http.StatusTooManyRequests:
				other.Add(1)
			default:
				t.Errorf("status %d: %s", got.status, got.body)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 1 || other.Load() != 49 {
		t.Fatalf("201s = %d, others = %d", created.Load(), other.Load())
	}
	if len(r.rec.inputs()) != 1 {
		t.Fatalf("audit rows = %d", len(r.rec.inputs()))
	}
}

func TestEnrollBadRequestLeavesTokenUnused(t *testing.T) {
	r := newEnrollRig(t)
	pt, _ := r.create(t, EnrollCreateOpts{Name: "n", WorkerID: "worker-1"})
	rsaKey := mustRSACSR(t)
	cases := map[string]any{
		"not json":      "{nope",
		"empty csr":     map[string]string{"token": pt, "csr": ""},
		"garbage csr":   map[string]string{"token": pt, "csr": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"},
		"wrong block":   map[string]string{"token": pt, "csr": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
		"rsa key":       map[string]string{"token": pt, "csr": rsaKey},
		"tampered csr":  map[string]string{"token": pt, "csr": tamperedCSR(t)},
		"unknown token": map[string]string{"token": "wet_x", "csr": "nope"},
	}
	for name, body := range cases {
		got := r.post(t, body)
		if got.status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, got.status, got.body)
		}
	}
	if tok, err := r.store.Peek(pt); err != nil || tok.Uses != 0 {
		t.Fatalf("token after bad requests: %+v %v", tok, err)
	}
	if got := r.enroll(t, pt, ""); got.status != http.StatusCreated {
		t.Fatalf("a valid request after the bad ones: %d %s", got.status, got.body)
	}
	// Over 16 KiB.
	big := r.post(t, `{"token":"`+strings.Repeat("a", 17<<10)+`"}`)
	if big.status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", big.status)
	}
	if r.srv.EnrollCount(EnrollOutcomeBadCSR) == 0 {
		t.Error("bad_csr counter did not move")
	}
}

func mustRSACSR(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(testRand{}, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(testRand{}, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// tamperedCSR is a valid CSR with a flipped signature byte.
func tamperedCSR(t *testing.T) string {
	t.Helper()
	blk, _ := pem.Decode([]byte(csrPEM(t)))
	blk.Bytes[len(blk.Bytes)-1] ^= 0xff
	return string(pem.EncodeToMemory(blk))
}

func TestEnrollPrefixPool(t *testing.T) {
	r := newEnrollRig(t)
	pt, _ := r.create(t, EnrollCreateOpts{Name: "pool", WorkerIDPrefix: "pool-a-", MaxUses: 3})
	for _, s := range []string{"h1", "h2", "h3"} {
		got := r.enroll(t, pt, s)
		var out enrollResponse
		_ = json.Unmarshal([]byte(got.body), &out)
		if got.status != http.StatusCreated || out.WorkerID != "pool-a-"+s {
			t.Fatalf("suffix %s: %d %s", s, got.status, got.body)
		}
	}
	if got := r.enroll(t, pt, "h4"); got.status != http.StatusUnauthorized {
		t.Fatalf("fourth: %d", got.status)
	}
	pt2, _ := r.create(t, EnrollCreateOpts{Name: "pool2", WorkerIDPrefix: "pool-b-", MaxUses: 2})
	r.clk.Advance(time.Minute)
	for _, bad := range []string{"../x", "", "a/b"} {
		if got := r.enroll(t, pt2, bad); got.status != http.StatusBadRequest {
			t.Errorf("suffix %q: %d %s", bad, got.status, got.body)
		}
	}
	if tok, err := r.store.Peek(pt2); err != nil || tok.Uses != 0 {
		t.Fatalf("uses after bad suffixes: %+v %v", tok, err)
	}
}

func TestEnrollCADegradedIs503BeforeConsumingTheToken(t *testing.T) {
	r := newEnrollRig(t)
	pt, _ := r.create(t, EnrollCreateOpts{Name: "n", WorkerID: "worker-1"})
	r.srv.SetWorkerCA(nil)
	got := r.enroll(t, pt, "")
	if got.status != http.StatusServiceUnavailable || !strings.Contains(got.body, "ca_unavailable") {
		t.Fatalf("degraded: %d %s", got.status, got.body)
	}
	if tok, err := r.store.Peek(pt); err != nil || tok.Uses != 0 {
		t.Fatalf("token consumed while degraded: %+v %v", tok, err)
	}
	if r.srv.EnrollCount(EnrollOutcomeCAUnavailable) != 1 || len(r.rec.inputs()) != 0 {
		t.Errorf("counter %d, audit %d", r.srv.EnrollCount(EnrollOutcomeCAUnavailable), len(r.rec.inputs()))
	}
	r.srv.SetWorkerCA(r.ca) // the key backend came back: the same token works
	if got := r.enroll(t, pt, ""); got.status != http.StatusCreated {
		t.Fatalf("after recovery: %d %s", got.status, got.body)
	}
}

func TestEnrollRateLimits(t *testing.T) {
	r := newEnrollRig(t)
	unknown, _ := generateEnrollToken()
	var limited int
	for i := range 12 {
		got := r.enroll(t, unknown, "")
		if got.status == http.StatusTooManyRequests {
			limited++
			if got.header.Get("Retry-After") == "" {
				t.Error("no Retry-After")
			}
		} else if i < 10 && got.status != http.StatusUnauthorized {
			t.Fatalf("request %d: %d", i, got.status)
		}
	}
	if limited != 2 {
		t.Fatalf("429s = %d, want 2 (10 per minute per address)", limited)
	}
	r.clk.Advance(time.Minute)
	if got := r.enroll(t, unknown, ""); got.status != http.StatusUnauthorized {
		t.Fatalf("after a minute: %d", got.status)
	}
	if r.srv.EnrollCount(EnrollOutcomeRateLimited) != 2 {
		t.Errorf("rate_limited counter = %d", r.srv.EnrollCount(EnrollOutcomeRateLimited))
	}

	// Per token id: ten different addresses, then the eleventh is limited by the token.
	pt, tok := r.create(t, EnrollCreateOpts{Name: "tok", WorkerID: "w-tok"})
	if err := r.store.Revoke(context.Background(), tok.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	csr := csrPEM(t)
	code := func(addr string) int {
		body, _ := json.Marshal(map[string]string{"token": pt, "csr": csr})
		req := httptest.NewRequest(http.MethodPost, enrollPath, bytes.NewReader(body))
		req.RemoteAddr = addr + ":4000"
		rr := httptest.NewRecorder()
		r.srv.handleEnroll(rr, req)
		return rr.Code
	}
	for i := range 10 {
		if c := code("10.0.0." + string(rune('1'+i))); c != http.StatusUnauthorized {
			t.Fatalf("address %d: %d", i, c)
		}
	}
	if c := code("10.0.1.1"); c != http.StatusTooManyRequests {
		t.Fatalf("eleventh address for one token: %d", c)
	}
}

func TestEnrollAuditFailureRevokesTheCertificate(t *testing.T) {
	r := newEnrollRig(t)
	pt, _ := r.create(t, EnrollCreateOpts{Name: "n", WorkerID: "worker-1"})
	r.rec.set(errors.New("audit is down"), nil)
	got := r.enroll(t, pt, "")
	if got.status != http.StatusInternalServerError || strings.Contains(got.body, "BEGIN CERTIFICATE") {
		t.Fatalf("audit down: %d %s", got.status, got.body)
	}
	var serial string
	var revoked *int64
	if err := r.db.SQL().QueryRow(`SELECT serial, revoked_at FROM worker_certs`).Scan(&serial, &revoked); err != nil || revoked == nil {
		t.Fatalf("the unrecorded certificate was not revoked: %v %v", serial, revoked)
	}
	if strings.Contains(r.slog.String(), "BEGIN") {
		t.Error("log holds PEM")
	}
}

func TestEnrollNotMounted(t *testing.T) {
	e := newEnrollEnv(t)
	base := Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Clock: e.clk}
	off := base // workerCA disabled
	off.Enrollment, off.WorkerCerts = e.store, e.store
	noStore := base // workerCA enabled but no state dir behind it
	noStore.WorkerCAEnabled, noStore.WorkerCA = true, e.ca
	for name, cfg := range map[string]Config{"workerCA disabled": off, "no state": noStore} {
		ts := httptest.NewServer(New(cfg).Handler())
		resp, err := http.Post(ts.URL+enrollPath, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		ts.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", name, resp.StatusCode)
		}
	}
	if (&Server{}).EnrollCount(EnrollOutcomeOK) != 0 {
		t.Error("counter of an unmounted route")
	}
}

func TestEnrollMethodNotAllowed(t *testing.T) {
	r := newEnrollRig(t)
	resp, err := http.Get(r.ts.URL + enrollPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("GET: %d %q", resp.StatusCode, resp.Header.Get("Allow"))
	}
}

func TestEnrollLogsAreRateLimitedAndSecretFree(t *testing.T) {
	r := newEnrollRig(t)
	pt, tok := r.create(t, EnrollCreateOpts{Name: "n", WorkerID: "worker-1"})
	if got := r.enroll(t, pt, ""); got.status != http.StatusCreated {
		t.Fatal(got.body)
	}
	for range 5 { // five reuses from one address: one log line
		r.enroll(t, pt, "")
	}
	out := r.slog.String()
	if n := strings.Count(out, `"worker enroll rejected"`); n != 1 {
		t.Fatalf("rejection lines = %d, want 1\n%s", n, out)
	}
	if !strings.Contains(out, `"reason":"exhausted"`) || !strings.Contains(out, `"token_id":"`+tok.ID+`"`) || !strings.Contains(out, `"remote_addr":"127.0.0.1"`) {
		t.Errorf("rejection line lacks reason, token id or address:\n%s", out)
	}
	r.clk.Advance(2 * time.Minute)
	r.enroll(t, pt, "")
	if n := strings.Count(r.slog.String(), `"worker enroll rejected"`); n != 2 {
		t.Fatalf("after the quiet period: %d lines, want 2", n)
	}
	sum := sha256.Sum256([]byte(pt))
	all := r.slog.String() + r.logs.String()
	for _, secret := range []string{pt, hex.EncodeToString(sum[:]), "CERTIFICATE REQUEST", "BEGIN"} {
		if strings.Contains(all, secret) {
			t.Errorf("logs hold %q", secret[:min(len(secret), 12)])
		}
	}
}

// testRand is crypto/rand.Reader under a name that keeps the RSA helper short.
type testRand struct{}

func (testRand) Read(p []byte) (int, error) { return rand.Read(p) }
