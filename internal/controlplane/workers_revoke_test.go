package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/dashboard"
)

// stubWorkerCerts is a WorkerCertAdmin whose every call succeeds; it lets a
// test reach the revoke route without a certificate store.
type stubWorkerCerts struct{}

func (stubWorkerCerts) Revoke(context.Context, string, string) (int, error) { return 1, nil }

// TestWorkerCertRevoke covers the store (by worker and by serial, idempotence,
// the not-found errors, the renewal refusal) and the console adapter: the index
// is synced at once, the held long-poll returns 401 within a second and the
// counter rises.
func TestWorkerCertRevoke(t *testing.T) {
	ctx := context.Background()
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	b := c.issue(t, "worker-2")

	if _, err := c.store.RevokeWorker(ctx, "nobody", "admin", RevokeReasonAdmin); !errors.Is(err, ErrWorkerNotFound) || !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("RevokeWorker(unknown) = %v, want ErrWorkerNotFound", err)
	}
	// A serial of another worker is not found, and revokes nothing.
	if _, err := c.store.RevokeWorkerSerial(ctx, "worker-1", b.serial(), "admin", RevokeReasonAdmin); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("RevokeWorkerSerial(foreign serial) = %v, want ErrCertNotFound", err)
	}
	if rec, err := c.store.Cert(ctx, b.serial()); err != nil || !rec.RevokedAt.IsZero() {
		t.Fatalf("worker-2's row after a foreign revoke = %+v, %v", rec, err)
	}
	got, err := c.store.RevokeWorkerSerial(ctx, "worker-1", a.serial(), "admin", RevokeReasonAdmin)
	if err != nil || len(got) != 1 || got[0] != a.serial() {
		t.Fatalf("RevokeWorkerSerial = %v, %v", got, err)
	}
	// Idempotent: nothing more to revoke, no error, the first revoker kept.
	if got, err := c.store.RevokeWorkerSerial(ctx, "worker-1", a.serial(), "other", RevokeReasonAdmin); err != nil || len(got) != 0 {
		t.Fatalf("second RevokeWorkerSerial = %v, %v, want none", got, err)
	}
	if got, err := c.store.RevokeWorker(ctx, "worker-1", "other", RevokeReasonAdmin); err != nil || len(got) != 0 {
		t.Fatalf("RevokeWorker after the serial = %v, %v, want none", got, err)
	}
	if rec, _ := c.store.Cert(ctx, a.serial()); rec.RevokedBy != "admin" || rec.RevokeReason != RevokeReasonAdmin || rec.RevokedAt.IsZero() {
		t.Errorf("revoked row = %+v", rec)
	}
	// A renewal from a revoked serial is refused.
	if _, _, err := c.store.RenewCert(ctx, "worker-1", a.serial(), "newspki", func(string) bool { return false }, func(bool) bool { return true },
		func(string) (*x509.Certificate, *x509.Certificate, error) {
			return nil, nil, errors.New("must not issue")
		}); !errors.Is(err, ErrCertRevoked) {
		t.Errorf("RenewCert from a revoked serial = %v, want ErrCertRevoked", err)
	}
	if _, err := c.store.RevokeWorker(ctx, "worker-2", "", RevokeReasonAdmin); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("RevokeWorker with no actor = %v, want ErrInvalidInput", err)
	}
	if _, err := c.store.RevokeWorkerSerial(ctx, "worker-2", b.serial(), "", RevokeReasonAdmin); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("RevokeWorkerSerial with no actor = %v, want ErrInvalidInput", err)
	}
}

func TestWorkerCertRevokeAdapter(t *testing.T) {
	c := newCertEnv(t)
	a, b := c.issue(t, "worker-1"), c.issue(t, "worker-2")
	adm := workerCertAdmin{s: c.srv}
	admin := WithPrincipal(context.Background(), Principal{Sub: "ada"})

	// No console identity: refused, nothing revoked.
	if _, err := adm.Revoke(context.Background(), "worker-1", ""); !errors.Is(err, dashboard.ErrWorkerCertNoActor) {
		t.Fatalf("Revoke without a principal = %v, want ErrWorkerCertNoActor", err)
	}
	if _, err := adm.Revoke(admin, "worker-1", "not hex!"); !errors.Is(err, dashboard.ErrWorkerCertInvalid) {
		t.Fatalf("Revoke with a bad serial = %v, want ErrWorkerCertInvalid", err)
	}
	if _, err := adm.Revoke(admin, "nobody", ""); !errors.Is(err, dashboard.ErrWorkerCertNotFound) {
		t.Fatalf("Revoke(unknown) = %v, want ErrWorkerCertNotFound", err)
	}
	if rec := c.do(http.MethodGet, "/policy", a.cert, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("/policy before = %d", rec.Code)
	}
	etag := strings.Trim(c.do(http.MethodGet, "/policy", a.cert, "", "").Header().Get("ETag"), `"`)
	held := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/policy?wait=30s", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{a.cert}}
		r.Header.Set("If-None-Match", `"`+etag+`"`)
		rr := httptest.NewRecorder()
		c.h.ServeHTTP(rr, r)
		held <- rr
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.srv.workerAuth.cancelMu.Lock()
		parked := c.srv.workerAuth.cancels[certCancelKey(a.serial())] != nil
		c.srv.workerAuth.cancelMu.Unlock()
		if parked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the long-poll never parked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Uppercase hex is accepted, and the write needs no poll to take effect.
	n, err := adm.Revoke(admin, "worker-1", strings.ToUpper(a.serial()))
	if err != nil || n != 1 {
		t.Fatalf("Revoke = %d, %v, want 1", n, err)
	}
	select {
	case rr := <-held:
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("held poll after revoke = %d, want 401", rr.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("the held long-poll was not cut by the revocation")
	}
	if rec := c.do(http.MethodGet, "/policy", a.cert, "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("/policy with the revoked cert = %d, want 401", rec.Code)
	}
	if rec := c.do(http.MethodGet, "/policy", b.cert, "", ""); rec.Code != http.StatusOK {
		t.Errorf("/policy of another worker = %d, want 200", rec.Code)
	}
	if got := c.srv.CertRevokedCount(); got != 1 {
		t.Errorf("CertRevokedCount = %d, want 1", got)
	}
	if !strings.Contains(c.logs.String(), "worker certs revoked") {
		t.Errorf("no `worker certs revoked` log line: %s", c.logs.String())
	}
	// Repeat: 0, still no error.
	if n, err := adm.Revoke(admin, "worker-1", ""); err != nil || n != 0 {
		t.Errorf("repeat Revoke = %d, %v, want 0", n, err)
	}
}

// TestWorkerCertPrune: rows go 30 days after not_after, a revoked certificate
// stays in the index until it expires, and nothing unexpired is deleted.
func TestWorkerCertPrune(t *testing.T) {
	ctx := context.Background()
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	if _, err := c.store.RevokeWorker(ctx, "worker-1", "admin", RevokeReasonAdmin); err != nil {
		t.Fatal(err)
	}
	idx := newCertIndex(c.store, c.clk, slog.New(slog.DiscardHandler))
	if err := idx.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if idx.Len() != 1 {
		t.Fatalf("index after the revoke holds %d, want 1", idx.Len())
	}
	notAfter := a.cert.NotAfter
	// A revoked certificate that has not expired is never pruned, whatever the cutoff says.
	if n, err := c.store.PruneCerts(ctx, notAfter.Add(-time.Second)); err != nil || n != 0 {
		t.Fatalf("PruneCerts before not_after = %d, %v, want 0", n, err)
	}
	// Expired but inside the retention: kept. The index drops it at expiry.
	c.clk.Advance(notAfter.Sub(c.clk.Now()) + time.Minute)
	if err := idx.Rebuild(ctx); err != nil || idx.Len() != 0 {
		t.Fatalf("index after not_after holds %d (%v), want 0", idx.Len(), err)
	}
	if n, err := c.store.PruneCerts(ctx, c.clk.Now().Add(-certRetention)); err != nil || n != 0 {
		t.Fatalf("PruneCerts inside the retention = %d, %v, want 0", n, err)
	}
	// Past it: deleted.
	c.clk.Advance(certRetention)
	if n, err := c.store.PruneCerts(ctx, c.clk.Now().Add(-certRetention)); err != nil || n != 1 {
		t.Fatalf("PruneCerts past the retention = %d, %v, want 1", n, err)
	}
	if _, err := c.store.Cert(ctx, a.serial()); !errors.Is(err, ErrCertNotFound) {
		t.Errorf("row after the prune = %v, want ErrCertNotFound", err)
	}
}

// TestWorkerCertPruneKeepsPredecessors: the row a surviving certificate names
// as prev_serial stays, so the key-reuse walk and the lineage chain are whole.
func TestWorkerCertPruneKeepsPredecessors(t *testing.T) {
	ctx := context.Background()
	c := newCertEnv(t)
	first := c.issue(t, "worker-1")
	c.clk.Advance(23 * time.Hour)
	_, csr, _ := newKeyCSR(t)
	cert, err := c.ca.Issue(csr, "worker-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rec := RecordFor(cert, c.ca.Intermediate(), "worker-1", CertIssuedViaRenew, c.clk.Now())
	rec.PrevSerial = first.serial()
	if err := c.store.RecordCert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	cutoff := first.cert.NotAfter.Add(time.Hour) // first is past it, the renewal is not
	if n, err := c.store.PruneCerts(ctx, cutoff); err != nil || n != 0 {
		t.Fatalf("PruneCerts = %d, %v, want 0 (first is the renewal's predecessor)", n, err)
	}
	if _, err := c.store.Cert(ctx, first.serial()); err != nil {
		t.Errorf("predecessor row: %v", err)
	}
	// Once the renewal is past the cutoff too, both go.
	if n, err := c.store.PruneCerts(ctx, cert.NotAfter.Add(time.Hour)); err != nil || n != 2 {
		t.Fatalf("PruneCerts = %d, %v, want 2", n, err)
	}
}

// TestCertIndexPrunesOnItsLoop: Run deletes expired rows once per interval on
// the control plane clock and not before.
func TestCertIndexPrunesOnItsLoop(t *testing.T) {
	ctx := context.Background()
	c := newCertEnv(t)
	a := c.issue(t, "worker-1")
	idx := newCertIndex(c.store, c.clk, slog.New(slog.DiscardHandler))
	idx.prune(ctx) // first call runs at once; nothing is expired
	if _, err := c.store.Cert(ctx, a.serial()); err != nil {
		t.Fatalf("a live row was pruned: %v", err)
	}
	c.clk.Advance(24*time.Hour + certRetention + time.Hour)
	idx.prune(ctx)
	if _, err := c.store.Cert(ctx, a.serial()); !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("the expired row survived the prune: %v", err)
	}
}
