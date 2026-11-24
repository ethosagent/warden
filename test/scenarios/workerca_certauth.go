package scenarios

import (
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/harness"
)

// Worker certificate authentication and renewal (W-P2-WCA-04). A worker that
// enrolled presents its certificate on the control plane's TLS listener; the
// authenticator verifies it per request on /policy, /control/heartbeat and
// /central/ingest, binds the worker id to the SAN, and POST /control/renew
// rolls the certificate over under a lineage rule that cuts off a copied key.

func workerCACertAuthOpts() []harness.Option {
	return []harness.Option{harness.WithWorkerCA(), harness.WithAdminAudit(), harness.WithControlPlaneAdminToken()}
}

func workerCAStrictCertsOpts() []harness.Option {
	return []harness.Option{harness.WithRequireWorkerCerts(), harness.WithAdminAudit()}
}

var certWorkerRoutes = []struct {
	method, path, body string
	ok                 int
}{
	{http.MethodGet, "/policy", "", http.StatusOK},
	{http.MethodPost, "/control/heartbeat", `{"policyETag":"x"}`, http.StatusNoContent},
	{http.MethodPost, "/central/ingest", `{"events":[{"type":"allow","host":"api.openai.com"}]}`, http.StatusNoContent},
}

// certStatus sends the route as a worker presenting cert (and optionally a
// bearer and a proxy id header) and returns the status.
func certStatus(h *harness.H, cert harness.WorkerCert, route int, bearer, proxyID string) int {
	rt := certWorkerRoutes[route]
	return h.CP().WithClientCert(cert).DoWorker(rt.method, rt.path, bearer, proxyID, rt.body).Status
}

func workerCAEnrolled(t *testing.T, h *harness.H, id string) harness.WorkerCert {
	t.Helper()
	return h.EnrollWorkerWhenLoaded(h.CreateEnrollToken(id, "", 0, 0), "")
}

func workerCACertAuth(t *testing.T, h *harness.H) {
	workerCAMakeReady(t, h)
	w1, w2 := workerCAEnrolled(t, h, "worker-1"), workerCAEnrolled(t, h, "worker-2")

	// A valid certificate authenticates on the three worker routes.
	for i, rt := range certWorkerRoutes {
		if got := certStatus(h, w1, i, "", ""); got != rt.ok {
			t.Fatalf("%s with a worker cert = %d, want %d", rt.path, got, rt.ok)
		}
	}
	// The id is the certificate's: the fleet view lists worker-1 as cert, and the
	// forwarded events were ingested under that id.
	var seen *dashboard.WorkerView
	h.Eventually("the fleet view to list the cert worker", func() bool {
		views, err := h.CP().Workers()
		if err != nil {
			t.Fatal(err)
		}
		for i := range views {
			if views[i].ProxyID == "worker-1" && views[i].AuthKind == "cert" {
				seen = &views[i]
			}
		}
		return seen != nil
	})
	if seen.CertSerial != w1.Serial() || seen.CertNotAfter != w1.Cert.NotAfter.UTC().Format(time.RFC3339) || seen.EventsForwarded != 1 {
		t.Errorf("fleet view of worker-1: %+v", *seen)
	}

	// One worker cannot speak as another.
	for i, rt := range certWorkerRoutes {
		if got := certStatus(h, w1, i, "", "worker-2"); got != http.StatusForbidden {
			t.Errorf("%s: cert worker-1 with header worker-2 = %d, want 403", rt.path, got)
		}
		if got := certStatus(h, w1, i, "", "worker-1"); got != rt.ok {
			t.Errorf("%s: cert worker-1 with header worker-1 = %d, want %d", rt.path, got, rt.ok)
		}
	}

	// Hostile certificates are an HTTP 401 (not a handshake failure) on every
	// worker route, even with a valid shared token riding in the same request.
	hostile := map[string]harness.WorkerCert{
		"another worker CA":    h.MintWorkerCert(harness.CertMint{WorkerID: "worker-1", Issuer: "other-ca"}),
		"the proxy CA":         h.MintWorkerCert(harness.CertMint{WorkerID: "worker-1", Issuer: "proxy-ca"}),
		"serverAuth only":      h.MintWorkerCert(harness.CertMint{WorkerID: "worker-1", EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}),
		"another trust domain": h.MintWorkerCert(harness.CertMint{WorkerID: "worker-1", TrustDomain: "evil.example"}),
	}
	for name, bad := range hostile {
		for i, rt := range certWorkerRoutes {
			if got := certStatus(h, bad, i, h.CP().Token(), ""); got != http.StatusUnauthorized {
				t.Errorf("%s: %s = %d, want 401", name, rt.path, got)
			}
		}
	}
	// A worker certificate never opens a human route: /central/secrets answers
	// 401 to every method, while the admin bearer and the dashboard work with no
	// client certificate at all.
	cw := h.CP().WithClientCert(w1)
	for _, m := range []struct{ method, path string }{
		{http.MethodGet, "/central/secrets"}, {http.MethodPost, "/central/secrets"}, {http.MethodDelete, "/central/secrets/k"},
	} {
		if status, _, err := cw.Do(m.method, m.path, "", []byte(`{"key":"k","value":"v"}`)); err != nil || status != http.StatusUnauthorized {
			t.Errorf("%s %s with only a worker cert = %d, %v, want 401", m.method, m.path, status, err)
		}
	}
	admin := h.ControlPlaneAdminToken()
	if status, _, err := h.CP().Do(http.MethodGet, "/central/secrets", admin, nil); err != nil || status != http.StatusOK {
		t.Errorf("GET /central/secrets with the admin bearer = %d, %v, want 200", status, err)
	}
	if status, _, err := h.CP().Do(http.MethodGet, "/dashboard/api/workers", admin, nil); err != nil || status != http.StatusOK {
		t.Errorf("GET /dashboard/api/workers with the admin bearer = %d, %v, want 200", status, err)
	}

	// An expired certificate is a 401 while a live one keeps working.
	short := h.MintWorkerCert(harness.CertMint{WorkerID: "worker-3"})
	if got := certStatus(h, short, 0, "", ""); got != http.StatusOK {
		t.Fatalf("a fresh minted cert = %d, want 200", got)
	}
	h.Clock().Advance(2 * time.Hour)
	if got := certStatus(h, short, 0, h.CP().Token(), ""); got != http.StatusUnauthorized {
		t.Errorf("an expired cert = %d, want 401", got)
	}
	if got := certStatus(h, w2, 0, "", ""); got != http.StatusOK {
		t.Errorf("worker-2's 24h cert after 2h = %d, want 200", got)
	}
	logs := h.Logs()
	for _, reason := range []string{"bad_chain", "bad_eku", "expired"} {
		if !strings.Contains(logs, `"reason":"`+reason+`"`) {
			t.Errorf("no worker auth rejection with reason %s in the control plane log", reason)
		}
	}
	for _, marker := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE"} {
		if strings.Contains(logs, marker) {
			t.Errorf("control plane log carries %q", marker)
		}
	}
}

func workerCARenew(t *testing.T, h *harness.H) {
	// While the CA key is unavailable a certificate from the pinned intermediate
	// still authenticates (the startup verifier), and renew says 503.
	early := h.MintWorkerCert(harness.CertMint{WorkerID: "worker-0"})
	if got := certStatus(h, early, 0, "", ""); got != http.StatusOK {
		t.Fatalf("a cert while the worker CA is degraded: /policy = %d, want 200", got)
	}
	if status, body, _, _ := h.CP().Renew(early); status != http.StatusServiceUnavailable || !strings.Contains(body, "ca_unavailable") {
		t.Fatalf("renew while degraded = %d %s, want 503 ca_unavailable", status, body)
	}
	workerCAMakeReady(t, h)

	a := workerCAEnrolled(t, h, "worker-1")
	other := workerCAEnrolled(t, h, "worker-2")
	h.Clock().Advance(time.Hour)

	// Renewal: a new serial, prev_serial naming the old one, the same worker id.
	status, body, b, prev := h.CP().Renew(a)
	if status != http.StatusCreated {
		t.Fatalf("renew = %d %s, want 201", status, body)
	}
	if prev != a.Serial() || b.Serial() == a.Serial() || b.Cert.URIs[0].String() != a.Cert.URIs[0].String() {
		t.Fatalf("renewed %s prev %s (old %s)", b.Serial(), prev, a.Serial())
	}
	for _, w := range []harness.WorkerCert{a, b} {
		if got := certStatus(h, w, 0, "", ""); got != http.StatusOK {
			t.Fatalf("/policy with %s = %d, want 200", w.Serial()[:6], got)
		}
	}
	// At most one renewal per worker per 10 minutes.
	if status, _, _, _ := h.CP().Renew(b); status != http.StatusTooManyRequests {
		t.Errorf("a second renew inside 10 minutes = %d, want 429", status)
	}
	// The key must change, and bad requests issue nothing.
	h.Clock().Advance(11 * time.Minute)
	if status, body, _, _ := h.CP().RenewWithCSR(b, b.Key, csrForKey(t, b)); status != http.StatusBadRequest || !strings.Contains(body, "same_key") {
		t.Errorf("renew with the same key = %d %s, want 400 same_key", status, body)
	}
	if status, _, _, _ := h.CP().RenewWithCSR(b, b.Key, "not a csr"); status != http.StatusBadRequest {
		t.Errorf("renew with a bad CSR = %d, want 400", status)
	}
	// A bearer is never enough to renew.
	if status, _, err := h.CP().Do(http.MethodPost, "/control/renew", h.CP().Token(), []byte(`{"csr":"x"}`)); err != nil || status != http.StatusUnauthorized {
		t.Errorf("renew with only the shared token = %d, %v, want 401", status, err)
	}

	// The worker moved on to B, so the superseded A is a copied key: renewing
	// from it revokes the worker, and its next /policy is a 401.
	if status, body, _, _ := h.CP().Renew(a); status != http.StatusUnauthorized {
		t.Fatalf("renew from the superseded serial = %d %s, want 401", status, body)
	}
	for _, w := range []harness.WorkerCert{a, b} {
		if got := certStatus(h, w, 0, "", ""); got != http.StatusUnauthorized {
			t.Errorf("after the lineage conflict /policy with %s = %d, want 401", w.Serial()[:6], got)
		}
	}
	if got := certStatus(h, other, 0, "", ""); got != http.StatusOK {
		t.Errorf("an unrelated worker after the conflict = %d, want 200", got)
	}
	var conflicts int
	for _, r := range h.AdminAuditRows() {
		switch r.Action {
		case "worker.renewed":
			t.Errorf("a renewal was admin-audited: %+v", r)
		case "worker.cert_lineage_conflict":
			conflicts++
			if r.TargetRef != "worker:worker-1" || r.Outcome != "denied" {
				t.Errorf("conflict row %+v", r)
			}
		}
	}
	if conflicts != 1 {
		t.Errorf("worker.cert_lineage_conflict rows = %d, want 1", conflicts)
	}
	if logs := h.Logs(); strings.Contains(logs, "CERTIFICATE REQUEST") || strings.Contains(logs, "PRIVATE KEY") {
		t.Errorf("control plane log carries CSR or key material")
	}
}

func csrForKey(t *testing.T, w harness.WorkerCert) string {
	t.Helper()
	return harness.CSRFor(t, w.Key)
}

func workerCAStrictCerts(t *testing.T, h *harness.H) {
	workerCAMakeReady(t, h)
	if !strings.Contains(h.Logs(), "auth_mode") || !strings.Contains(h.Logs(), "strict-certs") {
		t.Errorf("the startup log has no auth_mode strict-certs line")
	}
	w := workerCAEnrolled(t, h, "worker-1")
	// Certificates only: no credential, the shared token and a wwt_-shaped token
	// are all refused, the certificate is accepted.
	for i, rt := range certWorkerRoutes {
		for name, bearer := range map[string]string{"nothing": "", "shared token": h.CP().Token(), "wwt_ token": "wwt_" + strings.Repeat("a", 52)} {
			if got := h.CP().DoWorker(rt.method, rt.path, bearer, "", rt.body).Status; got != http.StatusUnauthorized {
				t.Errorf("%s with %s = %d, want 401", rt.path, name, got)
			}
		}
		if got := certStatus(h, w, i, "", ""); got != rt.ok {
			t.Errorf("%s with a worker cert = %d, want %d", rt.path, got, rt.ok)
		}
	}
}
