package scenarios

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/workerca"
	"github.com/ethosagent/warden/test/harness"
)

// The worker side of worker certificates (W-P2-WCA-03), driven with the real
// cpclient Enroller and Renewer on the harness clock: a worker enrolls with a
// wet_ token, reuses its persisted certificate on restart without contacting
// /control/enroll, uses it with no bearer on /policy, /control/heartbeat and
// /central/ingest, renews at half of its lifetime, and is refused once its
// certificate is revoked (the renewal included) while the old certificate stays
// in use until it expires.

func workerCAClient(t *testing.T, h *harness.H) {
	workerCAMakeReady(t, h)
	dir := filepath.Join(t.TempDir(), "state")

	// A rejected token is a permanent refusal and leaves nothing on disk.
	if _, err := h.TryEnrollCertClient(dir, "wet_0000000000000000000000000000000000000000000", ""); err == nil {
		t.Fatal("a made-up token enrolled a worker")
	}
	if _, err := os.Stat(filepath.Join(dir, "cert", "worker-cert.pem")); err == nil {
		t.Error("a refused enrollment left a certificate on disk")
	}

	cc := h.EnrollCertClient(dir, h.CreateEnrollToken("wc-1", "", 0, 0), "")
	first := cc.Source.Current()
	if first.WorkerID() != "wc-1" {
		t.Fatalf("enrolled as %q, want wc-1", first.WorkerID())
	}
	if got := h.CP().EnrollCount("ok"); got != 1 {
		t.Fatalf("enroll ok count = %d, want 1", got)
	}

	// The certificate alone opens the three worker routes: no Authorization header.
	for _, rt := range certWorkerRoutes {
		if got := cc.Do(rt.method, rt.path, rt.body); got != rt.ok {
			t.Errorf("%s with the enrolled certificate = %d, want %d", rt.path, got, rt.ok)
		}
	}

	// A restart reuses the persisted certificate and asks the control plane for nothing.
	badBefore := h.CP().EnrollCount("bad_token")
	again, err := h.TryEnrollCertClient(dir, "", "")
	if err != nil {
		t.Fatalf("restart with the persisted certificate: %v", err)
	}
	if again.Source.Current().Serial() != first.Serial() || h.CP().EnrollCount("ok") != 1 || h.CP().EnrollCount("bad_token") != badBefore {
		t.Errorf("restart: serial %s (want %s), enroll ok %d, bad_token %d", again.Source.Current().Serial(), first.Serial(),
			h.CP().EnrollCount("ok"), h.CP().EnrollCount("bad_token"))
	}

	// Renewal: the harness clock reaches half of the 24h lifetime and the real
	// Renewer swaps in a certificate for the same worker.
	cc.StartRenewer()
	h.Eventually("the renewer to swap in a new certificate at half of the lifetime", func() bool {
		if cc.Source.Current().Serial() != first.Serial() {
			return true
		}
		h.Clock().Advance(time.Hour)
		return false
	})
	renewed := cc.Source.Current()
	if renewed.WorkerID() != "wc-1" || h.CP().RenewCount("ok") != 1 {
		t.Fatalf("renewed worker %q, renew ok count %d", renewed.WorkerID(), h.CP().RenewCount("ok"))
	}
	disk, err := os.ReadFile(filepath.Join(dir, "cert", "worker-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if certs, err := workerca.ParseCertsPEM(disk); err != nil || certs[0].SerialNumber.Text(16) != renewed.Serial() {
		t.Errorf("worker-cert.pem holds %v (%v), want serial %s", certs, err, renewed.Serial())
	}
	for _, rt := range certWorkerRoutes {
		if got := cc.Do(rt.method, rt.path, rt.body); got != rt.ok {
			t.Errorf("%s with the renewed certificate = %d, want %d", rt.path, got, rt.ok)
		}
	}
	h.Eventually("the fleet view to show the renewed serial", func() bool {
		views, err := h.CP().Workers()
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range views {
			if v.ProxyID == "wc-1" && v.CertSerial == renewed.Serial() {
				return true
			}
		}
		return false
	})

	// Revoked on the control plane (the offline CLI path): the next requests are
	// 401 and so is the renewal; the worker keeps its last certificate.
	ctx := context.Background()
	o, err := controlplane.OpenWorkerCertsOffline(ctx, h.WorkerCAStateDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	n, _, err := o.Revoke(ctx, "wc-1", "")
	if cerr := o.Close(); err == nil {
		err = cerr
	}
	if err != nil || n < 1 {
		t.Fatalf("revoke wc-1 = %d, %v", n, err)
	}
	h.Eventually("the revoked certificate to be refused", func() bool {
		h.Clock().Advance(2 * time.Second) // the control plane picks the revoke up on its 2s poll
		return cc.Do(http.MethodGet, "/policy", "") == http.StatusUnauthorized
	})
	for _, rt := range certWorkerRoutes {
		if got := cc.Do(rt.method, rt.path, rt.body); got != http.StatusUnauthorized {
			t.Errorf("%s with a revoked certificate = %d, want 401", rt.path, got)
		}
	}
	h.Eventually("the renewer's attempt with the revoked certificate to be refused", func() bool {
		if slices.Contains(cc.Outcomes(), "unauthorized") {
			return true
		}
		h.Clock().Advance(time.Hour)
		return false
	})
	if cc.Source.Current().Serial() != renewed.Serial() {
		t.Error("a refused renewal replaced the certificate in use")
	}
	if h.CP().RenewCount("unauthorized") < 1 {
		t.Errorf("renew unauthorized count = %d, want at least 1", h.CP().RenewCount("unauthorized"))
	}
}
