package scenarios

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Worker certificate revocation (W-P2-WCA-05). An admin revokes a worker from
// the console (or an operator from the CLI): its next request, renewal
// included, is a 401, its held /policy long-poll ends, other workers are
// untouched, and the row that expired certificates leave behind is pruned only
// once it is safely past use.

func workerCARevokeOpts() []harness.Option {
	return []harness.Option{harness.WithWorkerCA(), harness.WithAdminAudit(), harness.WithConsoleOIDC()}
}

const wcrPath = "/dashboard/api/workers/"

// wcrHold parks a long-poll for the worker on /policy, once it has an ETag.
func wcrHold(t *testing.T, h *harness.H, w harness.WorkerCert) <-chan harness.RawResponse {
	t.Helper()
	cp := h.CP().WithClientCert(w)
	first := cp.DoWorker(http.MethodGet, "/policy", "", "", "")
	etag := first.Header.Get("ETag")
	if first.Status != http.StatusOK || etag == "" {
		t.Fatalf("/policy before the hold = %d, ETag %q", first.Status, etag)
	}
	held := cp.HoldWorker(http.MethodGet, "/policy?wait=30s", "", http.Header{"If-None-Match": {etag}})
	time.Sleep(200 * time.Millisecond) // let it park; the assertions hold either way
	return held
}

// wcrExpect401 drives the harness clock until the held request returns, and
// fails unless it is a 401.
func wcrExpect401(t *testing.T, h *harness.H, held <-chan harness.RawResponse, what string) {
	t.Helper()
	var got harness.RawResponse
	h.Eventually(what+" to be cut off", func() bool {
		h.Clock().Advance(time.Second)
		select {
		case got = <-held:
			return true
		default:
			return false
		}
	})
	if got.Status != http.StatusUnauthorized {
		t.Fatalf("%s = %d %q, want 401", what, got.Status, got.Body)
	}
}

func wcrAllRoutes(t *testing.T, h *harness.H, w harness.WorkerCert, want func(i int) int, label string) {
	t.Helper()
	for i, rt := range certWorkerRoutes {
		if got := certStatus(h, w, i, "", ""); got != want(i) {
			t.Errorf("%s: %s = %d, want %d", label, rt.path, got, want(i))
		}
	}
}

func workerCARevokeAPI(t *testing.T, h *harness.H) {
	workerCAMakeReady(t, h)
	w1, w2 := workerCAEnrolled(t, h, "cert-a"), workerCAEnrolled(t, h, "cert-b")
	admin, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	viewer, vcsrf := consoleLogin(t, h, fakes.Valid("vera", "vera@example.com", harness.ConsoleViewerGroup))
	post := func(b *harness.Browser, token, path, body string) (int, string) {
		t.Helper()
		hdr := http.Header{controlplane.CSRFHeader: {token}, "Content-Type": {"application/json"}}
		resp, err := b.DoBody(http.MethodPost, path, hdr, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, string(data)
	}
	ok := func(i int) int { return certWorkerRoutes[i].ok }
	wcrAllRoutes(t, h, w1, ok, "cert-a before")

	// A viewer, an unknown worker and a serial of another worker change nothing.
	if code, _ := post(viewer, vcsrf, wcrPath+"cert-a/revoke", ""); code != http.StatusForbidden {
		t.Errorf("viewer POST = %d, want 403", code)
	}
	if code, _ := post(admin, csrf, wcrPath+"nobody/revoke", ""); code != http.StatusNotFound {
		t.Errorf("unknown worker = %d, want 404", code)
	}
	if code, _ := post(admin, csrf, wcrPath+"cert-a/revoke", `{"serial":"`+w2.Serial()+`"}`); code != http.StatusNotFound {
		t.Errorf("another worker's serial = %d, want 404", code)
	}
	if code, _ := post(admin, csrf, wcrPath+"cert-a/revoke", `{"serial":"not hex"}`); code != http.StatusBadRequest {
		t.Errorf("a malformed serial = %d, want 400", code)
	}
	wcrAllRoutes(t, h, w1, ok, "cert-a after refused revokes")

	held := wcrHold(t, h, w1)
	code, body := post(admin, csrf, wcrPath+"cert-a/revoke", "")
	if code != http.StatusOK || strings.ReplaceAll(body, " ", "") != "{\"revoked\":1}\n" {
		t.Fatalf("revoke = %d %q, want 200 {revoked:1}", code, body)
	}
	// The held long-poll is cut, the next requests are 401, and so is a renewal.
	wcrExpect401(t, h, held, "cert-a's held /policy")
	wcrAllRoutes(t, h, w1, func(int) int { return http.StatusUnauthorized }, "cert-a revoked")
	if status, _, _, _ := h.CP().Renew(w1); status != http.StatusUnauthorized {
		t.Errorf("renew with the revoked cert = %d, want 401", status)
	}
	wcrAllRoutes(t, h, w2, ok, "cert-b untouched")

	// The fleet view says so.
	h.Eventually("the fleet view to show cert-a revoked", func() bool {
		resp, err := admin.DoBody(http.MethodGet, "/dashboard/api/workers", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var views []dashboard.WorkerView
		if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
			t.Fatal(err)
		}
		for _, v := range views {
			if v.ProxyID == "cert-a" {
				return v.CertRevoked
			}
		}
		return false
	})

	// Idempotent: a second revoke is 200 {revoked:0}.
	if code, body := post(admin, csrf, wcrPath+"cert-a/revoke", ""); code != http.StatusOK || !strings.Contains(body, `"revoked":0`) {
		t.Errorf("second revoke = %d %q, want 200 revoked 0", code, body)
	}

	// One serial only: cert-b keeps its other certificate? It has one, so
	// revoking it by serial is the whole worker.
	if code, body := post(admin, csrf, wcrPath+"cert-b/revoke", `{"serial":"`+w2.Serial()+`"}`); code != http.StatusOK || !strings.Contains(body, `"revoked":1`) {
		t.Errorf("revoke by serial = %d %q, want 200 revoked 1", code, body)
	}
	wcrAllRoutes(t, h, w2, func(int) int { return http.StatusUnauthorized }, "cert-b revoked by serial")

	// Re-enrolling with a new admin-issued token works.
	again := workerCAEnrolled(t, h, "cert-a")
	wcrAllRoutes(t, h, again, ok, "cert-a re-enrolled")

	var revoked []harness.AdminAuditRow
	for _, r := range h.AdminAuditRows() {
		if r.Action == "worker.revoked" {
			revoked = append(revoked, r)
		}
	}
	// cert-a (200), its repeat (200), cert-b (200); the viewer's 403 and the
	// 404s are denied or failed rows of their own.
	var okRows int
	for _, r := range revoked {
		if r.Target != "worker_certs" {
			t.Errorf("row target %q", r.Target)
		}
		if r.Outcome == adminaudit.OutcomeOK {
			okRows++
			if r.Sub != "ada" || r.AuthMethod == "cli" || !strings.Contains(r.Details, `"worker_id"`) || !strings.Contains(r.Details, `"count"`) {
				t.Errorf("revoke row = %+v", r)
			}
		}
	}
	if okRows != 3 {
		t.Errorf("worker.revoked ok rows = %d, want 3 (rows %+v)", okRows, revoked)
	}
}

// workerCARevokeCLI: an offline revoke on the state dir reaches the running
// control plane inside the data_version poll and cuts the held long-poll.
func workerCARevokeCLI(t *testing.T, h *harness.H) {
	workerCAMakeReady(t, h)
	w1, w2 := workerCAEnrolled(t, h, "cert-a"), workerCAEnrolled(t, h, "cert-b")
	ok := func(i int) int { return certWorkerRoutes[i].ok }
	held := wcrHold(t, h, w1)

	ctx := context.Background()
	o, err := controlplane.OpenWorkerCertsOffline(ctx, h.WorkerCAStateDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	n, err := o.Revoke(ctx, "cert-a", "")
	if cerr := o.Close(); err == nil {
		err = cerr
	}
	if err != nil || n != 1 {
		t.Fatalf("offline revoke = %d, %v, want 1", n, err)
	}
	// The poll runs every 2s on the harness clock.
	wcrExpect401(t, h, held, "cert-a's held /policy after a CLI revoke")
	wcrAllRoutes(t, h, w1, func(int) int { return http.StatusUnauthorized }, "cert-a revoked by the CLI")
	if status, _, _, _ := h.CP().Renew(w1); status != http.StatusUnauthorized {
		t.Errorf("renew with the revoked cert = %d, want 401", status)
	}
	wcrAllRoutes(t, h, w2, ok, "cert-b untouched")

	var rows []harness.AdminAuditRow
	for _, r := range h.AdminAuditRows() {
		if r.Action == "worker.revoked" {
			rows = append(rows, r)
		}
	}
	if len(rows) != 1 || rows[0].AuthMethod != "cli" || rows[0].TargetRef != "worker:cert-a" || !strings.Contains(rows[0].Details, `"count":"1"`) {
		t.Errorf("worker.revoked rows = %+v, want one cli row", rows)
	}
	o, err = controlplane.OpenWorkerCertsOffline(ctx, h.WorkerCAStateDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	if _, err := o.Revoke(ctx, "nobody", ""); err == nil {
		t.Error("revoking an unknown worker succeeded")
	}
}

// workerCAPrune: rows go 30 days after their not_after, not before; a row a
// surviving certificate names as its predecessor stays with it; revoked rows
// follow the same rule.
func workerCAPrune(t *testing.T, h *harness.H) {
	workerCAMakeReady(t, h)
	old := workerCAEnrolled(t, h, "worker-old")
	first := workerCAEnrolled(t, h, "worker-live")
	h.Clock().Advance(23 * time.Hour)
	status, body, second, _ := h.CP().Renew(first) // second expires 23h after first
	if status != http.StatusCreated {
		t.Fatalf("renew = %d %s", status, body)
	}
	admin, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	hdr := http.Header{controlplane.CSRFHeader: {csrf}, "Content-Type": {"application/json"}}
	resp, err := admin.DoBody(http.MethodPost, wcrPath+"worker-live/revoke", hdr, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke worker-live: %v %v", resp, err)
	}
	_ = resp.Body.Close()

	has := func(serial string) bool {
		db, err := cpstate.OpenReadOnly(context.Background(), filepath.Join(h.WorkerCAStateDir(), "warden-cp.db"), controlplane.StateMigrations())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		var n int
		if err := db.SQL().QueryRow(`SELECT count(*) FROM worker_certs WHERE serial = ?`, serial).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	// Just before old's not_after + 30 days nothing is pruned, revoked or not.
	h.Clock().Advance(old.Cert.NotAfter.Sub(h.Clock().Now()) + 29*24*time.Hour)
	h.Clock().Advance(time.Hour)
	if !has(old.Serial()) || !has(first.Serial()) || !has(second.Serial()) {
		t.Fatal("a row was pruned before 30 days past its not_after")
	}
	// Past it: old goes; the revoked second certificate is still a day short, and
	// keeps the first one it renewed from.
	h.Clock().Advance(24 * time.Hour)
	h.Eventually("worker-old's row to be pruned", func() bool {
		h.Clock().Advance(time.Minute)
		return !has(old.Serial())
	})
	if !has(second.Serial()) || !has(first.Serial()) {
		t.Fatal("a revoked certificate, or the predecessor of a surviving one, was pruned early")
	}
	// A day later the second is past retention too, and takes the first with it.
	h.Clock().Advance(24 * time.Hour)
	h.Eventually("worker-live's rows to be pruned", func() bool {
		h.Clock().Advance(time.Minute)
		return !has(second.Serial()) && !has(first.Serial())
	})
}
