package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The enrollment token admin API (W-P2-WCA-08). An admin creates a wet_ token
// from the console, a worker enrolls with it, and the token is single use, never
// listed back, never in an audit row, a log or the database, and revocable
// before use.

func workerCAEnrollAdminOpts() []harness.Option {
	return []harness.Option{harness.WithWorkerCA(), harness.WithAdminAudit(), harness.WithConsoleOIDC()}
}

const enrAdminPath = "/dashboard/api/worker-enrollments"

type enrAdminCreated struct {
	dashboard.EnrollmentView
	Token string `json:"token"`
}

func workerCAEnrollAdmin(t *testing.T, h *harness.H) {
	workerCAMakeReady(t, h)
	admin, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	viewer, vcsrf := consoleLogin(t, h, fakes.Valid("vera", "vera@example.com", harness.ConsoleViewerGroup))
	do := func(b *harness.Browser, token, method, path, body string) (*http.Response, string) {
		t.Helper()
		hdr := http.Header{controlplane.CSRFHeader: {token}, "Content-Type": {"application/json"}}
		var rb []byte
		if body != "" {
			rb = []byte(body)
		}
		resp, err := b.DoBody(method, path, hdr, rb)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp, string(data)
	}
	list := func() []dashboard.EnrollmentView {
		t.Helper()
		resp, body := do(admin, csrf, http.MethodGet, enrAdminPath, "")
		var out []dashboard.EnrollmentView
		if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &out) != nil {
			t.Fatalf("GET %s = %d %s", enrAdminPath, resp.StatusCode, body)
		}
		return out
	}
	create := func(body string) (enrAdminCreated, string) {
		t.Helper()
		resp, raw := do(admin, csrf, http.MethodPost, enrAdminPath, body)
		if resp.StatusCode != http.StatusCreated || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("POST %s = %d, Cache-Control %q; want 201 no-store", enrAdminPath, resp.StatusCode, resp.Header.Get("Cache-Control"))
		}
		var c enrAdminCreated
		if err := json.Unmarshal([]byte(raw), &c); err != nil || !strings.HasPrefix(c.Token, "wet_") || c.ID == "" || c.CreatedBy != "ada" {
			t.Fatalf("201 body has no token and metadata (err %v)", err)
		}
		return c, raw
	}

	// A viewer cannot mint, list or revoke, and nothing is created.
	if resp, _ := do(viewer, vcsrf, http.MethodPost, enrAdminPath, `{"name":"nope","workerId":"worker-x"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer POST = %d, want 403", resp.StatusCode)
	}
	if resp, _ := do(viewer, vcsrf, http.MethodGet, enrAdminPath, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer GET = %d, want 403", resp.StatusCode)
	}
	if n := len(list()); n != 0 {
		t.Fatalf("%d tokens after a refused viewer POST, want 0", n)
	}
	// A bad request, a taken name and a lifetime above workerCA.enrollTokenMaxTTL.
	for _, body := range []string{`{"name":"x"}`, `{"name":"x","workerId":"w","workerIdPrefix":"p-"}`, `{"name":"x","workerId":"w","expiresIn":"9999h"}`} {
		if resp, raw := do(admin, csrf, http.MethodPost, enrAdminPath, body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST %s = %d %s, want 400", body, resp.StatusCode, raw)
		}
	}

	// The admin mints a token; a worker enrolls with it once.
	c1, _ := create(`{"name":"scn-one","workerId":"worker-1"}`)
	if got := enrollOK(t, h, c1.Token, ""); got.WorkerID != "worker-1" {
		t.Fatalf("enrolled %+v, want worker-1", got)
	}
	h.Clock().Advance(time.Minute)
	if status, body := h.CP().Enroll(c1.Token, scenarioCSR(t), ""); status != http.StatusUnauthorized || strings.TrimSpace(body) != "unauthorized" {
		t.Fatalf("reused token = %d %q, want 401 unauthorized", status, body)
	}
	if resp, _ := do(admin, csrf, http.MethodPost, enrAdminPath, `{"name":"scn-one","workerId":"worker-2"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate name = %d, want 409", resp.StatusCode)
	}

	// A pool token revoked before use enrolls nobody, and shows revokedAt.
	c2, _ := create(`{"name":"scn-pool","workerIdPrefix":"pool-","maxUses":2,"expiresIn":"2h"}`)
	if resp, _ := do(viewer, vcsrf, http.MethodDelete, enrAdminPath+"/"+c2.ID, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer DELETE = %d, want 403", resp.StatusCode)
	}
	if resp, _ := do(admin, csrf, http.MethodDelete, enrAdminPath+"/"+c2.ID, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", resp.StatusCode)
	}
	if resp, _ := do(admin, csrf, http.MethodDelete, enrAdminPath+"/et_unknown", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE unknown = %d, want 404", resp.StatusCode)
	}
	h.Clock().Advance(time.Minute)
	if status, body := h.CP().Enroll(c2.Token, scenarioCSR(t), "h1"); status != http.StatusUnauthorized || strings.TrimSpace(body) != "unauthorized" {
		t.Fatalf("revoked token = %d %q, want 401 unauthorized", status, body)
	}

	// The list carries metadata only: uses, revokedAt, never the token.
	rows := list()
	byID := map[string]dashboard.EnrollmentView{}
	for _, v := range rows {
		byID[v.ID] = v
	}
	if len(rows) != 2 || byID[c1.ID].Uses != 1 || byID[c1.ID].WorkerID != "worker-1" || byID[c1.ID].RevokedAt != "" ||
		byID[c2.ID].WorkerIDPrefix != "pool-" || byID[c2.ID].MaxUses != 2 || byID[c2.ID].RevokedAt == "" {
		t.Fatalf("list = %+v", rows)
	}
	_, listBody := do(admin, csrf, http.MethodGet, enrAdminPath, "")
	for _, tok := range []string{c1.Token, c2.Token} {
		if strings.Contains(listBody, tok) {
			t.Error("GET carries a plaintext enrollment token")
		}
	}

	// One audit row per write, attributed to the admin, never carrying a token.
	got := map[string][]harness.AdminAuditRow{}
	for _, r := range h.AdminAuditRows() {
		if strings.HasPrefix(r.Action, "worker_enroll_token.") && r.AuthMethod != "cli" {
			got[r.Action+"/"+r.Outcome] = append(got[r.Action+"/"+r.Outcome], r)
		}
	}
	creates, revokes := got["worker_enroll_token.create/"+adminaudit.OutcomeOK], got["worker_enroll_token.revoke/"+adminaudit.OutcomeOK]
	if len(creates) != 2 || len(revokes) != 1 {
		t.Fatalf("audit rows: %d creates, %d revokes, want 2 and 1 (%+v)", len(creates), len(revokes), got)
	}
	for _, r := range append(append([]harness.AdminAuditRow{}, creates...), revokes...) {
		if r.Sub != "ada" || r.Target != "worker_enrollments" || !strings.HasPrefix(r.TargetRef, "enroll_token:et_") || r.BeforeHash == r.AfterHash {
			t.Errorf("audit row = %+v", r)
		}
	}
	if creates[0].TargetRef != "enroll_token:"+c1.ID || revokes[0].TargetRef != "enroll_token:"+c2.ID {
		t.Errorf("target refs: create %q, revoke %q", creates[0].TargetRef, revokes[0].TargetRef)
	}

	// No plaintext token or hash in the database, audit rows or logs; the one
	// enrollment is the worker.enrolled row.
	workerCAEnrollAuditAndSecrets(t, h, []string{c1.Token, c2.Token}, 1)
}
