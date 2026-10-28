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

// The worker token admin API (W-P1-WTOK-03): an admin mints a token from the
// console (the plaintext appears once, in the 201), lists and revokes it, the
// fleet view says how each worker authenticates, and create and revoke are
// admin audit rows that never carry the token.

func workerTokenAdminOpts() []harness.Option {
	return []harness.Option{harness.WithConsoleOIDC(), harness.WithAdminAudit(), harness.WithWorkerTokens()}
}

const wtAdminPath = "/dashboard/api/worker-tokens"

type wtAdminToken struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ProxyID   string `json:"proxyID"`
	CreatedBy string `json:"createdBy"`
	RevokedAt string `json:"revokedAt"`
	Token     string `json:"token"`
}

func workerTokenAdminAPI(t *testing.T, h *harness.H) {
	cp := h.CP()
	admin, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	hdr := http.Header{controlplane.CSRFHeader: {csrf}, "Content-Type": {"application/json"}}
	do := func(b *harness.Browser, method, path, body string, hdr http.Header) (*http.Response, string) {
		t.Helper()
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

	// Mint: 201, the token once, never cached.
	resp, body := do(admin, http.MethodPost, wtAdminPath, `{"name":"scn-tok","proxyID":"scn-worker"}`, hdr)
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("POST %s = %d %q, Cache-Control %q; want 201 no-store", wtAdminPath, resp.StatusCode, "<body>", resp.Header.Get("Cache-Control"))
	}
	var made wtAdminToken
	if err := json.Unmarshal([]byte(body), &made); err != nil || !strings.HasPrefix(made.Token, "wwt_") || made.ID == "" || made.CreatedBy != "ada" {
		t.Fatalf("201 body does not carry a token and its metadata (err %v)", err)
	}

	// The token authenticates the worker plane as its bound id, and the fleet
	// view says so; the harness's own workers still use the shared token.
	if got := cp.DoWorker(http.MethodGet, "/policy", made.Token, "", ""); got.Status != http.StatusOK {
		t.Fatalf("/policy with the minted token = %d, want 200", got.Status)
	}
	workers := func() map[string]dashboard.WorkerView {
		_, wb := do(admin, http.MethodGet, "/dashboard/api/workers", "", nil)
		var ws []dashboard.WorkerView
		if err := json.Unmarshal([]byte(wb), &ws); err != nil {
			t.Fatalf("GET workers: %v", err)
		}
		out := map[string]dashboard.WorkerView{}
		for _, w := range ws {
			out[w.ProxyID] = w
		}
		return out
	}
	if w := workers()["scn-worker"]; w.AuthKind != "token" || w.TokenName != "scn-tok" || w.LegacyRequests != 0 {
		t.Errorf("token worker in the fleet view = %+v", w)
	}
	h.Eventually("a shared-token worker to show as legacy", func() bool {
		w := workers()["worker-1"]
		return w.AuthKind == "legacy" && w.LegacyRequests > 0
	})

	// List: the token with its metadata, no plaintext.
	resp, body = do(admin, http.MethodGet, wtAdminPath, "", nil)
	if resp.StatusCode != http.StatusOK || strings.Contains(body, made.Token) || !strings.Contains(body, made.ID) {
		t.Fatalf("GET %s = %d (token in body: %v)", wtAdminPath, resp.StatusCode, strings.Contains(body, made.Token))
	}

	// A viewer cannot mint or revoke; a worker token or the shared token cannot
	// stand in for a session; neither changes anything.
	viewer, vcsrf := consoleLogin(t, h, fakes.Valid("vera", "vera@example.com", harness.ConsoleViewerGroup))
	vhdr := http.Header{controlplane.CSRFHeader: {vcsrf}, "Content-Type": {"application/json"}}
	if resp, _ := do(viewer, http.MethodPost, wtAdminPath, `{"name":"v","proxyID":"v"}`, vhdr); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer POST = %d, want 403", resp.StatusCode)
	}
	if resp, _ := do(viewer, http.MethodDelete, wtAdminPath+"/"+made.ID, "", vhdr); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer DELETE = %d, want 403", resp.StatusCode)
	}
	for _, bearer := range []string{made.Token, cp.Token()} {
		if got := cp.DoWorker(http.MethodPost, wtAdminPath, bearer, "", `{"name":"x","proxyID":"x"}`); got.Status != http.StatusUnauthorized {
			t.Errorf("POST %s with a bearer and no session = %d, want 401", wtAdminPath, got.Status)
		}
	}

	// Revoke: 204, shown as revoked, and the next /policy is refused.
	if resp, _ := do(admin, http.MethodDelete, wtAdminPath+"/"+made.ID, "", hdr); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", resp.StatusCode)
	}
	_, body = do(admin, http.MethodGet, wtAdminPath, "", nil)
	var list []wtAdminToken
	if err := json.Unmarshal([]byte(body), &list); err != nil || len(list) != 1 || list[0].RevokedAt == "" {
		t.Errorf("list after revoke = %s (err %v), want one revoked token", body, err)
	}
	if got := cp.DoWorker(http.MethodGet, "/policy", made.Token, "", ""); got.Status != http.StatusUnauthorized {
		t.Errorf("/policy with the revoked token = %d, want 401", got.Status)
	}
	if resp, _ := do(admin, http.MethodDelete, wtAdminPath+"/wt_unknown", "", hdr); resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE of an unknown id = %d, want 404", resp.StatusCode)
	}

	// Audit: genesis, the create and the revoke (plus the viewer's two denied
	// writes), each naming its actor and the token id, none carrying the token.
	var create, revoke []harness.AdminAuditRow
	for _, r := range h.AdminAuditRows() {
		switch {
		case r.Action == "worker_token.create" && r.Outcome == adminaudit.OutcomeOK:
			create = append(create, r)
		case r.Action == "worker_token.revoke" && r.Outcome == adminaudit.OutcomeOK && r.TargetRef == "token:"+made.ID:
			revoke = append(revoke, r)
		}
		if r.Action == "worker_token.create" || r.Action == "worker_token.revoke" {
			if r.Target != "worker_tokens" || strings.Contains(r.TargetRef+r.BeforeHash+r.AfterHash, made.Token) {
				t.Errorf("audit row = %+v", r)
			}
		}
	}
	if len(create) != 1 || create[0].TargetRef != "token:"+made.ID || create[0].Sub != "ada" || create[0].ActorRole != "admin" ||
		create[0].HTTPStatus != http.StatusCreated || create[0].BeforeHash == create[0].AfterHash {
		t.Errorf("create rows = %+v", create)
	}
	if len(revoke) != 1 || revoke[0].Sub != "ada" || revoke[0].HTTPStatus != http.StatusNoContent || revoke[0].BeforeHash == revoke[0].AfterHash {
		t.Errorf("revoke rows = %+v", revoke)
	}
	if strings.Contains(h.Logs(), made.Token) {
		t.Error("the minted token appears in the logs")
	}
}

// workerTokenAdminUseCLI: with console.auth none the API lists but does not
// mint or revoke, even for the shared bearer the harness holds.
func workerTokenAdminUseCLI(t *testing.T, h *harness.H) {
	cp := h.CP()
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, wtAdminPath},
		{http.MethodDelete, wtAdminPath + "/wt_x"},
	} {
		code, body, err := cp.Do(c.method, c.path, cp.Token(), []byte(`{"name":"x","proxyID":"x"}`))
		if err != nil || code != http.StatusForbidden || !strings.Contains(body, `"use_cli"`) || !strings.Contains(body, "warden control-plane token") {
			t.Errorf("%s %s = %d %q, %v; want 403 use_cli", c.method, c.path, code, body, err)
		}
	}
	var list []json.RawMessage
	if err := cp.GetJSON(wtAdminPath, &list); err != nil || len(list) != 0 {
		t.Errorf("GET %s = %v, %v; want an empty list", wtAdminPath, list, err)
	}
	// An out-of-process mint shows in the list, without its plaintext.
	pt, id := mintWorkerToken(t, h, "cli-tok", "cli-worker")
	var rows []wtAdminToken
	h.Eventually("the list to show the CLI-minted token", func() bool {
		h.Clock().Advance(3 * time.Second)
		rows = nil
		return cp.GetJSON(wtAdminPath, &rows) == nil && len(rows) == 1 && rows[0].ID == id
	})
	if b, _ := json.Marshal(rows); strings.Contains(string(b), pt) {
		t.Error("the list carries the plaintext")
	}
}
