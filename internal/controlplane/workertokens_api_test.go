package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/dashboard"
)

const wtPath = "/dashboard/api/worker-tokens"

type wtCreated struct {
	dashboard.WorkerTokenView
	Token string `json:"token"`
}

// mint creates a token as the admin session and returns the decoded 201 body.
func (e *auditEnv) mint(t *testing.T, admin, name, proxy string) wtCreated {
	t.Helper()
	rec := e.send(admin, "", http.MethodPost, wtPath, fmt.Sprintf(`{"name":%q,"proxyID":%q}`, name, proxy))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s = %d %s, want 201", wtPath, rec.Code, rec.Body.String())
	}
	var c wtCreated
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *auditEnv) workerGet(path, bearer string) *httptest.ResponseRecorder {
	return e.send("", bearer, http.MethodGet, path, "")
}

func TestWorkerTokensAPI(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)

	rec := e.send(admin, "", http.MethodGet, wtPath, "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list = %d %q, want 200 []", rec.Code, rec.Body.String())
	}
	c := e.mint(t, admin, "w-one", "proxy-1")
	if !strings.HasPrefix(c.Token, "wwt_") || c.Name != "w-one" || c.ProxyID != "proxy-1" || c.CreatedBy != "u1" || c.ID == "" {
		t.Fatalf("created = %+v", c.WorkerTokenView)
	}
	rec = e.send(admin, "", http.MethodPost, wtPath, `{"name":"w-one","proxyID":"proxy-2"}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("duplicate name = %d, want 409", rec.Code)
	}
	e.mint(t, admin, "w-two", "proxy-1")
	rec = e.send(admin, "", http.MethodPost, wtPath, `{"name":"w-three","proxyID":"proxy-1"}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("third active token for a proxy id = %d, want 409", rec.Code)
	}
	for _, body := range []string{
		`{"name":"x","proxyID":""}`,
		`{"name":"","proxyID":"p"}`,
		`{"name":"x","proxyIDPrefix":"p-"}`,
		`{"name":"x","proxyID":"bad id"}`,
		`{"name":"x","proxyID":"p","expiresIn":"soon"}`,
		`{"name":"x","proxyID":"p","expiresIn":"-1h"}`,
		`{"name":"x","proxyID":"p"} {}`,
		`not json`,
	} {
		if rec := e.send(admin, "", http.MethodPost, wtPath, body); rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d %s, want 400", body, rec.Code, rec.Body.String())
		}
	}
	big := `{"name":"` + strings.Repeat("a", 9<<10) + `","proxyID":"p"}`
	if rec := e.send(admin, "", http.MethodPost, wtPath, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body = %d, want 413", rec.Code)
	}
	// An expiry in the future is accepted and reported.
	rec = e.send(admin, "", http.MethodPost, wtPath, `{"name":"w-exp","proxyID":"proxy-9","expiresIn":"24h"}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"expiresAt":"2027-01-1`) {
		t.Errorf("create with expiresIn = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.send(admin, "", http.MethodDelete, wtPath+"/wt_nope", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodPut, wtPath, `{}`); rec.Code != http.StatusForbidden {
		t.Errorf("PUT = %d, want 403 (no row)", rec.Code)
	}
}

func TestWorkerTokensNoPlaintextAnywhere(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	// Capture what the hasher is asked to hash.
	var hashed []string
	e.srv.audit.mac = func(target string, data []byte) (string, error) {
		hashed = append(hashed, string(data))
		return fakeMAC(target, data)
	}

	rec := e.send(admin, "", http.MethodPost, wtPath, `{"name":"w-one","proxyID":"proxy-1"}`)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create = %d, Cache-Control %q; want 201 no-store", rec.Code, rec.Header().Get("Cache-Control"))
	}
	var c wtCreated
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || !wellFormed(c.Token) {
		t.Fatalf("201 body has no well-formed token: %v", err)
	}
	sum := hashToken(c.Token)
	secrets := []string{c.Token, hex.EncodeToString(sum[:])}

	// The worker authenticates with it, so log lines about its use exist too.
	if rec := e.workerGet("/policy", c.Token); rec.Code != http.StatusOK {
		t.Fatalf("/policy with the new token = %d", rec.Code)
	}
	e.workerGet("/policy", c.Token+"x") // a rejection line
	e.store().Flush(context.Background())

	check := func(what, got string) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(got, s) {
				t.Errorf("%s contains the token or its sha256", what)
			}
		}
	}
	list := e.send(admin, "", http.MethodGet, wtPath, "")
	check("GET list", list.Body.String())
	if list.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("GET list Cache-Control = %q, want no-store", list.Header().Get("Cache-Control"))
	}
	check("GET workers", e.send(admin, "", http.MethodGet, "/dashboard/api/workers", "").Body.String())
	check("logs", e.log.String())
	check("audit rows", fmt.Sprintf("%+v", e.rec.inputs()))
	check("hasher input", strings.Join(hashed, "\n"))
	if len(hashed) == 0 {
		t.Error("the worker_tokens hasher was never called")
	}
	for _, in := range e.rec.inputs() {
		if in.TargetRef != "token:"+c.ID {
			t.Errorf("target_ref = %q, want token:%s", in.TargetRef, c.ID)
		}
	}
}

func (e *auditEnv) store() *WorkerTokenStore { return e.srv.cfg.WorkerTokens }

func TestWorkerTokensRoles(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	c := e.mint(t, admin, "w-one", "proxy-1")
	for _, g := range []string{groupViewer, groupEditor, "g-unmapped"} {
		raw := e.session(t, g)
		if rec := e.send(raw, "", http.MethodPost, wtPath, `{"name":"x","proxyID":"p"}`); rec.Code != http.StatusForbidden {
			t.Errorf("POST as %s = %d, want 403", g, rec.Code)
		}
		if rec := e.send(raw, "", http.MethodDelete, wtPath+"/"+c.ID, ""); rec.Code != http.StatusForbidden {
			t.Errorf("DELETE as %s = %d, want 403", g, rec.Code)
		}
	}
	for _, g := range []string{groupViewer, groupEditor, groupAdmin} {
		if rec := e.send(e.session(t, g), "", http.MethodGet, wtPath, ""); rec.Code != http.StatusOK {
			t.Errorf("GET as %s = %d, want 200", g, rec.Code)
		}
	}
	// No session: refused, and a bearer (admin or worker) never stands in.
	for _, bearer := range []string{"", dashTestToken, c.Token} {
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			path := wtPath
			if m == http.MethodDelete {
				path += "/" + c.ID
			}
			if rec := e.send("", bearer, m, path, `{"name":"x","proxyID":"p"}`); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s with no session (bearer %q...) = %d, want 401", m, bearer[:min(len(bearer), 4)], rec.Code)
			}
		}
	}
	if n := len(e.store().idxLen()); n != 1 {
		t.Errorf("a refused request changed the store: %d tokens, want 1", n)
	}
}

func (s *WorkerTokenStore) idxLen() []Token {
	toks, _ := s.List(context.Background())
	return toks
}

// console.auth none has no identity to attribute a mint to: the console is not
// a credential minter there, even with the CP admin bearer.
func TestWorkerTokensRolesAuthNone(t *testing.T) {
	e := newAuditEnv(t, auditEnvOpts{token: "worker-shared", adminToken: dashTestToken})
	for _, m := range []string{http.MethodPost, http.MethodDelete} {
		path := wtPath
		if m == http.MethodDelete {
			path += "/wt_x"
		}
		rec := e.send("", dashTestToken, m, path, `{"name":"x","proxyID":"p"}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"use_cli"`) || !strings.Contains(rec.Body.String(), "warden control-plane token") {
			t.Errorf("%s with the admin bearer = %d %s, want 403 use_cli", m, rec.Code, rec.Body.String())
		}
		if rec := e.send("", "", m, path, `{"name":"x","proxyID":"p"}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with no bearer = %d, want 401 from the write guard", m, rec.Code)
		}
		if rec := e.send("", "worker-shared", m, path, `{}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with the shared worker token = %d, want 401", m, rec.Code)
		}
	}
	if rec := e.send("", "", http.MethodGet, wtPath, ""); rec.Code != http.StatusOK {
		t.Errorf("GET in none mode = %d, want 200", rec.Code)
	}
	if n := len(e.store().idxLen()); n != 0 {
		t.Errorf("a use_cli refusal minted %d tokens", n)
	}
}

func TestWorkerTokensRevokeEffect(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	c := e.mint(t, admin, "w-one", "proxy-1")
	other := e.mint(t, admin, "w-two", "proxy-2")
	if rec := e.workerGet("/policy", c.Token); rec.Code != http.StatusOK {
		t.Fatalf("/policy before revoke = %d", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodDelete, wtPath+"/"+c.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", rec.Code)
	}
	var list []dashboard.WorkerTokenView
	rec := e.send(admin, "", http.MethodGet, wtPath, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	got := map[string]dashboard.WorkerTokenView{}
	for _, v := range list {
		got[v.ID] = v
	}
	if got[c.ID].RevokedAt == "" || got[other.ID].RevokedAt != "" {
		t.Errorf("revokedAt after DELETE: revoked=%q other=%q", got[c.ID].RevokedAt, got[other.ID].RevokedAt)
	}
	if rec := e.workerGet("/policy", c.Token); rec.Code != http.StatusUnauthorized {
		t.Errorf("/policy with the revoked token = %d, want 401", rec.Code)
	}
	if rec := e.workerGet("/policy", other.Token); rec.Code != http.StatusOK {
		t.Errorf("/policy with another token = %d, want 200", rec.Code)
	}
	// Revoking again is idempotent.
	if rec := e.send(admin, "", http.MethodDelete, wtPath+"/"+c.ID, ""); rec.Code != http.StatusNoContent {
		t.Errorf("second DELETE = %d, want 204", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodDelete, wtPath+"/wt_unknown", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}
}

func TestWorkerTokensAudit(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	c := e.mint(t, admin, "w-one", "proxy-1")
	rows := e.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("create wrote %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.Action != "worker_token.create" {
		t.Errorf("create action = %q", r.Action)
	}
	if r.Target != "worker_tokens" || r.TargetRef != "token:"+c.ID || r.Outcome != adminaudit.OutcomeOK ||
		r.HTTPStatus != http.StatusCreated || r.Actor.Sub != "u1" || r.ActorRole != "admin" ||
		r.AuthMethod != adminaudit.AuthMethodOIDC {
		t.Errorf("create row = %+v", r)
	}
	if r.BeforeHash == "" || r.AfterHash == "" || r.BeforeHash == r.AfterHash {
		t.Errorf("create hashes before=%q after=%q, want both set and different", r.BeforeHash, r.AfterHash)
	}
	if rec := e.send(admin, "", http.MethodDelete, wtPath+"/"+c.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	rows = e.rec.inputs()
	if len(rows) != 2 {
		t.Fatalf("after revoke %d rows, want 2", len(rows))
	}
	v := rows[1]
	if v.Action != "worker_token.revoke" || v.Target != "worker_tokens" || v.TargetRef != "token:"+c.ID || v.HTTPStatus != http.StatusNoContent ||
		v.Actor.Sub != "u1" || v.BeforeHash == v.AfterHash {
		t.Errorf("revoke row = %+v", v)
	}
	// A refused write (viewer) is a denied row with unchanged hashes, and a GET
	// writes nothing.
	viewer := e.session(t, groupViewer)
	e.send(viewer, "", http.MethodPost, wtPath, `{"name":"y","proxyID":"p"}`)
	e.send(admin, "", http.MethodGet, wtPath, "")
	rows = e.rec.inputs()
	if len(rows) != 3 || rows[2].Outcome != adminaudit.OutcomeDenied || rows[2].BeforeHash != rows[2].AfterHash {
		t.Errorf("rows after a denied POST and a GET: %d, last %+v", len(rows), rows[len(rows)-1])
	}
}

// The state hash moves with token metadata (a revoke) and not with last use.
func TestWorkerTokensStateHash(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	c := e.mint(t, admin, "w-one", "proxy-1")
	ctx := context.Background()
	h1, err := e.srv.workerTokensStateHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e.store().MarkUsed(c.ID, time.Unix(1_800_000_500, 0))
	if err := e.store().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if h2, _ := e.srv.workerTokensStateHash(ctx); h2 != h1 {
		t.Error("the state hash moved with a last-used write")
	}
	if err := e.store().Revoke(ctx, c.ID, "x"); err != nil {
		t.Fatal(err)
	}
	if h3, _ := e.srv.workerTokensStateHash(ctx); h3 == h1 {
		t.Error("the state hash did not move with a revoke")
	}
}

// TestAuditSkipsWorkerRoutes: the admin audit middleware never wraps a
// worker-plane route, whatever credential it carries, and a worker token
// writes no row anywhere.
func TestAuditSkipsWorkerRoutes(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	c := e.mint(t, admin, "w-one", "proxy-1")
	before := len(e.rec.inputs())
	for _, bearer := range []string{dashTestToken, c.Token} {
		for range 20 {
			for _, rt := range []struct{ method, path, body string }{
				{http.MethodGet, "/policy", ""},
				{http.MethodPost, "/control/heartbeat", `{"policyETag":"x"}`},
				{http.MethodPost, "/central/ingest", `{"events":[]}`},
			} {
				rec := e.send("", bearer, rt.method, rt.path, rt.body)
				if rec.Header().Get(RequestIDHeader) != "" {
					t.Fatalf("%s went through the audit chain (has a request id)", rt.path)
				}
				if rec.Code >= 500 {
					t.Fatalf("%s = %d", rt.path, rec.Code)
				}
			}
		}
	}
	if n := len(e.rec.inputs()); n != before {
		t.Fatalf("worker-plane requests wrote %d audit rows", n-before)
	}
	for _, rt := range []string{"/policy", "/control/heartbeat", "/central/ingest"} {
		var found bool
		for k, row := range cpRouteTable() {
			if k.Path == rt {
				found = true
				if row.Class != classWorkerPlane || row.Audited {
					t.Errorf("%s is classified %q audited=%v, want worker-plane", rt, row.Class, row.Audited)
				}
			}
		}
		if !found {
			t.Errorf("%s has no route-table row", rt)
		}
	}
}

func TestWorkerViewAuthFields(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	c := e.mint(t, admin, "w-one", "tok-worker")
	// A token worker, a legacy worker (shared token + header, twice) and one
	// that has never authenticated successfully.
	if rec := e.workerGet("/policy", c.Token); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/policy", nil)
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		req.Header.Set(analytics.ProxyIDHeader, "legacy-worker")
		e.h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if err := e.store().Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var views []dashboard.WorkerView
	rec := e.send(admin, "", http.MethodGet, "/dashboard/api/workers", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatal(err)
	}
	by := map[string]dashboard.WorkerView{}
	for _, v := range views {
		by[v.ProxyID] = v
	}
	tw := by["tok-worker"]
	if tw.AuthKind != "token" || tw.TokenName != "w-one" || tw.TokenLastUsed == "" || tw.LegacyRequests != 0 {
		t.Errorf("token worker = %+v", tw)
	}
	lw := by["legacy-worker"]
	if lw.AuthKind != "legacy" || lw.TokenName != "" || lw.TokenLastUsed != "" || lw.LegacyRequests != 2 {
		t.Errorf("legacy worker = %+v", lw)
	}
	if !strings.Contains(rec.Body.String(), `"authKind":"token"`) || !strings.Contains(rec.Body.String(), `"legacyRequests":2`) {
		t.Errorf("workers JSON lacks the auth fields: %s", rec.Body.String())
	}
}

// Without a token store (no state dir) the routes answer 404 and the fleet
// view carries no token fields.
func TestWorkerTokensRoutesAbsentWithoutStore(t *testing.T) {
	e := newAuthzEnv(t)
	admin := e.session(t, groupAdmin)
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if rec := e.do(admin, m, wtPath, `{"name":"x","proxyID":"p"}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s without a store = %d, want 404", m, rec.Code)
		}
	}
	if rec := e.do(admin, http.MethodDelete, wtPath+"/wt_x", ""); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE without a store = %d, want 404", rec.Code)
	}
}
