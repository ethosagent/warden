package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/dashboard"
)

const enPath = "/dashboard/api/worker-enrollments"

type enCreated struct {
	dashboard.EnrollmentView
	Token string `json:"token"`
}

// mintEnroll creates an enrollment token as the admin session and returns the
// decoded 201 body.
func (e *auditEnv) mintEnroll(t *testing.T, admin, body string) enCreated {
	t.Helper()
	rec := e.send(admin, "", http.MethodPost, enPath, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST %s %s = %d %s, want 201", enPath, body, rec.Code, rec.Body.String())
	}
	var c enCreated
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnrollmentsAdminAPI(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)

	rec := e.send(admin, "", http.MethodGet, enPath, "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list = %d %q, want 200 []", rec.Code, rec.Body.String())
	}
	c := e.mintEnroll(t, admin, `{"name":"en-one","workerId":"worker-1"}`)
	if !strings.HasPrefix(c.Token, "wet_") || c.Name != "en-one" || c.WorkerID != "worker-1" || c.CreatedBy != "u1" ||
		c.MaxUses != 1 || c.Uses != 0 || c.ExpiresAt == "" || c.ID == "" {
		t.Fatalf("created = %+v", c.EnrollmentView)
	}
	p := e.mintEnroll(t, admin, `{"name":"en-pool","workerIdPrefix":"pool-","maxUses":4,"expiresIn":"2h"}`)
	if p.WorkerIDPrefix != "pool-" || p.WorkerID != "" || p.MaxUses != 4 {
		t.Fatalf("pool created = %+v", p.EnrollmentView)
	}

	var list []dashboard.EnrollmentView
	rec = e.send(admin, "", http.MethodGet, enPath, "")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("list = %s (%v)", rec.Body.String(), err)
	}

	for name, body := range map[string]string{
		"duplicate name":   `{"name":"en-one","workerId":"worker-2"}`,
		"no binding":       `{"name":"x"}`,
		"both bindings":    `{"name":"x","workerId":"w","workerIdPrefix":"p-"}`,
		"no name":          `{"workerId":"w"}`,
		"bad worker id":    `{"name":"x","workerId":"bad id"}`,
		"uses on id token": `{"name":"x","workerId":"w","maxUses":2}`,
		"too many uses":    `{"name":"x","workerIdPrefix":"p-","maxUses":101}`,
		"ttl over the cap": `{"name":"x","workerId":"w","expiresIn":"48h"}`,
		"unknown field":    `{"name":"x","workerId":"w","extra":1}`,
	} {
		want := http.StatusBadRequest
		if name == "duplicate name" {
			want = http.StatusConflict
		}
		if rec := e.send(admin, "", http.MethodPost, enPath, body); rec.Code != want {
			t.Errorf("%s: POST %s = %d %s, want %d", name, body, rec.Code, rec.Body.String(), want)
		}
	}
	if rec := e.send(admin, "", http.MethodDelete, enPath+"/et_nope", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}

	// Revoke: 204, revokedAt in the next GET, idempotent, and the token no
	// longer resolves (what POST /control/enroll answers 401 on).
	if _, err := e.srv.cfg.Enrollment.(*EnrollmentStore).Peek(c.Token); err != nil {
		t.Fatalf("a new token does not resolve: %v", err)
	}
	for i := 0; i < 2; i++ {
		if rec := e.send(admin, "", http.MethodDelete, enPath+"/"+c.ID, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("DELETE #%d = %d, want 204", i+1, rec.Code)
		}
	}
	rec = e.send(admin, "", http.MethodGet, enPath, "")
	list = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, v := range list {
		if (v.ID == c.ID) != (v.RevokedAt != "") {
			t.Errorf("revokedAt of %s = %q", v.ID, v.RevokedAt)
		}
	}
	if _, err := e.srv.cfg.Enrollment.(*EnrollmentStore).Peek(c.Token); err == nil {
		t.Error("a revoked token still resolves")
	}
}

func TestEnrollmentsAdminRoles(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	c := e.mintEnroll(t, admin, `{"name":"en-one","workerId":"worker-1"}`)
	// Admin only, for reads too: the list names workers and pools.
	for _, g := range []string{groupViewer, groupEditor, "g-unmapped"} {
		raw := e.session(t, g)
		for _, req := range []struct{ method, path string }{
			{http.MethodGet, enPath},
			{http.MethodPost, enPath},
			{http.MethodDelete, enPath + "/" + c.ID},
		} {
			if rec := e.send(raw, "", req.method, req.path, `{"name":"x","workerId":"w"}`); rec.Code != http.StatusForbidden {
				t.Errorf("%s as %s = %d, want 403", req.method, g, rec.Code)
			}
		}
	}
	// No session: refused, and a bearer (admin or worker) never stands in.
	for _, bearer := range []string{"", dashTestToken, c.Token} {
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			path := enPath
			if m == http.MethodDelete {
				path += "/" + c.ID
			}
			if rec := e.send("", bearer, m, path, `{"name":"x","workerId":"w"}`); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s with no session (bearer %q...) = %d, want 401", m, bearer[:min(len(bearer), 4)], rec.Code)
			}
		}
	}
	toks, _ := e.srv.cfg.Enrollment.List(context.Background())
	if len(toks) != 1 || !toks[0].RevokedAt.IsZero() {
		t.Errorf("a refused request changed the store: %+v", toks)
	}
}

// console.auth none has no identity to attribute a mint to: POST and DELETE
// are 403 pointing at the CLI, GET still lists.
func TestEnrollmentsAdminAuthNone(t *testing.T) {
	e := newAuditEnv(t, auditEnvOpts{token: "worker-shared", adminToken: dashTestToken})
	for _, m := range []string{http.MethodPost, http.MethodDelete} {
		path := enPath
		if m == http.MethodDelete {
			path += "/et_x"
		}
		rec := e.send("", dashTestToken, m, path, `{"name":"x","workerId":"w"}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"use_cli"`) || !strings.Contains(rec.Body.String(), "warden control-plane enroll-token") {
			t.Errorf("%s with the admin bearer = %d %s, want 403 use_cli", m, rec.Code, rec.Body.String())
		}
		if rec := e.send("", "worker-shared", m, path, `{}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with the shared worker token = %d, want 401", m, rec.Code)
		}
	}
	if rec := e.send("", "", http.MethodGet, enPath, ""); rec.Code != http.StatusOK {
		t.Errorf("GET in none mode = %d, want 200", rec.Code)
	}
	if toks, _ := e.srv.cfg.Enrollment.List(context.Background()); len(toks) != 0 {
		t.Errorf("a use_cli refusal minted %d tokens", len(toks))
	}
}

// TestEnrollmentsAudit: one row per write, with the target, action and
// target_ref the CLI uses, and never the token or its hash anywhere: not in the
// 201 of a later GET, a row, a state hash input or a log line.
func TestEnrollmentsAudit(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	var hashed []string
	e.srv.audit.mac = func(target string, data []byte) (string, error) {
		hashed = append(hashed, string(data))
		return fakeMAC(target, data)
	}

	rec := e.send(admin, "", http.MethodPost, enPath, `{"name":"en-one","workerId":"worker-1"}`)
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create = %d, Cache-Control %q; want 201 no-store", rec.Code, rec.Header().Get("Cache-Control"))
	}
	var c enCreated
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || !enrollWellFormed(c.Token) {
		t.Fatalf("201 body has no well-formed token: %v", err)
	}
	sum := sha256.Sum256([]byte(c.Token))
	secrets := []string{c.Token, hex.EncodeToString(sum[:])}

	rows := e.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("create wrote %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.Action != "worker_enroll_token.create" || r.Target != "worker_enrollments" || r.TargetRef != "enroll_token:"+c.ID ||
		r.Outcome != adminaudit.OutcomeOK || r.HTTPStatus != http.StatusCreated || r.Actor.Sub != "u1" ||
		r.ActorRole != "admin" || r.AuthMethod != adminaudit.AuthMethodOIDC {
		t.Errorf("create row = %+v", r)
	}
	if r.BeforeHash == "" || r.AfterHash == "" || r.BeforeHash == r.AfterHash {
		t.Errorf("create hashes before=%q after=%q, want both set and different", r.BeforeHash, r.AfterHash)
	}

	list := e.send(admin, "", http.MethodGet, enPath, "")
	if rec := e.send(admin, "", http.MethodDelete, enPath+"/"+c.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	rows = e.rec.inputs()
	if len(rows) != 2 {
		t.Fatalf("after revoke %d rows, want 2 (a GET writes none)", len(rows))
	}
	v := rows[1]
	if v.Action != "worker_enroll_token.revoke" || v.Target != "worker_enrollments" || v.TargetRef != "enroll_token:"+c.ID ||
		v.HTTPStatus != http.StatusNoContent || v.Actor.Sub != "u1" || v.BeforeHash == v.AfterHash {
		t.Errorf("revoke row = %+v", v)
	}
	// A refused write is a denied row with unchanged hashes.
	e.send(e.session(t, groupViewer), "", http.MethodPost, enPath, `{"name":"y","workerId":"w"}`)
	rows = e.rec.inputs()
	if len(rows) != 3 || rows[2].Outcome != adminaudit.OutcomeDenied || rows[2].BeforeHash != rows[2].AfterHash {
		t.Errorf("rows after a denied POST: %d, last %+v", len(rows), rows[len(rows)-1])
	}

	check := func(what, got string) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(got, s) {
				t.Errorf("%s contains the token or its sha256", what)
			}
		}
	}
	check("GET list", list.Body.String())
	check("logs", e.log.String())
	check("audit rows", fmt.Sprintf("%+v", e.rec.inputs()))
	check("hasher input", strings.Join(hashed, "\n"))
	if len(hashed) == 0 {
		t.Error("the worker_enrollments hasher was never called")
	}
}

// The state hash moves with token metadata (a revoke) and not with use.
func TestEnrollmentsStateHash(t *testing.T) {
	e := newOIDCAuditEnv(t)
	admin := e.session(t, groupAdmin)
	c := e.mintEnroll(t, admin, `{"name":"en-pool","workerIdPrefix":"pool-","maxUses":3}`)
	ctx := context.Background()
	h1, err := e.srv.enrollmentsStateHash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := e.srv.cfg.Enrollment.(*EnrollmentStore)
	if _, err := store.db.ExecContext(ctx, `UPDATE worker_enroll_tokens SET uses = 1 WHERE id = ?`, c.ID); err != nil {
		t.Fatal(err)
	}
	if h2, _ := e.srv.enrollmentsStateHash(ctx); h2 != h1 {
		t.Error("the state hash moved with a use")
	}
	if err := store.Revoke(ctx, c.ID, "x"); err != nil {
		t.Fatal(err)
	}
	if h3, _ := e.srv.enrollmentsStateHash(ctx); h3 == h1 {
		t.Error("the state hash did not move with a revoke")
	}
}
