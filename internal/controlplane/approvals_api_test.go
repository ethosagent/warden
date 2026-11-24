package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
)

// The change draft API (W-P2-APPR-04) over a real control plane: oidc console,
// versioned policy store, approvals on, admin audit recorded by a fake.

const draftsPath = "/dashboard/api/changes"

// draftEnv is a control plane with approvals on and sessions created through
// SessionStore.Create (no login flow).
type draftEnv struct {
	srv *Server
	h   http.Handler
	rec *fakeRecorder
	pub *recFindings
	// sessions by name: u1, u2, u3 (editors), viewer, admin, breakglass.
	raw map[string]string
}

func newDraftEnv(t *testing.T, mutate func(*config.ConsoleApprovals)) *draftEnv {
	return newDraftEnvAt(t, mutate, nil)
}

// newDraftEnvAt is newDraftEnv on the fake clock clk (nil = the real clock).
func newDraftEnvAt(t *testing.T, mutate func(*config.ConsoleApprovals), clk *clocktest.Fake) *draftEnv {
	t.Helper()
	ac := config.DefaultConsoleApprovals()
	ac.Enabled = true
	ac.MaxOpenDrafts = 20
	if mutate != nil {
		mutate(&ac)
	}
	console := authzConsole(defaultRoles())
	console.Approvals = ac
	db, err := cpstate.Open(context.Background(), t.TempDir()+"/warden-cp.db", stateMigrationsWithApprovals(StateMigrations(), ac))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logger, _ := testLogger()
	cfg := Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: db,
		PolicyStore: PolicyStoreVersioned, Console: console, Logger: logger,
	}
	if clk != nil {
		cfg.Clock = clk
	}
	srv := New(cfg)
	if srv.Approvals() == nil {
		t.Fatal("approvals service not built")
	}
	// Registered after the DB's cleanup, so it runs first.
	t.Cleanup(srv.Approvals().Replayer().Close)
	if err := srv.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.sessions = NewSessionStore(db.SQL(), time.Hour, 12*time.Hour, newFakeClock().Now)
	srv.sessionReader = srv.sessions
	e := &draftEnv{srv: srv, rec: &fakeRecorder{}, pub: &recFindings{}, raw: map[string]string{}}
	srv.findings = e.pub
	srv.enableAdminAudit(e.rec, e.rec.probe, fakeMAC)
	e.h = srv.Handler()
	for _, s := range []struct{ name, group, method string }{
		{"u1", groupEditor, "oidc"}, {"u2", groupEditor, "oidc"}, {"u3", groupEditor, "oidc"},
		{"viewer", groupViewer, "oidc"}, {"admin", groupAdmin, "oidc"}, {"breakglass", "", AuthMethodBreakglass},
	} {
		in := testSessionInput()
		in.Sub, in.Email, in.AuthMethod = s.name, s.name+"@example.com", s.method
		if s.group != "" {
			in.Groups = []string{s.group}
		} else {
			in.Groups = nil
		}
		if s.method == AuthMethodBreakglass {
			in.Sub = "breakglass:ops"
		}
		raw, _, err := srv.sessions.Create(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		e.raw[s.name] = raw
	}
	return e
}

// do sends a request as the named session ("" = none), with its CSRF token on
// every write. hdr is name, value pairs.
func (e *draftEnv) do(who, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if raw := e.raw[who]; raw != "" {
		req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: raw})
		if method != http.MethodGet {
			req.Header.Set(CSRFHeader, CSRFToken(raw))
		}
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

type draftErr struct {
	Error     string   `json:"error"`
	Need      string   `json:"need"`
	Fields    []string `json:"fields"`
	Head      int64    `json:"head"`
	Conflicts []string `json:"conflicts"`
}

func (e *draftEnv) wantErr(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) draftErr {
	t.Helper()
	b := decodeBody[draftErr](t, rec)
	if rec.Code != status || b.Error != code {
		t.Fatalf("response = %d %s, want %d %q", rec.Code, rec.Body.String(), status, code)
	}
	return b
}

// docWith is the head doc (api.openai.com allowed, evil.example.com denied)
// plus the given extra allow entries as JSON.
func docWith(extra ...string) string {
	allow := `{"domain":"api.openai.com"}`
	for _, x := range extra {
		allow += "," + x
	}
	return `{"allowlist":[` + allow + `],"denylist":[{"domain":"evil.example.com"}]}`
}

// create makes a draft as who and returns it.
func (e *draftEnv) create(t *testing.T, who, doc string) dashboard.ChangeDraftDetail {
	t.Helper()
	rec := e.do(who, http.MethodPost, draftsPath, `{"target":"policy","message":"test change","doc":`+doc+`}`, "If-Match", `"v1"`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	return decodeBody[dashboard.ChangeDraftDetail](t, rec)
}

func (e *draftEnv) submit(t *testing.T, who, id string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(who, http.MethodPost, draftsPath+"/"+id+"/submit", "")
}

// approveBody is an approve request for d citing replayID ("" = acknowledge).
func approveBody(d dashboard.ChangeDraftView, replayID, comment string) string {
	b, _ := json.Marshal(map[string]any{
		"revision": d.Revision, "doc_sha256": d.DocSHA256, "replay_id": replayID,
		"acknowledgeNoReplay": replayID == "", "comment": comment,
	})
	return string(b)
}

// settledReplay waits for the draft's replay and returns it.
func (e *draftEnv) settledReplay(t *testing.T, id string) approvals.Replay {
	t.Helper()
	return waitSettled(t, e.srv.Approvals(), id)
}

func (e *draftEnv) view(t *testing.T, id string) dashboard.ChangeDraftDetail {
	t.Helper()
	rec := e.do("viewer", http.MethodGet, draftsPath+"/"+id, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET draft = %d %s", rec.Code, rec.Body.String())
	}
	return decodeBody[dashboard.ChangeDraftDetail](t, rec)
}

func (e *draftEnv) head(t *testing.T) int64 {
	t.Helper()
	h, err := e.srv.versions.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (e *draftEnv) actions() []string {
	var out []string
	for _, in := range e.rec.inputs() {
		out = append(out, in.Action)
	}
	return out
}

// TestChangeDraftAPI walks the whole life of a widening draft over HTTP and
// then the refusals around it.
func TestChangeDraftAPI(t *testing.T) {
	e := newDraftEnv(t, nil)
	// Fleet events for the replay to compare.
	if err := e.srv.central.StoreAggregatedEvent(replayEvent("api.openai.com", "allow", "/v1")); err != nil {
		t.Fatal(err)
	}
	etagBefore := e.srv.policy.currentETag()

	d := e.create(t, "u1", docWith(`{"domain":"new.example.com"}`))
	if d.State != "draft" || d.Revision != 1 || !d.Widening || d.RequiredRole != "editor" || d.BaseVersion != 1 ||
		len(d.Reasons) != 1 || d.Reasons[0].Code != approvals.CodeAllowAdded {
		t.Fatalf("created draft = %+v", d.ChangeDraftView)
	}
	if strings.Contains(string(marshalJSON(t, d)), "secretAccessKey") {
		t.Error("a draft response names a credential field")
	}

	// The viewer reads it, lists it and sees the structural diff.
	if got := e.view(t, d.ID); got.ID != d.ID || len(got.ApprovalRows) != 0 {
		t.Errorf("GET draft = %+v", got)
	}
	list := decodeBody[struct {
		Drafts []dashboard.ChangeDraftView `json:"drafts"`
	}](t, e.do("viewer", http.MethodGet, draftsPath+"?target=policy&state=draft&limit=10", ""))
	if len(list.Drafts) != 1 || list.Drafts[0].ID != d.ID {
		t.Errorf("list = %+v", list)
	}
	diff := e.do("viewer", http.MethodGet, draftsPath+"/"+d.ID+"/diff", "")
	if diff.Code != http.StatusOK || !strings.Contains(diff.Body.String(), "new.example.com") || !strings.Contains(diff.Body.String(), `"base_version":1`) {
		t.Errorf("diff = %d %s", diff.Code, diff.Body.String())
	}

	// Submit queues a replay and raises the info Finding; the draft is pending.
	sub := e.submit(t, "u1", d.ID)
	if sub.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", sub.Code, sub.Body.String())
	}
	if r := decodeBody[dashboard.ChangeResult](t, sub); r.State != "pending" || r.Version != 0 {
		t.Errorf("submit result = %+v", r)
	}
	fs := e.pub.byRule("policy_approval_requested")
	if len(fs) != 1 || fs[0].Severity != integration.SevInfo || fs[0].DedupKey != "policy_approval_requested:"+d.ID {
		t.Errorf("approval finding = %+v", fs)
	}
	rp := e.settledReplay(t, d.ID)
	if rp.Status != approvals.ReplayDone {
		t.Fatalf("replay = %+v", rp)
	}

	// u2 approves, citing the replay, and the same request publishes.
	// A worker long-polling /policy with the old ETag gets the new one.
	polled := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/policy?wait=20s", nil)
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		req.Header.Set("If-None-Match", `"`+etagBefore+`"`)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		polled <- rec
	}()
	resp := e.do("u2", http.MethodPost, draftsPath+"/"+d.ID+"/approve", approveBody(d.ChangeDraftView, rp.ID, "looks right\x00\x07"))
	if resp.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", resp.Code, resp.Body.String())
	}
	res := decodeBody[dashboard.ChangeResult](t, resp)
	if res.State != "applied" || res.Version != 2 || resp.Header().Get(dashboard.PolicyVersionHeader) != "2" {
		t.Fatalf("approve result = %+v header %q", res, resp.Header().Get(dashboard.PolicyVersionHeader))
	}
	if e.head(t) != 2 || e.srv.policy.currentETag() == etagBefore {
		t.Errorf("head %d / etag unchanged after the approval", e.head(t))
	}
	select {
	case rec := <-polled:
		if rec.Code != http.StatusOK || strings.Trim(rec.Header().Get("ETag"), `"`) != e.srv.policy.currentETag() ||
			!strings.Contains(rec.Body.String(), "new.example.com") {
			t.Errorf("long-polling worker got %d etag %q, want 200 with the new policy", rec.Code, rec.Header().Get("ETag"))
		}
	case <-time.After(15 * time.Second):
		t.Error("the long-polling worker never received the new ETag")
	}
	v, err := e.srv.versions.Get(context.Background(), 2)
	if err != nil || v.Source != SourceApproval || v.Author.Sub != "u1" || !strings.HasPrefix(v.Message, "draft "+d.ID+"@r1: ") {
		t.Errorf("version 2 = %+v (%v), want source approval authored by u1", v, err)
	}
	if got := e.view(t, d.ID); got.State != "applied" || got.AppliedVersion != 2 || len(got.ApprovalRows) != 1 ||
		got.ApprovalRows[0].Comment != "looks right" || got.ApprovalRows[0].ReplayID != rp.ID || got.ApprovalRows[0].Approver.Sub != "u2" {
		t.Errorf("applied draft = %+v", got)
	}

	// The admin audit holds create, submit, approve in order, with the draft
	// ref and no doc content; the hashes move with the draft.
	rows := e.rec.inputs()
	if len(rows) != 4 || rows[0].Action != "change.draft.create" || rows[1].Action != "change.draft.submit" || rows[2].Action != "change.draft.approve" || rows[3].Action != "policy.write" {
		t.Fatalf("audit actions = %v, want create, submit, approve, policy.write", e.actions())
	}
	// The policy row follows the approval: the approver is the actor, the policy
	// hash moved, and it names the version and the approval source.
	if p := rows[3]; p.Target != "policy" || p.Actor.Sub != "u2" || p.Outcome != adminaudit.OutcomeOK || p.Details["applied_version"] != "2" ||
		p.Details["source"] != "approval" || p.BeforeHash == "" || p.BeforeHash == p.AfterHash || p.RequestID != rows[2].RequestID || !strings.HasPrefix(p.TargetRef, "policy@") {
		t.Errorf("policy row = %+v", p)
	}
	if rows[2].TargetRef != "draft:"+d.ID+"@r1" || rows[2].Target != "change_draft" || rows[2].Actor.Sub != "u2" || rows[2].Outcome != adminaudit.OutcomeOK {
		t.Errorf("approve row = %+v", rows[2])
	}
	if det := rows[2].Details; det["applied_version"] != "2" || det["base_version"] != "1" || det["widening"] != "true" ||
		det["reasons"] != approvals.CodeAllowAdded || det["replay_status"] != "done" || det["acknowledge_no_replay"] != "false" {
		t.Errorf("approve details = %v", det)
	}
	if rows[0].BeforeHash != "" || rows[0].AfterHash == "" {
		t.Errorf("create hashes = %q -> %q, want the draft to appear", rows[0].BeforeHash, rows[0].AfterHash)
	}
	if rows[2].BeforeHash == rows[2].AfterHash {
		t.Error("approve left the change_draft hash unchanged")
	}
	for _, r := range rows {
		if b, _ := json.Marshal(r); strings.Contains(string(b), "new.example.com") {
			t.Errorf("an audit row carries doc content: %s", b)
		}
	}
}

func marshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestChangeDraftAPIRefusals: the shape rules of every route.
func TestChangeDraftAPIRefusals(t *testing.T) {
	e := newDraftEnv(t, nil)
	d := e.create(t, "u1", docWith(`{"domain":"new.example.com"}`))
	path := draftsPath + "/" + d.ID

	// Authn / authz.
	if rec := e.do("", http.MethodGet, draftsPath, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session = %d, want 401", rec.Code)
	}
	if rec := e.do("viewer", http.MethodPost, draftsPath, `{}`, "If-Match", `"v1"`); rec.Code != http.StatusForbidden {
		t.Errorf("viewer create = %d, want 403", rec.Code)
	}
	if rec := e.do("viewer", http.MethodPost, path+"/approve", `{}`); rec.Code != http.StatusForbidden {
		t.Errorf("viewer approve = %d, want 403", rec.Code)
	}

	// Create: If-Match and body.
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath, `{"target":"policy","doc":`+docWith()+`}`), http.StatusPreconditionRequired, "precondition_required")
	if rec := e.do("u1", http.MethodPost, draftsPath, `{"target":"policy","doc":`+docWith()+`}`, "If-Match", `"7"`); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed If-Match = %d, want 400", rec.Code)
	}
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath, `{"target":"policy","doc":`+docWith()+`}`, "If-Match", `"v9"`), http.StatusBadRequest, "unknown_base_version")
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath, `{"target":"agents","doc":`+docWith()+`}`, "If-Match", `"v1"`), http.StatusBadRequest, "unsupported_target")
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath, `{"target":"policy","doc":{"allowlist":[],"denylist":[],"bogus":1}}`, "If-Match", `"v1"`), http.StatusBadRequest, "invalid_doc")
	if rec := e.do("u1", http.MethodPost, draftsPath, `{"target":"policy",`, "If-Match", `"v1"`); rec.Code != http.StatusBadRequest {
		t.Errorf("truncated JSON = %d, want 400", rec.Code)
	}
	huge := `{"target":"policy","message":"` + strings.Repeat("a", 1<<20) + `","doc":` + docWith() + `}`
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath, huge, "If-Match", `"v1"`), http.StatusRequestEntityTooLarge, "body_too_large")
	if rec := e.do("u1", http.MethodPost, draftsPath, `{"target":"policy","message":"`+strings.Repeat("m", 513)+`","doc":`+docWith()+`}`, "If-Match", `"v1"`); rec.Code != http.StatusBadRequest {
		t.Errorf("long message = %d, want 400", rec.Code)
	}

	// Unknown id, wrong method.
	e.wantErr(t, e.do("viewer", http.MethodGet, draftsPath+"/cd_missing", ""), http.StatusNotFound, "not_found")
	if rec := e.do("viewer", http.MethodGet, draftsPath+"/bad%20id", ""); rec.Code != http.StatusNotFound {
		t.Errorf("bad id = %d, want 404", rec.Code)
	}
	if rec := e.do("u1", http.MethodGet, path+"/submit", ""); rec.Code != http.StatusForbidden {
		t.Errorf("GET submit = %d, want 403 (no authz row for the method)", rec.Code)
	}

	// PUT: If-Match "r<rev>", author only, stale revision.
	put := `{"message":"edit","doc":` + docWith(`{"domain":"new.example.com"}`, `{"domain":"two.example.com"}`) + `}`
	e.wantErr(t, e.do("u1", http.MethodPut, path, put), http.StatusPreconditionRequired, "precondition_required")
	e.wantErr(t, e.do("u2", http.MethodPut, path, put, "If-Match", `"r1"`), http.StatusForbidden, "author_only")
	rec := e.do("u1", http.MethodPut, path, put, "If-Match", `"r1"`)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"r2"` {
		t.Fatalf("PUT = %d %s etag %q", rec.Code, rec.Body.String(), rec.Header().Get("ETag"))
	}
	d2 := decodeBody[dashboard.ChangeDraftDetail](t, rec)
	e.wantErr(t, e.do("u1", http.MethodPut, path, put, "If-Match", `"r1"`), http.StatusConflict, "revision_changed")

	// An approval of a draft that is not pending, then of a stale revision.
	e.wantErr(t, e.do("u2", http.MethodPost, path+"/approve", approveBody(d2.ChangeDraftView, "", "")), http.StatusConflict, "illegal_transition")
	if rec := e.do("u2", http.MethodPost, path+"/approve", `{"revision":0}`); rec.Code != http.StatusBadRequest {
		t.Errorf("approve without a revision = %d, want 400", rec.Code)
	}
	if rec := e.submit(t, "u1", d.ID); rec.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", rec.Code, rec.Body.String())
	}
	e.wantErr(t, e.submit(t, "u1", d.ID), http.StatusConflict, "illegal_transition")
	e.wantErr(t, e.submit(t, "u2", d.ID), http.StatusForbidden, "author_only")
	stale := d2.ChangeDraftView
	stale.Revision, stale.DocSHA256 = 1, d.DocSHA256
	e.wantErr(t, e.do("u2", http.MethodPost, path+"/approve", approveBody(stale, "", "")), http.StatusConflict, "revision_changed")
	if e.head(t) != 1 {
		t.Errorf("a refused approval created version %d", e.head(t))
	}
	if long := e.do("u2", http.MethodPost, path+"/approve", strings.Replace(approveBody(d2.ChangeDraftView, "", ""), `"comment":""`, `"comment":"`+strings.Repeat("c", 1025)+`"`, 1)); long.Code != http.StatusBadRequest {
		t.Errorf("long comment = %d, want 400", long.Code)
	}

	// Replay evidence: a draft with no done replay cannot be approved by
	// citing none or a made-up one; reject and withdraw end it.
	e.wantErr(t, e.do("u2", http.MethodPost, path+"/approve", approveBody(d2.ChangeDraftView, "nope", "")), http.StatusConflict, "replay_required")
	e.wantErr(t, e.do("u2", http.MethodPost, path+"/approve", `{"revision":2,"doc_sha256":"`+d2.DocSHA256+`"}`), http.StatusConflict, "replay_required")
	e.wantErr(t, e.do("u2", http.MethodPost, path+"/reject", `{"revision":1,"doc_sha256":"`+d.DocSHA256+`"}`), http.StatusConflict, "revision_changed")
	rj := e.do("u2", http.MethodPost, path+"/reject", `{"revision":2,"doc_sha256":"`+d2.DocSHA256+`","comment":"no"}`)
	if rj.Code != http.StatusOK || decodeBody[dashboard.ChangeResult](t, rj).State != "rejected" {
		t.Errorf("reject = %d %s", rj.Code, rj.Body.String())
	}
	e.wantErr(t, e.do("u1", http.MethodPost, path+"/withdraw", ""), http.StatusConflict, "illegal_transition")

	d3 := e.create(t, "u1", docWith(`{"domain":"three.example.com"}`))
	e.wantErr(t, e.do("u2", http.MethodPost, draftsPath+"/"+d3.ID+"/withdraw", ""), http.StatusForbidden, "author_only")
	wd := e.do("u1", http.MethodPost, draftsPath+"/"+d3.ID+"/withdraw", "", "If-Match", `"r1"`)
	if wd.Code != http.StatusOK || decodeBody[dashboard.ChangeResult](t, wd).State != "withdrawn" {
		t.Errorf("withdraw = %d %s", wd.Code, wd.Body.String())
	}
	// Rebase only applies to a draft that needs one.
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath+"/"+d3.ID+"/rebase", ""), http.StatusConflict, "illegal_transition")
	// A replay can be re-run only on an open draft by an editor.
	if rec := e.do("viewer", http.MethodPost, draftsPath+"/"+d3.ID+"/replay", ""); rec.Code != http.StatusForbidden {
		t.Errorf("viewer replay = %d, want 403", rec.Code)
	}
	e.wantErr(t, e.do("u1", http.MethodPost, draftsPath+"/"+d3.ID+"/replay", ""), http.StatusConflict, "illegal_transition")
	if rec := e.do("viewer", http.MethodGet, draftsPath+"?state=bogus", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad state filter = %d, want 400", rec.Code)
	}
}

// TestTwoPersonRule: who may approve.
func TestTwoPersonRule(t *testing.T) {
	e := newDraftEnv(t, nil)
	d := e.create(t, "u1", docWith(`{"domain":"new.example.com"}`))
	if rec := e.submit(t, "u1", d.ID); rec.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", rec.Code, rec.Body.String())
	}
	path := draftsPath + "/" + d.ID + "/approve"
	body := approveBody(d.ChangeDraftView, "", "")
	before := len(e.rec.inputs())

	// The author cannot approve their own change: 403 and a denied audit row.
	e.wantErr(t, e.do("u1", http.MethodPost, path, body), http.StatusForbidden, "self_approval_forbidden")
	rows := e.rec.inputs()
	if len(rows) != before+1 {
		t.Fatalf("self approval wrote %d rows", len(rows)-before)
	}
	if r := rows[len(rows)-1]; r.Action != "change.draft.approve" || r.Outcome != adminaudit.OutcomeDenied || r.HTTPStatus != http.StatusForbidden {
		t.Errorf("self approval row = %+v", r)
	}
	// A break-glass session is admin but can never approve.
	e.wantErr(t, e.do("breakglass", http.MethodPost, path, body), http.StatusForbidden, "breakglass_cannot_approve")
	if e.head(t) != 1 {
		t.Fatalf("a refused approval created version %d", e.head(t))
	}
	// Nothing was recorded for either.
	if got := e.view(t, d.ID); len(got.ApprovalRows) != 0 || got.State != "pending" {
		t.Errorf("draft after refusals = %+v", got)
	}
	// A different editor (acknowledging there is no replay: none exists with an
	// empty fleet) publishes.
	if rp := e.settledReplay(t, d.ID); rp.Status != approvals.ReplayUnavailable {
		t.Fatalf("replay = %+v, want unavailable with no events", rp)
	}
	ok := e.do("u2", http.MethodPost, path, body)
	if ok.Code != http.StatusOK || decodeBody[dashboard.ChangeResult](t, ok).Version != 2 {
		t.Fatalf("u2 approve = %d %s", ok.Code, ok.Body.String())
	}
	if got := e.view(t, d.ID); !got.ApprovalRows[0].AcknowledgeNoReplay {
		t.Errorf("approval = %+v, want the acknowledgement recorded", got.ApprovalRows)
	}
}

// A widening draft that adds an llmProviders entry needs an admin approver.
func TestTwoPersonRuleRoleRequired(t *testing.T) {
	e := newDraftEnv(t, nil)
	doc := `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"}],` +
		`"settings":{"llmProviders":[{"name":"p1","baseURL":"https://api.openai.com/v1","model":"gpt-4o-mini","apiKeyEnv":"OPENAI_API_KEY"}]}}`
	d := e.create(t, "u1", doc)
	if d.RequiredRole != "admin" {
		t.Fatalf("required role = %q, want admin", d.RequiredRole)
	}
	if rec := e.submit(t, "u1", d.ID); rec.Code != http.StatusOK {
		t.Fatalf("submit = %d %s", rec.Code, rec.Body.String())
	}
	path := draftsPath + "/" + d.ID + "/approve"
	body := approveBody(d.ChangeDraftView, "", "")
	b := e.wantErr(t, e.do("u2", http.MethodPost, path, body), http.StatusForbidden, "role_required")
	if b.Need != "admin" || len(b.Fields) != 1 || b.Fields[0] != "llmProviders" {
		t.Errorf("role_required = %+v, want admin naming llmProviders", b)
	}
	e.settledReplay(t, d.ID)
	if rec := e.do("admin", http.MethodPost, path, body); rec.Code != http.StatusOK || decodeBody[dashboard.ChangeResult](t, rec).State != "applied" {
		t.Fatalf("admin approve = %d %s", rec.Code, rec.Body.String())
	}
}

// With minApprovals 2 the approvers must be distinct and the last one applies.
func TestTwoPersonRuleMinApprovals(t *testing.T) {
	e := newDraftEnv(t, func(a *config.ConsoleApprovals) { a.MinApprovals = 2 })
	d := e.create(t, "u1", docWith(`{"domain":"new.example.com"}`))
	e.submit(t, "u1", d.ID)
	e.settledReplay(t, d.ID)
	path := draftsPath + "/" + d.ID + "/approve"
	body := approveBody(d.ChangeDraftView, "", "")

	first := e.do("u2", http.MethodPost, path, body)
	r := decodeBody[dashboard.ChangeResult](t, first)
	if first.Code != http.StatusOK || r.State != "pending" || r.Approvals != 1 || r.ApprovalsRequired != 2 {
		t.Fatalf("first approval = %d %+v", first.Code, r)
	}
	e.wantErr(t, e.do("u2", http.MethodPost, path, body), http.StatusConflict, "already_approved")
	if e.head(t) != 1 {
		t.Fatalf("one approver of two created version %d", e.head(t))
	}
	last := e.do("u3", http.MethodPost, path, body)
	if last.Code != http.StatusOK || decodeBody[dashboard.ChangeResult](t, last).Version != 2 {
		t.Fatalf("second approver = %d %s", last.Code, last.Body.String())
	}
}

// A narrowing draft applies at submit with decision self, queues no replay and
// raises no Finding; with allowSelfApproveNarrowing off it waits for a second
// person like any other.
func TestChangeDraftNarrowing(t *testing.T) {
	e := newDraftEnv(t, nil)
	d := e.create(t, "u1", `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"bad.example.com"}]}`)
	if d.Widening {
		t.Fatalf("adding a deny entry classified as widening: %+v", d.Reasons)
	}
	resp := e.submit(t, "u1", d.ID)
	r := decodeBody[dashboard.ChangeResult](t, resp)
	if resp.Code != http.StatusOK || r.State != "applied" || r.Version != 2 {
		t.Fatalf("narrowing submit = %d %+v", resp.Code, r)
	}
	if got := e.view(t, d.ID); len(got.ApprovalRows) != 1 || got.ApprovalRows[0].Decision != "self" || got.LatestReplay != nil {
		t.Errorf("narrowing draft = %+v, want one self decision and no replay", got)
	}
	if len(e.pub.byRule("policy_approval_requested")) != 0 {
		t.Error("a narrowing submit raised an approval Finding")
	}

	strict := newDraftEnv(t, func(a *config.ConsoleApprovals) { a.AllowSelfApproveNarrowing = false })
	d = strict.create(t, "u1", `{"allowlist":[{"domain":"api.openai.com"}],"denylist":[{"domain":"evil.example.com"},{"domain":"bad.example.com"}]}`)
	if r := decodeBody[dashboard.ChangeResult](t, strict.submit(t, "u1", d.ID)); r.State != "pending" {
		t.Fatalf("submit with self-approval off = %+v, want pending", r)
	}
}

// head moves after submit: approve is a 409 rebase_required, rebase makes
// revision 2 (earlier approvals void), and a key changed on both sides is a
// rebase_conflict.
func TestChangeDraftRebase(t *testing.T) {
	e := newDraftEnv(t, func(a *config.ConsoleApprovals) { a.MinApprovals = 2 })
	ctx := sessionCtx("someone", "someone@example.com")
	d := e.create(t, "u1", docWith(`{"domain":"mine.example.com"}`))
	e.submit(t, "u1", d.ID)
	e.settledReplay(t, d.ID)
	path := draftsPath + "/" + d.ID

	// u2 approves (1 of 2), then head moves under the draft.
	if rec := e.do("u2", http.MethodPost, path+"/approve", approveBody(d.ChangeDraftView, "", "")); rec.Code != http.StatusOK {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	if err := e.srv.WritePolicy(ctx, plusAllow(t, e.srv, "theirs.example.com"), dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	b := e.wantErr(t, e.do("u3", http.MethodPost, path+"/approve", approveBody(d.ChangeDraftView, "", "")), http.StatusConflict, "rebase_required")
	if b.Head != 2 {
		t.Errorf("rebase_required head = %d, want 2", b.Head)
	}
	if got := e.view(t, d.ID); got.State != "needs_rebase" {
		t.Fatalf("state = %s, want needs_rebase", got.State)
	}
	if e.head(t) != 2 {
		t.Errorf("head = %d, the refused approval must not publish", e.head(t))
	}

	// Only the author rebases; the merge keeps head's entry and the draft's.
	e.wantErr(t, e.do("u2", http.MethodPost, path+"/rebase", ""), http.StatusForbidden, "author_only")
	rb := e.do("u1", http.MethodPost, path+"/rebase", "")
	r := decodeBody[dashboard.ChangeResult](t, rb)
	if rb.Code != http.StatusOK || r.State != "pending" || r.Revision != 2 || r.BaseVersion != 2 || r.Approvals != 0 {
		t.Fatalf("rebase = %d %+v", rb.Code, r)
	}
	got := e.view(t, d.ID)
	doc, err := json.Marshal(got.Doc)
	if err != nil || !strings.Contains(string(doc), "theirs.example.com") || !strings.Contains(string(doc), "mine.example.com") {
		t.Errorf("rebased doc = %s (%v), want both entries", doc, err)
	}
	// The earlier approval was of revision 1: two fresh approvals are needed.
	e.settledReplay(t, d.ID)
	if got.LatestReplay != nil && got.LatestReplay.Revision != 2 {
		t.Errorf("latest replay is of revision %d", got.LatestReplay.Revision)
	}
	body2 := approveBody(got.ChangeDraftView, "", "")
	if first := decodeBody[dashboard.ChangeResult](t, e.do("u2", http.MethodPost, path+"/approve", body2)); first.State != "pending" || first.Approvals != 1 {
		t.Fatalf("u2 after the rebase = %+v, want 1 of 2 (the earlier approval is void)", first)
	}
	final := e.do("u3", http.MethodPost, path+"/approve", body2)
	if final.Code != http.StatusOK || decodeBody[dashboard.ChangeResult](t, final).Version != 3 {
		t.Fatalf("final approval = %d %s", final.Code, final.Body.String())
	}

	// A conflict: head and the draft both change the entry for one domain.
	c := e.create2(t, "u1", `{"domain":"clash.example.com","methods":["GET"]}`)
	e.submit(t, "u1", c.ID)
	if err := e.srv.WritePolicy(ctx, config.Policy{
		Allowlist: append(plusAllow(t, e.srv, "x").Allowlist[:len(plusAllow(t, e.srv, "x").Allowlist)-1], config.AllowlistEntry{Domain: "clash.example.com", Methods: []string{"POST"}}),
		Denylist:  plusAllow(t, e.srv, "x").Denylist,
	}, dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	e.settledReplay(t, c.ID)
	if rec := e.do("u2", http.MethodPost, draftsPath+"/"+c.ID+"/approve", approveBody(c.ChangeDraftView, "", "")); rec.Code != http.StatusOK {
		t.Fatalf("first approval = %d %s", rec.Code, rec.Body.String())
	}
	e.wantErr(t, e.do("u3", http.MethodPost, draftsPath+"/"+c.ID+"/approve", approveBody(c.ChangeDraftView, "", "")), http.StatusConflict, "rebase_required")
	conf := e.wantErr(t, e.do("u1", http.MethodPost, draftsPath+"/"+c.ID+"/rebase", ""), http.StatusConflict, "rebase_conflict")
	if len(conf.Conflicts) != 1 || !strings.Contains(conf.Conflicts[0], "clash.example.com") {
		t.Errorf("rebase_conflict = %+v, want the clashing key named", conf)
	}
	if got := e.view(t, c.ID); got.State != "needs_rebase" || got.Revision != 1 {
		t.Errorf("a conflicting rebase changed the draft: %+v", got.ChangeDraftView)
	}
}

// create2 creates a draft on the current head: the head doc plus extra.
func (e *draftEnv) create2(t *testing.T, who, extra string) dashboard.ChangeDraftDetail {
	t.Helper()
	head, doc, err := e.srv.headDoc(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(draftDoc(doc))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var allow []json.RawMessage
	_ = json.Unmarshal(m["allowlist"], &allow)
	allow = append(allow, json.RawMessage(extra))
	m["allowlist"], _ = json.Marshal(allow)
	raw, _ := json.Marshal(m)
	rec := e.do(who, http.MethodPost, draftsPath, `{"target":"policy","doc":`+string(raw)+`}`, "If-Match", `"v`+strconv.FormatInt(head, 10)+`"`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	return decodeBody[dashboard.ChangeDraftDetail](t, rec)
}

// Without approvals configured the routes answer 404 (a worker, or a control
// plane with the gate off).
func TestChangeDraftRoutesAbsentWithoutApprovals(t *testing.T) {
	e := newAuthzEnv(t)
	raw := e.session(t, groupAdmin)
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, draftsPath}, {http.MethodGet, draftsPath + "/cd_1"}, {http.MethodPost, draftsPath + "/cd_1/approve"},
	} {
		if rec := e.do(raw, rt.method, rt.path, "{}"); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", rt.method, rt.path, rec.Code)
		}
	}
}

// mergeDocs: a three-way merge by entry key and settings path.
func TestMergeDocs(t *testing.T) {
	allow := func(d string, methods ...string) config.AllowlistEntry {
		return config.AllowlistEntry{Domain: d, Methods: methods}
	}
	base := approvals.Doc{Allowlist: []config.AllowlistEntry{allow("a.com"), allow("b.com")}}
	draft := approvals.Doc{Allowlist: []config.AllowlistEntry{allow("a.com"), allow("d.com")}} // drops b, adds d
	head := approvals.Doc{Allowlist: []config.AllowlistEntry{allow("a.com"), allow("b.com"), allow("c.com")}}
	got, conflicts, err := mergeDocs(base, draft, head)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("merge = %v, %v", conflicts, err)
	}
	var domains []string
	for _, e := range got.Allowlist {
		domains = append(domains, e.Domain)
	}
	if strings.Join(domains, ",") != "a.com,c.com,d.com" {
		t.Errorf("merged allowlist = %v, want a, c, d", domains)
	}
	// Both sides changed b.com differently.
	head2 := approvals.Doc{Allowlist: []config.AllowlistEntry{allow("a.com"), allow("b.com", "GET")}}
	if _, conflicts, _ := mergeDocs(base, draft, head2); len(conflicts) != 1 || !strings.Contains(conflicts[0], "b.com") {
		t.Errorf("conflicts = %v", conflicts)
	}
	// Both sides made the same change: no conflict.
	if _, conflicts, _ := mergeDocs(base, draft, draft); len(conflicts) != 0 {
		t.Errorf("identical changes conflicted: %v", conflicts)
	}

	// Settings merge by path: the draft and head change different paths and
	// both stand; the same path to different values conflicts.
	ttl := func(n int) *int { return &n }
	bs := &config.SettingsWire{Logging: &config.LoggingSettings{Level: "info"}, CacheTTLSeconds: ttl(10)}
	ds := &config.SettingsWire{Logging: &config.LoggingSettings{Level: "debug"}, CacheTTLSeconds: ttl(10)}
	hs := &config.SettingsWire{Logging: &config.LoggingSettings{Level: "info"}, CacheTTLSeconds: ttl(30)}
	merged, conflicts, err := mergeDocs(approvals.Doc{Settings: bs}, approvals.Doc{Settings: ds}, approvals.Doc{Settings: hs})
	if err != nil || len(conflicts) != 0 || merged.Settings.Logging.Level != "debug" || *merged.Settings.CacheTTLSeconds != 30 {
		t.Errorf("settings merge = %+v, %v, %v", merged.Settings, conflicts, err)
	}
	hs.Logging.Level = "warn"
	if _, conflicts, _ := mergeDocs(approvals.Doc{Settings: bs}, approvals.Doc{Settings: ds}, approvals.Doc{Settings: hs}); len(conflicts) != 1 || !strings.Contains(conflicts[0], "logging") {
		t.Errorf("settings conflicts = %v", conflicts)
	}
}
