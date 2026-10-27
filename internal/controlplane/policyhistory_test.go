package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The policy history API (W-P1-PVER-03) end to end through Server.Handler:
// list, get and diff for viewers, rollback for editors as a new version
// through the versioned publish path, with If-Match, admin audit and the
// credential and serve-time overlays left as they are.

// stubHistory is a PolicyHistory whose every call succeeds; it lets a test
// reach the rollback route without a versioned store.
type stubHistory struct{}

func (stubHistory) List(context.Context, int64, int) ([]dashboard.PolicyVersionMeta, int64, error) {
	return nil, 0, nil
}

func (stubHistory) Get(_ context.Context, v int64) (dashboard.PolicyVersionDoc, error) {
	return dashboard.PolicyVersionDoc{PolicyVersionMeta: dashboard.PolicyVersionMeta{Version: v}}, nil
}

func (stubHistory) Diff(_ context.Context, v, against int64) (dashboard.PolicyVersionDiff, error) {
	return dashboard.PolicyVersionDiff{From: against, To: v}, nil
}

func (stubHistory) Rollback(_ context.Context, _ int64, _ string, meta dashboard.WriteMeta) (dashboard.RollbackResult, error) {
	return dashboard.RollbackResult{Head: meta.ExpectedHead}, nil
}

// historyEnvOpts configures newHistoryEnv.
type historyEnvOpts struct {
	oidc, audit bool
	policyPath  string    // "" = writePolicyFile
	logs        io.Writer // nil discards
	// overlay, when set, is registered as a serve-time overlay before the
	// handler is built (as W-P1-BLOCK-03 registers blocked_users in New).
	overlay *wireOverlay
}

// newHistoryEnv is a versioned control plane after the initial import (head
// v1), as newContractEnv, with the options above.
func newHistoryEnv(t *testing.T, o historyEnvOpts) *contractEnv {
	t.Helper()
	db := openPolicyState(t)
	console := config.ConsoleConfig{}
	if o.oidc {
		console = authzConsole(defaultRoles())
	}
	if o.policyPath == "" {
		o.policyPath = writePolicyFile(t, "api.openai.com")
	}
	srv := New(Config{
		PolicyPath: o.policyPath, Token: dashTestToken, State: db,
		PolicyStore: PolicyStoreVersioned, Console: console, Logger: testJSONLogger(o.logs),
	})
	if o.overlay != nil {
		// New sealed registration with its initial load; reopen it for the
		// test overlay and load again, so it is part of every served wire.
		srv.policy.sealed.Store(false)
		if err := srv.policy.addOverlay(*o.overlay); err != nil {
			t.Fatal(err)
		}
		srv.policy.Refresh()
	}
	if err := srv.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o.oidc {
		srv.sessions = NewSessionStore(db.SQL(), time.Hour, 12*time.Hour, newFakeClock().Now)
		srv.sessionReader = srv.sessions
	}
	e := &contractEnv{srv: srv, oidc: o.oidc}
	if o.audit {
		e.rec = &fakeRecorder{}
		srv.enableAdminAudit(e.rec, e.rec.probe, fakeMAC)
	}
	e.h = srv.Handler()
	return e
}

// sessionAs creates a session in group for sub and returns its raw id.
func sessionAs(t *testing.T, e *contractEnv, sub, group string) string {
	t.Helper()
	in := testSessionInput()
	in.Sub, in.Email, in.Groups = sub, sub+"@example.com", []string{group}
	raw, _, err := e.srv.sessions.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rollbackPath(v int64) string {
	return fmt.Sprintf("/dashboard/api/policy/versions/%d/rollback", v)
}

// rollbackBody decodes a 200 rollback response.
func rollbackBody(t *testing.T, rec *httptest.ResponseRecorder) dashboard.RollbackResult {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d %s, want 200", rec.Code, rec.Body.String())
	}
	var res dashboard.RollbackResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func versionAt(t *testing.T, s *Server, v int64) PolicyVersion {
	t.Helper()
	pv, err := s.versions.Get(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	return pv
}

// TestPolicyRollback: given versions 1 to 3, an editor's rollback to v1 with
// If-Match "v3" creates v4 with v1's doc, and a worker long-polling /policy
// gets the new ETag within one wait cycle. Rolling back again is a no-op.
func TestPolicyRollback(t *testing.T) {
	e := newHistoryEnv(t, historyEnvOpts{oidc: true})
	editor := sessionAs(t, e, "ed1", groupEditor)
	e.advanceTo(t, editor, 3)
	v1 := versionAt(t, e.srv, 1)

	ts := httptest.NewServer(e.h)
	t.Cleanup(ts.Close)
	auth := map[string]string{"Authorization": "Bearer " + dashTestToken}
	_, _, etag := getPolicy(t, ts.URL+"/policy", auth)
	type poll struct {
		code int
		etag string
		err  error
	}
	woke := make(chan poll, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/policy?wait=5s", nil)
		if err != nil {
			woke <- poll{err: err}
			return
		}
		req.Header.Set("Authorization", auth["Authorization"])
		req.Header.Set("If-None-Match", etag)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			woke <- poll{err: err}
			return
		}
		_ = resp.Body.Close()
		woke <- poll{code: resp.StatusCode, etag: resp.Header.Get("ETag")}
	}()

	rec := e.send(editor, http.MethodPost, rollbackPath(1), "", ifMatch(3))
	if res := rollbackBody(t, rec); res.Head != 4 || !res.Changed {
		t.Fatalf("rollback = %+v, want head 4 changed", res)
	}
	if got := rec.Header().Get(dashboard.PolicyVersionHeader); got != "4" {
		t.Fatalf("rollback version header = %q, want 4", got)
	}
	v4 := headVersion(t, e.srv)
	if v4.Version != 4 || v4.Parent != 3 || v4.Source != SourceRollback || v4.Message != "rollback to v1" ||
		v4.Author.Sub != "ed1" || v4.DocSHA256 != v1.DocSHA256 {
		t.Fatalf("v4 = %+v, want parent 3, source rollback, message 'rollback to v1', author ed1, doc_sha256 %s", v4, v1.DocSHA256)
	}
	select {
	case p := <-woke:
		if p.err != nil || p.code != http.StatusOK || p.etag == "" || strings.Trim(p.etag, `"`) == etag {
			t.Fatalf("long poll = %d etag %q (err %v), want 200 with a new ETag (old %q)", p.code, p.etag, p.err, etag)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-polling worker did not get the rollback within one wait cycle")
	}

	// Rolling back to the doc head already has creates nothing.
	n := countRows(t, e.srv, "policy_versions")
	if res := rollbackBody(t, e.send(editor, http.MethodPost, rollbackPath(1), "", ifMatch(4))); res.Head != 4 || res.Changed {
		t.Fatalf("no-op rollback = %+v, want head 4 unchanged", res)
	}
	if got := countRows(t, e.srv, "policy_versions"); got != n {
		t.Fatalf("%d versions after a no-op rollback, want %d", got, n)
	}
}

// TestPolicyHistoryRoles: a viewer can list, get and diff; a viewer's
// rollback is 403 and recorded as denied; an editor's rollback succeeds.
func TestPolicyHistoryRoles(t *testing.T) {
	e := newHistoryEnv(t, historyEnvOpts{oidc: true, audit: true})
	editor := sessionAs(t, e, "ed1", groupEditor)
	viewer := sessionAs(t, e, "vw1", groupViewer)
	e.advanceTo(t, editor, 2)
	for _, p := range []string{
		"/dashboard/api/policy/versions",
		"/dashboard/api/policy/versions/1",
		"/dashboard/api/policy/versions/1/diff",
		"/dashboard/api/policy/versions/1/diff?against=2",
	} {
		if rec := e.send(viewer, http.MethodGet, p, "", ""); rec.Code != http.StatusOK {
			t.Errorf("viewer GET %s = %d %s, want 200", p, rec.Code, rec.Body.String())
		}
	}
	before := len(e.rec.inputs())
	rec := e.send(viewer, http.MethodPost, rollbackPath(1), "", ifMatch(2))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer rollback = %d %s, want 403", rec.Code, rec.Body.String())
	}
	rows := e.rec.inputs()[before:]
	if len(rows) != 1 || rows[0].Action != "policy.rollback" || rows[0].Target != auditTargetPolicy ||
		rows[0].Outcome != adminaudit.OutcomeDenied || rows[0].Actor.Sub != "vw1" {
		t.Fatalf("denied rollback rows = %+v, want one policy.rollback outcome=denied by vw1", rows)
	}
	if h := mustHead(t, e.srv.versions); h != 2 {
		t.Fatalf("head = %d after a denied rollback, want 2", h)
	}
	// No session at all: 401, nothing created.
	if rec := e.send("-", http.MethodPost, rollbackPath(1), "", ifMatch(2)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rollback without a session = %d, want 401", rec.Code)
	}
	if res := rollbackBody(t, e.send(editor, http.MethodPost, rollbackPath(1), "", ifMatch(2))); res.Head != 3 {
		t.Fatalf("editor rollback = %+v, want head 3", res)
	}
}

// TestPolicyRollbackAudited: a rollback writes one admin audit row for target
// policy with before v3:<sha> and after v4:<sha>, and one log line naming the
// versions and the actor, never doc content.
func TestPolicyRollbackAudited(t *testing.T) {
	var logs bytes.Buffer
	e := newHistoryEnv(t, historyEnvOpts{audit: true, logs: &logs})
	e.advanceTo(t, "", 3)
	v3 := headVersion(t, e.srv)
	before := len(e.rec.inputs())
	rollbackBody(t, e.send("", http.MethodPost, rollbackPath(1), `{"note":"bad deploy"}`, ifMatch(3)))
	v4 := headVersion(t, e.srv)
	if v4.Message != "rollback to v1: bad deploy" {
		t.Fatalf("v4 message = %q", v4.Message)
	}
	rows := e.rec.inputs()[before:]
	if len(rows) != 1 {
		t.Fatalf("%d audit rows, want 1: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Action != "policy.rollback" || r.Target != auditTargetPolicy || r.Outcome != adminaudit.OutcomeOK ||
		r.BeforeHash != fmt.Sprintf("v3:%s", v3.DocSHA256) || r.AfterHash != fmt.Sprintf("v4:%s", v4.DocSHA256) {
		t.Fatalf("row = action %q target %q outcome %q before %q after %q, want policy.rollback policy ok v3:%s -> v4:%s",
			r.Action, r.Target, r.Outcome, r.BeforeHash, r.AfterHash, v3.DocSHA256, v4.DocSHA256)
	}
	if !strings.HasPrefix(r.TargetRef, "policy@") {
		t.Errorf("row target_ref %q, want policy@<etag>", r.TargetRef)
	}
	var line map[string]any
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, `"msg":"policy rollback"`) {
			if err := json.Unmarshal([]byte(l), &line); err != nil {
				t.Fatal(err)
			}
		}
	}
	if line == nil || line["from_head"] != float64(3) || line["to_version"] != float64(1) || line["new_head"] != float64(4) ||
		line["actor_sub"] != anonymousAuthorSub {
		t.Fatalf("rollback log line = %v, want from_head 3 to_version 1 new_head 4 actor_sub anonymous", line)
	}
	if strings.Contains(logs.String(), "v3.example.com") {
		t.Fatal("a log line carries doc content")
	}
}

// TestPolicyRollbackKeepsCredentialAndOverlays: a rollback past a credential
// rotation keeps the current credential, a serve-time overlay is identical
// before and after, and no response or log line holds a raw secretAccessKey.
func TestPolicyRollbackKeepsCredentialAndOverlays(t *testing.T) {
	var logs bytes.Buffer
	blocked := wireOverlay{name: "blocked_users", apply: func(_ context.Context, w *policyWire) (string, error) {
		w.Denylist = append(append([]config.DenylistEntry(nil), w.Denylist...), config.DenylistEntry{Domain: "blocked.example"})
		return "fp-blocked-users", nil
	}}
	e := newHistoryEnv(t, historyEnvOpts{policyPath: writeCredentialPolicyFile(t), logs: &logs, overlay: &blocked})
	const rotated = "sk-live-PVER03-rotated"
	in := awsSettings(rotated)
	in.Agents = []config.AgentSettings{{ID: "a1", Policy: "read only"}}
	if err := e.srv.WriteSettings(context.Background(), in, dashboard.WriteMeta{ExpectedHead: 1}); err != nil {
		t.Fatal(err)
	}
	if got := servedSecret(t, e.srv); got != rotated {
		t.Fatal("the rotated credential is not served")
	}
	overlayBefore := e.srv.policy.overlayFingerprints()
	var bodies []string
	keep := func(rec *httptest.ResponseRecorder) *httptest.ResponseRecorder {
		bodies = append(bodies, rec.Body.String())
		return rec
	}

	res := rollbackBody(t, keep(e.send("", http.MethodPost, rollbackPath(1), "", ifMatch(2))))
	if res.Head != 3 || !res.Changed {
		t.Fatalf("rollback = %+v, want head 3", res)
	}
	if got := servedSecret(t, e.srv); got != rotated {
		t.Fatal("the rollback restored the old credential; it must keep the current one")
	}
	v3 := headVersion(t, e.srv)
	if v3.Doc.Settings == nil || v3.Doc.Settings.Secrets == nil || v3.Doc.Settings.Secrets.SecretAccessKey != redactCredential(rotated) {
		t.Fatalf("v3 credential = %+v, want the rotated key's fingerprint", v3.Doc.Settings)
	}
	if v3.Doc.Settings.Agents != nil {
		t.Fatalf("v3 agents = %+v, want v1's (none)", v3.Doc.Settings.Agents)
	}
	overlayAfter := e.srv.policy.overlayFingerprints()
	if overlayBefore["blocked_users"] != "fp-blocked-users" || overlayAfter["blocked_users"] != overlayBefore["blocked_users"] {
		t.Fatalf("blocked_users overlay before %v after %v, want identical", overlayBefore, overlayAfter)
	}
	w, _, _, _ := e.srv.policy.snapshot()
	found := false
	for _, d := range w.Denylist {
		found = found || d.Domain == "blocked.example"
	}
	if !found {
		t.Fatalf("served denylist %+v lost the blocked_users overlay", w.Denylist)
	}

	for _, p := range []string{
		"/dashboard/api/policy/versions",
		"/dashboard/api/policy/versions/1",
		"/dashboard/api/policy/versions/2",
		"/dashboard/api/policy/versions/3",
		"/dashboard/api/policy/versions/1/diff",
		"/dashboard/api/policy/versions/2/diff?against=1",
	} {
		if rec := keep(e.send("", http.MethodGet, p, "", "")); rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", p, rec.Code, rec.Body.String())
		}
	}
	for _, b := range append(bodies, logs.String()) {
		if strings.Contains(b, policyStoreSecret) || strings.Contains(b, rotated) {
			t.Fatalf("a response or log line carries a raw secretAccessKey: %.300s", b)
		}
	}
}

// TestPolicyHistoryAPI: the read routes' shapes, and every rollback refusal:
// unknown v 404, non-integer v 400, stale If-Match 409, missing If-Match 428,
// a target that no longer validates 422; none creates a version.
func TestPolicyHistoryAPI(t *testing.T) {
	e := newHistoryEnv(t, historyEnvOpts{})
	e.advanceTo(t, "", 2)
	// v3 holds a doc today's loader refuses (an empty allowlist): stored
	// directly, as if it were valid under an older rule.
	if _, _, err := e.srv.versions.Create(context.Background(), policyWire{}, testAuthor, "old rules", SourcePolicy, 2); err != nil {
		t.Fatal(err)
	}
	e.advanceTo(t, "", 4)

	rec := e.send("", http.MethodGet, "/dashboard/api/policy/versions?limit=2", "", "")
	var page struct {
		Head       int64            `json:"head"`
		Versions   []map[string]any `json:"versions"`
		NextCursor int64            `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s (%v)", rec.Code, rec.Body.String(), err)
	}
	if page.Head != 4 || len(page.Versions) != 2 || page.Versions[0]["version"] != float64(4) || page.NextCursor != 3 {
		t.Fatalf("list page = %+v, want head 4, v4 and v3, next cursor 3", page)
	}
	for _, k := range []string{"version", "parent", "created_at", "author_sub", "author_email", "author_kind", "message", "source", "doc_sha256"} {
		if _, ok := page.Versions[0][k]; !ok {
			t.Errorf("list entry has no %q: %v", k, page.Versions[0])
		}
	}
	if _, ok := page.Versions[0]["doc"]; ok {
		t.Error("list entries carry the doc; they are metadata only")
	}
	rec = e.send("", http.MethodGet, "/dashboard/api/policy/versions?cursor=3", "", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Versions) != 2 || page.Versions[0]["version"] != float64(2) || page.NextCursor != 0 {
		t.Fatalf("page after cursor 3 = %+v (%v), want v2, v1 and no next", page, err)
	}
	if rec := e.send("", http.MethodGet, "/dashboard/api/policy/versions/2", "", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"doc":{"allowlist":[`) || !strings.Contains(rec.Body.String(), "v2.example.com") {
		t.Fatalf("get v2 = %d %s", rec.Code, rec.Body.String())
	}
	rec = e.send("", http.MethodGet, "/dashboard/api/policy/versions/2/diff", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"from":4,"to":2`) || !strings.Contains(rec.Body.String(), "v4.example.com") {
		t.Fatalf("diff v2 against head = %d %s", rec.Code, rec.Body.String())
	}

	n := countRows(t, e.srv, "policy_versions")
	for _, c := range []struct {
		method, path, ifMatch string
		status                int
	}{
		{http.MethodGet, "/dashboard/api/policy/versions/99", "", http.StatusNotFound},
		{http.MethodGet, "/dashboard/api/policy/versions/99/diff", "", http.StatusNotFound},
		{http.MethodGet, "/dashboard/api/policy/versions/1/diff?against=99", "", http.StatusNotFound},
		{http.MethodGet, "/dashboard/api/policy/versions/abc", "", http.StatusBadRequest},
		{http.MethodPost, rollbackPath(99), ifMatch(4), http.StatusNotFound},
		{http.MethodPost, "/dashboard/api/policy/versions/v1/rollback", ifMatch(4), http.StatusBadRequest},
		{http.MethodPost, rollbackPath(1), ifMatch(3), http.StatusConflict},
		{http.MethodPost, rollbackPath(3), ifMatch(2), http.StatusConflict}, // stale wins over invalid
		{http.MethodPost, rollbackPath(1), "", http.StatusPreconditionRequired},
		{http.MethodPost, rollbackPath(3), ifMatch(4), http.StatusUnprocessableEntity},
	} {
		rec := e.send("", c.method, c.path, "", c.ifMatch)
		if rec.Code != c.status {
			t.Errorf("%s %s (If-Match %s) = %d %s, want %d", c.method, c.path, c.ifMatch, rec.Code, rec.Body.String(), c.status)
		}
		if c.status == http.StatusUnprocessableEntity && !strings.Contains(rec.Body.String(), "allowlist") {
			t.Errorf("422 body %s does not carry the loader error", rec.Body.String())
		}
		if c.status == http.StatusConflict {
			if head, _ := conflictBody(t, rec); head != 4 {
				t.Errorf("409 head = %d, want 4", head)
			}
		}
	}
	if got := countRows(t, e.srv, "policy_versions"); got != n {
		t.Fatalf("%d versions after refused rollbacks, want %d", got, n)
	}
	// console.auth none: a rollback without the CP bearer is refused.
	if rec := e.send("-", http.MethodPost, rollbackPath(1), "", ifMatch(4)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rollback without the bearer = %d, want 401", rec.Code)
	}
	if h := mustHead(t, e.srv.versions); h != 4 {
		t.Fatalf("head = %d, want 4", h)
	}
}

// TestPolicyHistoryNotWiredFileMode: a file-mode control plane serves none of
// the four routes (404), with or without credentials.
func TestPolicyHistoryNotWiredFileMode(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken})
	h := srv.Handler()
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/policy/versions"},
		{http.MethodGet, "/dashboard/api/policy/versions/1"},
		{http.MethodGet, "/dashboard/api/policy/versions/1/diff"},
		{http.MethodPost, rollbackPath(1)},
	} {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		req.Header.Set("If-Match", ifMatch(1))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("file mode %s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
}
