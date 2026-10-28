package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
)

// The block list admin API (W-P1-BLOCK-11) on the control plane: the three
// routes over a real BlockStore, behind the bearer guard (console.auth none)
// or the oidc role table, with admin audit rows.

const blockAPIPath = "/dashboard/api/blocked-users"

// noneAPI is a console.auth none control plane with a state DB and the admin
// bearer, served over HTTP.
func noneAPI(t *testing.T, logs io.Writer) (*Server, *httptest.Server) {
	t.Helper()
	s := blockServer(t, logs, func(c *Config) { c.AdminToken = dashTestToken })
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func doJSON(t *testing.T, method, url, bearer, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

type blockPostResp struct {
	ID        string `json:"id"`
	Sub       string `json:"sub"`
	Email     string `json:"email"`
	Reason    string `json:"reason"`
	CreatedBy string `json:"createdBy"`
	CreatedAt string `json:"createdAt"`
	Hint      string `json:"hint"`
}

func TestBlockedUsers_PostWakesLongPoll(t *testing.T) {
	s, ts := noneAPI(t, nil)
	_ = s
	_, _, etag := getPolicy(t, ts.URL+"/policy", nil)

	type result struct {
		code int
		body []byte
		at   time.Time
	}
	done := make(chan result, 1)
	go func() {
		code, body, _ := getPolicy(t, ts.URL+"/policy?wait=5s", map[string]string{"If-None-Match": etag})
		done <- result{code, body, time.Now()}
	}()
	start := time.Now()
	code, body := doJSON(t, http.MethodPost, ts.URL+blockAPIPath, dashTestToken, `{"email":"alice@corp.com","reason":"offboarded"}`)
	if code != http.StatusCreated {
		t.Fatalf("POST = %d %s, want 201", code, body)
	}
	var resp blockPostResp
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID == "" || resp.Email != "alice@corp.com" || resp.Hint == "" || resp.CreatedBy != "cp-admin-token" {
		t.Errorf("POST body = %+v, want id, email, a hint and created_by cp-admin-token", resp)
	}
	select {
	case r := <-done:
		if r.code != http.StatusOK {
			t.Fatalf("long-poll = %d, want 200", r.code)
		}
		if d := r.at.Sub(start); d > time.Second {
			t.Errorf("long-poll woke after %s, want within 1s", d)
		}
		got := wireBlocked(t, r.body)
		if len(got) != 1 || got[0] != (config.BlockedUser{Email: "alice@corp.com"}) {
			t.Errorf("blockedUsers = %+v, want [{email alice@corp.com}]", got)
		}
		if strings.Contains(string(r.body), "reason") || strings.Contains(string(r.body), "offboarded") {
			t.Errorf("wire carries the reason: %s", r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll waiter not woken by POST")
	}

	// A sub in the request drops the hint.
	code, body = doJSON(t, http.MethodPost, ts.URL+blockAPIPath, dashTestToken, `{"sub":"u-42","email":"bob@corp.com","reason":"x"}`)
	if code != http.StatusCreated || strings.Contains(body, "hint") {
		t.Errorf("POST with sub and email = %d %s, want 201 without a hint", code, body)
	}
	// GET returns the envelope.
	code, body = doJSON(t, http.MethodGet, ts.URL+blockAPIPath, "", "")
	var list struct {
		Entries []blockPostResp `json:"entries"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &list) != nil || len(list.Entries) != 2 {
		t.Fatalf("GET = %d %s, want 200 with two entries", code, body)
	}
	// DELETE removes.
	if code, body := doJSON(t, http.MethodDelete, ts.URL+blockAPIPath+"/"+resp.ID, dashTestToken, ""); code != http.StatusNoContent {
		t.Errorf("DELETE = %d %s, want 204", code, body)
	}
}

// TestBlockedUsers_WriteGuard: console.auth none refuses a write without the
// bearer, with a wrong one, and (fail closed) when no token is configured.
func TestBlockedUsers_WriteGuard(t *testing.T) {
	s, ts := noneAPI(t, nil)
	for _, bearer := range []string{"", "wrong"} {
		if code, _ := doJSON(t, http.MethodPost, ts.URL+blockAPIPath, bearer, `{"email":"a@b.co"}`); code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Errorf("POST with bearer %q = %d, want 401/403", bearer, code)
		}
	}
	id, err := s.blocks.Add(context.Background(), BlockEntry{Email: "a@b.co"}, "cli:t")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := doJSON(t, http.MethodDelete, ts.URL+blockAPIPath+"/"+id, "", ""); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Errorf("DELETE without bearer = %d, want 401/403", code)
	}
	if l, _ := s.blocks.List(context.Background()); len(l) != 1 {
		t.Errorf("list has %d entries after refused writes, want 1", len(l))
	}

	open := blockServer(t, nil, nil) // no token at all
	ots := httptest.NewServer(open.Handler())
	defer ots.Close()
	if code, _ := doJSON(t, http.MethodPost, ots.URL+blockAPIPath, "", `{"email":"a@b.co"}`); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Errorf("POST with no token configured = %d, want a refusal", code)
	}
}

// oidcBlockEnv is the audited oidc control plane.
func oidcBlockEnv(t *testing.T) *auditEnv {
	t.Helper()
	return newOIDCAuditEnv(t)
}

func TestBlockedUsers_RBACAndAudit(t *testing.T) {
	e := oidcBlockEnv(t)
	viewer, editor, admin := e.session(t, groupViewer), e.session(t, groupEditor), e.session(t, groupAdmin)
	ctx := context.Background()
	id, err := e.srv.blocks.Add(ctx, BlockEntry{Email: "victim@corp.com"}, "cli:t")
	if err != nil {
		t.Fatal(err)
	}

	for name, sess := range map[string]string{"viewer": viewer, "editor": editor} {
		before := len(e.rec.inputs())
		for _, c := range []struct{ method, target, body string }{
			{http.MethodPost, blockAPIPath, `{"email":"x@corp.com"}`},
			{http.MethodDelete, blockAPIPath + "/" + id, ""},
		} {
			rec := e.send(sess, "", c.method, c.target, c.body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s = %d, want 403", name, c.method, c.target, rec.Code)
			}
		}
		if rec := e.send(sess, "", http.MethodGet, blockAPIPath, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s GET = %d, want 403", name, rec.Code)
		}
		rows := e.rec.inputs()[before:]
		if len(rows) != 2 {
			t.Fatalf("%s: %d audit rows, want 2 (the two writes): %+v", name, len(rows), rows)
		}
		for _, r := range rows {
			if r.Outcome != adminaudit.OutcomeDenied || r.HTTPStatus != http.StatusForbidden || r.Target != blockedUsersTarget {
				t.Errorf("%s row = %+v, want denied 403 on blocked_users", name, r)
			}
		}
	}
	if l, _ := e.srv.blocks.List(ctx); len(l) != 1 {
		t.Fatalf("denied writes changed the list: %d entries", len(l))
	}

	// No session and no bearer (the bearer never opens a human route in oidc).
	before := len(e.rec.inputs())
	for _, bearer := range []string{"", dashTestToken} {
		if rec := e.send("", bearer, http.MethodPost, blockAPIPath, `{"email":"x@corp.com"}`); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Errorf("unauthenticated POST (bearer %q) = %d, want 401/403", bearer, rec.Code)
		}
	}
	if got := len(e.rec.inputs()); got != before {
		t.Errorf("unauthenticated requests wrote %d rows, want 0", got-before)
	}

	// Admin add and remove: ok rows with differing hashes and a clean annotation.
	rec := e.send(admin, "", http.MethodPost, blockAPIPath, `{"sub":"s-1","email":"new@corp.com","reason":"incident"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin POST = %d %s", rec.Code, rec.Body)
	}
	var created blockPostResp
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.CreatedBy != "oidc:u1" {
		t.Errorf("created_by = %q, want oidc:u1", created.CreatedBy)
	}
	add := e.rec.inputs()[before]
	if add.Action != "blocked_users.add" || add.Outcome != adminaudit.OutcomeOK || add.Target != blockedUsersTarget ||
		add.BeforeHash == "" || add.AfterHash == "" || add.BeforeHash == add.AfterHash {
		t.Errorf("add row = %+v, want ok with differing hashes", add)
	}
	if add.TargetRef != "block:"+created.ID || add.Details["has_sub"] != "true" || add.Details["has_email"] != "true" {
		t.Errorf("add annotation = %q %v", add.TargetRef, add.Details)
	}
	if rec := e.send(admin, "", http.MethodDelete, blockAPIPath+"/"+id, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("admin DELETE = %d %s", rec.Code, rec.Body)
	}
	rm := e.rec.inputs()[before+1]
	if rm.Action != "blocked_users.remove" || rm.Outcome != adminaudit.OutcomeOK || rm.BeforeHash == rm.AfterHash || rm.TargetRef != "block:"+id {
		t.Errorf("remove row = %+v", rm)
	}
	if rec := e.send(admin, "", http.MethodGet, blockAPIPath, ""); rec.Code != http.StatusOK {
		t.Errorf("admin GET = %d", rec.Code)
	}
	if got := len(e.rec.inputs()); got != before+2 {
		t.Errorf("a GET wrote an audit row (%d rows)", got-before)
	}
}

func TestBlockedUsers_APIValidation(t *testing.T) {
	e := oidcBlockEnv(t)
	admin := e.session(t, groupAdmin) // sub u1, email u1@example.com
	post := func(body string) *httptest.ResponseRecorder {
		return e.send(admin, "", http.MethodPost, blockAPIPath, body)
	}
	if rec := post(`{"reason":"nothing to block"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("neither field = %d %s, want 400", rec.Code, rec.Body)
	}
	if rec := post(`{"email":"nope"}`); rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "policy.blockedUsers") {
		t.Errorf("email without @ = %d %s, want 400 in request wording", rec.Code, rec.Body)
	}
	for _, body := range []string{`{"email":"a@b.co","extra":1}`, `not json`, `{"email":"a@b.co"} {}`, `{"email":7}`} {
		if rec := post(body); rec.Code != http.StatusBadRequest {
			t.Errorf("body %q = %d, want 400", body, rec.Code)
		}
	}
	big := `{"email":"a@b.co","reason":"` + strings.Repeat("x", 9<<10) + `"}`
	if rec := post(big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body = %d, want 413", rec.Code)
	}
	if rec := post(`{"email":"Dup@Corp.com","reason":"r"}`); rec.Code != http.StatusCreated {
		t.Fatalf("first add = %d %s", rec.Code, rec.Body)
	}
	if rec := post(`{"email":"dup@corp.COM"}`); rec.Code != http.StatusConflict {
		t.Errorf("duplicate email in another case = %d, want 409", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodDelete, blockAPIPath+"/bu_0000000000000000", ""); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE unknown id = %d, want 404", rec.Code)
	}
	if rec := e.send(admin, "", http.MethodPut, blockAPIPath, `{}`); rec.Code == http.StatusCreated || rec.Code == http.StatusOK {
		t.Errorf("PUT = %d, want a refusal", rec.Code)
	}

	// Self-unblock: an entry matching the caller's email (any case) or sub
	// ends the caller's session (W-P1-BLOCK-07), so the caller cannot lift it.
	ctx := context.Background()
	for _, entry := range []BlockEntry{{Email: "U1@Example.com"}, {Sub: "u1"}} {
		admin = e.session(t, groupAdmin)
		id, err := e.srv.blocks.Add(ctx, entry, "cli:t")
		if err != nil {
			t.Fatal(err)
		}
		rec := e.send(admin, "", http.MethodDelete, blockAPIPath+"/"+id, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("self DELETE = %d %s, want 401 (the blocked caller's session is revoked)", rec.Code, rec.Body)
		}
		if l, _ := e.srv.blocks.List(ctx); !hasBlockID(l, id) {
			t.Error("the caller's own block was removed")
		}
		// Another admin may remove it.
		other := e.sessionAs(t, groupAdmin, "u2", "u2@example.com")
		if rec := e.send(other, "", http.MethodDelete, blockAPIPath+"/"+id, ""); rec.Code != http.StatusNoContent {
			t.Errorf("another admin DELETE = %d %s, want 204", rec.Code, rec.Body)
		}
	}

	// Limits: 422 above the count and above the byte budget.
	full := blockServer(t, nil, func(c *Config) { c.AdminToken = dashTestToken })
	fillBlocks(t, full, config.MaxBlockedUsers, 0)
	fts := httptest.NewServer(full.Handler())
	defer fts.Close()
	if code, body := doJSON(t, http.MethodPost, fts.URL+blockAPIPath, dashTestToken, `{"email":"over@corp.com"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("over the count = %d %s, want 422", code, body)
	}
	big2 := blockServer(t, nil, func(c *Config) { c.AdminToken = dashTestToken })
	fillBlocks(t, big2, 2000, 250)
	bts := httptest.NewServer(big2.Handler())
	defer bts.Close()
	if code, body := doJSON(t, http.MethodPost, bts.URL+blockAPIPath, dashTestToken, `{"email":"over@corp.com"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("over the bytes = %d %s, want 422", code, body)
	}
}

func hasBlockID(l []BlockEntry, id string) bool {
	for _, e := range l {
		if e.ID == id {
			return true
		}
	}
	return false
}

// TestBlockedUsers_BearerHasNoSelf: with the admin bearer there is no
// Principal, so deleting an entry never trips the self-unblock check.
func TestBlockedUsers_BearerHasNoSelf(t *testing.T) {
	s, ts := noneAPI(t, nil)
	id, err := s.blocks.Add(context.Background(), BlockEntry{Email: "admin@corp.com"}, "cli:t")
	if err != nil {
		t.Fatal(err)
	}
	if code, body := doJSON(t, http.MethodDelete, ts.URL+blockAPIPath+"/"+id, dashTestToken, ""); code != http.StatusNoContent {
		t.Errorf("bearer DELETE = %d %s, want 204", code, body)
	}
}

func TestBlockedUsers_ActorAndSelf(t *testing.T) {
	bg := WithPrincipal(context.Background(), Principal{Kind: PrincipalBreakglass, Sub: "root", Email: "root@corp.com"})
	if got := blockActor(bg); got != "breakglass:root" {
		t.Errorf("breakglass actor = %q", got)
	}
	if got := blockActor(context.Background()); got != "cp-admin-token" {
		t.Errorf("bearer actor = %q", got)
	}
	if !isSelf(bg, BlockEntry{Sub: "root"}) || !isSelf(bg, BlockEntry{Email: "root@corp.com"}) || isSelf(bg, BlockEntry{Sub: "other"}) {
		t.Error("break-glass self match is wrong")
	}
	if isSelf(context.Background(), BlockEntry{Sub: "root"}) {
		t.Error("a caller with no Principal has no self")
	}
}

func TestBlockedUsers_NoState(t *testing.T) {
	wantBody, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{PolicyPath: filepath.Join("testdata", "policy_overlay_none.yaml"), AdminToken: dashTestToken})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, blockAPIPath, ""},
		{http.MethodPost, blockAPIPath, `{"email":"a@b.co","reason":"r"}`},
		{http.MethodDelete, blockAPIPath + "/bu_1", ""},
	} {
		code, body := doJSON(t, c.method, ts.URL+c.path, dashTestToken, c.body)
		if code != http.StatusServiceUnavailable || !strings.Contains(body, `"state_dir_required"`) {
			t.Errorf("%s %s = %d %s, want 503 state_dir_required", c.method, c.path, code, body)
		}
	}
	code, body, _ := getPolicy(t, ts.URL+"/policy", nil)
	if code != http.StatusOK || !bytes.Equal(body, wantBody) {
		t.Errorf("/policy changed with the stub mounted: %d %s", code, body)
	}
}

// TestBlockedUsers_ReasonNotLogged: a request's reason text is in no log line,
// audit row or state-hash input, on add, list, remove and a refused add.
func TestBlockedUsers_ReasonNotLogged(t *testing.T) {
	const reason = "REASON-CANARY-7f3a"
	e := oidcBlockEnv(t)
	var hashed [][]byte
	e.srv.enableAdminAudit(e.rec, e.rec.probe, func(target string, data []byte) (string, error) {
		hashed = append(hashed, append([]byte(target+"\x00"), data...))
		return fakeMAC(target, data)
	})
	e.h = e.srv.Handler()
	admin, viewer := e.session(t, groupAdmin), e.session(t, groupViewer)

	rec := e.send(admin, "", http.MethodPost, blockAPIPath, `{"email":"r@corp.com","reason":"`+reason+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	var created blockPostResp
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	e.send(viewer, "", http.MethodPost, blockAPIPath, `{"email":"v@corp.com","reason":"`+reason+`"}`)
	e.send(admin, "", http.MethodPost, blockAPIPath, `{"email":"r@corp.com","reason":"`+reason+`"}`) // duplicate
	e.send(admin, "", http.MethodGet, blockAPIPath, "")
	e.send(admin, "", http.MethodDelete, blockAPIPath+"/"+created.ID, "")

	if strings.Contains(e.log.String(), reason) {
		t.Errorf("a log line carries the reason:\n%s", e.log)
	}
	if rows := e.rec.inputs(); strings.Contains(strings.TrimSpace(strings.Join(rowStrings(rows), "\n")), reason) {
		t.Errorf("an audit row carries the reason: %+v", rows)
	}
	if len(hashed) == 0 {
		t.Fatal("no state hash was computed")
	}
	for _, h := range hashed {
		if bytes.Contains(h, []byte(reason)) {
			t.Errorf("hash input carries the reason: %q", h)
		}
	}
}

func rowStrings(rows []adminaudit.Input) []string {
	b, _ := json.Marshal(rows)
	return []string{string(b)}
}

// sessionAs creates a session for another user in group.
func (e *auditEnv) sessionAs(t *testing.T, group, sub, email string) string {
	t.Helper()
	in := testSessionInput()
	in.Sub, in.Email, in.Groups = sub, email, []string{group}
	raw, _, err := e.srv.sessions.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
