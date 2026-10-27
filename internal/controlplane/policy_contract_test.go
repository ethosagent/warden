package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The policy version contract (W-P1-PVER-08) end to end through Server.Handler:
// GETs report the shared head, writes name it with If-Match, a stale write is
// a 409 policy_conflict naming the head's author, and the admin audit log
// records versioned saves as v<N>:<doc_sha256>.

// contractEnv is a versioned control plane after the initial import (head v1)
// with its HTTP handler. In oidc mode it has in-process sessions; otherwise
// writes carry the CP admin bearer, as in production.
type contractEnv struct {
	srv  *Server
	h    http.Handler
	oidc bool
	rec  *fakeRecorder // nil unless admin audit is on
}

func newContractEnv(t *testing.T, oidc, audit bool) *contractEnv {
	t.Helper()
	db := openPolicyState(t)
	console := config.ConsoleConfig{}
	if oidc {
		console = authzConsole(defaultRoles())
	}
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: db,
		PolicyStore: PolicyStoreVersioned, Console: console, Logger: testJSONLogger(nil),
	})
	if err := srv.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if oidc {
		srv.sessions = NewSessionStore(db.SQL(), time.Hour, 12*time.Hour, newFakeClock().Now)
		srv.sessionReader = srv.sessions
	}
	e := &contractEnv{srv: srv, oidc: oidc}
	if audit {
		e.rec = &fakeRecorder{}
		srv.enableAdminAudit(e.rec, e.rec.probe, fakeMAC)
	}
	e.h = srv.Handler()
	return e
}

// session creates an admin session for sub/email and returns its raw id.
func (e *contractEnv) session(t *testing.T, sub, email string) string {
	t.Helper()
	in := testSessionInput()
	in.Sub, in.Email, in.Groups = sub, email, []string{groupAdmin}
	raw, _, err := e.srv.sessions.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// send issues one request as rawID (oidc) or with the admin bearer (none;
// rawID "-" sends no credential). ifMatch "" sends no If-Match.
func (e *contractEnv) send(rawID, method, path, body, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	switch {
	case e.oidc && rawID != "" && rawID != "-":
		req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: rawID})
		if method != http.MethodGet {
			req.Header.Set(CSRFHeader, CSRFToken(rawID))
		}
	case !e.oidc && rawID != "-":
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// version is the head a GET of path reports, checking the header and the
// body agree.
func (e *contractEnv) version(t *testing.T, rawID, path string) int64 {
	t.Helper()
	rec := e.send(rawID, http.MethodGet, path, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, rec.Code, rec.Body.String())
	}
	var body struct {
		Version int64 `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if hdr := rec.Header().Get(dashboard.PolicyVersionHeader); hdr != strconv.FormatInt(body.Version, 10) {
		t.Fatalf("GET %s header %q, body version %d", path, hdr, body.Version)
	}
	return body.Version
}

func ifMatch(v int64) string { return fmt.Sprintf(`"v%d"`, v) }

func allowBody(domains ...string) string {
	entries := make([]string, len(domains))
	for i, d := range domains {
		entries[i] = `{"domain":"` + d + `"}`
	}
	return `{"allowlist":[` + strings.Join(entries, ",") + `],"denylist":[]}`
}

// advanceTo saves policy as rawID until head is target.
func (e *contractEnv) advanceTo(t *testing.T, rawID string, target int64) {
	t.Helper()
	for v := mustHead(t, e.srv.versions); v < target; v++ {
		body := allowBody("api.openai.com", fmt.Sprintf("v%d.example.com", v+1))
		if rec := e.send(rawID, http.MethodPost, "/dashboard/api/policy", body, ifMatch(v)); rec.Code != http.StatusOK {
			t.Fatalf("save to v%d = %d %s", v+1, rec.Code, rec.Body.String())
		}
	}
}

// conflictBody decodes a 409 policy_conflict body.
func conflictBody(t *testing.T, rec *httptest.ResponseRecorder) (head int64, author map[string]string) {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d %s, want 409", rec.Code, rec.Body.String())
	}
	var body struct {
		Error  string            `json:"error"`
		Head   int64             `json:"head"`
		Author map[string]string `json:"author"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "policy_conflict" {
		t.Fatalf("409 error = %q, want policy_conflict", body.Error)
	}
	if strings.Contains(rec.Body.String(), "allowlist") || strings.Contains(rec.Body.String(), "example.com") {
		t.Fatalf("409 body carries doc content: %s", rec.Body.String())
	}
	return body.Head, body.Author
}

// TestPolicyWriteConflict: two editors save from head v5; the second gets
// 409 naming v6 and the first editor as its author.
func TestPolicyWriteConflict(t *testing.T) {
	e := newContractEnv(t, true, false)
	alice := e.session(t, "u1", "a@x")
	bob := e.session(t, "u2", "b@x")
	e.advanceTo(t, alice, 5)
	if v := e.version(t, bob, "/dashboard/api/policy"); v != 5 {
		t.Fatalf("GET version = %d, want 5", v)
	}

	first := e.send(alice, http.MethodPut, "/dashboard/api/policy", allowBody("api.openai.com", "alice.example.com"), ifMatch(5))
	if first.Code != http.StatusOK || first.Header().Get(dashboard.PolicyVersionHeader) != "6" {
		t.Fatalf("first save = %d (version header %q) %s, want 200 at v6", first.Code, first.Header().Get(dashboard.PolicyVersionHeader), first.Body.String())
	}
	head, author := conflictBody(t, e.send(bob, http.MethodPut, "/dashboard/api/policy", allowBody("api.openai.com", "bob.example.com"), ifMatch(5)))
	if head != 6 || author["sub"] != "u1" || author["email"] != "a@x" {
		t.Fatalf("409 head %d author %v, want v6 by u1/a@x", head, author)
	}
	if h := mustHead(t, e.srv.versions); h != 6 {
		t.Fatalf("head = %d after the conflict, want 6", h)
	}
}

// TestPolicyIfMatchStale: replaying a save with the old If-Match is a 409 and
// creates no version, even when the body equals head.
func TestPolicyIfMatchStale(t *testing.T) {
	e := newContractEnv(t, false, false)
	e.advanceTo(t, "", 3)
	body := allowBody("api.openai.com", "replay.example.com")
	if rec := e.send("", http.MethodPost, "/dashboard/api/policy", body, ifMatch(3)); rec.Code != http.StatusOK {
		t.Fatalf("save = %d", rec.Code)
	}
	n := countRows(t, e.srv, "policy_versions")
	for range 2 {
		head, author := conflictBody(t, e.send("", http.MethodPost, "/dashboard/api/policy", body, ifMatch(3)))
		if head != 4 || author["sub"] != anonymousAuthorSub {
			t.Fatalf("replay 409 head %d author %v, want v4 by anonymous", head, author)
		}
	}
	if got := countRows(t, e.srv, "policy_versions"); got != n {
		t.Fatalf("%d versions after replays, want %d", got, n)
	}
	// The writer error unwraps to the store's ErrConflict.
	err := e.srv.WritePolicy(context.Background(), config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "x.example.com"}}}, dashboard.WriteMeta{ExpectedHead: 2})
	var ce *dashboard.ConflictError
	if !errors.As(err, &ce) || !errors.Is(err, ErrConflict) || ce.Head != 4 {
		t.Fatalf("stale WritePolicy = %v, want a ConflictError at v4 wrapping ErrConflict", err)
	}
}

// TestPolicyIfMatchCurrent: a save with the current If-Match creates a version
// authored by the session user. In console.auth none the bearer is required:
// a write without it is refused by the guard and creates nothing.
func TestPolicyIfMatchCurrent(t *testing.T) {
	t.Run("oidc", func(t *testing.T) {
		e := newContractEnv(t, true, false)
		raw := e.session(t, "u1", "a@x")
		v := e.version(t, raw, "/dashboard/api/policy")
		rec := e.send(raw, http.MethodPost, "/dashboard/api/policy", allowBody("api.openai.com", "cur.example.com"), ifMatch(v))
		if rec.Code != http.StatusOK {
			t.Fatalf("save = %d %s", rec.Code, rec.Body.String())
		}
		hv := headVersion(t, e.srv)
		if hv.Version != v+1 || hv.Author.Sub != "u1" || hv.Author.Email != "a@x" {
			t.Fatalf("head = v%d by %+v, want v%d by u1", hv.Version, hv.Author, v+1)
		}
		var body struct {
			Version int64 `json:"version"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Version != v+1 {
			t.Fatalf("save echo version = %d (%v), want %d", body.Version, err, v+1)
		}
		if rec := e.send("-", http.MethodPost, "/dashboard/api/policy", allowBody("api.openai.com"), ifMatch(v+1)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("write without a session = %d, want 401", rec.Code)
		}
	})
	t.Run("none", func(t *testing.T) {
		e := newContractEnv(t, false, false)
		if rec := e.send("-", http.MethodPost, "/dashboard/api/policy", allowBody("api.openai.com", "x.example.com"), ifMatch(1)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("write without the bearer = %d, want 401", rec.Code)
		}
		if h := mustHead(t, e.srv.versions); h != 1 {
			t.Fatalf("head = %d after a refused write, want 1", h)
		}
		if rec := e.send("", http.MethodPost, "/dashboard/api/policy", allowBody("api.openai.com", "x.example.com"), ifMatch(1)); rec.Code != http.StatusOK {
			t.Fatalf("save with the bearer = %d %s", rec.Code, rec.Body.String())
		}
		// A missing If-Match is still accepted (W-P1-PVER-04 makes it 428).
		if rec := e.send("", http.MethodPost, "/dashboard/api/policy", allowBody("api.openai.com", "y.example.com"), ""); rec.Code != http.StatusOK {
			t.Fatalf("save without If-Match = %d", rec.Code)
		}
		if h := mustHead(t, e.srv.versions); h != 3 {
			t.Fatalf("head = %d, want 3", h)
		}
	})
}

// TestPolicyIfMatchMalformed: a malformed If-Match is a 400 on every writer
// and creates nothing.
func TestPolicyIfMatchMalformed(t *testing.T) {
	e := newContractEnv(t, true, false)
	raw := e.session(t, "u1", "a@x")
	for path, body := range map[string]string{
		"/dashboard/api/policy":       allowBody("api.openai.com", "m.example.com"),
		"/dashboard/api/settings":     `{"agents":[{"id":"a1","policy":"read only"}]}`,
		"/dashboard/api/llmproviders": `[]`,
	} {
		for _, bad := range []string{"v1", `"1"`, `W/"v1"`, `*`} {
			if rec := e.send(raw, http.MethodPost, path, body, bad); rec.Code != http.StatusBadRequest {
				t.Errorf("%s If-Match %q = %d, want 400", path, bad, rec.Code)
			}
		}
	}
	if h := mustHead(t, e.srv.versions); h != 1 {
		t.Fatalf("head = %d, want 1", h)
	}
}

// TestSharedHeadConflict: policy, settings and llmProviders share one head,
// so a settings or llmProviders save makes a concurrent policy save based on
// the same version conflict.
func TestSharedHeadConflict(t *testing.T) {
	e := newContractEnv(t, true, false)
	alice := e.session(t, "u1", "a@x")
	bob := e.session(t, "u2", "b@x")
	saves := map[string]string{
		"/dashboard/api/settings":     `{"agents":[{"id":"a1","policy":"read only"}]}`,
		"/dashboard/api/llmproviders": `[{"name":"p1","baseURL":"https://api.openai.com/v1","model":"gpt-4o-mini","apiKeyEnv":"OPENAI_API_KEY"}]`,
	}
	for path, body := range saves {
		v := e.version(t, bob, "/dashboard/api/policy")
		for _, p := range []string{"/dashboard/api/settings", "/dashboard/api/llmproviders"} {
			if got := e.version(t, alice, p); got != v {
				t.Fatalf("GET %s version %d, policy %d: want one shared head", p, got, v)
			}
		}
		if rec := e.send(alice, http.MethodPost, path, body, ifMatch(v)); rec.Code != http.StatusOK {
			t.Fatalf("%s save = %d %s", path, rec.Code, rec.Body.String())
		}
		head, author := conflictBody(t, e.send(bob, http.MethodPost, "/dashboard/api/policy", allowBody("api.openai.com", "bob.example.com"), ifMatch(v)))
		if head != v+1 || author["sub"] != "u1" {
			t.Fatalf("after %s: policy 409 head %d author %v, want v%d by u1", path, head, author, v+1)
		}
	}
}

// TestPolicyHasherVersioned: with admin audit on, a versioned save writes one
// row whose before and after hashes are v<N>:<doc_sha256> of the old and new
// head.
func TestPolicyHasherVersioned(t *testing.T) {
	e := newContractEnv(t, false, true)
	v1 := headVersion(t, e.srv)
	if rec := e.send("", http.MethodPost, "/dashboard/api/policy", allowBody("api.openai.com", "h.example.com"), ifMatch(1)); rec.Code != http.StatusOK {
		t.Fatalf("save = %d %s", rec.Code, rec.Body.String())
	}
	v2 := headVersion(t, e.srv)
	rows := e.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("%d audit rows, want 1: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Target != auditTargetPolicy || r.Outcome != adminaudit.OutcomeOK ||
		r.BeforeHash != fmt.Sprintf("v1:%s", v1.DocSHA256) || r.AfterHash != fmt.Sprintf("v2:%s", v2.DocSHA256) {
		t.Fatalf("row target %q outcome %q before %q after %q, want policy ok v1:%s -> v2:%s",
			r.Target, r.Outcome, r.BeforeHash, r.AfterHash, v1.DocSHA256, v2.DocSHA256)
	}
	if !strings.HasPrefix(r.TargetRef, "policy@") {
		t.Errorf("row target_ref %q, want policy@<etag>", r.TargetRef)
	}

	// File mode keeps the built-in hasher (a keyed hash of allow/deny).
	f := newAuditEnv(t, auditEnvOpts{console: authzConsole(defaultRoles()), token: dashTestToken})
	h, err := f.srv.audit.stateHash(context.Background(), auditTargetPolicy)
	if err != nil || !strings.HasPrefix(h, adminaudit.StateHashPrefix) {
		t.Fatalf("file mode policy hash = %q (%v), want the keyed built-in hash", h, err)
	}
}

// TestPolicyConflictAudited: a 409 is recorded as outcome rejected with the
// head unchanged before and after.
func TestPolicyConflictAudited(t *testing.T) {
	e := newContractEnv(t, false, true)
	e.advanceTo(t, "", 2)
	v2 := headVersion(t, e.srv)
	rec := e.send("", http.MethodPost, "/dashboard/api/policy", allowBody("api.openai.com", "stale.example.com"), ifMatch(1))
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale save = %d, want 409", rec.Code)
	}
	rows := e.rec.inputs()
	if len(rows) != 2 {
		t.Fatalf("%d audit rows, want 2", len(rows))
	}
	r := rows[1]
	want := fmt.Sprintf("v2:%s", v2.DocSHA256)
	if r.Outcome != adminaudit.OutcomeRejected || r.HTTPStatus != http.StatusConflict || r.BeforeHash != want || r.AfterHash != want {
		t.Fatalf("conflict row outcome %q status %d before %q after %q, want rejected 409 %s both", r.Outcome, r.HTTPStatus, r.BeforeHash, r.AfterHash, want)
	}
}

// TestPolicyContractFileMode: in file mode the GETs carry no version and an
// If-Match is ignored.
func TestPolicyContractFileMode(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken})
	h := srv.Handler()
	for _, path := range []string{"/dashboard/api/policy", "/dashboard/api/settings", "/dashboard/api/llmproviders"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Header().Get(dashboard.PolicyVersionHeader) != "" || strings.Contains(rec.Body.String(), `"version"`) {
			t.Errorf("file mode GET %s carries a version: %v %s", path, rec.Header(), rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", strings.NewReader(allowBody("api.openai.com", "f.example.com")))
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	req.Header.Set("If-Match", "garbage")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("file mode save with an If-Match = %d %s, want 200", rec.Code, rec.Body.String())
	}
}
