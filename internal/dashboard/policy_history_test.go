package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// The policy history routes (W-P1-PVER-03) against a fake PolicyHistory: the
// handlers parse and bound their input, map errors to fixed responses, and
// answer 404 wherever no history is wired (a worker, a file-mode CP).

// fakeHistory records its calls and returns err (nil: canned success).
type fakeHistory struct {
	err      error
	cursor   int64
	limit    int
	version  int64
	against  int64
	note     string
	meta     WriteMeta
	rollback RollbackResult
}

func (f *fakeHistory) List(_ context.Context, cursor int64, limit int) ([]PolicyVersionMeta, int64, error) {
	f.cursor, f.limit = cursor, limit
	if f.err != nil {
		return nil, 0, f.err
	}
	return []PolicyVersionMeta{{Version: 2, Parent: 1, Source: "policy"}, {Version: 1, Source: "import"}}, 0, nil
}

func (f *fakeHistory) Get(_ context.Context, v int64) (PolicyVersionDoc, error) {
	f.version = v
	if f.err != nil {
		return PolicyVersionDoc{}, f.err
	}
	return PolicyVersionDoc{PolicyVersionMeta: PolicyVersionMeta{Version: v}, Doc: map[string]any{"allowlist": []any{}}}, nil
}

func (f *fakeHistory) Diff(_ context.Context, v, against int64) (PolicyVersionDiff, error) {
	f.version, f.against = v, against
	if f.err != nil {
		return PolicyVersionDiff{}, f.err
	}
	return PolicyVersionDiff{From: max(against, 2), To: v, Diff: map[string]any{"allow": []any{}}}, nil
}

func (f *fakeHistory) Rollback(_ context.Context, v int64, note string, meta WriteMeta) (RollbackResult, error) {
	f.version, f.note, f.meta = v, note, meta
	if f.err != nil {
		return RollbackResult{}, f.err
	}
	return f.rollback, nil
}

func historyServer(h PolicyHistory) http.Handler {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetPolicyVersion(func(context.Context) (int64, error) { return 2, nil })
	if h != nil {
		srv.SetPolicyHistory(h)
	}
	return srv.Handler()
}

func historyReq(h http.Handler, method, target, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// historyCalls are the four routes as concrete requests.
var historyCalls = []struct{ method, target string }{
	{http.MethodGet, "/dashboard/api/policy/versions"},
	{http.MethodGet, "/dashboard/api/policy/versions/1"},
	{http.MethodGet, "/dashboard/api/policy/versions/1/diff"},
	{http.MethodPost, "/dashboard/api/policy/versions/1/rollback"},
}

// TestPolicyHistoryNotWired: without SetPolicyHistory (a worker dashboard, or
// a control plane in file mode) the four routes answer 404, never the index
// page.
func TestPolicyHistoryNotWired(t *testing.T) {
	worker := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	worker.SetWriteGuard(AllowUngatedWritesForTests)
	for name, h := range map[string]http.Handler{"worker": worker.Handler(), "file-mode": historyServer(nil)} {
		for _, c := range historyCalls {
			rec := historyReq(h, c.method, c.target, "{}", "If-Match", `"v2"`)
			if rec.Code != http.StatusNotFound || strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
				t.Errorf("%s: %s %s = %d %q, want a 404", name, c.method, c.target, rec.Code, rec.Header().Get("Content-Type"))
			}
		}
	}
}

func TestPolicyHistoryList(t *testing.T) {
	f := &fakeHistory{}
	h := historyServer(f)
	rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions", "")
	if rec.Code != http.StatusOK || rec.Header().Get(PolicyVersionHeader) != "2" {
		t.Fatalf("list = %d (header %q) %s", rec.Code, rec.Header().Get(PolicyVersionHeader), rec.Body.String())
	}
	var body struct {
		Head       int64               `json:"head"`
		Versions   []PolicyVersionMeta `json:"versions"`
		NextCursor int64               `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Head != 2 || len(body.Versions) != 2 || body.Versions[0].Version != 2 {
		t.Fatalf("list body %+v (%v)", body, err)
	}
	if f.cursor != 0 || f.limit != defaultHistoryLimit {
		t.Fatalf("default page = cursor %d limit %d, want 0 and %d", f.cursor, f.limit, defaultHistoryLimit)
	}
	if rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions?cursor=7&limit=500", ""); rec.Code != http.StatusOK || f.cursor != 7 || f.limit != maxHistoryLimit {
		t.Fatalf("limit=500 = %d, cursor %d limit %d, want clamped to %d", rec.Code, f.cursor, f.limit, maxHistoryLimit)
	}
	for _, q := range []string{"limit=0", "limit=-1", "limit=abc", "cursor=x", "cursor=-3", "limit=1e3"} {
		if rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions?"+q, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400", q, rec.Code)
		}
	}
	f.err = errors.New("disk on fire at /var/lib/warden")
	if rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions", ""); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "disk") {
		t.Fatalf("store error = %d %s, want a fixed 500", rec.Code, rec.Body.String())
	}
}

func TestPolicyHistoryGetAndDiff(t *testing.T) {
	f := &fakeHistory{}
	h := historyServer(f)
	if rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions/3", ""); rec.Code != http.StatusOK || f.version != 3 || !strings.Contains(rec.Body.String(), `"doc":{"allowlist":[]}`) {
		t.Fatalf("get = %d %s (version %d)", rec.Code, rec.Body.String(), f.version)
	}
	rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions/1/diff", "")
	if rec.Code != http.StatusOK || f.version != 1 || f.against != 0 || !strings.Contains(rec.Body.String(), `"from":2,"to":1`) {
		t.Fatalf("diff = %d %s (against %d), want against head", rec.Code, rec.Body.String(), f.against)
	}
	if rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions/1/diff?against=5", ""); rec.Code != http.StatusOK || f.against != 5 {
		t.Fatalf("diff against=5 = %d (against %d)", rec.Code, f.against)
	}
	if rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions/1/diff?against=x", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("against=x = %d, want 400", rec.Code)
	}
	for _, p := range []string{"abc", "0", "-1", "1.5", "99999999999999999999"} {
		if rec := historyReq(h, http.MethodGet, "/dashboard/api/policy/versions/"+p, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("GET versions/%s = %d, want 400", p, rec.Code)
		}
	}
	for _, p := range []string{"/dashboard/api/policy/versions/1/", "/dashboard/api/policy/versions/1/other", "/dashboard/api/policy/versions/1/diff/x"} {
		if rec := historyReq(h, http.MethodGet, p, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
	f.err = ErrPolicyVersionNotFound
	for _, c := range historyCalls[1:3] {
		if rec := historyReq(h, c.method, c.target, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s unknown version = %d, want 404", c.method, c.target, rec.Code)
		}
	}
}

func TestPolicyHistoryMethods(t *testing.T) {
	h := historyServer(&fakeHistory{})
	for _, c := range []struct{ method, target string }{
		{http.MethodPost, "/dashboard/api/policy/versions"},
		{http.MethodPut, "/dashboard/api/policy/versions/1"},
		{http.MethodPost, "/dashboard/api/policy/versions/1/diff"},
		{http.MethodGet, "/dashboard/api/policy/versions/1/rollback"},
		{http.MethodDelete, "/dashboard/api/policy/versions/1/rollback"},
	} {
		if rec := historyReq(h, c.method, c.target, "{}"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", c.method, c.target, rec.Code)
		}
	}
}

func TestPolicyHistoryRollbackHandler(t *testing.T) {
	f := &fakeHistory{rollback: RollbackResult{Head: 3, Changed: true}}
	h := historyServer(f)
	const path = "/dashboard/api/policy/versions/1/rollback"

	rec := historyReq(h, http.MethodPost, path, "")
	if rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), "precondition_required") || f.version != 0 {
		t.Fatalf("no If-Match = %d %s, want 428 without a call", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{"v2", `"2"`, `W/"v2"`, "*"} {
		if rec := historyReq(h, http.MethodPost, path, "", "If-Match", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("If-Match %q = %d, want 400", bad, rec.Code)
		}
	}
	rec = historyReq(h, http.MethodPost, path, `{"note":"undo\u0000 the\nbad edit"}`, "If-Match", `"v2"`)
	if rec.Code != http.StatusOK || rec.Header().Get(PolicyVersionHeader) != "3" || !strings.Contains(rec.Body.String(), `"head":3,"changed":true`) {
		t.Fatalf("rollback = %d %s", rec.Code, rec.Body.String())
	}
	if f.version != 1 || f.meta.ExpectedHead != 2 || f.note != "undo thebad edit" {
		t.Fatalf("rollback call = v%d expected %d note %q", f.version, f.meta.ExpectedHead, f.note)
	}
	// An empty body is allowed (no note).
	if rec := historyReq(h, http.MethodPost, path, "", "If-Match", `"v2"`); rec.Code != http.StatusOK || f.note != "" {
		t.Fatalf("empty body = %d note %q", rec.Code, f.note)
	}
	long := `{"note":"` + strings.Repeat("é", maxRollbackNote+1) + `"}`
	if rec := historyReq(h, http.MethodPost, path, long, "If-Match", `"v2"`); rec.Code != http.StatusBadRequest {
		t.Fatalf("long note = %d, want 400", rec.Code)
	}
	if rec := historyReq(h, http.MethodPost, path, `{"note":"`+strings.Repeat("é", maxRollbackNote)+`"}`, "If-Match", `"v2"`); rec.Code != http.StatusOK {
		t.Fatalf("512-char note = %d, want 200", rec.Code)
	}
	for _, body := range []string{"{", `{"note":3}`, `{"note":"` + strings.Repeat("a", maxRollbackBody) + `"}`} {
		if rec := historyReq(h, http.MethodPost, path, body, "If-Match", `"v2"`); rec.Code != http.StatusBadRequest {
			t.Errorf("body %.20q = %d, want 400", body, rec.Code)
		}
	}

	for _, c := range []struct {
		err    error
		status int
		want   string
	}{
		{ErrPolicyVersionNotFound, http.StatusNotFound, "not found"},
		{&InvalidPolicyError{Err: errors.New("policy: allowlist is empty")}, http.StatusUnprocessableEntity, "allowlist is empty"},
		{&ConflictError{Head: 4, Author: ConflictAuthor{Sub: "u9"}}, http.StatusConflict, `"policy_conflict"`},
		{&RoleRequiredError{Need: "admin"}, http.StatusForbidden, "role_required"},
		{errors.New("sqlite: database is locked"), http.StatusInternalServerError, "policy history error"},
	} {
		f.err = c.err
		rec := historyReq(h, http.MethodPost, path, "", "If-Match", `"v2"`)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.want) || strings.Contains(rec.Body.String(), "sqlite") {
			t.Errorf("rollback error %v = %d %s, want %d with %q", c.err, rec.Code, rec.Body.String(), c.status, c.want)
		}
	}
}

func TestRoutePath(t *testing.T) {
	for in, want := range map[string]string{
		"/dashboard/api/policy/versions":                 "/dashboard/api/policy/versions",
		"/dashboard/api/policy/versions/3":               "/dashboard/api/policy/versions/{v}",
		"/dashboard/api/policy/versions/abc":             "/dashboard/api/policy/versions/{v}",
		"/dashboard/api/policy/versions/{v}":             "/dashboard/api/policy/versions/{v}",
		"/dashboard/api/policy/versions/3/diff":          "/dashboard/api/policy/versions/{v}/diff",
		"/dashboard/api/policy/versions/3/rollback":      "/dashboard/api/policy/versions/{v}/rollback",
		"/dashboard/api/policy/versions/":                "/dashboard/api/policy/versions/",
		"/dashboard/api/policy/versions/3/":              "/dashboard/api/policy/versions/3/",
		"/dashboard/api/policy/versions/3/other":         "/dashboard/api/policy/versions/3/other",
		"/dashboard/api/policy/versions/3/rollback/x":    "/dashboard/api/policy/versions/3/rollback/x",
		"/dashboard/api/policy/versions//rollback":       "/dashboard/api/policy/versions//rollback",
		"/dashboard/api/policy":                          "/dashboard/api/policy",
		"/dashboard/api/settings":                        "/dashboard/api/settings",
		"/dashboard/api/policy/versionsX/3":              "/dashboard/api/policy/versionsX/3",
		"/dashboard/api/policy/versions/3/diff?against=": "/dashboard/api/policy/versions/3/diff?against=",
	} {
		if got := RoutePath(in); got != want {
			t.Errorf("RoutePath(%q) = %q, want %q", in, got, want)
		}
	}
}
