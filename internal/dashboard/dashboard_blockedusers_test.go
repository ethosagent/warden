package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// fakeBlockList is a BlockListStore with a canned error.
type fakeBlockList struct {
	entries []BlockListEntry
	err     error
	added   []BlockListAdd
	noCap   []string
}

func (f *fakeBlockList) WorkersWithoutEnforcement(context.Context) (int, []string) {
	return len(f.noCap), f.noCap
}

func (f *fakeBlockList) List(context.Context) ([]BlockListEntry, error) { return f.entries, f.err }

func (f *fakeBlockList) Add(_ context.Context, in BlockListAdd) (BlockListEntry, error) {
	if f.err != nil {
		return BlockListEntry{}, f.err
	}
	f.added = append(f.added, in)
	return BlockListEntry{ID: "bu_1", Sub: in.Sub, Email: in.Email, Reason: in.Reason, CreatedBy: "t", CreatedAt: "2026-01-01T00:00:00Z"}, nil
}

func (f *fakeBlockList) Remove(context.Context, string) error { return f.err }

func blockListHandler(st BlockListStore) http.Handler {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	if st != nil {
		srv.SetBlockListStore(st)
	}
	return srv.Handler()
}

// TestBlockedUsers_NotWired: without SetBlockListStore (a worker) the routes are
// 404, a wrong method stays 405, and RoutePath maps an entry path to its template.
func TestBlockedUsers_NotWired(t *testing.T) {
	h := blockListHandler(nil)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/dashboard/api/blocked-users"},
		{http.MethodPost, "/dashboard/api/blocked-users"},
		{http.MethodDelete, "/dashboard/api/blocked-users/bu_1"},
	} {
		if rec := adminAuditDo(h, c.method, c.path, `{}`); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
	if rec := adminAuditDo(h, http.MethodPut, "/dashboard/api/blocked-users", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT = %d, want 405", rec.Code)
	}
	for in, want := range map[string]string{
		"/dashboard/api/blocked-users/bu_1":  "/dashboard/api/blocked-users/{id}",
		"/dashboard/api/blocked-users":       "/dashboard/api/blocked-users",
		"/dashboard/api/blocked-users/":      "/dashboard/api/blocked-users/",
		"/dashboard/api/blocked-users/a/b":   "/dashboard/api/blocked-users/a/b",
		"/dashboard/api/policy/versions/3":   "/dashboard/api/policy/versions/{v}",
		"/dashboard/api/blocked-usersX/bu_1": "/dashboard/api/blocked-usersX/bu_1",
	} {
		if got := RoutePath(in); got != want {
			t.Errorf("RoutePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBlockedUsers_ErrorMapping: each store error has one fixed status and body.
func TestBlockedUsers_ErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int
		body   string
	}{
		{ErrBlockStateRequired, http.StatusServiceUnavailable, "state_dir_required"},
		{fmt.Errorf("%w: sub or email is required", ErrBlockInvalid), http.StatusBadRequest, "sub or email is required"},
		{ErrBlockDuplicate, http.StatusConflict, "already_blocked"},
		{ErrBlockTooMany, http.StatusUnprocessableEntity, "block_list_full"},
		{ErrBlockNotFound, http.StatusNotFound, "not_found"},
		{ErrBlockSelfUnblock, http.StatusForbidden, "self_unblock_forbidden"},
		{fmt.Errorf("sqlite: disk on fire"), http.StatusInternalServerError, "block list unavailable"},
	}
	for _, c := range cases {
		h := blockListHandler(&fakeBlockList{err: c.err})
		for _, req := range []struct{ method, path, body string }{
			{http.MethodGet, "/dashboard/api/blocked-users", ""},
			{http.MethodPost, "/dashboard/api/blocked-users", `{"email":"a@b.co"}`},
			{http.MethodDelete, "/dashboard/api/blocked-users/bu_1", ""},
		} {
			rec := adminAuditDo(h, req.method, req.path, req.body)
			if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.body) || strings.Contains(rec.Body.String(), "disk on fire") {
				t.Errorf("%v on %s %s = %d %s, want %d %q", c.err, req.method, req.path, rec.Code, rec.Body, c.status, c.body)
			}
		}
	}
}

func TestBlockedUsers_Handlers(t *testing.T) {
	st := &fakeBlockList{}
	h := blockListHandler(st)
	if rec := adminAuditDo(h, http.MethodGet, "/dashboard/api/blocked-users", ""); rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), `{"entries":[],`) {
		t.Errorf("empty GET = %d %s, want an empty entries envelope", rec.Code, rec.Body)
	}
	rec := adminAuditDo(h, http.MethodPost, "/dashboard/api/blocked-users", `{"email":"a@b.co","reason":"r"}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"hint"`) || len(st.added) != 1 {
		t.Errorf("email-only POST = %d %s, want 201 with a hint", rec.Code, rec.Body)
	}
	rec = adminAuditDo(h, http.MethodPost, "/dashboard/api/blocked-users", `{"sub":"s","email":"a@b.co"}`)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), `"hint"`) {
		t.Errorf("sub+email POST = %d %s, want 201 without a hint", rec.Code, rec.Body)
	}
	if rec := adminAuditDo(h, http.MethodDelete, "/dashboard/api/blocked-users/bu_1", ""); rec.Code != http.StatusNoContent {
		t.Errorf("DELETE = %d, want 204", rec.Code)
	}
	for _, p := range []string{"/dashboard/api/blocked-users/", "/dashboard/api/blocked-users/a/b"} {
		if rec := adminAuditDo(h, http.MethodDelete, p, ""); rec.Code != http.StatusNotFound {
			t.Errorf("DELETE %s = %d, want 404", p, rec.Code)
		}
	}
	if rec := adminAuditDo(h, http.MethodPost, "/dashboard/api/blocked-users", `{"email":"a@b.co","x":1}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field = %d, want 400", rec.Code)
	}
}

// TestWorkersMissingBlocklistCap: the list response carries the count and ids
// of workers without blocklist/v1 next to entries, ids bounded at 50.
func TestWorkersMissingBlocklistCap(t *testing.T) {
	ids := make([]string, 70)
	for i := range ids {
		ids[i] = fmt.Sprintf("w%02d", i)
	}
	st := &fakeBlockList{noCap: ids}
	rec := adminAuditDo(blockListHandler(st), http.MethodGet, "/dashboard/api/blocked-users", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	var got struct {
		Entries []BlockListEntry `json:"entries"`
		N       int              `json:"workersWithoutEnforcement"`
		IDs     []string         `json:"workersWithoutEnforcementIDs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.N != 70 || len(got.IDs) != 50 || got.IDs[0] != "w00" {
		t.Errorf("n=%d ids=%d first=%v, want 70 / 50 / w00", got.N, len(got.IDs), got.IDs)
	}
	rec = adminAuditDo(blockListHandler(&fakeBlockList{}), http.MethodGet, "/dashboard/api/blocked-users", "")
	if !strings.Contains(rec.Body.String(), `"workersWithoutEnforcement":0`) || !strings.Contains(rec.Body.String(), `"workersWithoutEnforcementIDs":[]`) {
		t.Errorf("empty body = %s, want zero count and [] ids", rec.Body.String())
	}
}

// blockPanelJS returns the blockedusers script block of the served page.
func blockPanelJS(t *testing.T, html string) string {
	t.Helper()
	a, b := strings.Index(html, "/* blockedusers:begin */"), strings.Index(html, "/* blockedusers:end */")
	if a < 0 || b < a {
		t.Fatal("no blockedusers script block")
	}
	return html[a:b]
}

// blockFieldRef matches a read of a field the panel renders from the API.
var blockFieldRef = regexp.MustCompile(`\b\w+\.(sub|email|reason|createdBy|hint)\b`)

// TestBlockedUsersPanelServedHTML pins the Blocked users panel in the served
// page: markup, the API route, CSRF-bearing writes through api(), admin-only
// visibility, the non-enforcement banner on the panel and the Fleet page, and
// that sub, email and reason only reach the DOM through esc() or textContent.
func TestBlockedUsersPanelServedHTML(t *testing.T) {
	html := servedIndex(t)
	for _, want := range []string{
		`id="blockedusers-card"`, `>Blocked users</h3>`, `id="bu-sub"`, `id="bu-email"`, `id="bu-reason"`,
		`id="bu-add"`, `id="bu-banner"`, `id="fleet-block-banner"`, `loadBlockedUsers();`,
		`do not enforce the block list`, `self_unblock_forbidden`, `Caps</th>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("served page has no %s", want)
		}
	}
	js := blockPanelJS(t, html)
	for _, want := range []string{
		`api('GET','/dashboard/api/blocked-users')`,
		`api('POST','/dashboard/api/blocked-users'`,
		`api('DELETE','/dashboard/api/blocked-users/'`,
		`window.confirm(`,
		`if(!roleAllows('admin')){ card.style.display='none'; return; }`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("panel script lacks %s", want)
		}
	}
	if strings.Contains(js, "fetch(") {
		t.Error("panel calls fetch() directly instead of api() (no CSRF header)")
	}
	refs := blockFieldRef.FindAllStringIndex(js, -1)
	if len(refs) < 5 {
		t.Fatalf("found only %d field reads; the pattern no longer matches the panel", len(refs))
	}
	for _, loc := range refs {
		ref := js[loc[0]:loc[1]]
		if strings.HasPrefix(ref, "me.") || strings.HasPrefix(ref, "q.") || strings.HasPrefix(ref, "pre.") {
			continue // the signed-in user and the prefill object are not rendered raw
		}
		if insideEsc(js, loc[0]) || assignedToTextContent(js, loc[0]) {
			continue
		}
		t.Errorf("%s is rendered without esc()/textContent: %q", ref, js[max(0, loc[0]-60):loc[1]])
	}
}

// assignedToTextContent reports whether the field read at pos sits on the right
// of a .textContent/.value assignment (a DOM sink that never parses markup).
func assignedToTextContent(js string, pos int) bool {
	start := strings.LastIndex(js[:pos], "\n") + 1
	line := js[start:pos]
	return strings.Contains(line, ".textContent=") || strings.Contains(line, ".value=") || strings.Contains(line, ".textContent =")
}

// TestBlockThisUserLink: a traffic user row links to the block form with both
// sub and email as prefill parameters, built with encodeURIComponent, and the
// form recommends keeping both and shows the POST hint.
func TestBlockThisUserLink(t *testing.T) {
	html := servedIndex(t)
	a, b := strings.Index(html, "function renderTopUsers("), strings.Index(html, "function renderDonut(")
	if a < 0 || b < a {
		t.Fatal("no renderTopUsers")
	}
	rows := html[a:b]
	for _, want := range []string{`blockUserHref(u.sub, u.email)`, `'data-min-role'`, `'Block'`} {
		if !strings.Contains(rows, want) {
			t.Errorf("traffic user row lacks %s", want)
		}
	}
	js := blockPanelJS(t, html)
	for _, want := range []string{
		`'#blocked-users?sub='+encodeURIComponent(`, `'&email='+encodeURIComponent(`,
		`new URLSearchParams(`, `.hint`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("block script lacks %s", want)
		}
	}
	if !strings.Contains(html, "Keep both") || !strings.Contains(html, "authoritative") {
		t.Error("block form does not recommend keeping both sub and email")
	}
}

// TestBlockedUsersPanelAdminOnly: the panel card and the traffic row action
// carry data-min-role=admin, which the served CSS hides below admin, and the
// script fetches nothing unless the signed-in role allows admin.
func TestBlockedUsersPanelAdminOnly(t *testing.T) {
	html := servedIndex(t)
	i := strings.Index(html, `id="blockedusers-card"`)
	if i < 0 {
		t.Fatal("no panel card")
	}
	tag := html[strings.LastIndex(html[:i], "<div") : i+strings.Index(html[i:], ">")]
	if !strings.Contains(tag, `data-min-role="admin"`) {
		t.Errorf("panel card is not gated: %q", tag)
	}
	for _, want := range []string{
		`html[data-role="editor"] [data-min-role="admin"]`,
		`html[data-role="viewer"] [data-min-role="admin"]`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("CSS lost %s", want)
		}
	}
	js := blockPanelJS(t, html)
	if g, f := strings.Index(js, `!roleAllows('admin')`), strings.Index(js, `api('GET'`); g < 0 || f < g {
		t.Error("the role check does not precede the first API call")
	}
	a, b := strings.Index(html, "function renderTopUsers("), strings.Index(html, "function renderDonut(")
	if a < 0 || b < a || !strings.Contains(html[a:b], `setAttribute('data-min-role','admin')`) {
		t.Error("traffic row block action is not admin-gated")
	}
}
