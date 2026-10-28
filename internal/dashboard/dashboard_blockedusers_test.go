package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// fakeBlockList is a BlockListStore with a canned error.
type fakeBlockList struct {
	entries []BlockListEntry
	err     error
	added   []BlockListAdd
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
	if rec := adminAuditDo(h, http.MethodGet, "/dashboard/api/blocked-users", ""); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"entries":[]}` {
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
