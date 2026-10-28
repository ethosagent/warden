package controlplane

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
)

// Console denial for blocked principals (W-P1-BLOCK-07).

func blockAdd(t *testing.T, s *Server, e BlockEntry) string {
	t.Helper()
	id, err := s.blocks.Add(context.Background(), e, "oidc:admin")
	if err != nil {
		t.Fatalf("BlockStore.Add: %v", err)
	}
	return id
}

func rowsByAction(rec *fakeRecorder, action string) []adminaudit.Input {
	var out []adminaudit.Input
	for _, in := range rec.inputs() {
		if in.Action == action {
			out = append(out, in)
		}
	}
	return out
}

func sessionCount(t *testing.T, s *Server) int {
	t.Helper()
	var n int
	if err := s.cfg.State.SQL().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBlockedPrincipal_LoginDenied(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry BlockEntry
	}{
		{"by sub", BlockEntry{Sub: "alice"}},
		{"by email", BlockEntry{Email: "Alice@Example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, rec := newAuditRig(t)
			adminLogin(r.idp)
			blockAdd(t, r.srv, tc.entry)
			res := r.finish(r.start(""))
			if res.Code != http.StatusForbidden || errBody(t, res) != "user_blocked" {
				t.Fatalf("callback = %d %s, want 403 user_blocked", res.Code, res.Body)
			}
			if cookieNamed(res, "warden_console") != nil || r.sessionRows() != 0 {
				t.Fatal("a blocked principal got a session")
			}
			row := wantOneRow(t, rec)
			if row.Action != "auth.blocked_login" || row.Target != "session" || row.Outcome != adminaudit.OutcomeDenied ||
				row.AuthMethod != adminaudit.AuthMethodOIDC || row.HTTPStatus != http.StatusForbidden ||
				row.Actor != (adminaudit.Actor{Sub: "alice", Email: "alice@example.com"}) ||
				row.Details["reason"] != "user_blocked" || row.RequestID == "" {
				t.Fatalf("blocked login row = %+v", row)
			}
		})
	}
}

func TestBlockedPrincipal_LoginDeniedWithoutAudit(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.ready()
	adminLogin(r.idp)
	blockAdd(t, r.srv, BlockEntry{Sub: "alice"})
	res := r.finish(r.start(""))
	if res.Code != http.StatusForbidden || cookieNamed(res, "warden_console") != nil {
		t.Fatalf("callback = %d, want 403 and no cookie", res.Code)
	}
}

func TestBlockedPrincipal_UnblockedLoginUnchanged(t *testing.T) {
	r, _ := newAuditRig(t)
	adminLogin(r.idp)
	blockAdd(t, r.srv, BlockEntry{Sub: "someone-else"})
	wantRedirect(t, r.finish(r.start("")), "/dashboard/")
}

func TestBlockedPrincipal_SessionRevoked(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	raw, _ := login(t, r.srv, "warden-admins")
	if r.me(raw).Code != http.StatusOK {
		t.Fatal("/auth/me before the block is not 200")
	}
	id := blockAdd(t, r.srv, BlockEntry{Sub: "u1"})
	if n := sessionCount(t, r.srv); n != 0 {
		t.Fatalf("%d sessions after the block, want 0", n)
	}
	if code := r.me(raw).Code; code != http.StatusUnauthorized {
		t.Fatalf("/auth/me after the block = %d, want 401 (the session is gone)", code)
	}
	if err := r.srv.blocks.Remove(context.Background(), id, "oidc:admin"); err != nil {
		t.Fatal(err)
	}
	if code := r.me(raw).Code; code != http.StatusUnauthorized || sessionCount(t, r.srv) != 0 {
		t.Fatalf("/auth/me after the unblock = %d, want 401: an unblock does not resurrect the session", code)
	}
}

func TestBlockedPrincipal_SessionDeniedFromSnapshot(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	raw, _ := login(t, r.srv, "warden-admins")
	// No revoker: the session survives the block, so the middleware is what
	// refuses it (the state after a CLI write, before the control plane sees it).
	r.srv.blocks.SetSessionRevoker(nil)
	id := blockAdd(t, r.srv, BlockEntry{Email: "U1@example.com"})
	for _, path := range []string{"/auth/me", "/dashboard/api/sessions"} {
		rec := authReq(r.h, r.srv, http.MethodGet, path, raw, "")
		if rec.Code != http.StatusForbidden || errBody(t, rec) != "user_blocked" {
			t.Fatalf("GET %s = %d %s, want 403 user_blocked", path, rec.Code, rec.Body)
		}
	}
	// A state-changing request is refused as blocked before the CSRF check.
	if rec := authReq(r.h, r.srv, http.MethodPost, "/auth/logout", raw, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("POST /auth/logout = %d, want 403", rec.Code)
	}

	rows := rowsByAction(r.rec, "auth.blocked_session")
	if len(rows) != 1 {
		t.Fatalf("blocked_session rows = %+v, want one (rate limited to a row a minute per principal)", rows)
	}
	row := rows[0]
	if row.Target != "session" || row.Outcome != adminaudit.OutcomeDenied || row.AuthMethod != adminaudit.AuthMethodOIDC ||
		row.HTTPStatus != http.StatusForbidden || row.Actor.Sub != "u1" || row.TargetRef == "" || row.RequestID == "" {
		t.Fatalf("blocked session row = %+v", row)
	}
	r.clk.Advance(61 * time.Second)
	authReq(r.h, r.srv, http.MethodGet, "/auth/me", raw, "")
	if got := len(rowsByAction(r.rec, "auth.blocked_session")); got != 2 {
		t.Fatalf("blocked_session rows after a minute = %d, want 2", got)
	}

	if err := r.srv.blocks.Remove(context.Background(), id, "oidc:admin"); err != nil {
		t.Fatal(err)
	}
	if code := r.me(raw).Code; code != http.StatusOK {
		t.Fatalf("/auth/me after the unblock = %d, want 200 (this session was never revoked)", code)
	}
}

func TestBlockedPrincipal_NoAuditNoRows(t *testing.T) {
	r := newBGRig(t, bgOpts{noAudit: true})
	raw, _ := login(t, r.srv, "warden-admins")
	r.srv.blocks.SetSessionRevoker(nil)
	blockAdd(t, r.srv, BlockEntry{Sub: "u1"})
	if code := r.me(raw).Code; code != http.StatusForbidden {
		t.Fatalf("/auth/me = %d, want 403 with admin audit off", code)
	}
}

func TestBlockedPrincipal_RevokedByEmail(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	ctx := context.Background()
	mk := func(sub, email string) string {
		raw, _, err := r.srv.sessions.Create(ctx, SessionInput{Iss: "i", Sub: sub, Email: email, Groups: []string{"warden-admins"}, AuthMethod: "oidc"})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	a1, a2, other := mk("sub-1", "Ada@Example.com"), mk("sub-2", "ada@example.com"), mk("sub-3", "bob@example.com")
	blockAdd(t, r.srv, BlockEntry{Email: "ADA@example.com"}) // no sub: found by email only
	for _, raw := range []string{a1, a2} {
		if _, live, _ := r.srv.sessions.Lookup(ctx, raw); live {
			t.Error("a session of the blocked email survived")
		}
	}
	if _, live, _ := r.srv.sessions.Lookup(ctx, other); !live {
		t.Error("another user's session was revoked")
	}
	if n, err := r.srv.sessions.DeleteByEmail(ctx, ""); n != 0 || err != nil {
		t.Errorf("DeleteByEmail(\"\") = %d, %v; want 0, nil", n, err)
	}
}

func TestBlockedPrincipal_BreakGlassExempt(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	// Every admin is blocked, including a sub that spells the break-glass actor.
	blockAdd(t, r.srv, BlockEntry{Sub: "breakglass:" + bgUser})
	blockAdd(t, r.srv, BlockEntry{Sub: "u1"})
	blockAdd(t, r.srv, BlockEntry{Email: "u1@example.com"})
	raw, _ := login(t, r.srv, "warden-admins")
	if code := r.me(raw).Code; code != http.StatusForbidden {
		t.Fatalf("a blocked OIDC admin's /auth/me = %d, want 403", code)
	}

	rec := r.post("192.0.2.1", bgUser, bgPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("break-glass login with every admin blocked = %d %s, want 200", rec.Code, rec.Body)
	}
	ck := r.cookie(rec)
	if ck == nil {
		t.Fatal("no break-glass cookie")
	}
	if code := r.me(ck.Value).Code; code != http.StatusOK {
		t.Fatalf("break-glass /auth/me = %d, want 200", code)
	}
	if rec := authReq(r.h, r.srv, http.MethodGet, "/dashboard/api/sessions", ck.Value, ""); rec.Code != http.StatusOK {
		t.Fatalf("break-glass admin route = %d, want 200", rec.Code)
	}
	if got := rowsByAction(r.rec, "auth.blocked_session"); len(got) != 1 || got[0].Actor.Sub != "u1" {
		t.Fatalf("blocked_session rows = %+v, want one, for the OIDC admin only", got)
	}
}

func TestBlockedPrincipal_NoQueryPerRequest(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	blockedRaw, _ := login(t, r.srv, "warden-admins")
	r.srv.blocks.SetSessionRevoker(nil)
	blockAdd(t, r.srv, BlockEntry{Sub: "u1"})
	okRaw, _, err := r.srv.sessions.Create(context.Background(), SessionInput{
		Iss: "i", Sub: "u2", Email: "u2@example.com", Groups: []string{"warden-admins"}, AuthMethod: "oidc",
	})
	if err != nil {
		t.Fatal(err)
	}
	// With the table gone any query against it would fail, so a correct answer
	// proves the check reads the snapshot only.
	if _, err := r.srv.cfg.State.SQL().Exec(`DROP TABLE blocked_users`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if code := r.me(blockedRaw).Code; code != http.StatusForbidden {
			t.Fatalf("blocked principal = %d, want 403", code)
		}
		if code := r.me(okRaw).Code; code != http.StatusOK {
			t.Fatalf("unblocked principal = %d, want 200", code)
		}
	}
	if !r.srv.blocks.IsBlocked("u1", "") || r.srv.blocks.IsBlocked("u2", "u2@example.com") {
		t.Fatal("IsBlocked disagrees with the snapshot")
	}
}

func TestBlockedPrincipal_FailedRefreshKeepsSnapshot(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	blockAdd(t, r.srv, BlockEntry{Sub: "u1"})
	if _, err := r.srv.cfg.State.SQL().Exec(`DROP TABLE blocked_users`); err != nil {
		t.Fatal(err)
	}
	r.srv.blocks.watchChanged(context.Background())
	if !r.srv.blocks.IsBlocked("u1", "") || !r.srv.blocks.Ready() {
		t.Fatal("a failed refresh dropped the previous snapshot")
	}
	if !strings.Contains(r.logs.String(), "snapshot refresh failed") {
		t.Error("a failed refresh was not logged")
	}
}

func TestBlockedPrincipal_FirstLoadFailureFailsClosedForLogin(t *testing.T) {
	r := newRig(t, rigOpts{noStart: true})
	if _, err := r.db.SQL().Exec(`DROP TABLE blocked_users`); err != nil {
		t.Fatal(err)
	}
	// A fresh store over the broken table never loaded a list.
	r.srv.blocks = NewBlockStore(r.db, BlockStoreOptions{Logger: r.srv.cfg.Logger})
	r.srv.auth.blocks = r.srv.blocks
	if r.srv.blocks.Ready() {
		t.Fatal("a store whose first load failed reports Ready")
	}
	r.srv.Start(context.Background())
	r.ready()
	rec := r.serve(http.MethodGet, "/auth/login")
	if rec.Code != http.StatusServiceUnavailable || errBody(t, rec) != "block_list_unavailable" {
		t.Fatalf("/auth/login = %d %s, want 503 block_list_unavailable", rec.Code, rec.Body)
	}
}

func TestBlockedPrincipal_ForeignWriteRevokesSessions(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	raw, _ := login(t, r.srv, "warden-admins")
	// Another BlockStore on the same database stands in for the offline CLI.
	cli := NewBlockStore(r.srv.cfg.State, BlockStoreOptions{})
	if _, err := cli.Add(context.Background(), BlockEntry{Sub: "u1"}, "cli:ops"); err != nil {
		t.Fatal(err)
	}
	if r.srv.blocks.IsBlocked("u1", "") {
		t.Fatal("the control plane saw the write before its watcher ran")
	}
	r.srv.blocks.watchChanged(context.Background())
	if !r.srv.blocks.IsBlocked("u1", "") {
		t.Fatal("the watcher did not refresh the snapshot")
	}
	if _, live, _ := r.srv.sessions.Lookup(context.Background(), raw); live {
		t.Fatal("the watcher did not revoke the blocked principal's session")
	}
}

func TestBlockedPrincipal_IsBlockedMatching(t *testing.T) {
	r := newBGRig(t, bgOpts{})
	blockAdd(t, r.srv, BlockEntry{Sub: "Sub-A"})
	blockAdd(t, r.srv, BlockEntry{Email: "Mixed@Case.com"})
	b := r.srv.blocks
	for _, tc := range []struct {
		sub, email string
		want       bool
	}{
		{"Sub-A", "", true}, {"sub-a", "", false}, {"", "mixed@case.com", true}, {"", "MIXED@CASE.COM", true},
		{"x", "other@case.com", false}, {"", "", false},
	} {
		if got := b.IsBlocked(tc.sub, tc.email); got != tc.want {
			t.Errorf("IsBlocked(%q, %q) = %v, want %v", tc.sub, tc.email, got, tc.want)
		}
	}
}
