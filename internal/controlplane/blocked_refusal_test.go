package controlplane

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/oauthbroker/oauthbrokertest"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/test/fakes"
)

// Blocked-user refusals across the portal and connect entry points
// (W-P3-OFFB-06).

// keepSessionsStore is a portal session store whose deletes are no-ops, so a
// blocked principal's row survives and the middleware's own block check is
// the only thing standing between them and the handlers.
type keepSessionsStore struct{ portalSessionBackend }

func (keepSessionsStore) Delete(context.Context, string) error               { return nil }
func (keepSessionsStore) DeleteBySub(context.Context, string) (int, error)   { return 0, nil }
func (keepSessionsStore) DeleteByEmail(context.Context, string) (int, error) { return 0, nil }

// blockedRig is a portal and connect rig with a signed-in user, an open
// pending and a connect attempt in flight, audit on, and a consent.store the
// test can inspect.
type blockedRig struct {
	*portalRig
	ex     *stubExchange
	vault  *fakes.MemorySecretStore
	rec    *fakeRecorder
	cookie *http.Cookie
	state  string
	cc     *http.Cookie
}

func newBlockedRig(t *testing.T) *blockedRig {
	t.Helper()
	r, ex, vault, c := callbackRig(t)
	rec := &fakeRecorder{}
	r.srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	r.h = r.srv.Handler()
	state, cc := r.startFlow(c)
	// The user's pending: a JIT request waiting for the connect to finish.
	pend := oauthbrokertest.NewPending("pat", "google", "drive.readonly")
	pend.Iss, pend.UserKey = r.idp.Issuer(), mustUserKey(t, r, "pat")
	if _, err := r.srv.cfg.GrantStore.CreatePending(context.Background(), pend, time.Hour); err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	return &blockedRig{portalRig: r, ex: ex, vault: vault, rec: rec, cookie: c, state: state, cc: cc}
}

// writes is every table and store the refusals must leave alone.
type writes struct{ sessions, attempts, grants, pendings, keys int }

func (b *blockedRig) writes(t *testing.T) writes {
	t.Helper()
	keys, err := b.vault.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return writes{
		sessions: b.count("portal_sessions"), attempts: b.count("connect_attempts"),
		grants: b.count("oauth_grants"), pendings: b.count("pending_authorizations"), keys: len(keys),
	}
}

// TestBlockedUserRefusals: a user with an open portal session, an open pending
// and a connect attempt in flight is blocked while the session row survives
// (the block's session delete is stubbed out). Every portal and connect entry
// point then refuses 403 user_blocked, writes nothing to portal_sessions,
// connect_attempts, oauth_grants or consent.store, never reaches the provider,
// and the connect refusals leave their connect.denied audit row.
func TestBlockedUserRefusals(t *testing.T) {
	b := newBlockedRig(t)
	b.srv.portal.store = keepSessionsStore{b.srv.portal.store}
	b.srv.blocks.SetPortalSessionRevoker(nil)
	before := b.writes(t)
	blockAdd(t, b.srv, BlockEntry{Sub: "pat"})

	t.Run("portal JSON", func(t *testing.T) {
		rec := b.serve(http.MethodGet, "/portal/api/me", b.cookie)
		if rec.Code != http.StatusForbidden || errBody(t, rec) != portal.CodeUserBlocked {
			t.Fatalf("GET /portal/api/me = %d %s, want 403 user_blocked", rec.Code, rec.Body)
		}
		rec = b.portalReq(http.MethodPost, "/portal/api/logout", "", map[string]string{CSRFHeader: portalCSRF(b.cookie)}, b.cookie)
		if rec.Code != http.StatusForbidden || errBody(t, rec) != portal.CodeUserBlocked {
			t.Fatalf("POST /portal/api/logout = %d %s, want 403 user_blocked", rec.Code, rec.Body)
		}
	})
	t.Run("portal page shows no session", func(t *testing.T) {
		if b.signedIn(b.cookie, "pat@example.com") {
			t.Fatal("a blocked principal is shown as signed in")
		}
	})
	t.Run("connect start", func(t *testing.T) {
		form := url.Values{"provider": {"google"}, "scopes": {"drive.readonly"}}.Encode()
		rec := b.connectPost(b.cookie, portalCSRF(b.cookie), form, nil)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), portal.CodeUserBlocked) {
			t.Fatalf("POST /connect/start = %d %s, want 403 user_blocked", rec.Code, rec.Body)
		}
	})
	t.Run("connect callback", func(t *testing.T) {
		target := "/connect/callback?state=" + url.QueryEscape(b.state) + "&code=the-code"
		rec := b.serve(http.MethodGet, target, b.cookie, b.cc)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), portal.CodeUserBlocked) {
			t.Fatalf("GET /connect/callback = %d %s, want 403 user_blocked", rec.Code, rec.Body)
		}
		if b.ex.count() != 0 {
			t.Fatal("a blocked user's code was exchanged at the provider")
		}
	})
	t.Run("portal login", func(t *testing.T) {
		b.idp.SetLogin(fakes.Valid("pat", "pat@example.com", "staff"))
		res := b.finish(b.start(""))
		wantRedirect(t, res, "/portal?login_error="+portal.CodeBlocked)
		if cookieNamed(res, portalCookie) != nil {
			t.Fatal("a blocked login got a portal cookie")
		}
	})
	t.Run("nothing written", func(t *testing.T) {
		if got := b.writes(t); got != before {
			t.Fatalf("writes after the refusals = %+v, before = %+v", got, before)
		}
	})
	t.Run("audit rows", func(t *testing.T) {
		denied := rowsByAction(b.rec, "connect.denied")
		if len(denied) != 2 {
			t.Fatalf("connect.denied rows = %d, want 2 (start, callback): %+v", len(denied), denied)
		}
		for _, in := range denied {
			if in.Outcome != adminaudit.OutcomeDenied || in.Details["reason"] != "user_blocked" || in.Actor.Sub != "pat" ||
				in.HTTPStatus != http.StatusForbidden {
				t.Fatalf("connect.denied row = %+v", in)
			}
			for _, v := range in.Details {
				if strings.Contains(v, b.state) || strings.Contains(v, "token") {
					t.Fatalf("audit detail %q looks secret", v)
				}
			}
		}
		failed := rowsByAction(b.rec, actionPortalLoginFailed)
		if len(failed) != 1 || failed[0].Outcome != adminaudit.OutcomeDenied || failed[0].Details[detailReason] != portal.CodeBlocked {
			t.Fatalf("portal.login_failed rows = %+v", failed)
		}
	})
	t.Run("logs carry no email", func(t *testing.T) {
		if strings.Contains(b.logs.String(), "pat@example.com") {
			t.Fatal("a log line holds the blocked user's email")
		}
	})
}

// TestBlockedUserRefusalsUnreadableList: with no loaded block list every
// entry point refuses 503 (never 200) and writes nothing.
func TestBlockedUserRefusalsUnreadableList(t *testing.T) {
	b := newBlockedRig(t)
	before := b.writes(t)
	b.srv.blocks.snap.Store(nil)

	if rec := b.serve(http.MethodGet, "/portal/api/me", b.cookie); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /portal/api/me = %d %s, want 503", rec.Code, rec.Body)
	}
	form := url.Values{"provider": {"google"}, "scopes": {"drive.readonly"}}.Encode()
	if rec := b.connectPost(b.cookie, portalCSRF(b.cookie), form, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /connect/start = %d %s, want 503", rec.Code, rec.Body)
	}
	target := "/connect/callback?state=" + url.QueryEscape(b.state) + "&code=the-code"
	if rec := b.serve(http.MethodGet, target, b.cookie, b.cc); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /connect/callback = %d %s, want 503", rec.Code, rec.Body)
	}
	if rec := b.serve(http.MethodGet, "/portal/login"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /portal/login = %d, want 503", rec.Code)
	}
	if b.ex.count() != 0 {
		t.Fatal("the provider was called with an unreadable block list")
	}
	if got := b.writes(t); got != before {
		t.Fatalf("writes with an unreadable list = %+v, before = %+v", got, before)
	}
}

// TestBlockedUserRefusalsEmptyList: with an empty block list the same user
// signs in, starts a connect and completes it.
func TestBlockedUserRefusalsEmptyList(t *testing.T) {
	b := newBlockedRig(t)
	if rec := b.serve(http.MethodGet, "/portal/api/me", b.cookie); rec.Code != http.StatusOK {
		t.Fatalf("GET /portal/api/me = %d %s, want 200", rec.Code, rec.Body)
	}
	target := "/connect/callback?state=" + url.QueryEscape(b.state) + "&code=the-code"
	if rec := b.serve(http.MethodGet, target, b.cookie, b.cc); rec.Code != http.StatusSeeOther {
		t.Fatalf("GET /connect/callback = %d %s, want 303", rec.Code, rec.Body)
	}
	if len(rowsByAction(b.rec, "connect.denied")) != 0 {
		t.Fatal("an empty block list produced a connect.denied row")
	}
}
