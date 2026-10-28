package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/test/fakes"
)

// Login and logout events (W-P1-AAUD-07), driven through the real OIDC flow
// against the issuer fake with a fake Recorder.

// newAuditRig is the login rig with admin audit on through a fake recorder.
func newAuditRig(t *testing.T) (*rig, *fakeRecorder) {
	t.Helper()
	r := newRig(t, rigOpts{})
	rec := &fakeRecorder{}
	r.srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	r.h = r.srv.Handler()
	r.ready()
	return r, rec
}

// wantOneRow returns the only recorded row, failing on any other count.
func wantOneRow(t *testing.T, rec *fakeRecorder) adminaudit.Input {
	t.Helper()
	rows := rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("recorded %d rows, want 1: %+v", len(rows), rows)
	}
	return rows[0]
}

func TestAdminAuditLogin(t *testing.T) {
	r, rec := newAuditRig(t)
	adminLogin(r.idp)
	res := r.finish(r.start(""))
	wantRedirect(t, res, "/dashboard/")
	sc := cookieNamed(res, "warden_console")
	if sc == nil {
		t.Fatal("no session cookie")
	}
	row := wantOneRow(t, rec)
	if row.Action != "auth.login" || row.Target != "session" || row.Outcome != adminaudit.OutcomeOK ||
		row.AuthMethod != adminaudit.AuthMethodOIDC || row.HTTPStatus != http.StatusFound {
		t.Fatalf("login row = %+v", row)
	}
	if row.Actor != (adminaudit.Actor{Sub: "alice", Email: "alice@example.com"}) || row.ActorRole != "admin" ||
		len(row.Details) != 1 || row.Details["role"] != "admin" {
		t.Fatalf("login row actor/role/details = %+v", row)
	}
	if row.TargetRef != shortHash(hashID(sc.Value)) {
		t.Errorf("target_ref = %q, want the session's short hash", row.TargetRef)
	}
	if row.RequestID == "" || row.RequestID != res.Header().Get(RequestIDHeader) {
		t.Errorf("request_id = %q, response header %q", row.RequestID, res.Header().Get(RequestIDHeader))
	}
	if row.ClientIP != "192.0.2.1" {
		t.Errorf("client_ip = %q, want the remote address", row.ClientIP)
	}
}

func TestAdminAuditLoginFailedNoRole(t *testing.T) {
	r, rec := newAuditRig(t)
	r.idp.SetLogin(fakes.Valid("mallory", "m@example.com", "strangers"))
	res := r.finish(r.start(""))
	wantRedirect(t, res, "/dashboard/?login_error=no_role")
	if cookieNamed(res, "warden_console") != nil || r.sessionRows() != 0 {
		t.Fatal("a session was created for a user with no role")
	}
	row := wantOneRow(t, rec)
	if row.Action != "auth.login_failed" || row.Target != "session" || row.Outcome != adminaudit.OutcomeDenied ||
		row.AuthMethod != adminaudit.AuthMethodOIDC || row.HTTPStatus != http.StatusFound || row.TargetRef != "" {
		t.Fatalf("no_role row = %+v", row)
	}
	// The token was verified, so the attempt is attributed to its subject.
	if row.Actor != (adminaudit.Actor{Sub: "mallory", Email: "m@example.com"}) || row.ActorRole != "" ||
		len(row.Details) != 1 || row.Details["reason"] != "no_role" {
		t.Fatalf("no_role row actor/details = %+v", row)
	}
	if row.ClientIP != "192.0.2.1" || row.RequestID == "" {
		t.Errorf("client_ip %q, request_id %q", row.ClientIP, row.RequestID)
	}
}

// TestAdminAuditLoginFailedReasons maps every callback failure after the
// state was consumed onto the closed reason enum; an unverified token is
// anonymous, and a callback that consumed no state writes nothing.
func TestAdminAuditLoginFailedReasons(t *testing.T) {
	tests := []struct {
		name, reason, outcome string
		setup                 func(*rig)
		mutate                func(*flow)
	}{
		{name: "nonce mismatch", reason: "bad_token", outcome: adminaudit.OutcomeDenied, setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithNonce("not-the-nonce"))
		}},
		{name: "wrong signing key", reason: "bad_token", outcome: adminaudit.OutcomeDenied, setup: func(r *rig) {
			r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithUnpublishedKey())
		}},
		{name: "idp error", reason: "idp_error", outcome: adminaudit.OutcomeError, setup: func(r *rig) {
			r.idp.FailAuthorize("access_denied")
		}},
		{name: "token endpoint fails", reason: "exchange_failed", outcome: adminaudit.OutcomeError, setup: func(r *rig) {
			r.idp.SetTokenStatus(500)
		}},
		{name: "another browser's login cookie", reason: "state_invalid", outcome: adminaudit.OutcomeDenied, mutate: func(f *flow) {
			f.loginCookie = &http.Cookie{Name: f.loginCookie.Name, Value: "someone-else"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, rec := newAuditRig(t)
			adminLogin(r.idp)
			if tc.setup != nil {
				tc.setup(r)
			}
			f := r.start("")
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			r.finish(f)
			row := wantOneRow(t, rec)
			if row.Action != "auth.login_failed" || row.Outcome != tc.outcome || row.Details["reason"] != tc.reason || len(row.Details) != 1 {
				t.Fatalf("row = %+v, want reason %s outcome %s", row, tc.reason, tc.outcome)
			}
			if row.Actor != (adminaudit.Actor{}) || row.ActorRole != "" {
				t.Fatalf("an unverified attempt is attributed: %+v", row.Actor)
			}
		})
	}

	for _, target := range []string{"/auth/callback?code=x&state=forged", "/auth/callback?code=x", "/auth/callback"} {
		t.Run("no state consumed "+target, func(t *testing.T) {
			r, rec := newAuditRig(t)
			wantRedirect(t, r.serve(http.MethodGet, target), "/dashboard/?login_error=state_invalid")
			if rows := rec.inputs(); len(rows) != 0 {
				t.Fatalf("a callback that consumed no state was recorded: %+v", rows)
			}
		})
	}
}

func TestAdminAuditLoginFailedRateLimited(t *testing.T) {
	r, rec := newAuditRig(t)
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	r.srv.audit.loginFailed.clock = clk
	r.idp.FailAuthorize("access_denied")
	for range 100 {
		r.finish(r.start(""))
	}
	if n := len(rec.inputs()); n != loginFailedPerMinute {
		t.Fatalf("100 failed callbacks in one minute left %d rows, want %d", n, loginFailedPerMinute)
	}
	if got := r.srv.audit.loginFailedDropped.Load(); got != 80 {
		t.Errorf("dropped counter = %d, want 80", got)
	}
	if strings.Count(r.logs.String(), `"msg":"admin_audit_login_failed_rate_limited"`) != 1 {
		t.Errorf("want one rate-limit log line per address per minute: %s", r.logs)
	}
	// A successful login is never rate-limited.
	adminLogin(r.idp)
	r.idp.FailAuthorize("")
	wantRedirect(t, r.finish(r.start("")), "/dashboard/")
	rows := rec.inputs()
	if last := rows[len(rows)-1]; last.Action != "auth.login" {
		t.Fatalf("successful login after the limit was not recorded: %+v", last)
	}
	// The next minute opens a new window.
	clk.Advance(time.Minute)
	r.idp.FailAuthorize("access_denied")
	r.finish(r.start(""))
	if n := len(rec.inputs()); n != loginFailedPerMinute+2 {
		t.Fatalf("after a minute: %d rows, want %d", n, loginFailedPerMinute+2)
	}
}

func TestLoginFailedLimiterBoundsAddresses(t *testing.T) {
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	l := newWindowLimiter(clk, 2, time.Minute, 2)
	got := []bool{l.allow("a"), l.allow("a"), l.allow("a")}
	if !got[0] || !got[1] || got[2] {
		t.Fatalf("allow(a) x3 = %v, want true, true, false", got)
	}
	if !l.allow("b") {
		t.Fatal("second key refused")
	}
	if l.allow("c") {
		t.Fatal("a third key was admitted past the key cap while the others are live")
	}
	clk.Advance(time.Minute)
	if !l.allow("c") {
		t.Fatal("expired windows were not pruned for a new key")
	}
}

func TestAdminAuditLogout(t *testing.T) {
	r, rec := newAuditRig(t)
	adminLogin(r.idp)
	sc := cookieNamed(r.finish(r.start("")), "warden_console")
	if sc == nil {
		t.Fatal("no session cookie")
	}
	rec.reset()

	res := authReq(r.h, r.srv, http.MethodPost, "/auth/logout", sc.Value, CSRFToken(sc.Value))
	if res.Code != http.StatusNoContent {
		t.Fatalf("logout = %d %s", res.Code, res.Body)
	}
	if _, live, _ := r.srv.sessions.Lookup(context.Background(), sc.Value); live || r.sessionRows() != 0 {
		t.Fatal("the session row survived logout")
	}
	row := wantOneRow(t, rec)
	if row.Action != "auth.logout" || row.Target != "session" || row.Outcome != adminaudit.OutcomeOK ||
		row.AuthMethod != adminaudit.AuthMethodOIDC || row.HTTPStatus != http.StatusNoContent {
		t.Fatalf("logout row = %+v", row)
	}
	if row.Actor != (adminaudit.Actor{Sub: "alice", Email: "alice@example.com"}) || row.ActorRole != "admin" ||
		row.TargetRef != shortHash(hashID(sc.Value)) {
		t.Fatalf("logout row actor/role/ref = %+v", row)
	}
	if row.RequestID == "" || row.RequestID != res.Header().Get(RequestIDHeader) || row.ClientIP != "192.0.2.1" {
		t.Errorf("request_id %q (header %q), client_ip %q", row.RequestID, res.Header().Get(RequestIDHeader), row.ClientIP)
	}

	// A logout without a live session (none, or the one just ended) and a
	// CSRF-refused logout record nothing.
	rec.reset()
	authReq(r.h, r.srv, http.MethodPost, "/auth/logout", "", "")
	authReq(r.h, r.srv, http.MethodPost, "/auth/logout", sc.Value, CSRFToken(sc.Value))
	sc2 := cookieNamed(r.finish(r.start("")), "warden_console")
	rec.reset()
	if res := authReq(r.h, r.srv, http.MethodPost, "/auth/logout", sc2.Value, ""); res.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF = %d, want 403", res.Code)
	}
	if rows := rec.inputs(); len(rows) != 0 {
		t.Fatalf("logouts without a session or CSRF were recorded: %+v", rows)
	}
}

// TestAdminAuditLoginRecorderError: a Recorder failure is logged at ERROR and
// marks the store degraded, but the login and the logout still succeed.
func TestAdminAuditLoginRecorderError(t *testing.T) {
	r, rec := newAuditRig(t)
	rec.set(errors.New("disk full"), errors.New("disk full"))
	adminLogin(r.idp)
	res := r.finish(r.start(""))
	wantRedirect(t, res, "/dashboard/")
	sc := cookieNamed(res, "warden_console")
	if sc == nil || r.sessionRows() != 1 {
		t.Fatal("a recorder error turned a successful login into a failure")
	}
	if !r.srv.audit.degraded.Load() {
		t.Error("recorder error did not mark admin audit degraded")
	}
	logs := r.logs.String()
	if !strings.Contains(logs, `"level":"ERROR","msg":"admin_audit_persist_failed"`) || !strings.Contains(logs, `"action":"auth.login"`) {
		t.Fatalf("no ERROR persist_failed line for auth.login: %s", logs)
	}
	if res := authReq(r.h, r.srv, http.MethodPost, "/auth/logout", sc.Value, CSRFToken(sc.Value)); res.Code != http.StatusNoContent {
		t.Fatalf("logout with a failing recorder = %d", res.Code)
	}
	if !strings.Contains(r.logs.String(), `"action":"auth.logout"`) {
		t.Error("no persist_failed line for auth.logout")
	}
	// A later append that succeeds clears the flag.
	rec.set(nil, nil)
	r.finish(r.start(""))
	if r.srv.audit.degraded.Load() {
		t.Error("a successful append did not clear the degraded flag")
	}
}

func TestAdminAuditAuthNoSecrets(t *testing.T) {
	r, rec := newAuditRig(t)
	var secrets []string
	collect := func(f flow) {
		if f.loginCookie != nil {
			secrets = append(secrets, f.loginCookie.Value)
		}
		u := f.callback
		for _, k := range []string{"code", "state"} {
			if strings.Contains(u, k+"=") {
				secrets = append(secrets, mustQuery(t, u, k))
			}
		}
	}
	var verifiers []string
	pending := func() {
		rows, err := r.db.SQL().Query(`SELECT verifier, nonce FROM oidc_pending`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var v, n string
			if err := rows.Scan(&v, &n); err != nil {
				t.Fatal(err)
			}
			verifiers = append(verifiers, v, n)
		}
	}

	adminLogin(r.idp)
	f := r.start("")
	collect(f)
	pending()
	sc := cookieNamed(r.finish(f), "warden_console")
	secrets = append(secrets, sc.Value, CSRFToken(sc.Value))
	authReq(r.h, r.srv, http.MethodPost, "/auth/logout", sc.Value, CSRFToken(sc.Value))

	r.idp.SetLogin(fakes.Valid("mallory", "m@example.com", "strangers"))
	f = r.start("")
	collect(f)
	pending()
	r.finish(f)

	r.idp.SetLogin(fakes.Valid("alice", "a@example.com", "admins"), fakes.WithNonce("not-the-nonce"))
	f = r.start("")
	collect(f)
	pending()
	r.finish(f)

	// A failing recorder logs the whole entry; it must be clean too.
	rec.set(errors.New("disk full"), nil)
	adminLogin(r.idp)
	f = r.start("")
	collect(f)
	pending()
	r.finish(f)

	for _, a := range r.idp.AuthRequests() {
		secrets = append(secrets, a.Nonce, a.State, a.Challenge)
	}
	secrets = append(secrets, verifiers...)
	secrets = append(secrets, "eyJ", "fake-access-token", rigClientSecret)

	rec.set(nil, nil)
	rows := fmt.Sprintf("%+v", rec.inputs())
	if !strings.Contains(rows, "auth.login_failed") || !strings.Contains(rows, "auth.logout") {
		t.Fatalf("expected login, failure and logout rows: %s", rows)
	}
	logs := r.logs.String()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(rows, s) {
			t.Errorf("a recorded row contains a secret value (%d bytes)", len(s))
		}
		if strings.Contains(logs, s) {
			t.Errorf("a log line contains a secret value (%d bytes)", len(s))
		}
	}
}

// TestAdminAuditAuthDisabledUnchanged: with admin audit off the callback and
// logout carry no request id, exactly as before.
func TestAdminAuditAuthDisabledUnchanged(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.ready()
	adminLogin(r.idp)
	res := r.finish(r.start(""))
	wantRedirect(t, res, "/dashboard/")
	if res.Header().Get(RequestIDHeader) != "" {
		t.Error("callback set a request id with admin audit off")
	}
	sc := cookieNamed(res, "warden_console")
	out := authReq(r.h, r.srv, http.MethodPost, "/auth/logout", sc.Value, CSRFToken(sc.Value))
	if out.Code != http.StatusNoContent || out.Header().Get(RequestIDHeader) != "" {
		t.Errorf("logout = %d, request id %q", out.Code, out.Header().Get(RequestIDHeader))
	}
	if strings.Contains(r.logs.String(), "admin_audit") {
		t.Error("admin audit log lines with admin audit off")
	}
}

func (f *fakeRecorder) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = nil
}
