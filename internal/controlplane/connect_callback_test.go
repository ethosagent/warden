package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/oauthbroker"
	oauthbrokerhttp "github.com/ethosagent/warden/internal/oauthbroker/http"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// The connect callback route and its assembly (W-P3-BRKR-04).

type stubExchange struct {
	mu    sync.Mutex
	calls int
	resp  oauthbroker.TokenResponse
	err   error
}

func (s *stubExchange) Exchange(context.Context, oauthbroker.ExchangeRequest) (oauthbroker.TokenResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.resp, s.err
}

func (s *stubExchange) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func callbackRig(t *testing.T) (*portalRig, *stubExchange, *fakes.MemorySecretStore, *http.Cookie) {
	t.Helper()
	ex := &stubExchange{resp: oauthbroker.TokenResponse{
		AccessToken: "access-token-value", RefreshToken: "refresh-token-value", TokenType: "Bearer", Scope: "drive.readonly",
		Expiry: time.Now().Add(time.Hour),
	}}
	store := fakes.NewMemorySecretStore()
	r := newPortalRig(t, portalRigOpts{providers: connectProviders(), userStore: store, exchanger: ex})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com", "staff"))
	return r, ex, store, r.login("")
}

// startFlow posts /connect/start as c and returns the state and the connect
// cookie.
func (r *portalRig) startFlow(c *http.Cookie) (state string, cookie *http.Cookie) {
	r.t.Helper()
	rec := r.connectPost(c, portalCSRF(c), url.Values{"provider": {"google"}, "scopes": {"drive.readonly"}}.Encode(), nil)
	if rec.Code != http.StatusSeeOther {
		r.t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		r.t.Fatal(err)
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == connectCookieName {
			cookie = ck
		}
	}
	if cookie == nil {
		r.t.Fatal("no connect cookie")
	}
	return loc.Query().Get("state"), cookie
}

func TestConnectCallbackRoutePath(t *testing.T) {
	if connectCallbackPath != oauthbrokerhttp.CallbackPath {
		t.Errorf("connectCallbackPath = %q, transport says %q", connectCallbackPath, oauthbrokerhttp.CallbackPath)
	}
}

// TestConnectCallbackRoute: a signed-in user finishing a flow gets the token in
// consent.store under users/<userKey>/google and a 303 to the portal; a replay
// is a 400 page; a signed-out request is a 401 page, never a redirect.
func TestConnectCallbackRoute(t *testing.T) {
	r, ex, store, c := callbackRig(t)
	state, cc := r.startFlow(c)
	rec := r.serve(http.MethodGet, "/connect/callback?state="+url.QueryEscape(state)+"&code=the-code", c, cc)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/portal?connected=google" {
		t.Fatalf("callback = %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", rec.Header())
	}
	uk, _ := secrets.UserKey(r.srv.cfg.Consent.OIDC.Issuer, "pat")
	key, _ := secrets.UserGrantKey(uk, "google")
	raw, ok := store.Value(key)
	if !ok || !strings.Contains(raw, "access-token-value") || !strings.Contains(raw, `"refresh_token":"refresh-token-value"`) {
		t.Fatalf("consent.store at %s: %v %q", key, ok, raw)
	}
	g, err := r.srv.cfg.GrantStore.GetGrant(context.Background(), uk, "google")
	if err != nil || g.State != oauthbroker.GrantActive || !strings.Contains(raw, `"grant_id":"`+g.GrantID+`"`) {
		t.Fatalf("grant = %+v, %v", g, err)
	}
	if strings.Contains(r.logs.String(), "access-token-value") || strings.Contains(r.logs.String(), state) {
		t.Error("the logs hold a token or the state")
	}
	if got := r.srv.OAuthConnectCounts()[oauthbroker.ConnectKey{Provider: "google", Stage: "callback", Outcome: "ok"}]; got != 1 {
		t.Errorf("callback counter = %d", got)
	}
	if got := r.srv.OAuthExchangeSeconds()["google"]; got[0] != 1 {
		t.Errorf("exchange timing = %v", got)
	}

	// Replay.
	rec = r.serve(http.MethodGet, "/connect/callback?state="+url.QueryEscape(state)+"&code=the-code", c, cc)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "state_invalid") || ex.count() != 1 {
		t.Fatalf("replay = %d, exchanges %d", rec.Code, ex.count())
	}
	// Signed out: 401, not a redirect, and no exchange.
	rec = r.serve(http.MethodGet, "/connect/callback?state=x&code=y")
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Location") != "" || ex.count() != 1 {
		t.Fatalf("signed out = %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	// A POST is refused (the route is GET only) and cannot start anything.
	rec = r.portalReq(http.MethodPost, "/connect/callback", "state=x", map[string]string{CSRFHeader: portalCSRF(c)}, c)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST callback = %d", rec.Code)
	}
}

// TestConnectCallbackAudit: with admin audit on, connect.granted is one row
// with auth_method portal, target grant:google, target_ref grant_id:<id> and
// details naming the provider and scopes only; an unhealthy recorder is a 503
// before the code exchange (and the state stays usable); connect.denied is
// recorded for a refused callback.
func TestConnectCallbackAudit(t *testing.T) {
	r, ex, _, c := callbackRig(t)
	rec := &fakeRecorder{}
	r.srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	r.h = r.srv.Handler()

	state, cc := r.startFlow(c)
	rec.set(nil, errors.New("audit store read-only"))
	resp := r.serve(http.MethodGet, "/connect/callback?state="+url.QueryEscape(state)+"&code=the-code", c, cc)
	if resp.Code != http.StatusServiceUnavailable || !strings.Contains(resp.Body.String(), "admin_audit_unavailable") || ex.count() != 0 {
		t.Fatalf("unhealthy audit = %d, exchanges %d", resp.Code, ex.count())
	}
	rec.set(nil, nil)
	resp = r.serve(http.MethodGet, "/connect/callback?state="+url.QueryEscape(state)+"&code=the-code", c, cc)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("callback after recovery = %d %s", resp.Code, resp.Body)
	}
	var granted adminaudit.Input
	for _, in := range rec.inputs() {
		if in.Action == "connect.granted" {
			granted = in
		}
	}
	g, _ := r.srv.cfg.GrantStore.GetGrant(context.Background(), mustUserKey(t, r, "pat"), "google")
	if granted.AuthMethod != adminaudit.AuthMethodPortal || granted.Target != "grant:google" || granted.TargetRef != "grant_id:"+g.GrantID ||
		granted.Outcome != adminaudit.OutcomeOK || granted.Actor.Sub != "pat" || granted.Details["provider"] != "google" || granted.Details["scopes"] != "drive.readonly" {
		t.Fatalf("connect.granted row = %+v", granted)
	}
	for k, v := range granted.Details {
		if strings.Contains(v, "token") || strings.Contains(v, state) || strings.Contains(k, "token") {
			t.Errorf("audit detail %s=%q looks secret", k, v)
		}
	}

	// A foreign browser: state_invalid is unattributable and unaudited; a
	// session mismatch is a connect.denied row.
	state2, cc2 := r.startFlow(c)
	r.idp.SetLogin(fakes.Valid("eve", "eve@example.com", "staff"))
	eve := r.login("")
	resp = r.serve(http.MethodGet, "/connect/callback?state="+url.QueryEscape(state2)+"&code=x", eve, cc2)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("session mismatch = %d %s", resp.Code, resp.Body)
	}
	var denied adminaudit.Input
	for _, in := range rec.inputs() {
		if in.Action == "connect.denied" {
			denied = in
		}
	}
	if denied.Outcome != adminaudit.OutcomeDenied || denied.Details["reason"] != "session_mismatch" || denied.Actor.Sub != "eve" || denied.AuthMethod != adminaudit.AuthMethodPortal {
		t.Fatalf("connect.denied row = %+v", denied)
	}
}

func mustUserKey(t *testing.T, r *portalRig, sub string) string {
	t.Helper()
	uk, err := secrets.UserKey(r.srv.cfg.Consent.OIDC.Issuer, sub)
	if err != nil {
		t.Fatal(err)
	}
	return uk
}

// TestConnectCallbackNeedsStoreAndExchanger: without consent.store or the
// exchanger only /connect/start works; the callback route answers 404 behind
// the session middleware and no sweeper reconciler runs.
func TestConnectCallbackNeedsStoreAndExchanger(t *testing.T) {
	r, c, _ := connectRig(t)
	rec := r.serve(http.MethodGet, "/connect/callback?state=x&code=y", c)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("callback without a store = %d", rec.Code)
	}
}

// TestBrokerVaultKeys: the consent.store adapter lists logical keys for the
// orphan pass.
func TestBrokerVaultKeys(t *testing.T) {
	store := fakes.NewMemorySecretStore()
	ctx := context.Background()
	_ = store.Put(ctx, "users/k/google", "{}")
	_ = store.Put(ctx, "idp/k", "x")
	v := brokerVault{store: store}
	keys, err := v.Keys(ctx)
	if err != nil || len(keys) != 2 || keys[0] != "idp/k" || keys[1] != "users/k/google" {
		t.Fatalf("Keys = %v, %v", keys, err)
	}
	store.SetErrors(nil, nil, nil, errors.New("down"))
	if _, err := v.Keys(ctx); err == nil {
		t.Fatal("a failing List must fail Keys")
	}
}

// TestFitDetail: a scope list longer than an audit detail value is cut at a
// separator.
func TestFitDetail(t *testing.T) {
	long := strings.Repeat("scope-name,", 40)
	got := fitDetail(long)
	if len(got) > adminaudit.MaxDetailValueLen || strings.HasSuffix(got, ",") || !strings.HasPrefix(long, got) {
		t.Fatalf("fitDetail = %d bytes %q", len(got), got[len(got)-12:])
	}
	if fitDetail("a,b") != "a,b" {
		t.Fatal("a short value must be unchanged")
	}
}

// TestConnectCallbackSignedOutPage: a signed-out callback is the HTML 401 page,
// not JSON, with no-store and no-referrer.
func TestConnectCallbackSignedOutPage(t *testing.T) {
	r, _, _, _ := callbackRig(t)
	rec := r.serve(http.MethodGet, "/connect/callback?state=x&code=y")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(rec.Body.String(), "Connection failed") || strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("signed out = %d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", rec.Header())
	}
}

// TestBrokerAuditSystemRow: the orphan sweep's connect.revoked row is written
// by the system actor with auth_method system, naming the grant and provider and
// no secret reference.
func TestBrokerAuditSystemRow(t *testing.T) {
	r, _, _, _ := callbackRig(t)
	rec := &fakeRecorder{}
	r.srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	err := brokerAudit{s: r.srv}.Record(context.Background(), oauthbroker.AuditEvent{
		Action: oauthbroker.AuditActionRevoked, Outcome: adminaudit.OutcomeOK, Reason: "orphan_key_deleted",
		System: true, Provider: "google", GrantID: "g1",
	})
	if err != nil {
		t.Fatal(err)
	}
	row := wantOneRow(t, rec)
	if row.Action != "connect.revoked" || row.AuthMethod != adminaudit.AuthMethodSystem || row.Actor.Sub != "system" ||
		row.Target != "grant:google" || row.TargetRef != "grant_id:g1" || row.Details["reason"] != "orphan_key_deleted" {
		t.Fatalf("row = %+v", row)
	}
}
