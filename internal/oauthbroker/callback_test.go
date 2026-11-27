package oauthbroker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/oauthbroker/adapters/exchange"
	"github.com/ethosagent/warden/internal/oauthbroker/oauthbrokertest"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// memVault is the fakes.MemorySecretStore as the broker's TokenVault.
type memVault struct{ *fakes.MemorySecretStore }

func (m memVault) Keys(ctx context.Context) ([]string, error) {
	list, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.Key)
	}
	return out, nil
}

// fakeAudit collects connect audit events; ready, when set, is Ready's answer.
type fakeAudit struct {
	mu     sync.Mutex
	events []oauthbroker.AuditEvent
	ready  error
}

func (f *fakeAudit) Ready(context.Context) error { return f.ready }
func (f *fakeAudit) Record(_ context.Context, ev oauthbroker.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}
func (f *fakeAudit) all() []oauthbroker.AuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}

// flipBlocks reports a user as blocked from the n-th IsBlocked call on.
type flipBlocks struct {
	mu    sync.Mutex
	calls int
	from  int
	err   error
}

func (f *flipBlocks) IsBlocked(context.Context, string, string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.from > 0 && f.calls >= f.from, f.err
}

type cbEnv struct {
	b      *oauthbroker.Broker
	store  oauthbroker.GrantStore
	prov   *fakes.OAuthProvider
	vault  *fakes.MemorySecretStore
	blocks *flipBlocks
	audit  *fakeAudit
	clk    *clocktest.Fake
	logs   *bytes.Buffer
	cfg    oauthbroker.Config
}

const cbSub = "alice"

func newCBEnv(t *testing.T) *cbEnv {
	t.Helper()
	prov := fakes.NewOAuthProvider(t)
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reg, err := oauthbroker.NewRegistry([]config.OAuthProviderConfig{
		{ID: "google", Type: config.OAuthProviderGoogle, ClientID: fakes.OAuthDefaultClientID, ClientSecretEnv: "CB_SECRET",
			AuthURL: prov.AuthURL(), TokenURL: prov.TokenURL(),
			AllowedScopes: []string{"calendar.readonly", "drive.readonly"}, DefaultScopes: []string{"drive.readonly"}},
		{ID: "github", Type: config.OAuthProviderGitHub, ClientID: fakes.OAuthDefaultClientID, ClientSecretEnv: "CB_SECRET",
			AuthURL: prov.AuthURL(), TokenURL: prov.TokenURL(),
			AllowedScopes: []string{"read:user", "repo"}, DefaultScopes: []string{"read:user"}},
	}, oauthbroker.Options{
		LookupEnv: func(string) (string, bool) { return fakes.OAuthDefaultSecret, true }, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := exchange.New(exchange.Options{AllowPrivate: []string{"127.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	clk := clocktest.NewFake(oauthbrokertest.Start)
	store := newSQLiteStore(t, clk)
	vault := fakes.NewMemorySecretStore()
	blocks := &flipBlocks{}
	audit := &fakeAudit{}
	cfg := oauthbroker.Config{
		Registry: reg, Store: store, Blocks: blocks, RedirectURL: startRedir,
		UserKey: startUserKey, Rand: rand.Reader, Now: clk.Now, Logger: logger,
		Vault: memVault{vault}, GrantKey: secrets.UserGrantKey,
		NotFound:  func(err error) bool { return errors.Is(err, secrets.ErrSecretNotFound) },
		Exchanger: ex, Audit: audit,
	}
	b, err := oauthbroker.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &cbEnv{b: b, store: store, prov: prov, vault: vault, blocks: blocks, audit: audit, clk: clk, logs: logs, cfg: cfg}
}

// flow is one started and authorized connect, ready for its callback.
type flow struct {
	req       oauthbroker.CallbackRequest
	state     string
	pendingID string
}

// connect starts a flow for sub and plays the browser at the provider. A
// non-empty withPending creates a pending first.
func (e *cbEnv) connect(t *testing.T, sub, provider string, withPending bool, scopes ...string) flow {
	t.Helper()
	ctx := context.Background()
	sr := req(sub, provider, scopes...)
	var f flow
	if withPending {
		p, err := e.store.CreatePending(ctx, oauthbroker.Pending{
			Iss: startIss, Sub: sub, UserKey: wantUserKey(sub), Provider: provider, Scopes: []string{"calendar.readonly", "drive.readonly", "read:user", "repo"},
		}, 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		sr.PendingID, f.pendingID = p.ID, p.ID
	}
	res, err := e.b.Start(ctx, sr)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	cb, err := e.prov.Authorize(res.RedirectURL, false)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(cb)
	if err != nil {
		t.Fatal(err)
	}
	f.state = u.Query().Get("state")
	f.req = oauthbroker.CallbackRequest{
		Iss: startIss, Sub: sub, Email: sub + "@example.com",
		State: f.state, Code: u.Query().Get("code"), BrowserToken: res.BrowserToken,
	}
	return f
}

func cbCode(t *testing.T, err error) (string, int) {
	t.Helper()
	var ce *oauthbroker.CallbackError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want a *CallbackError", err)
	}
	return ce.Code, ce.Status()
}

func (e *cbEnv) keyOf(sub, provider string) string {
	k, _ := secrets.UserGrantKey(wantUserKey(sub), provider)
	return k
}

func (e *cbEnv) record(t *testing.T, sub, provider string) oauthbroker.TokenRecord {
	t.Helper()
	raw, ok := e.vault.Value(e.keyOf(sub, provider))
	if !ok {
		t.Fatalf("no key %s in consent.store", e.keyOf(sub, provider))
	}
	rec, err := oauthbroker.ParseTokenRecord([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func (e *cbEnv) noKey(t *testing.T, sub, provider string) {
	t.Helper()
	if v, ok := e.vault.Value(e.keyOf(sub, provider)); ok {
		t.Fatalf("consent.store holds %s (%d bytes), want nothing", e.keyOf(sub, provider), len(v))
	}
}

func (e *cbEnv) grant(t *testing.T, sub, provider string) (oauthbroker.Grant, error) {
	t.Helper()
	return e.store.GetGrant(context.Background(), wantUserKey(sub), provider)
}

// TestConnectCallback: start then callback against the fake provider stores
// the token record at users/<userKey>/google with the fake's access token and a
// grant_id equal to the active grants row, completes the pending granted and
// closes its Subscribe channel within a second.
func TestConnectCallback(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	f := e.connect(t, cbSub, "google", true, "drive.readonly")
	ch, cancel := e.store.Subscribe(f.pendingID)
	defer cancel()

	res, err := e.b.Callback(ctx, f.req)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if res.Result != oauthbroker.ResultGranted || res.PendingID != f.pendingID || res.Provider != "google" {
		t.Fatalf("result = %+v", res)
	}
	rec := e.record(t, cbSub, "google")
	g, err := e.grant(t, cbSub, "google")
	if err != nil {
		t.Fatal(err)
	}
	if rec.AccessToken != e.prov.AccessToken(1) || rec.RefreshToken != e.prov.RefreshToken(1) || rec.GrantID != g.GrantID ||
		g.State != oauthbroker.GrantActive || rec.ClientID != fakes.OAuthDefaultClientID || rec.Scope != "drive.readonly" ||
		rec.TokenType != "Bearer" || rec.ObtainedAt != oauthbrokertest.Start.Unix() || rec.Expiry <= rec.ObtainedAt-1 {
		t.Fatalf("record %v, grant %+v", rec, g)
	}
	if !slices.Equal(g.Scopes, []string{"drive.readonly"}) {
		t.Fatalf("grant scopes = %v", g.Scopes)
	}
	if got := oauthbrokertest.Received(t, ch); got != oauthbroker.StatusGranted {
		t.Fatalf("Subscribe delivered %q", got)
	}
	p, _ := e.store.GetPending(ctx, f.pendingID)
	if p.Status != oauthbroker.StatusGranted {
		t.Fatalf("pending = %+v", p)
	}
	// The form the provider saw carried the verifier, the secret and the
	// configured redirect.
	form := e.prov.LastTokenForm()
	if form.Get("code_verifier") == "" || form.Get("client_secret") != fakes.OAuthDefaultSecret || form.Get("redirect_uri") != startRedir {
		t.Fatalf("token form = %v", form)
	}
	if evs := e.audit.all(); len(evs) != 1 || evs[0].Action != oauthbroker.AuditActionGranted || evs[0].Outcome != oauthbroker.OutcomeOK ||
		evs[0].GrantID != g.GrantID || evs[0].PendingID != f.pendingID || evs[0].Sub != cbSub {
		t.Fatalf("audit = %+v", evs)
	}
	if !strings.Contains(e.logs.String(), `"msg":"connect"`) || !strings.Contains(e.logs.String(), `"schema":"warden.consent.v1"`) {
		t.Error("no connect log line with schema warden.consent.v1")
	}
	if n := e.b.ConnectCounts()[oauthbroker.ConnectKey{Provider: "google", Stage: oauthbroker.StageCallback, Outcome: oauthbroker.OutcomeOK}]; n != 1 {
		t.Errorf("callback ok counter = %d", n)
	}
	if got := e.b.ExchangeSeconds()["google"]; got[0] != 1 {
		t.Errorf("exchange timing = %v", got)
	}
}

// TestConnectCallbackWrongUser: a valid state completed by another portal user
// is 403 before any exchange: the fake receives no request, the store and the
// grants stay empty. Replaying the used state is then 400 state_invalid.
func TestConnectCallbackWrongUser(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	f := e.connect(t, cbSub, "google", false, "drive.readonly")
	other := f.req
	other.Sub = "mallory"
	_, err := e.b.Callback(ctx, other)
	if code, status := cbCode(t, err); code != oauthbroker.CodeSessionMismatch || status != 403 {
		t.Fatalf("wrong user = %s %d", code, status)
	}
	if n := e.prov.TokenRequests(); n != 0 {
		t.Fatalf("the token endpoint got %d requests", n)
	}
	e.noKey(t, cbSub, "google")
	if _, err := e.grant(t, cbSub, "google"); !errors.Is(err, oauthbroker.ErrNotFound) {
		t.Fatalf("grant after a refused callback = %v", err)
	}
	// The attempt was consumed by the refusal: the rightful user cannot reuse
	// it either, and a replay is state_invalid.
	_, err = e.b.Callback(ctx, f.req)
	if code, status := cbCode(t, err); code != oauthbroker.CodeStateInvalid || status != 400 {
		t.Fatalf("replay = %s %d", code, status)
	}
	if evs := e.audit.all(); len(evs) != 1 || evs[0].Action != oauthbroker.AuditActionDenied || evs[0].Reason != oauthbroker.CodeSessionMismatch {
		t.Fatalf("audit = %+v", evs)
	}
}

// TestConnectCallbackReplay: the first callback succeeds, the second with the
// same state is refused without another exchange.
func TestConnectCallbackReplay(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	f := e.connect(t, cbSub, "google", false, "drive.readonly")
	if _, err := e.b.Callback(ctx, f.req); err != nil {
		t.Fatal(err)
	}
	_, err := e.b.Callback(ctx, f.req)
	if code, _ := cbCode(t, err); code != oauthbroker.CodeStateInvalid {
		t.Fatalf("replay = %v", err)
	}
	if e.prov.TokenRequests() != 1 {
		t.Fatalf("token requests = %d, want 1", e.prov.TokenRequests())
	}
	// A state nobody issued, and an empty one, are refused the same way.
	for _, st := range []string{"never-issued", ""} {
		r := f.req
		r.State = st
		_, err := e.b.Callback(ctx, r)
		if code, status := cbCode(t, err); code != oauthbroker.CodeStateInvalid || status != 400 {
			t.Fatalf("state %q = %s %d", st, code, status)
		}
	}
}

// TestConnectCallbackWrongBrowser: the right session user with another
// browser's cookie (or none) is state_invalid and the attempt is spent.
func TestConnectCallbackWrongBrowser(t *testing.T) {
	for name, token := range map[string]string{"other cookie": "another-browsers-cookie-value-0123456789abcdef", "no cookie": ""} {
		t.Run(name, func(t *testing.T) {
			e := newCBEnv(t)
			f := e.connect(t, cbSub, "google", false, "drive.readonly")
			r := f.req
			r.BrowserToken = token
			_, err := e.b.Callback(context.Background(), r)
			if code, status := cbCode(t, err); code != oauthbroker.CodeStateInvalid || status != 400 {
				t.Fatalf("= %s %d", code, status)
			}
			if e.prov.TokenRequests() != 0 {
				t.Fatal("the provider was called")
			}
			e.noKey(t, cbSub, "google")
			if _, err := e.b.Callback(context.Background(), f.req); err == nil {
				t.Fatal("the attempt survived a refused callback")
			}
		})
	}
}

// TestConnectCallbackExpiredAttempt: an attempt older than its 10 minutes is
// state_invalid.
func TestConnectCallbackExpiredAttempt(t *testing.T) {
	e := newCBEnv(t)
	f := e.connect(t, cbSub, "google", false, "drive.readonly")
	e.clk.Advance(oauthbroker.AttemptTTL + time.Second)
	_, err := e.b.Callback(context.Background(), f.req)
	if code, _ := cbCode(t, err); code != oauthbroker.CodeStateInvalid {
		t.Fatalf("expired = %v", err)
	}
	if e.prov.TokenRequests() != 0 {
		t.Fatal("the provider was called")
	}
}

// TestConnectCallbackAccessDenied: the user's refusal at the provider (the
// error parameter) completes the pending denied and records connect.denied; no
// exchange runs and nothing is stored.
func TestConnectCallbackAccessDenied(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	f := e.connect(t, cbSub, "google", true, "drive.readonly")
	f.req.Code, f.req.ProviderError = "", "access_denied"
	res, err := e.b.Callback(ctx, f.req)
	if err != nil || res.Result != oauthbroker.ResultDenied || res.Reason != oauthbroker.ReasonAccessDenied {
		t.Fatalf("Callback = %+v, %v", res, err)
	}
	p, _ := e.store.GetPending(ctx, f.pendingID)
	if p.Status != oauthbroker.StatusDenied || p.Reason != "access_denied" {
		t.Fatalf("pending = %+v", p)
	}
	if evs := e.audit.all(); len(evs) != 1 || evs[0].Action != oauthbroker.AuditActionDenied || evs[0].Reason != "access_denied" {
		t.Fatalf("audit = %+v", evs)
	}
	if e.prov.TokenRequests() != 0 {
		t.Fatal("exchange ran for a denial")
	}
	e.noKey(t, cbSub, "google")

	// Any other provider error fails the attempt but leaves the pending open.
	g := e.connect(t, "bob", "google", true, "drive.readonly")
	g.req.Code, g.req.ProviderError = "", "server_error"
	_, err = e.b.Callback(ctx, g.req)
	if code, _ := cbCode(t, err); code != oauthbroker.CodeExchangeFailed {
		t.Fatalf("provider error = %v", err)
	}
	if p, _ := e.store.GetPending(ctx, g.pendingID); p.Status != oauthbroker.StatusPending {
		t.Fatalf("pending = %+v, want still open", p)
	}
}

// TestConnectCallbackProviderErrorField: a GitHub-style HTTP 200 carrying an
// error field writes no secret and leaves the pending open; so does a Google
// style 400 invalid_grant. The provider's text is not in the error.
func TestConnectCallbackProviderErrorField(t *testing.T) {
	for name, style := range map[string]fakes.OAuthStyle{"github 200": fakes.OAuthGitHub, "google 400": fakes.OAuthGoogle} {
		t.Run(name, func(t *testing.T) {
			e := newCBEnv(t)
			e.prov.SetStyle(style)
			provider, scope := "google", "drive.readonly"
			if style == fakes.OAuthGitHub {
				provider, scope = "github", "read:user"
			}
			f := e.connect(t, cbSub, provider, true, scope)
			e.prov.FailToken("bad_verification_code", 400)
			_, err := e.b.Callback(context.Background(), f.req)
			code, status := cbCode(t, err)
			if code != oauthbroker.CodeExchangeFailed || status != 400 {
				t.Fatalf("= %s %d", code, status)
			}
			if strings.Contains(err.Error(), "fake provider text") {
				t.Fatal("provider text reached the error")
			}
			e.noKey(t, cbSub, provider)
			if _, gerr := e.grant(t, cbSub, provider); !errors.Is(gerr, oauthbroker.ErrNotFound) {
				t.Fatalf("a grant row exists after a failed exchange: %v", gerr)
			}
			if p, _ := e.store.GetPending(context.Background(), f.pendingID); p.Status != oauthbroker.StatusPending {
				t.Fatalf("pending = %+v, want open", p)
			}
		})
	}
}

// TestConnectCallbackProviderDown: a 5xx is provider_unreachable (502), the
// pending stays open.
func TestConnectCallbackProviderDown(t *testing.T) {
	e := newCBEnv(t)
	f := e.connect(t, cbSub, "google", true, "drive.readonly")
	e.prov.FailToken("server_error", 503)
	_, err := e.b.Callback(context.Background(), f.req)
	if code, status := cbCode(t, err); code != oauthbroker.CodeProviderUnreachable || status != 502 {
		t.Fatalf("= %s %d", code, status)
	}
	if p, _ := e.store.GetPending(context.Background(), f.pendingID); p.Status != oauthbroker.StatusPending {
		t.Fatalf("pending = %+v", p)
	}
	e.noKey(t, cbSub, "google")
}

// TestConnectCallbackReconnectKeepsRefreshToken: a reconnect whose response
// has no refresh token keeps the stored one; the grant id is new and the
// previous token is replaced.
func TestConnectCallbackReconnectKeepsRefreshToken(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	if _, err := e.b.Callback(ctx, e.connect(t, cbSub, "google", false, "drive.readonly").req); err != nil {
		t.Fatal(err)
	}
	first := e.record(t, cbSub, "google")
	e.prov.OmitRefreshToken(true)
	e.clk.Advance(time.Minute)
	if _, err := e.b.Callback(ctx, e.connect(t, cbSub, "google", false, "drive.readonly").req); err != nil {
		t.Fatal(err)
	}
	second := e.record(t, cbSub, "google")
	if second.RefreshToken != first.RefreshToken || second.RefreshToken == "" {
		t.Fatalf("refresh token %q, want the stored %q", second.RefreshToken, first.RefreshToken)
	}
	if second.AccessToken != e.prov.AccessToken(2) || second.GrantID == first.GrantID {
		t.Fatalf("second record %v, first %v", second, first)
	}
	if g, _ := e.grant(t, cbSub, "google"); g.GrantID != second.GrantID || g.State != oauthbroker.GrantActive {
		t.Fatalf("grant = %+v", g)
	}
}

// TestConnectCallbackScopeExceeded: a provider that grants a scope outside the
// operator's cap (even when the user was asked for less) writes no secret and
// no active grant, and the pending is denied scope_exceeded.
func TestConnectCallbackScopeExceeded(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	f := e.connect(t, cbSub, "google", true, "drive.readonly")
	e.prov.GrantScopes("drive.readonly gmail.send")
	_, err := e.b.Callback(ctx, f.req)
	if code, status := cbCode(t, err); code != oauthbroker.CodeScopeExceeded || status != 403 {
		t.Fatalf("= %s %d", code, status)
	}
	if e.vault.Puts != 0 {
		t.Fatalf("Put called %d times", e.vault.Puts)
	}
	e.noKey(t, cbSub, "google")
	if _, gerr := e.grant(t, cbSub, "google"); !errors.Is(gerr, oauthbroker.ErrNotFound) {
		t.Fatalf("grant = %v, want none", gerr)
	}
	if p, _ := e.store.GetPending(ctx, f.pendingID); p.Status != oauthbroker.StatusDenied || p.Reason != "scope_exceeded" {
		t.Fatalf("pending = %+v", p)
	}
	if !strings.Contains(e.logs.String(), `"msg":"oauth_connect_scope_exceeded"`) {
		t.Error("no WARN for the exceeded scope")
	}
	// The cap is the provider's allowedScopes, not the attempt's: a scope the
	// operator allows but the attempt did not ask for is fine.
	g := e.connect(t, "bob", "google", false, "drive.readonly")
	e.prov.GrantScopes("drive.readonly calendar.readonly")
	if _, err := e.b.Callback(ctx, g.req); err != nil {
		t.Fatalf("a scope inside allowedScopes was refused: %v", err)
	}
	if rec := e.record(t, "bob", "google"); rec.Scope != "calendar.readonly drive.readonly" {
		t.Fatalf("stored scope = %q", rec.Scope)
	}
}

// TestConnectCallbackInsufficientScope: fewer scopes than requested are stored
// as returned and the pending ends denied insufficient_scope.
func TestConnectCallbackInsufficientScope(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	f := e.connect(t, cbSub, "google", true, "drive.readonly", "calendar.readonly")
	e.prov.GrantScopes("drive.readonly")
	res, err := e.b.Callback(ctx, f.req)
	if err != nil || res.Result != oauthbroker.ResultDenied || res.Reason != oauthbroker.ReasonInsufficientScope {
		t.Fatalf("= %+v, %v", res, err)
	}
	if rec := e.record(t, cbSub, "google"); rec.Scope != "drive.readonly" {
		t.Fatalf("stored scope = %q", rec.Scope)
	}
	if g, _ := e.grant(t, cbSub, "google"); g.State != oauthbroker.GrantActive || !slices.Equal(g.Scopes, []string{"drive.readonly"}) {
		t.Fatalf("grant = %+v", g)
	}
	if p, _ := e.store.GetPending(ctx, f.pendingID); p.Status != oauthbroker.StatusDenied || p.Reason != "insufficient_scope" {
		t.Fatalf("pending = %+v", p)
	}
	// GitHub style: comma separated scopes parse the same way.
	e.prov.SetStyle(fakes.OAuthGitHub)
	e.prov.GrantScopes("read:user,repo")
	h := e.connect(t, "bob", "github", false, "read:user", "repo")
	if _, err := e.b.Callback(ctx, h.req); err != nil {
		t.Fatal(err)
	}
	if rec := e.record(t, "bob", "github"); rec.Scope != "read:user repo" || rec.RefreshToken != "" {
		t.Fatalf("github record = %v", rec)
	}
}

// TestConnectCallbackSecretStoreDown: a failing Put is 503
// secret_store_unavailable, the grant stays connecting, and after the
// reconciler runs the grant is revoked and no key exists.
func TestConnectCallbackSecretStoreDown(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	e.vault.SetErrors(nil, errors.New("backend down"), nil, nil)
	f := e.connect(t, cbSub, "google", true, "drive.readonly")
	_, err := e.b.Callback(ctx, f.req)
	if code, status := cbCode(t, err); code != oauthbroker.CodeSecretStoreDown || status != 503 {
		t.Fatalf("= %s %d", code, status)
	}
	g, gerr := e.grant(t, cbSub, "google")
	if gerr != nil || g.State != oauthbroker.GrantConnecting {
		t.Fatalf("grant = %+v, %v; want connecting", g, gerr)
	}
	if p, _ := e.store.GetPending(ctx, f.pendingID); p.Status != oauthbroker.StatusPending {
		t.Fatalf("pending = %+v, want open for a retry", p)
	}
	e.vault.SetErrors(nil, nil, nil, nil)
	e.clk.Advance(oauthbroker.ConnectingGrantTTL + time.Minute)
	res, serr := e.store.Sweep(ctx, e.clk.Now())
	if serr != nil || len(res.StaleConnecting) != 1 {
		t.Fatalf("Sweep = %+v, %v", res, serr)
	}
	e.b.Reconcile(ctx, res.StaleConnecting)
	if g, _ := e.grant(t, cbSub, "google"); g.State != oauthbroker.GrantRevoked {
		t.Fatalf("grant after reconcile = %+v, want revoked", g)
	}
	e.noKey(t, cbSub, "google")
}

// TestConnectCallbackReconcileRestoresReconnect: a reconnect that failed to
// write leaves the working token in place, and the reconciler restores the
// earlier grant instead of deleting it.
func TestConnectCallbackReconcileRestoresReconnect(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	if _, err := e.b.Callback(ctx, e.connect(t, cbSub, "google", false, "drive.readonly").req); err != nil {
		t.Fatal(err)
	}
	before := e.record(t, cbSub, "google")
	e.vault.SetErrors(nil, errors.New("backend down"), nil, nil)
	f := e.connect(t, cbSub, "google", false, "drive.readonly")
	if _, err := e.b.Callback(ctx, f.req); err == nil {
		t.Fatal("callback succeeded with a failing store")
	}
	e.vault.SetErrors(nil, nil, nil, nil)
	if g, _ := e.grant(t, cbSub, "google"); g.State != oauthbroker.GrantConnecting || g.PrevGrantID != before.GrantID {
		t.Fatalf("grant = %+v", g)
	}
	e.clk.Advance(oauthbroker.ConnectingGrantTTL + time.Minute)
	res, _ := e.store.Sweep(ctx, e.clk.Now())
	e.b.Reconcile(ctx, res.StaleConnecting)
	g, _ := e.grant(t, cbSub, "google")
	if g.State != oauthbroker.GrantActive || g.GrantID != before.GrantID {
		t.Fatalf("grant = %+v, want the earlier active grant", g)
	}
	if after := e.record(t, cbSub, "google"); after.AccessToken != before.AccessToken {
		t.Fatal("the working token was replaced")
	}
	// A reconcile of a row that moved on (a newer reconnect) does nothing.
	e.b.Reconcile(ctx, res.StaleConnecting)
	if g2, _ := e.grant(t, cbSub, "google"); g2.GrantID != before.GrantID || g2.State != oauthbroker.GrantActive {
		t.Fatalf("a stale reconcile changed the grant: %+v", g2)
	}
}

// TestConnectCallbackReconcileKeepsOnStoreError: with the store unreadable the
// row stays connecting; nothing is revoked while its key might survive.
func TestConnectCallbackReconcileKeepsOnStoreError(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	e.vault.SetErrors(nil, errors.New("down"), nil, nil)
	if _, err := e.b.Callback(ctx, e.connect(t, cbSub, "google", false, "drive.readonly").req); err == nil {
		t.Fatal("want an error")
	}
	e.vault.SetErrors(errors.New("down"), nil, nil, nil)
	e.clk.Advance(oauthbroker.ConnectingGrantTTL + time.Minute)
	res, _ := e.store.Sweep(ctx, e.clk.Now())
	e.b.Reconcile(ctx, res.StaleConnecting)
	if g, _ := e.grant(t, cbSub, "google"); g.State != oauthbroker.GrantConnecting {
		t.Fatalf("grant = %+v, want connecting until the store answers", g)
	}
}

// TestConnectCallbackBlocked: a user blocked before the exchange never reaches
// the provider; one blocked while the exchange ran has the key deleted and the
// grant revoked.
func TestConnectCallbackBlocked(t *testing.T) {
	t.Run("before", func(t *testing.T) {
		e := newCBEnv(t)
		f := e.connect(t, cbSub, "google", true, "drive.readonly")
		e.blocks.from = 1
		e.blocks.calls = 0
		_, err := e.b.Callback(context.Background(), f.req)
		if code, status := cbCode(t, err); code != oauthbroker.CodeUserBlocked || status != 403 {
			t.Fatalf("= %s %d", code, status)
		}
		if e.prov.TokenRequests() != 0 {
			t.Fatal("a blocked user reached the provider")
		}
		e.noKey(t, cbSub, "google")
	})
	t.Run("during", func(t *testing.T) {
		e := newCBEnv(t)
		ctx := context.Background()
		f := e.connect(t, cbSub, "google", true, "drive.readonly")
		e.blocks.calls = 0
		e.blocks.from = 2 // the pre-exchange check passes, the post-write check blocks
		_, err := e.b.Callback(ctx, f.req)
		if code, _ := cbCode(t, err); code != oauthbroker.CodeUserBlocked {
			t.Fatalf("= %v", err)
		}
		e.noKey(t, cbSub, "google")
		if g, _ := e.grant(t, cbSub, "google"); g.State != oauthbroker.GrantRevoked {
			t.Fatalf("grant = %+v, want revoked", g)
		}
		if p, _ := e.store.GetPending(ctx, f.pendingID); p.Status != oauthbroker.StatusDenied || p.Reason != "user_blocked" {
			t.Fatalf("pending = %+v", p)
		}
	})
	t.Run("list unavailable", func(t *testing.T) {
		e := newCBEnv(t)
		f := e.connect(t, cbSub, "google", false, "drive.readonly")
		e.blocks.err = errors.New("not loaded")
		_, err := e.b.Callback(context.Background(), f.req)
		if code, status := cbCode(t, err); code != oauthbroker.CodeBlockListUnavailable || status != 503 {
			t.Fatalf("= %s %d", code, status)
		}
		if e.prov.TokenRequests() != 0 {
			t.Fatal("the provider was called")
		}
	})
}

// TestConnectCallbackAuditUnhealthy: an unhealthy audit log is 503
// admin_audit_unavailable before the attempt is consumed or the exchange runs;
// once healthy the same state still works.
func TestConnectCallbackAuditUnhealthy(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	f := e.connect(t, cbSub, "google", false, "drive.readonly")
	e.audit.ready = errors.New("audit store read-only")
	_, err := e.b.Callback(ctx, f.req)
	if code, status := cbCode(t, err); code != oauthbroker.CodeAuditUnavailable || status != 503 {
		t.Fatalf("= %s %d", code, status)
	}
	if e.prov.TokenRequests() != 0 {
		t.Fatal("exchange ran with audit down")
	}
	e.audit.ready = nil
	if _, err := e.b.Callback(ctx, f.req); err != nil {
		t.Fatalf("retry after audit recovered: %v", err)
	}
}

// TestConnectCallbackNeedsAssembly: a Broker built without the callback
// dependencies refuses with an internal error instead of panicking.
func TestConnectCallbackNeedsAssembly(t *testing.T) {
	e := newStartEnv(t, nil)
	_, err := e.b.Callback(context.Background(), oauthbroker.CallbackRequest{Iss: startIss, Sub: "alice", State: "s"})
	if code, status := cbCode(t, err); code != oauthbroker.CodeInternal || status != 500 {
		t.Fatalf("= %s %d", code, status)
	}
}

// TestCountOrphans: keys under users/ with no live grant row are counted, and
// the gauge follows.
func TestCountOrphans(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	if _, err := e.b.Callback(ctx, e.connect(t, cbSub, "google", false, "drive.readonly").req); err != nil {
		t.Fatal(err)
	}
	if n, err := e.b.CountOrphans(ctx); err != nil || n != 0 {
		t.Fatalf("CountOrphans = %d, %v", n, err)
	}
	_ = e.vault.Put(ctx, "users/"+wantUserKey("nobody")+"/google", "{}")
	_ = e.vault.Put(ctx, "users/malformed", "{}")
	_ = e.vault.Put(ctx, "idp/"+wantUserKey(cbSub), "x") // another namespace: not counted
	if n, err := e.b.CountOrphans(ctx); err != nil || n != 2 || e.b.OrphanedGrants() != 2 {
		t.Fatalf("CountOrphans = %d, %v (gauge %d), want 2", n, err, e.b.OrphanedGrants())
	}
	if _, err := e.store.RevokeGrant(ctx, wantUserKey(cbSub), "google", ""); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.b.CountOrphans(ctx); n != 3 {
		t.Fatalf("a revoked grant's key = %d orphans, want 3", n)
	}
}

// TestCallbackNoSecretLeak: across success, denial, failure and refusal paths,
// no log line and no audit event holds an access token, refresh token, code,
// state, verifier, client secret or a sha256: reference.
func TestCallbackNoSecretLeak(t *testing.T) {
	e := newCBEnv(t)
	ctx := context.Background()
	var secretsSeen []string
	add := func(f flow) {
		secretsSeen = append(secretsSeen, f.state, f.req.Code, f.req.BrowserToken)
	}

	ok := e.connect(t, cbSub, "google", true, "drive.readonly")
	add(ok)
	if _, err := e.b.Callback(ctx, ok.req); err != nil {
		t.Fatal(err)
	}
	_, _ = e.b.Callback(ctx, ok.req) // replay

	wrong := e.connect(t, "bob", "google", false, "drive.readonly")
	add(wrong)
	w := wrong.req
	w.Sub = "mallory"
	_, _ = e.b.Callback(ctx, w)

	denied := e.connect(t, "carol", "google", true, "drive.readonly")
	add(denied)
	denied.req.Code, denied.req.ProviderError = "", "access_denied"
	_, _ = e.b.Callback(ctx, denied.req)

	wide := e.connect(t, "dave", "google", true, "drive.readonly")
	add(wide)
	e.prov.GrantScopes("drive.readonly gmail.send")
	_, _ = e.b.Callback(ctx, wide.req)
	e.prov.FailToken("invalid_grant", 400)
	bad := e.connect(t, "erin", "google", false, "drive.readonly")
	add(bad)
	_, _ = e.b.Callback(ctx, bad.req)
	e.prov.FailToken("", 0)

	e.vault.SetErrors(nil, errors.New("down"), nil, nil)
	e.prov.GrantScopes("drive.readonly")
	down := e.connect(t, "fred", "google", false, "drive.readonly")
	add(down)
	_, _ = e.b.Callback(ctx, down.req)
	e.vault.SetErrors(nil, nil, nil, nil)

	// Every verifier and code the provider saw (the attempts are consumed, so
	// the provider's record is the only copy left).
	for _, form := range e.prov.TokenForms() {
		secretsSeen = append(secretsSeen, form.Get("code_verifier"), form.Get("code"))
	}
	if len(e.prov.TokenForms()) < 4 {
		t.Fatalf("the provider saw %d exchanges, the scenarios above make at least 4", len(e.prov.TokenForms()))
	}
	secretsSeen = append(secretsSeen, fakes.OAuthDefaultSecret)
	for i := 1; i <= e.prov.Issued(); i++ {
		secretsSeen = append(secretsSeen, e.prov.AccessToken(i), e.prov.RefreshToken(i))
	}
	evJSON, err := json.Marshal(e.audit.all())
	if err != nil {
		t.Fatal(err)
	}
	haystack := e.logs.String() + string(evJSON)
	for _, s := range secretsSeen {
		if s != "" && strings.Contains(haystack, s) {
			t.Errorf("a log line or audit event holds %q", s)
		}
	}
	if strings.Contains(haystack, "sha256:") {
		t.Error("a log line or audit event holds a sha256: reference")
	}
	for _, ev := range e.audit.all() {
		if ev.Action != oauthbroker.AuditActionGranted && ev.Action != oauthbroker.AuditActionDenied {
			t.Errorf("unexpected audit action %q", ev.Action)
		}
	}
}

// TestExchangeRequestRedacts: the request and response types print neither
// secrets nor tokens under any verb.
func TestExchangeRequestRedacts(t *testing.T) {
	r := oauthbroker.ExchangeRequest{TokenURL: "https://t", ClientID: "c", ClientSecret: oauthbroker.NewSecret("S3CRET"), Code: "CODE123", Verifier: "VERIFIER456"}
	tr := oauthbroker.TokenResponse{AccessToken: "ACCESS789", RefreshToken: "REFRESH012", TokenType: "bearer"}
	var b bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&b, nil))
	logger.Info("x", "req", r, "tok", tr)
	for _, v := range []string{r.String(), r.GoString(), tr.String(), tr.GoString(), b.String()} {
		for _, s := range []string{"S3CRET", "CODE123", "VERIFIER456", "ACCESS789", "REFRESH012"} {
			if strings.Contains(v, s) {
				t.Errorf("%q leaks %s", v, s)
			}
		}
	}
}

// TestGrantLocks: one holder per (userKey, provider) at a time, other pairs do
// not wait, and the set drains.
func TestGrantLocks(t *testing.T) {
	l := oauthbroker.NewGrantLocks()
	unlock := l.Lock("u1", "google")
	got := make(chan struct{})
	go func() {
		u := l.Lock("u1", "google")
		close(got)
		u()
	}()
	other := l.Lock("u1", "github")
	other()
	l.Lock("u2", "google")()
	select {
	case <-got:
		t.Fatal("the second holder of (u1, google) ran while the first held it")
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	unlock() // idempotent
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter never got the lock")
	}
	deadline := time.Now().Add(2 * time.Second)
	for l.Held() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the lock set holds %d entries after every unlock", l.Held())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSafeErrorCode: only plausible OAuth error codes survive.
func TestSafeErrorCode(t *testing.T) {
	for in, want := range map[string]string{
		"invalid_grant": "invalid_grant", "access_denied": "access_denied",
		"": "invalid_response", "has space": "invalid_response", "<script>": "invalid_response",
		strings.Repeat("a", 65): "invalid_response",
	} {
		if got := oauthbroker.SafeErrorCode(in); got != want {
			t.Errorf("SafeErrorCode(%q) = %q, want %q", in, got, want)
		}
	}
}

type stubExchanger struct {
	resp oauthbroker.TokenResponse
	err  error
}

func (s stubExchanger) Exchange(context.Context, oauthbroker.ExchangeRequest) (oauthbroker.TokenResponse, error) {
	return s.resp, s.err
}

// TestConnectCallbackUnusableToken: an empty access token or a token type that
// is not bearer is a failed exchange; nothing is stored.
func TestConnectCallbackUnusableToken(t *testing.T) {
	for name, resp := range map[string]oauthbroker.TokenResponse{
		"mac":    {AccessToken: "AT", TokenType: "mac"},
		"empty":  {TokenType: "bearer"},
		"no typ": {AccessToken: "AT"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newCBEnv(t)
			cfg := e.cfg
			cfg.Exchanger = stubExchanger{resp: resp}
			b, err := oauthbroker.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			f := e.connect(t, cbSub, "google", true, "drive.readonly")
			_, err = b.Callback(context.Background(), f.req)
			if code, _ := cbCode(t, err); code != oauthbroker.CodeExchangeFailed {
				t.Fatalf("= %v", err)
			}
			e.noKey(t, cbSub, "google")
		})
	}
}
