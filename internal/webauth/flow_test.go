package webauth_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/webauth"
	"github.com/ethosagent/warden/internal/webauth/webauthtest"
	"github.com/ethosagent/warden/test/fakes"
)

const (
	consoleClient = "warden-console"
	portalClient  = "warden-portal"
	clientSecret  = "flow-test-secret"
)

// flowRig is two front doors over one shared pending table, each with its own
// client, purpose, login cookie and next rule, as the console and the portal
// are.
type flowRig struct {
	t       *testing.T
	idp     *webauthtest.FakeOIDC
	pending *webauth.PendingStore
	logs    *bytes.Buffer
}

func newFlowRig(t *testing.T) *flowRig {
	t.Helper()
	idp := webauthtest.NewFakeOIDC(t, webauthtest.Options{ClientID: consoleClient, ClientSecret: clientSecret})
	idp.RegisterClient(portalClient, clientSecret)
	db := openDB(t, webauth.PendingMigrations())
	return &flowRig{t: t, idp: idp, pending: webauth.NewPendingStore(db.SQL(), nil), logs: &bytes.Buffer{}}
}

func (r *flowRig) flow(name, clientID, purpose, callbackPath, cookieBase, home string, prefixes ...string) *webauth.Flow {
	r.t.Helper()
	redir := "http://127.0.0.1:7070" + callbackPath
	client, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: r.idp.Issuer(), InternalIssuerURL: r.idp.URL()})
	if err != nil {
		r.t.Fatal(err)
	}
	verifier, err := oidc.NewIDTokenVerifier(oidc.IDTokenConfig{Issuer: r.idp.Issuer(), ClientID: clientID, InternalIssuerURL: r.idp.URL()})
	if err != nil {
		r.t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := webauth.NewProvider(webauth.ProviderConfig{
		Name: name, Issuer: r.idp.Issuer(),
		OAuth: oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redir, Scopes: []string{"openid", "email"}},
		Discover: func(ctx context.Context) (webauth.Endpoints, error) {
			ep, err := oidc.Discover(ctx, client, r.idp.Issuer())
			return webauth.Endpoints{AuthURL: ep.AuthURL, TokenURL: ep.TokenURL}, err
		},
		HTTPContext: func(ctx context.Context) context.Context { return oidc.WithHTTPClient(ctx, client) },
		Logger:      logger,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p.Run(ctx)
	if !p.Ready() {
		r.t.Fatal("discovery did not succeed")
	}
	cookie, err := webauth.NewCookie(redir, cookieBase)
	if err != nil {
		r.t.Fatal(err)
	}
	return &webauth.Flow{
		Name: name, Provider: p, Verifier: verifier, Pending: r.pending, Purpose: purpose,
		LoginCookie: cookie.Named(cookieBase + "_login"),
		AllowNext:   func(n string) bool { return webauth.SafeNext(n, prefixes...) },
		DefaultNext: home, Logger: logger,
	}
}

func (r *flowRig) console() *webauth.Flow {
	return r.flow("console", consoleClient, webauth.PurposeConsole, "/auth/callback", "warden_console", "/dashboard/", "/dashboard/")
}

func (r *flowRig) portal() *webauth.Flow {
	return r.flow("portal", portalClient, webauth.PurposePortal, "/portal/callback", "warden_portal", "/portal", "/portal/", "/connect/")
}

// begin runs Begin and the IdP leg; it returns the login cookie and the
// callback request URI.
func (r *flowRig) begin(f *webauth.Flow, next string) (*http.Cookie, string) {
	r.t.Helper()
	rec := httptest.NewRecorder()
	if err := f.Begin(rec, httptest.NewRequest(http.MethodGet, "/login", nil), next); err != nil {
		r.t.Fatalf("Begin: %v", err)
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Cache-Control") != "no-store" {
		r.t.Fatalf("Begin = %d %v", rec.Code, rec.Header())
	}
	var lc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == f.LoginCookie.Name {
			lc = c
		}
	}
	if lc == nil || lc.MaxAge != int(webauth.PendingTTL.Seconds()) || !lc.HttpOnly {
		r.t.Fatalf("login cookie = %+v", lc)
	}
	return lc, r.idp.Authorize(r.t, rec.Header().Get("Location"))
}

func (r *flowRig) complete(f *webauth.Flow, callback string, cookies ...*http.Cookie) (webauth.Login, *httptest.ResponseRecorder, error) {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodGet, callback, nil)
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	l, err := f.Complete(rec, req)
	return l, rec, err
}

func wantCode(t *testing.T, err error, code string, consumed bool) {
	t.Helper()
	var fe *webauth.Error
	if !errors.As(err, &fe) || fe.Code != code || fe.Consumed != consumed {
		t.Fatalf("error = %v (%+v), want %s consumed=%v", err, fe, code, consumed)
	}
}

// A console state fails on the portal's callback and the reverse, and the
// failed attempt does not burn the other front door's login.
func TestFlowPurposeMismatch(t *testing.T) {
	r := newFlowRig(t)
	console, portal := r.console(), r.portal()

	clc, ccb := r.begin(console, "/dashboard/fleet")
	// The portal callback with the console's state, even carrying the
	// console's binding cookie, is refused before any exchange.
	_, _, err := r.complete(portal, ccb, clc)
	wantCode(t, err, webauth.CodeStateInvalid, false)
	if r.idp.TokenRequests() != 0 {
		t.Fatal("a mismatched purpose reached the token endpoint")
	}
	l, _, err := r.complete(console, ccb, clc)
	if err != nil || l.Claims.Sub != fakes.DefaultLoginSub || l.Next != "/dashboard/fleet" {
		t.Fatalf("console complete after the portal try = %+v %v", l, err)
	}

	plc, pcb := r.begin(portal, "/connect/github")
	_, _, err = r.complete(console, pcb, plc)
	wantCode(t, err, webauth.CodeStateInvalid, false)
	l, _, err = r.complete(portal, pcb, plc)
	if err != nil || l.Next != "/connect/github" {
		t.Fatalf("portal complete = %+v %v", l, err)
	}

	// An ID token minted for the console client does not complete a portal
	// login: the portal's verifier pins its own audience.
	r.idp.SetLogin(fakes.Valid("bob", "bob@example.com"), fakes.WithAud(consoleClient), fakes.WithAZP(consoleClient))
	plc, pcb = r.begin(portal, "")
	_, _, err = r.complete(portal, pcb, plc)
	wantCode(t, err, webauth.CodeTokenInvalid, true)
}

func TestFlowRefreshToken(t *testing.T) {
	r := newFlowRig(t)
	portal := r.portal()
	lc, cb := r.begin(portal, "")
	l, _, err := r.complete(portal, cb, lc)
	if err != nil || l.RefreshToken != "" || l.Next != "/portal" {
		t.Fatalf("without a refresh token = %+v %v", l, err)
	}
	r.idp.SetRefreshToken("fake-refresh-token")
	lc, cb = r.begin(portal, "https://evil.example/portal/")
	l, rec, err := r.complete(portal, cb, lc)
	if err != nil || l.RefreshToken != "fake-refresh-token" || l.Next != "/portal" {
		t.Fatalf("with a refresh token = %+v %v", l, err)
	}
	// The binding cookie is cleared, the response is no-store and the flow
	// sets no other cookie.
	cks := rec.Result().Cookies()
	if len(cks) != 1 || cks[0].Name != lc.Name || cks[0].MaxAge >= 0 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("callback response cookies %+v headers %v", cks, rec.Header())
	}
	if strings.Contains(r.logs.String(), "fake-refresh-token") {
		t.Fatal("the refresh token was logged")
	}
}

func TestFlowRejectsUnboundBrowser(t *testing.T) {
	r := newFlowRig(t)
	console := r.console()
	lc, cb := r.begin(console, "")
	_, _, err := r.complete(console, cb, &http.Cookie{Name: lc.Name, Value: "someone-else"})
	wantCode(t, err, webauth.CodeStateInvalid, true)
	// The state was consumed: the right browser cannot use it afterwards.
	_, _, err = r.complete(console, cb, lc)
	wantCode(t, err, webauth.CodeStateInvalid, false)
}

func TestFlowUnavailable(t *testing.T) {
	db := openDB(t, webauth.PendingMigrations())
	f := &webauth.Flow{
		Name: "portal", Provider: webauth.NewProvider(webauth.ProviderConfig{Name: "portal"}),
		Pending: webauth.NewPendingStore(db.SQL(), nil), Purpose: webauth.PurposePortal,
	}
	if f.Ready() {
		t.Fatal("an undiscovered provider is ready")
	}
	rec := httptest.NewRecorder()
	if err := f.Begin(rec, httptest.NewRequest(http.MethodGet, "/portal/login", nil), ""); !errors.Is(err, webauth.ErrUnavailable) {
		t.Fatalf("Begin = %v", err)
	}
	if _, err := f.Complete(rec, httptest.NewRequest(http.MethodGet, "/portal/callback?state=x&code=y", nil)); !errors.Is(err, webauth.ErrUnavailable) {
		t.Fatalf("Complete = %v", err)
	}
	if len(rec.Header()) != 0 || rec.Body.Len() != 0 {
		t.Fatalf("an unavailable flow wrote %v %q", rec.Header(), rec.Body)
	}
	var nilFlow *webauth.Flow
	if nilFlow.Ready() {
		t.Fatal("a nil flow is ready")
	}
}

func TestSafeNext(t *testing.T) {
	for raw, want := range map[string]bool{
		"/portal/":                     true,
		"/portal/links?x=1":            true,
		"/connect/github":              true,
		"/portal":                      false, // the bare home is the default, not a kept next
		"/dashboard/":                  false,
		"//evil.example/portal/":       false,
		"https://evil.example/portal/": false,
		"/portal//evil":                false,
		`/portal/\evil`:                false,
		"/portal/../dashboard/":        false,
		"/portal/%2e%2e/dashboard/":    false,
		"/portal/a%2F%2Fb":             false,
		"/portal/a%0d%0ab":             false,
		"/connect/" + strings.Repeat("a", webauth.MaxNextBytes): false,
	} {
		if got := webauth.SafeNext(raw, "/portal/", "/connect/"); got != want {
			t.Errorf("SafeNext(%q) = %v, want %v", raw, got, want)
		}
	}
}
