package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/oauthbroker"
	oauthbrokerhttp "github.com/ethosagent/warden/internal/oauthbroker/http"
	"github.com/ethosagent/warden/internal/portal"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// The connect routes behind the portal session (W-P3-BRKR-03).

const connectCookieName = "__Host-warden_connect"

func connectProviders() []config.OAuthProviderConfig {
	return []config.OAuthProviderConfig{{
		ID: "google", Type: config.OAuthProviderGoogle, ClientID: "g-client", ClientSecretEnv: "G_SECRET",
		AllowedScopes: []string{"calendar.readonly", "drive.readonly"}, DefaultScopes: []string{"drive.readonly"},
	}}
}

func connectRig(t *testing.T) (*portalRig, *http.Cookie, string) {
	t.Helper()
	r := newPortalRig(t, portalRigOpts{providers: connectProviders()})
	r.ready()
	r.idp.SetLogin(fakes.Valid("pat", "pat@example.com", "staff"))
	c := r.login("")
	return r, c, portalCSRF(c)
}

func (r *portalRig) connectPost(c *http.Cookie, tok, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r.t.Helper()
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if tok != "" {
		h[CSRFHeader] = tok
	}
	for k, v := range hdr {
		h[k] = v
	}
	var cookies []*http.Cookie
	if c != nil {
		cookies = append(cookies, c)
	}
	return r.portalReq(http.MethodPost, "/connect/start", body, h, cookies...)
}

func (r *portalRig) attemptRows() int { return r.count("connect_attempts") }

// TestConnectStartRoute: a signed-in user with the CSRF token starts a flow; the
// redirect, cookie and stored attempt match, and every refusal leaves no row.
func TestConnectStartRoute(t *testing.T) {
	r, c, tok := connectRig(t)
	form := url.Values{"provider": {"google"}, "scopes": {"drive.readonly"}}.Encode()
	rec := r.connectPost(c, tok, form, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST = %d %s, want 303", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Host != "accounts.google.com" {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != "https://cp.example/connect/callback" || q.Get("scope") != "drive.readonly email openid" {
		t.Errorf("query = %v", q)
	}
	var cookie *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == connectCookieName {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge != 600 {
		t.Fatalf("cookie = %+v", cookie)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers = %v", rec.Header())
	}
	var verifier, browser string
	if err := r.db.SQL().QueryRow(`SELECT verifier, browser_hash FROM connect_attempts WHERE state_hash = ?`,
		oauthbroker.HashState(q.Get("state"))).Scan(&verifier, &browser); err != nil {
		t.Fatalf("no attempt under the state hash: %v", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") || browser != oauthbroker.HashBrowserBinding(cookie.Value) {
		t.Error("the stored verifier or browser hash does not match the redirect and cookie")
	}
	if logs := r.logs.String(); strings.Contains(logs, q.Get("state")) || strings.Contains(logs, verifier) || strings.Contains(logs, cookie.Value) ||
		!strings.Contains(logs, `"msg":"oauth_connect_start"`) {
		t.Error("the start log line is missing or holds a state, verifier or cookie value")
	}
	if got := r.srv.OAuthConnectCounts()[oauthbroker.ConnectKey{Provider: "google", Stage: "start", Outcome: "ok"}]; got != 1 {
		t.Errorf("counter = %d, want 1", got)
	}

	before := r.attemptRows()
	pendings := r.count("pending_authorizations")
	// Scope outside the cap: 400 with the name, no rows.
	rec = r.connectPost(c, tok, url.Values{"provider": {"google"}, "scopes": {"drive.readonly gmail.send"}}.Encode(), nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"scope_not_allowed"`) || !strings.Contains(rec.Body.String(), "gmail.send") {
		t.Fatalf("outside scope = %d %s", rec.Code, rec.Body)
	}
	// A foreign pending and an unknown one are byte-identical 404s.
	other, err := r.srv.cfg.GrantStore.CreatePending(context.Background(), oauthbroker.Pending{
		Iss: "https://other-idp", Sub: "mallory", UserKey: "ab", Provider: "google", Scopes: []string{"drive.readonly"},
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pendings++
	a := r.connectPost(c, tok, url.Values{"provider": {"google"}, "pending": {other.ID}}.Encode(), nil)
	b := r.connectPost(c, tok, url.Values{"provider": {"google"}, "pending": {"does-not-exist"}}.Encode(), nil)
	if a.Code != http.StatusNotFound || a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Fatalf("foreign pending = %d %q, unknown = %d %q", a.Code, a.Body, b.Code, b.Body)
	}
	if rec := r.connectPost(c, tok, url.Values{"provider": {"nope"}}.Encode(), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown provider = %d", rec.Code)
	}
	if r.attemptRows() != before || r.count("pending_authorizations") != pendings {
		t.Fatalf("a refused start wrote a row: attempts %d->%d", before, r.attemptRows())
	}
}

// TestConnectStartRouteAuth: CSRF and Origin are enforced, a missing session is
// a 303 to the portal sign-in, console credentials never authenticate, and a
// GET writes nothing.
func TestConnectStartRouteAuth(t *testing.T) {
	r, c, tok := connectRig(t)
	form := url.Values{"provider": {"google"}}.Encode()

	if rec := r.connectPost(c, "", form, nil); rec.Code != http.StatusForbidden || errBody(t, rec) != portal.CodeCSRF {
		t.Fatalf("no csrf = %d %s", rec.Code, rec.Body)
	}
	if rec := r.connectPost(c, tok, form, map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign origin = %d", rec.Code)
	}
	if rec := r.connectPost(c, "", "csrf="+tok+"&"+form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("csrf as a form field = %d, want 303", rec.Code)
	}
	// No session: 303 to the sign-in for POST (no next) and GET (a relative next).
	rec := r.connectPost(nil, "", form, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/portal/login" {
		t.Fatalf("no session POST = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = r.serve(http.MethodGet, "/connect/start?pending=abc")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/portal/login?next=%2Fconnect%2Fstart%3Fpending%3Dabc" {
		t.Fatalf("no session GET = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Console credentials never authenticate here: 401, not a redirect.
	for name, hdr := range map[string]map[string]string{
		"bearer":     {"Authorization": "Bearer admin-token"},
		"worker tok": {"Authorization": "Bearer worker-token-value"},
		"api key":    {"Authorization": "Bearer wak_0123456789abcdef"},
	} {
		if rec := r.connectPost(nil, "", form, hdr); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, rec.Code)
		}
	}
	// The same holds for a signed-out GET: a credential is 401, not a redirect.
	greq := httptest.NewRequest(http.MethodGet, "/connect/start", nil)
	greq.Header.Set("Authorization", "Bearer admin-token")
	grec := httptest.NewRecorder()
	r.h.ServeHTTP(grec, greq)
	if grec.Code != http.StatusUnauthorized {
		t.Errorf("GET with a bearer and no session = %d, want 401", grec.Code)
	}
	greq = httptest.NewRequest(http.MethodGet, "/connect/start", nil)
	greq.AddCookie(&http.Cookie{Name: r.srv.sessionCookie.Name, Value: "console-session"})
	grec = httptest.NewRecorder()
	r.h.ServeHTTP(grec, greq)
	if grec.Code != http.StatusUnauthorized {
		t.Errorf("GET with a console cookie and no session = %d, want 401", grec.Code)
	}
	console := &http.Cookie{Name: r.srv.sessionCookie.Name, Value: "console-session"}
	if rec := r.connectPost(console, "", form, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("console cookie = %d, want 401", rec.Code)
	}
	// A bearer next to a portal session is ignored (stripped), not authority.
	if rec := r.connectPost(c, tok, form, map[string]string{"Authorization": "Bearer admin-token"}); rec.Code != http.StatusSeeOther {
		t.Fatalf("portal session + stray bearer = %d", rec.Code)
	}
	// GET changes nothing and redirects to the landing page or the portal.
	before := r.attemptRows()
	rec = r.serve(http.MethodGet, "/connect/start?pending=abc", c)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/portal/connect/abc" {
		t.Fatalf("GET = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec = r.serve(http.MethodGet, "/connect/start", c); rec.Header().Get("Location") != "/portal" || r.attemptRows() != before {
		t.Fatalf("GET without pending = %q, attempts %d->%d", rec.Header().Get("Location"), before, r.attemptRows())
	}
}

// TestConnectStartRouteBlocked: a user on the block list is refused with no
// row (the broker's own check is TestConnectStartBlocked in oauthbroker).
func TestConnectStartRouteBlocked(t *testing.T) {
	r, c, tok := connectRig(t)
	form := url.Values{"provider": {"google"}}.Encode()
	if _, err := r.srv.blocks.Add(context.Background(), BlockEntry{Sub: "pat"}, "admin"); err != nil {
		t.Fatal(err)
	}
	rec := r.connectPost(c, tok, form, nil)
	// Blocking ends the user's portal sessions, so the request is signed out
	// (303 to sign-in) or, in the instant before, 403 user_blocked: never a
	// redirect to the provider.
	toLogin := rec.Code == http.StatusSeeOther && rec.Header().Get("Location") == "/portal/login"
	if !toLogin && rec.Code != http.StatusForbidden {
		t.Fatalf("blocked user = %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if r.attemptRows() != 0 {
		t.Fatal("a blocked user left an attempt")
	}
}

// TestConnectStartRouteRateLimit: the 11th start in a minute is 429 with a
// Retry-After.
func TestConnectStartRouteRateLimit(t *testing.T) {
	r, c, tok := connectRig(t)
	form := url.Values{"provider": {"google"}}.Encode()
	for i := 0; i < oauthbroker.StartsPerMinute; i++ {
		if rec := r.connectPost(c, tok, form, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("start %d = %d %s", i+1, rec.Code, rec.Body)
		}
	}
	rec := r.connectPost(c, tok, form, nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Fatalf("11th start = %d %s Retry-After %q", rec.Code, rec.Body, rec.Header().Get("Retry-After"))
	}
}

// TestConnectRoutePaths pins the route constants to the transport package's.
func TestConnectRoutePaths(t *testing.T) {
	if connectStartPath != oauthbrokerhttp.StartPath {
		t.Errorf("connectStartPath = %q, transport says %q", connectStartPath, oauthbrokerhttp.StartPath)
	}
}

// TestOAuthBrokerGate: with no providers /connect/start is 404 for every
// method and nothing is created; providers with no consent.store, or the echo
// one, are refused at startup with the documented error; a persistent store
// passes.
func TestOAuthBrokerGate(t *testing.T) {
	t.Run("no providers is 404", func(t *testing.T) {
		r := newPortalRig(t, portalRigOpts{})
		r.ready()
		r.idp.SetLogin(fakes.Valid("pat", "pat@example.com"))
		c := r.login("")
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			rec := r.portalReq(m, "/connect/start", "provider=google", map[string]string{CSRFHeader: portalCSRF(c)}, c)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s /connect/start = %d, want 404", m, rec.Code)
			}
		}
		if r.srv.broker != nil || r.srv.OAuthConnectCounts() != nil {
			t.Error("a broker exists without providers")
		}
		if n := brokerTables(t, r.db); n != 0 {
			t.Errorf("%d broker tables without providers", n)
		}
	})
	t.Run("providers mount it", func(t *testing.T) {
		r, c, _ := connectRig(t)
		if r.srv.broker == nil {
			t.Fatal("no broker with providers")
		}
		if rec := r.serve(http.MethodGet, "/connect/start", c); rec.Code != http.StatusSeeOther {
			t.Errorf("GET = %d", rec.Code)
		}
	})
	t.Run("startup refusal", func(t *testing.T) {
		consent := &config.ConsentConfig{Enabled: true, Providers: connectProviders()}
		aws := secrets.NewAWSSecretStore(fakes.NewFakeAWSSecretsClient(), "us-east-1", config.DefaultConsentStoreNamePrefix)
		for name, tc := range map[string]struct {
			st      secrets.SecretStore
			wantErr bool
		}{
			"no store":         {nil, true},
			"echo store":       {secrets.NewEchoStore(), true},
			"persistent store": {aws, false},
		} {
			err := checkOAuthBrokerStore(consent, tc.st)
			if (err != nil) != tc.wantErr || (err != nil && !strings.Contains(err.Error(), "oauth broker requires a persistent consent.store")) {
				t.Errorf("%s: err = %v, want error=%v naming the persistent consent.store", name, err, tc.wantErr)
			}
		}
		if err := checkOAuthBrokerStore(&config.ConsentConfig{Enabled: true}, nil); err != nil {
			t.Errorf("no providers must pass with no store: %v", err)
		}
		if err := checkOAuthBrokerStore(nil, nil); err != nil {
			t.Errorf("consent off must pass: %v", err)
		}
	})
}

// TestOAuthBrokerGateRun: the real startup path refuses providers over the
// echo store (--dev allows echo, the broker does not) and over no store.
func TestOAuthBrokerGateRun(t *testing.T) {
	t.Setenv("WARDEN_CONSOLE_SECRET", "x")
	t.Setenv("WARDEN_PORTAL_DEX_CLIENT_SECRET", "x")
	t.Setenv("G_SECRET", "x")
	const providers = `  providers:
    - id: google
      type: google
      clientID: g-client
      clientSecretEnv: G_SECRET
      allowedScopes: [drive.readonly]
`
	identity := "identity:\n  defaultMode: attribute\n  issuer: https://idp.example.com\n  audience: warden\n"
	for name, tc := range map[string]struct {
		consent string
		dev     bool
	}{
		"no store":   {consentBlockYAML + "  idpLink:\n    enabled: false\n" + providers, false},
		"echo store": {consentBlockYAML + "  idpLink:\n    enabled: false\n  store:\n    backend: echo\n" + providers, true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "config.yaml")
			writeFileT(t, cfg, basePolicy+identity+consoleBlock+tc.consent)
			state := filepath.Join(dir, "state")
			if err := os.MkdirAll(state, 0o700); err != nil {
				t.Fatal(err)
			}
			err := Run(context.Background(), &strings.Builder{}, Params{
				ConfigPath: cfg, StateDir: state, ListenAddr: "127.0.0.1:0", AnalyticsProvider: "memory", Dev: tc.dev,
			})
			if err == nil || !strings.Contains(err.Error(), "oauth broker requires a persistent consent.store") {
				t.Fatalf("Run = %v, want the persistent consent.store refusal", err)
			}
		})
	}
}

// stubBlocks blocks every sub, standing in for a block list that changed
// between the middleware's snapshot read and the broker's own check.
type stubBlocks struct{ blocked bool }

func (s stubBlocks) IsBlocked(context.Context, string, string) (bool, error) { return s.blocked, nil }

// TestConnectStartRouteBrokerBlocked: when the broker's BlockChecker blocks a
// user the session middleware's snapshot let through, the broker answers 403
// user_blocked itself and writes no attempt.
func TestConnectStartRouteBrokerBlocked(t *testing.T) {
	r, c, tok := connectRig(t)
	b, err := oauthbroker.New(oauthbroker.Config{
		Registry: r.srv.cfg.OAuthRegistry, Store: r.srv.cfg.GrantStore, Blocks: stubBlocks{blocked: true},
		RedirectURL: "https://cp.example/connect/callback", UserKey: secrets.UserKey, Rand: rand.Reader, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := r.srv.connectWrap(oauthbrokerhttp.New(oauthbrokerhttp.Config{
		Broker: b, Cookie: oauthbrokerhttp.Cookie{Name: connectCookieName, Secure: true},
	}).Start())
	req := httptest.NewRequest(http.MethodPost, "/connect/start", strings.NewReader("provider=google"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(CSRFHeader, tok)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "user_blocked") {
		t.Fatalf("= %d %s, want the broker's 403 user_blocked", rec.Code, rec.Body)
	}
	if r.attemptRows() != 0 {
		t.Fatal("a blocked user left an attempt")
	}
}
