package scenarios

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The console OIDC login scenario (W-P1-SSO-03, and the harness item of
// W-P1-SSO-04): a real control plane in console.auth oidc, the in-process
// issuer fake as the IdP, and a browser that follows /auth/login, the issuer
// and /auth/callback. It proves, through the control plane's own HTTP surface
// and its state database only, that a login creates a session, that the
// session cookie carries the right flags, and that the session expires on the
// idle limit by the control plane's clock.

func consoleOpts() []harness.Option { return []harness.Option{harness.WithConsoleOIDC()} }

const (
	consoleSessionCookie = "__Host-warden_console"
	consoleLoginCookie   = "__Host-warden_login"
	// consoleWritePath is a dashboard write route: with a live session and no
	// CSRF header the session middleware must refuse it.
	consoleWritePath = "/dashboard/api/policy"
)

// consoleDo sends one request and returns status and body.
func consoleDo(t *testing.T, b *harness.Browser, method, target string, hdr http.Header) (*http.Response, string) {
	t.Helper()
	resp, err := b.Do(method, target, hdr)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(body)
}

func cookieIn(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// refusedForCSRF reports whether a state-changing request with the session
// cookie and no CSRF header was refused by the session middleware.
func refusedForCSRF(t *testing.T, b *harness.Browser) bool {
	t.Helper()
	resp, body := consoleDo(t, b, http.MethodPost, consoleWritePath, nil)
	return resp.StatusCode == http.StatusForbidden && strings.Contains(body, `"csrf"`)
}

func consoleOIDCLogin(t *testing.T, h *harness.H) {
	idp := h.Issuer()
	idp.SetLogin(fakes.Valid("carol", "carol@example.com", harness.ConsoleAdminGroup))
	b := h.ConsoleBrowser()

	// The control plane discovers the issuer in the background; /auth/callback
	// answers 503 until it has, and never creates state for a bare request.
	h.Eventually("the control plane has discovered the issuer", func() bool {
		resp, _ := consoleDo(t, b, http.MethodGet, "/auth/callback", nil)
		return resp.StatusCode != http.StatusServiceUnavailable
	})

	// 1. /auth/login redirects to the issuer with a PKCE challenge and binds the
	// attempt to this browser with a cookie.
	resp, _ := consoleDo(t, b, http.MethodGet, "/auth/login?next=/dashboard/", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/auth/login = %d, want 302", resp.StatusCode)
	}
	authURL := resp.Header.Get("Location")
	if !strings.HasPrefix(authURL, idp.Issuer()+"/auth?") {
		t.Fatalf("authorize redirect does not go to the issuer: %q", authURL)
	}
	q := mustParse(t, authURL).Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatalf("authorize query is missing PKCE, state or nonce: %v", q)
	}
	if lc := cookieIn(resp, consoleLoginCookie); lc == nil || !lc.Secure || !lc.HttpOnly || lc.SameSite != http.SameSiteLaxMode {
		t.Fatalf("login cookie flags wrong: %+v", lc)
	}
	if n := len(h.ConsoleSessions()); n != 0 {
		t.Fatalf("%d sessions exist before the callback", n)
	}

	// 2. The issuer signs the user in and sends the browser back with a code.
	idpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	idpResp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(idpReq)
	if err != nil {
		t.Fatalf("issuer authorize: %v", err)
	}
	_ = idpResp.Body.Close()
	callback := idpResp.Header.Get("Location")
	if idpResp.StatusCode != http.StatusFound || !strings.HasPrefix(callback, h.ConsoleURL()+"/auth/callback?") {
		t.Fatalf("issuer answered %d, Location %q", idpResp.StatusCode, callback)
	}

	// 3. The callback creates the session and sets the cookie.
	resp, _ = consoleDo(t, b, http.MethodGet, callback, nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/dashboard/" {
		t.Fatalf("/auth/callback = %d to %q, want 302 to /dashboard/", resp.StatusCode, resp.Header.Get("Location"))
	}
	sc := cookieIn(resp, consoleSessionCookie)
	if sc == nil {
		t.Fatal("the callback set no session cookie")
	}
	if !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" ||
		sc.MaxAge != int((12*time.Hour).Seconds()) || len(sc.Value) < 32 {
		t.Fatalf("session cookie flags wrong: Secure=%v HttpOnly=%v SameSite=%v Path=%q Domain=%q MaxAge=%d len=%d",
			sc.Secure, sc.HttpOnly, sc.SameSite, sc.Path, sc.Domain, sc.MaxAge, len(sc.Value))
	}
	if lc := cookieIn(resp, consoleLoginCookie); lc == nil || lc.MaxAge >= 0 {
		t.Fatalf("login cookie was not cleared: %+v", lc)
	}
	rows := h.ConsoleSessions()
	if len(rows) != 1 || rows[0].Sub != "carol" || rows[0].Iss != idp.Issuer() || rows[0].Email != "carol@example.com" {
		t.Fatalf("sessions table = %+v, want one row for carol at the issuer", rows)
	}
	created := rows[0].CreatedAt
	if got, want := rows[0].ExpiresAt-created, int64((12 * time.Hour).Seconds()); got != want {
		t.Fatalf("absolute expiry is %ds after creation, want %d", got, want)
	}

	// 4. The session is live: the session middleware refuses a write without the
	// CSRF header, which it does only for a request carrying a live session.
	if !refusedForCSRF(t, b) {
		t.Fatal("a write with the new session and no CSRF header was not refused for csrf")
	}
	// With the CSRF token it gets past the session middleware (the bearer write
	// guard that still protects the route answers instead).
	resp, body := consoleDo(t, b, http.MethodPost, consoleWritePath, http.Header{controlplane.CSRFHeader: {controlplane.CSRFToken(sc.Value)}})
	if strings.Contains(body, `"csrf"`) {
		t.Fatalf("a write with the right CSRF token was refused for csrf: %d %s", resp.StatusCode, body)
	}

	// 5. Idle expiry follows the control plane's clock. Use keeps the session
	// alive past the one-hour idle limit measured from creation ...
	h.Clock().Advance(50 * time.Minute)
	if resp, _ := consoleDo(t, b, http.MethodGet, "/dashboard/", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /dashboard/ at +50m = %d", resp.StatusCode)
	}
	if rows := h.ConsoleSessions(); len(rows) != 1 || rows[0].LastSeenAt <= created {
		t.Fatalf("use at +50m did not advance last_seen_at: %+v", rows)
	}
	h.Clock().Advance(50 * time.Minute)
	if !refusedForCSRF(t, b) {
		t.Fatal("the session died at +100m although it was used at +50m")
	}
	// ... and 61 idle minutes end it: the request no longer counts as a session
	// request, and the row is gone.
	h.Clock().Advance(61 * time.Minute)
	if refusedForCSRF(t, b) {
		t.Fatal("the session was still live 61 minutes after its last use")
	}
	if n := len(h.ConsoleSessions()); n != 0 {
		t.Fatalf("%d sessions rows remain after expiry, want 0", n)
	}

	// 6. Nothing sensitive reached the control plane's logs.
	logs := h.Logs()
	if !strings.Contains(logs, `"msg":"console_login"`) || !strings.Contains(logs, `"result":"ok"`) {
		t.Fatal("no successful console_login line in the control plane's logs")
	}
	for name, secret := range map[string]string{
		"session id": sc.Value, "csrf token": controlplane.CSRFToken(sc.Value),
		"authorization code": mustParse(t, callback).Query().Get("code"), "nonce": q.Get("nonce"),
	} {
		if secret != "" && strings.Contains(logs, secret) {
			t.Errorf("the logs contain the %s", name)
		}
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
