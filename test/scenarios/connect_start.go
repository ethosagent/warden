package scenarios

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The connect start scenario (W-P3-BRKR-03): with a real control plane,
// consent.providers set and the issuer fake, a signed-in portal user posts
// /connect/start and is redirected to the provider with PKCE S256, a state and
// the capped scopes, while the state database holds only the state's hash, the
// verifier and the cookie's hash. Refusals (a scope outside the cap, no CSRF
// token, no session, a blocked user, an eleventh start in a minute) write
// nothing. Observed only through the control plane's HTTP surface, its state
// database and its logs.

func connectOpts() []harness.Option { return []harness.Option{harness.WithOAuthBroker()} }

const connectCookie = "__Host-warden_connect"

func connectPost(t *testing.T, b *harness.Browser, csrf string, form url.Values) (*http.Response, string) {
	t.Helper()
	hdr := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	if csrf != "" {
		hdr.Set(controlplane.CSRFHeader, csrf)
	}
	resp, err := b.DoBody(http.MethodPost, "/connect/start", hdr, []byte(form.Encode()))
	if err != nil {
		t.Fatalf("POST /connect/start: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return resp, sb.String()
}

func connectStart(t *testing.T, h *harness.H) {
	pb, _ := portalSignIn(t, h, fakes.Valid("dana", "dana@example.com"))
	_, me := portalMe(t, pb)
	csrf, _ := me["csrf"].(string)
	if len(csrf) != 64 {
		t.Fatalf("portal csrf = %q", csrf)
	}
	pendings, grants := h.BrokerRowCounts()

	// 1. A valid start: 303 to the provider with PKCE S256, the capped scopes
	// and the configured redirect; the cookie is set and bound to the attempt.
	resp, body := connectPost(t, pb, csrf, url.Values{"provider": {"google"}, "scopes": {"drive.readonly"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /connect/start = %d %s, want 303", resp.StatusCode, body)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, harness.BrokerAuthURL+"?") {
		t.Fatalf("Location = %q, want the provider's authorization URL", loc)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("start response headers = %v", resp.Header)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	cc := cookieIn(resp, connectCookie)
	if cc == nil || !cc.Secure || !cc.HttpOnly || cc.SameSite != http.SameSiteLaxMode || cc.Path != "/" || cc.MaxAge != 600 {
		t.Fatalf("connect cookie = %+v", cc)
	}
	attempts := h.ConnectAttempts()
	if len(attempts) != 1 {
		t.Fatalf("connect_attempts = %d rows, want 1", len(attempts))
	}
	a := attempts[0]
	sum := sha256.Sum256([]byte(a.Verifier))
	hashOf := func(s string) string { x := sha256.Sum256([]byte(s)); return hexOf(x[:]) }
	for k, want := range map[string]string{
		"response_type": "code", "client_id": "harness-google-client", "scope": "drive.readonly email openid",
		"redirect_uri":          h.ConsoleURL() + "/connect/callback",
		"code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(sum[:]),
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if a.StateHash != hashOf(q.Get("state")) || a.BrowserHash != hashOf(cc.Value) || a.Sub != "dana" || a.Provider != "google" ||
		!slices.Equal(a.Scopes, []string{"drive.readonly"}) {
		t.Errorf("stored attempt %+v does not match the redirect and cookie", a)
	}
	if a.Verifier == q.Get("state") || len(a.Verifier) < 43 || len(q.Get("state")) < 43 || len(cc.Value) < 43 {
		t.Error("the state, verifier or cookie is too short or reused")
	}

	// 2. A scope outside the provider's list: 400 naming it, no row.
	resp, body = connectPost(t, pb, csrf, url.Values{"provider": {"google"}, "scopes": {"drive.readonly gmail.send"}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"scope_not_allowed"`) || !strings.Contains(body, "gmail.send") {
		t.Fatalf("scope outside the cap = %d %s", resp.StatusCode, body)
	}
	// An unknown pending (or another user's) is a plain 404, no row.
	resp, body = connectPost(t, pb, csrf, url.Values{"provider": {"google"}, "pending": {"no-such-pending"}})
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "pending_not_found") {
		t.Fatalf("unknown pending = %d %s", resp.StatusCode, body)
	}
	if resp, _ := connectPost(t, pb, csrf, url.Values{"provider": {"nope"}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown provider = %d", resp.StatusCode)
	}

	// 3. No CSRF token or a foreign Origin: 403; a GET changes nothing and
	// goes to the portal; no session goes to sign-in.
	if resp, body := connectPost(t, pb, "", url.Values{"provider": {"google"}}); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, `"csrf"`) {
		t.Fatalf("no csrf = %d %s", resp.StatusCode, body)
	}
	foreign := http.Header{controlplane.CSRFHeader: {csrf}, "Origin": {"https://evil.example"}, "Content-Type": {"application/x-www-form-urlencoded"}}
	fresp, err := pb.DoBody(http.MethodPost, "/connect/start", foreign, []byte("provider=google"))
	if err != nil {
		t.Fatal(err)
	}
	_ = fresp.Body.Close()
	if fresp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin = %d, want 403", fresp.StatusCode)
	}
	if resp, _ := consoleDo(t, pb, http.MethodGet, "/connect/start?pending=abc", nil); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/portal/connect/abc" {
		t.Fatalf("GET /connect/start = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	anon := h.ConsoleBrowser()
	if resp, _ := connectPost(t, anon, "", url.Values{"provider": {"google"}}); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/portal/login" {
		t.Fatalf("no session = %d %q, want 303 /portal/login", resp.StatusCode, resp.Header.Get("Location"))
	}
	if n := len(h.ConnectAttempts()); n != 1 {
		t.Fatalf("connect_attempts = %d after the refusals, want 1", n)
	}
	if p, g := h.BrokerRowCounts(); p != pendings || g != grants {
		t.Fatalf("pendings %d->%d, grants %d->%d: a start wrote one", pendings, p, grants, g)
	}

	// 4. A blocked user is refused and leaves no attempt.
	eb, ecsrf := func() (*harness.Browser, string) {
		b, _ := portalSignIn(t, h, fakes.Valid("erin", "erin@example.com"))
		_, m := portalMe(t, b)
		c, _ := m["csrf"].(string)
		return b, c
	}()
	admin, acsrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	if resp, body := blockAPIDo(t, admin, acsrf, http.MethodPost, "/dashboard/api/blocked-users", `{"sub":"erin"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("block erin = %d %s", resp.StatusCode, body)
	}
	resp, _ = connectPost(t, eb, ecsrf, url.Values{"provider": {"google"}})
	if resp.StatusCode == http.StatusSeeOther && strings.HasPrefix(resp.Header.Get("Location"), harness.BrokerAuthURL) {
		t.Fatal("a blocked user was sent to the provider")
	}
	if n := len(h.ConnectAttempts()); n != 1 {
		t.Fatalf("connect_attempts = %d after a blocked user's start, want 1", n)
	}

	// 5. The eleventh start inside a minute is 429 with a Retry-After.
	gb, _ := portalSignIn(t, h, fakes.Valid("gwen", "gwen@example.com"))
	_, gm := portalMe(t, gb)
	gcsrf, _ := gm["csrf"].(string)
	for i := 1; i <= 10; i++ {
		if resp, body := connectPost(t, gb, gcsrf, url.Values{"provider": {"google"}}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("start %d = %d %s", i, resp.StatusCode, body)
		}
	}
	resp, body = connectPost(t, gb, gcsrf, url.Values{"provider": {"google"}})
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" || !strings.Contains(body, "rate_limited") {
		t.Fatalf("11th start = %d %s Retry-After %q", resp.StatusCode, body, resp.Header.Get("Retry-After"))
	}

	// 6. The logs hold the start line and none of the secrets.
	logs := h.Logs()
	if !strings.Contains(logs, `"msg":"oauth_connect_start"`) {
		t.Error("no oauth_connect_start log line")
	}
	for name, secret := range map[string]string{
		"state": q.Get("state"), "verifier": a.Verifier, "challenge": q.Get("code_challenge"),
		"connect cookie": cc.Value, "client secret": harness.BrokerClientSecret(),
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the logs hold the %s", name)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
