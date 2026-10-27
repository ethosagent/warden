//go:build e2e

package identity

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness/compose"
)

const (
	// dexURL is Dex's issuer AND the host-side base: Dex is published on
	// 127.0.0.1:5556, so the host reaches it directly. Containers use
	// http://dex:5556 (internalIssuerURL in configs/config.e2e-identity-cp.yaml).
	dexURL        = "http://localhost:5556/dex"
	discoveryPath = "/.well-known/openid-configuration"

	// The password-grant client and scope the identity tests use (dev Dex
	// config: deploy/compose/dex/config.dev.yaml).
	harnessClientID = "agent-harness"
	tokenScope      = "openid email profile groups offline_access audience:server:client_id:warden"

	// The dev placeholder values live here (not secrets: see the file header).
	devEnvFile = "deploy/compose/dex/.env.example"
)

// hostClient is the plain client for everything the host sends to Dex: no
// dialer override, no hosts entry, just a timeout.
var hostClient = &http.Client{Timeout: 15 * time.Second}

// stackGate decides what a missing stack means: always a failure, so a test
// that could not run never reads as a pass (gates/test-skipped forbids a skip).
// Pure, so it is unit-tested without Docker.
func stackGate(available bool, reason string) (msg string) {
	if available {
		return ""
	}
	return "BLOCKED: the identity stack is unavailable (" + reason + "); run `make e2e-identity-up` or `make e2e-identity`"
}

// requireStack is the first line of every test in this package.
func requireStack(t *testing.T) {
	t.Helper()
	if msg := stackGate(stackUnavailable == "", stackUnavailable); msg != "" {
		t.Fatalf("%s", msg)
	}
}

// devEnv returns KEY's value: the caller's environment first (the Makefile
// honours exported overrides the same way), else the dev placeholder from
// deploy/compose/dex/.env.example.
func devEnv(t testing.TB, key string) string {
	t.Helper()
	v, err := lookupDevEnv(key)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return v
}

// lookupDevEnv is devEnv without a testing.TB, for TestMain's readiness poll.
func lookupDevEnv(key string) (string, error) {
	if v := os.Getenv(key); v != "" {
		return v, nil
	}
	root, err := compose.RepoRoot()
	if err != nil {
		return "", err
	}
	f, err := os.Open(filepath.Join(root, devEnvFile))
	if err != nil {
		return "", fmt.Errorf("open %s: %w", devEnvFile, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok && k == key && !strings.HasPrefix(line, "#") {
			return v, nil
		}
	}
	return "", fmt.Errorf("%s is not set and not in %s", key, devEnvFile)
}

// dexToken does the password grant for a seeded LDAP user on the agent-harness
// client and returns the raw ID token. It never logs the token, the password
// or the client secret; a failure reports only the HTTP status and Dex's
// error code.
func dexToken(t testing.TB, user string) string {
	t.Helper()
	return dexGrant(t, user).IDToken
}

// grant is the secret-bearing part of a Dex token response. Nothing in it may
// reach a log line.
type grant struct {
	IDToken      string
	RefreshToken string
}

// dexGrant is dexToken with the refresh token too (scope offline_access).
func dexGrant(t testing.TB, user string) grant {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"username":   {user},
		"password":   {devEnv(t, "DEX_TEST_PASSWORD")},
		"scope":      {tokenScope},
	}
	req, err := http.NewRequest(http.MethodPost, dexURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("identity: build the token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(harnessClientID, devEnv(t, "HARNESS_DEX_CLIENT_SECRET"))
	resp, err := hostClient.Do(req)
	if err != nil {
		t.Fatalf("identity: dex token request for %q failed: %v", user, redactURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("identity: read the token response for %q: %v", user, err)
	}
	var out struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("identity: dex token response for %q (status %d) is not JSON", user, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || out.IDToken == "" {
		t.Fatalf("identity: dex refused the password grant for %q: status %d, error %q", user, resp.StatusCode, out.Error)
	}
	return grant{IDToken: out.IDToken, RefreshToken: out.RefreshToken}
}

// redactURLError drops the request URL from a net/http error (it carries no
// secret today, the form body is not in it, but the helper's contract is that
// nothing sensitive can reach a log line).
func redactURLError(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// cpTraffic GETs the control plane's /dashboard/api/traffic?<query> and decodes
// the events. The CP console is in oidc mode on this stack, so the read goes
// through the signed-in fleet reader (consoleFleetBody), not the open read the
// base e2e stack allows.
func cpTraffic(t testing.TB, query string) []analytics.Event {
	t.Helper()
	path := compose.TrafficPath
	if query != "" {
		path += "?" + query
	}
	body, err := consoleFleetBody(path)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	evs, err := compose.DecodeEvents(body)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return evs
}

// agentExec runs args inside agent-1 (`docker compose exec -T`). A failure of
// the exec itself fails the test; the command's own exit code is in the result.
func agentExec(t testing.TB, args ...string) compose.Result {
	t.Helper()
	res, err := compose.AgentRunRaw(compose.SvcAgent1, args...)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return res
}

// workerLogs returns worker-1's logs, for token-leak sweeps.
func workerLogs(t testing.TB) string {
	t.Helper()
	res := compose.ComposeRun(compose.ComposeDeadline, "logs", "--no-color", compose.SvcWorker1)
	if res.Exit != 0 {
		t.Fatalf("identity: docker compose logs %s failed (exit %d): %s", compose.SvcWorker1, res.Exit, firstLine(res.Stderr))
	}
	return res.Stdout
}

// ---- Console sign-in (W-P1-SSO-07) ----
//
// The stack's CP runs console.auth oidc against Dex, so every /dashboard/*
// read needs a session. A session is obtained the way a browser obtains one:
// GET /auth/login, follow the redirect to Dex's public issuer, submit Dex's
// LDAP password form, follow Dex back to /auth/callback. The client is a plain
// net/http client with a cookie jar and the lab CA: no dialer override, no
// hosts entry. Nothing here logs a cookie, CSRF token, code, state or password;
// errors name URLs without their query.

const (
	// csrfHeader carries the session's CSRF token (from GET /auth/me) on
	// state-changing console requests.
	csrfHeader = "X-Warden-CSRF"
	// fleetReaderUser signs in for the package's CP reads. bob is an editor,
	// not the viewer carol, so TestConsoleSSORevoke revoking carol never logs
	// the readers out.
	fleetReaderUser = "bob"
)

// consoleSession is a signed-in console user: the browser-like client holding
// the CP session cookie, plus what GET /auth/me reported.
type consoleSession struct {
	client *http.Client
	csrf   string

	User  string
	Sub   string
	Email string
	Role  string
	// LoginRedirect is where /auth/login sent the browser, query dropped.
	LoginRedirect string
}

// loginRefused is a login that reached /auth/callback and came back with
// ?login_error=<Code> instead of a session.
type loginRefused struct{ Code string }

func (e *loginRefused) Error() string { return "the control plane refused the login: " + e.Code }

// newBrowser returns a client that trusts the lab CA (the CP's server cert),
// keeps cookies like a browser, and does not follow redirects, so each hop of
// the login is checked. Keep-alives are off, as in compose's one-shot clients.
func newBrowser() (*http.Client, error) {
	pool, err := compose.CAPool()
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// noQuery renders u without its query and fragment (state, code and the PKCE
// challenge live there).
func noQuery(u *url.URL) string {
	c := *u
	c.RawQuery, c.Fragment = "", ""
	return c.String()
}

// hop sends one request and returns the status, the body and, for a redirect,
// the resolved Location.
func hop(c *http.Client, method string, u *url.URL, form url.Values) (int, []byte, *url.URL, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("build %s %s: %w", method, noQuery(u), err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s %s: %w", method, noQuery(u), redactURLError(err))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read %s %s: %w", method, noQuery(u), err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		next, err := resp.Location()
		if err != nil {
			// Not wrapped: a parse error quotes the Location, query (code,
			// state) included.
			return 0, nil, nil, fmt.Errorf("%s %s: status %d without a usable Location", method, noQuery(u), resp.StatusCode)
		}
		return resp.StatusCode, b, next, nil
	}
	return resp.StatusCode, b, nil, nil
}

// passwordFormAction finds the action of Dex's LDAP password form
// (<form method="post" action="/dex/auth/ldap/login?...">).
var passwordFormAction = regexp.MustCompile(`(?is)<form[^>]*\bmethod="post"[^>]*\baction="([^"]+)"`)

// maxHops bounds each redirect walk; the real flow needs at most three.
const maxHops = 6

// consoleLogin signs user (a seeded LDAP uid, password DEX_TEST_PASSWORD) in
// to the console through Dex's browser flow and returns the session. A login
// the CP refuses returns *loginRefused.
func consoleLogin(user string) (*consoleSession, error) {
	password, err := lookupDevEnv("DEX_TEST_PASSWORD")
	if err != nil {
		return nil, err
	}
	b, err := newBrowser()
	if err != nil {
		return nil, err
	}
	cp, err := url.Parse(compose.CPBase)
	if err != nil {
		return nil, err
	}
	// 1. The CP starts the flow and sends the browser to the IdP.
	status, _, next, err := hop(b, http.MethodGet, cp.JoinPath("/auth/login"), nil)
	if err != nil {
		return nil, err
	}
	if next == nil {
		return nil, fmt.Errorf("GET /auth/login: status %d, want a redirect to Dex", status)
	}
	cs := &consoleSession{client: b, User: user, LoginRedirect: noQuery(next)}

	// 2. Walk Dex's redirects (connector choice, login page) to the form.
	u := next
	var action *url.URL
	for i := 0; i < maxHops && action == nil; i++ {
		status, body, next, err := hop(b, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if next != nil {
			u = next
			continue
		}
		m := passwordFormAction.FindSubmatch(body)
		if status != http.StatusOK || m == nil {
			return nil, fmt.Errorf("GET %s: status %d and no password form", noQuery(u), status)
		}
		ref, err := url.Parse(html.UnescapeString(string(m[1])))
		if err != nil {
			return nil, fmt.Errorf("dex password form action is not a URL: %w", err)
		}
		action = u.ResolveReference(ref)
	}
	if action == nil {
		return nil, fmt.Errorf("no dex password form within %d redirects", maxHops)
	}

	// 3. Submit the credentials, then follow Dex back to the CP callback and
	// the CP on to the dashboard.
	status, _, next, err = hop(b, http.MethodPost, action, url.Values{"login": {user}, "password": {password}})
	if err != nil {
		return nil, err
	}
	for i := 0; ; i++ {
		if next == nil {
			return nil, fmt.Errorf("login as %q stopped at status %d before reaching the dashboard (wrong password or a dex error page)", user, status)
		}
		if next.Host == cp.Host && next.Path == "/dashboard/" {
			if code := next.Query().Get("login_error"); code != "" {
				return nil, &loginRefused{Code: code}
			}
			break
		}
		if i == maxHops {
			return nil, fmt.Errorf("login as %q did not reach the dashboard within %d redirects (last %s)", user, maxHops, noQuery(next))
		}
		u = next
		if status, _, next, err = hop(b, http.MethodGet, u, nil); err != nil {
			return nil, err
		}
	}

	// 4. The session cookie is set; /auth/me names the user and the CSRF token.
	code, body, err := cs.do(http.MethodGet, "/auth/me", nil, false)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET /auth/me after login as %q: status %d, want 200", user, code)
	}
	var me struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Role  string `json:"role"`
		CSRF  string `json:"csrf"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		return nil, fmt.Errorf("GET /auth/me: not JSON: %w", err)
	}
	if me.Sub == "" || me.CSRF == "" {
		return nil, fmt.Errorf("GET /auth/me after login as %q: no sub or csrf in the response", user)
	}
	cs.Sub, cs.Email, cs.Role, cs.csrf = me.Sub, me.Email, me.Role, me.CSRF
	return cs, nil
}

// do sends one request to the CP with the session cookie. path may carry a
// query. withCSRF adds the session's CSRF header; body, when set, is JSON.
func (cs *consoleSession) do(method, path string, body []byte, withCSRF bool) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, compose.CPBase+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withCSRF {
		req.Header.Set(csrfHeader, cs.csrf)
	}
	resp, err := cs.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, redactURLError(err))
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

// loginAs is consoleLogin for a test: any failure fails it.
func loginAs(t testing.TB, user string) *consoleSession {
	t.Helper()
	cs, err := consoleLogin(user)
	if err != nil {
		t.Fatalf("identity: console login as %q: %v", user, err)
	}
	return cs
}

// mustDo is do for a test: a transport error fails it.
func (cs *consoleSession) mustDo(t testing.TB, method, path string, body []byte, withCSRF bool) (int, []byte) {
	t.Helper()
	code, b, err := cs.do(method, path, body, withCSRF)
	if err != nil {
		t.Fatalf("identity: %s as %s: %v", path, cs.User, err)
	}
	return code, b
}

// fleetReader is the signed-in session behind consoleFleetBody, created on
// first use and replaced once when the CP answers 401 (revoked or expired).
var fleetReader struct {
	mu sync.Mutex
	cs *consoleSession
}

// consoleFleetBody reads one control-plane fleet-API path as fleetReaderUser:
// compose.FleetBody for a console in oidc mode.
func consoleFleetBody(path string) ([]byte, error) {
	fleetReader.mu.Lock()
	defer fleetReader.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if fleetReader.cs == nil {
			cs, err := consoleLogin(fleetReaderUser)
			if err != nil {
				return nil, fmt.Errorf("console login as %q for fleet reads: %w", fleetReaderUser, err)
			}
			fleetReader.cs = cs
		}
		code, body, err := fleetReader.cs.do(http.MethodGet, path, nil, false)
		if err != nil {
			return nil, err
		}
		switch code {
		case http.StatusOK:
			return body, nil
		case http.StatusUnauthorized:
			fleetReader.cs = nil // sign in again
		default:
			return nil, fmt.Errorf("fleet API %s returned %d: %.200s", path, code, body)
		}
	}
	return nil, fmt.Errorf("fleet API %s returned 401 for a fresh session", path)
}
