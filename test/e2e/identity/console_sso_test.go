//go:build e2e

package identity

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/harness/compose"
)

// Console SSO against the real reference stack (W-P1-SSO-07): the CP in
// console.auth oidc (configs/config.e2e-identity-cp.yaml), Dex with the seeded
// LDAP users (deploy/compose/dex/seed.ldif: alice admin, bob editor, carol
// viewer, dave no warden group). Every login is the browser flow driven by a
// plain net/http client with a cookie jar (consoleLogin in helpers_test.go).

const (
	// cpTokenDefault is the shared bearer the compose files hand the CP and the
	// workers (WARDEN_CP_TOKEN, default dev-token).
	cpTokenDefault = "dev-token"
	// restoreDeadline bounds bringing Dex and the CP back after TestConsoleSSODexDown.
	restoreDeadline = 90 * time.Second
)

// bearerGet GETs a CP path with only the shared bearer: no cookie, no session.
func bearerGet(t testing.TB, path string) (int, []byte) {
	t.Helper()
	c, err := newBrowser()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, compose.CPBase+path, nil)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+cmp.Or(os.Getenv("WARDEN_CP_TOKEN"), cpTokenDefault))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("identity: GET %s with the shared bearer: %v", path, redactURLError(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body
}

// TestConsoleSSORoleMatrix proves the role checks and the split horizon with
// real Dex tokens: alice signs in through the public issuer while the CP talks
// to Dex only on its internal origin, a viewer reads but cannot write, the
// shared bearer opens the worker route but no human route, and a user with no
// mapped group gets no session.
func TestConsoleSSORoleMatrix(t *testing.T) {
	requireStack(t)

	t.Run("split horizon: alice signs in through the public issuer", func(t *testing.T) {
		resp, err := hostClient.Get(dexURL + discoveryPath)
		if err != nil {
			t.Fatalf("GET %s%s: %v", dexURL, discoveryPath, redactURLError(err))
		}
		var doc struct {
			Issuer                string `json:"issuer"`
			AuthorizationEndpoint string `json:"authorization_endpoint"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("host discovery: status %d, decode error %v", resp.StatusCode, err)
		}
		if doc.Issuer != dexURL {
			t.Fatalf("host discovery issuer = %q, want exactly %q", doc.Issuer, dexURL)
		}

		alice := loginAs(t, "alice")
		// The browser is sent to the public issuer's authorization endpoint,
		// never to the CP's internal origin.
		if alice.LoginRedirect != doc.AuthorizationEndpoint || !strings.HasPrefix(alice.LoginRedirect, dexURL+"/") {
			t.Errorf("/auth/login redirected to %q, want the public authorization endpoint %q under %s", alice.LoginRedirect, doc.AuthorizationEndpoint, dexURL)
		}
		// The callback succeeded, so the CP exchanged the code and verified the
		// ID token (issuer, audience, nonce) and mapped the groups.
		if alice.Role != "admin" || alice.Email != "alice@example.org" {
			t.Errorf("alice: role %q email %q, want admin alice@example.org", alice.Role, alice.Email)
		}
		// The session records the public issuer the token was verified against.
		code, body := alice.mustDo(t, http.MethodGet, "/dashboard/api/sessions", nil, false)
		if code != http.StatusOK {
			t.Fatalf("GET /dashboard/api/sessions as alice: status %d, want 200", code)
		}
		var rows []struct {
			Iss     string `json:"iss"`
			Sub     string `json:"sub"`
			Current bool   `json:"current"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			t.Fatalf("sessions list is not JSON: %v", err)
		}
		var found bool
		for _, r := range rows {
			if r.Current {
				found = true
				if r.Iss != dexURL || r.Sub != alice.Sub {
					t.Errorf("alice's session: iss %q sub %q, want iss %q sub %q", r.Iss, r.Sub, dexURL, alice.Sub)
				}
			}
		}
		if !found {
			t.Errorf("the sessions list has no current session for alice")
		}
		// The admin session opens the human route the shared bearer cannot.
		if code, _ := alice.mustDo(t, http.MethodGet, "/central/secrets", nil, false); code != http.StatusOK {
			t.Errorf("GET /central/secrets as admin: status %d, want 200", code)
		}
		// Inside the CP container localhost is the CP itself: the public issuer
		// origin is unreachable from there, so the exchange above went to dex:5556.
		cid := serviceContainer(t, compose.SvcCP)
		if res := compose.Run(".", compose.ComposeDeadline, "docker", "exec", cid, "wget", "-q", "-T", "5", "-O", "/dev/null", dexURL+discoveryPath); res.Exit == 0 {
			t.Errorf("the CP container reached %s; the split-horizon proof needs it unreachable there", dexURL)
		}
		if res := compose.Run(".", compose.ComposeDeadline, "docker", "exec", cid, "wget", "-q", "-T", "5", "-O", "/dev/null", dexInternalURL+discoveryPath); res.Exit != 0 {
			t.Errorf("the CP container cannot reach %s (exit %d): %s", dexInternalURL, res.Exit, firstLine(res.Stderr))
		}
	})

	t.Run("viewer reads but cannot change policy", func(t *testing.T) {
		carol := loginAs(t, "carol")
		if carol.Role != "viewer" {
			t.Fatalf("carol: role %q, want viewer", carol.Role)
		}
		if code, _ := carol.mustDo(t, http.MethodGet, "/dashboard/api/traffic", nil, false); code != http.StatusOK {
			t.Errorf("GET /dashboard/api/traffic as viewer: status %d, want 200", code)
		}
		code, policy := carol.mustDo(t, http.MethodGet, "/dashboard/api/policy", nil, false)
		if code != http.StatusOK {
			t.Fatalf("GET /dashboard/api/policy as viewer: status %d, want 200", code)
		}
		// POST the policy just read, with a valid CSRF token: the only reason
		// left to refuse it is the role, and a regression would change nothing.
		if code, body := carol.mustDo(t, http.MethodPost, "/dashboard/api/policy", policy, true); code != http.StatusForbidden {
			t.Errorf("POST /dashboard/api/policy as viewer: status %d, want 403 (body %.200s)", code, body)
		}
	})

	t.Run("shared bearer opens the worker route only", func(t *testing.T) {
		for _, path := range []string{"/dashboard/api/settings", "/central/secrets"} {
			if code, _ := bearerGet(t, path); code != http.StatusUnauthorized {
				t.Errorf("GET %s with only the shared bearer: status %d, want 401", path, code)
			}
		}
		if code, _ := bearerGet(t, "/policy"); code != http.StatusOK {
			t.Errorf("GET /policy with the shared bearer: status %d, want 200", code)
		}
	})

	t.Run("a user with no mapped group gets no session", func(t *testing.T) {
		_, err := consoleLogin("dave")
		var refused *loginRefused
		if !errors.As(err, &refused) || refused.Code != "no_role" {
			t.Errorf("login as dave: %v, want login_error=no_role", err)
		}
	})
}

// TestConsoleSSORevoke proves an admin revoke ends a live session: after alice
// deletes carol's sessions, carol's next request is 401.
func TestConsoleSSORevoke(t *testing.T) {
	requireStack(t)

	carol := loginAs(t, "carol")
	alice := loginAs(t, "alice")
	if code, _ := carol.mustDo(t, http.MethodGet, "/dashboard/api/traffic", nil, false); code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/traffic as carol before the revoke: status %d, want 200", code)
	}

	revoke := "/dashboard/api/sessions?sub=" + url.QueryEscape(carol.Sub)
	if code, _ := alice.mustDo(t, http.MethodDelete, revoke, nil, false); code != http.StatusForbidden {
		t.Errorf("DELETE sessions without CSRF: status %d, want 403", code)
	}
	if code, _ := carol.mustDo(t, http.MethodGet, "/dashboard/api/traffic", nil, false); code != http.StatusOK {
		t.Fatalf("carol after a refused revoke: status %d, want 200", code)
	}

	code, body := alice.mustDo(t, http.MethodDelete, revoke, nil, true)
	if code != http.StatusOK {
		t.Fatalf("DELETE %s as admin: status %d, want 200 (body %.200s)", "/dashboard/api/sessions?sub=<carol>", code, body)
	}
	var out struct {
		Revoked int `json:"revoked"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Revoked < 1 {
		t.Errorf("revoke response: revoked %d, decode error %v; want at least 1", out.Revoked, err)
	}

	if code, _ := carol.mustDo(t, http.MethodGet, "/dashboard/api/traffic", nil, false); code != http.StatusUnauthorized {
		t.Errorf("GET /dashboard/api/traffic as carol after the revoke: status %d, want 401", code)
	}
	if code, _ := carol.mustDo(t, http.MethodGet, "/auth/me", nil, false); code != http.StatusUnauthorized {
		t.Errorf("GET /auth/me as carol after the revoke: status %d, want 401", code)
	}
	if code, _ := alice.mustDo(t, http.MethodGet, "/dashboard/api/traffic", nil, false); code != http.StatusOK {
		t.Errorf("alice after revoking carol: status %d, want 200", code)
	}
}

// TestConsoleSSODexDown proves an unreachable IdP costs only the login: with
// Dex stopped and the CP restarted, workers still pull /policy and /auth/login
// answers 503 idp_unavailable. Dex and the CP are brought back (and the stack
// waited on) afterwards, pass or fail, so later tests see a normal stack.
func TestConsoleSSODexDown(t *testing.T) {
	requireStack(t)

	dex := serviceContainer(t, "dex")
	cp := serviceContainer(t, compose.SvcCP)
	docker := func(args ...string) error {
		if res := compose.Run(".", compose.ComposeDeadline, "docker", args...); res.Exit != 0 {
			return fmt.Errorf("docker %s: exit %d: %s", strings.Join(args, " "), res.Exit, firstLine(res.Stderr))
		}
		return nil
	}
	t.Cleanup(func() {
		if err := restoreDexAndCP(docker, dex, cp); err != nil {
			t.Errorf("restore the stack after the Dex outage: %v", err)
		}
	})

	if err := docker("stop", "-t", "5", dex); err != nil {
		t.Fatal(err)
	}
	if err := docker("restart", "-t", "10", cp); err != nil {
		t.Fatal(err)
	}
	if err := waitCPHealthy(); err != nil {
		t.Fatalf("the CP did not come back with Dex down: %v", err)
	}

	if code, body := bearerGet(t, "/policy"); code != http.StatusOK {
		t.Errorf("GET /policy with Dex down: status %d, want 200 (body %.200s)", code, body)
	}
	code, body := bearerGet(t, "/auth/login")
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &out)
	if code != http.StatusServiceUnavailable || out.Error != "idp_unavailable" {
		t.Errorf("GET /auth/login with Dex down: status %d error %q, want 503 idp_unavailable", code, out.Error)
	}
}

// waitCPHealthy polls the CP's /healthz until it answers 200.
func waitCPHealthy() error {
	return compose.PollUntil(restoreDeadline, func() (bool, string) {
		code, _, err := compose.TryGet(compose.CPBase + "/healthz")
		return err == nil && code == http.StatusOK, fmt.Sprintf("CP healthz: status %d err %v", code, err)
	})
}

// restoreDexAndCP starts Dex, waits for its discovery, restarts the CP so it
// discovers Dex at once instead of on its backoff, and waits for the whole
// stack (waitStackReady signs in through Dex, so login works again).
func restoreDexAndCP(docker func(...string) error, dex, cp string) error {
	if err := docker("start", dex); err != nil {
		return err
	}
	if err := compose.PollUntil(restoreDeadline, func() (bool, string) {
		code, _, err := compose.PlainGet(dexURL + discoveryPath)
		return err == nil && code == http.StatusOK, fmt.Sprintf("dex discovery: status %d err %v", code, err)
	}); err != nil {
		return err
	}
	if err := docker("restart", "-t", "10", cp); err != nil {
		return err
	}
	return waitStackReady()
}
