//go:build e2e

package identity

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness/compose"
)

const (
	// dexURL is Dex's issuer AND the host-side base: Dex is published on
	// 127.0.0.1:5556, so the host reaches it directly. Containers use
	// http://dex:5556 (internalIssuerURL, configured by the later tickets).
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

// stackGate decides what a missing stack means: under CI it is a failure (a
// skip must never let the e2e job go green), elsewhere a loud skip. Pure, so it
// is unit-tested without Docker.
func stackGate(ci, available bool, reason string) (fail bool, msg string) {
	switch {
	case available:
		return false, ""
	case ci:
		return true, "BLOCKED: the identity stack is unavailable (" + reason + "); run `make e2e-identity-up` or `make e2e-identity`"
	default:
		return false, "BLOCKED (skipped, not passed): the identity stack is unavailable (" + reason + "); this test did NOT run"
	}
}

// requireStack is the first line of every test in this package.
func requireStack(t *testing.T) {
	t.Helper()
	fail, msg := stackGate(os.Getenv("CI") == "true", stackUnavailable == "", stackUnavailable)
	if fail {
		t.Fatalf("%s", msg)
	}
	if msg != "" {
		t.Skip(msg)
	}
}

// devEnv returns KEY's value: the caller's environment first (the Makefile
// honours exported overrides the same way), else the dev placeholder from
// deploy/compose/dex/.env.example.
func devEnv(t testing.TB, key string) string {
	t.Helper()
	if v := os.Getenv(key); v != "" {
		return v
	}
	root, err := compose.RepoRoot()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	f, err := os.Open(filepath.Join(root, devEnvFile))
	if err != nil {
		t.Fatalf("identity: open %s: %v", devEnvFile, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok && k == key && !strings.HasPrefix(line, "#") {
			return v
		}
	}
	t.Fatalf("identity: %s is not set and not in %s", key, devEnvFile)
	return ""
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

// cpTraffic GETs the control plane's /dashboard/api/traffic?<query> (dashboard
// reads are open today) and decodes the events.
func cpTraffic(t testing.TB, query string) []analytics.Event {
	t.Helper()
	path := compose.TrafficPath
	if query != "" {
		path += "?" + query
	}
	body, err := compose.FleetBody(path)
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
