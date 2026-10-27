//go:build e2e

package identity

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/test/harness/compose"
)

// L2 test of `warden identity exec` (W-P1-IDC-07): the same real stack as the
// smoke (Dex, LDAP, worker-1 in attribute mode, agent-1 on the internal
// network only), but the token reaches the worker through the loopback
// forwarder that exec starts inside agent-1, never through the child's
// environment or argv. The test seeds agent-1's login cache with alice's
// token over stdin (agent-1 has no route to Dex, so it cannot log in itself);
// the token is still fresh, so exec never refreshes. Refresh while a child
// runs is proven by the unit test TestForwarderRefresh: Dex tokens last 1h.
// No assertion prints a token.

const (
	// execIssuer is the issuer in agent-1's identity config: the token's own
	// issuer (dexURL), a loopback http URL the CLI accepts. Nothing dials it
	// while the cached token is fresh.
	execIssuer   = dexURL
	execClientID = harnessClientID
	// execMarker separates the child's self-report from curl's output. The
	// child computes it (CURL-$((6*7))) so the literal is not in its own argv.
	execMarker = "CURL-42"
)

// execCache is a fresh per-test cache directory inside agent-1.
func execCache() string {
	return fmt.Sprintf("/tmp/warden-idc07-%d", time.Now().UnixNano())
}

// seedCache writes token into agent-1's login cache at dir (a 0700 directory,
// a 0600 file) through stdin, so it never appears on a command line. The
// directory is removed when the test ends.
func seedCache(t testing.TB, dir, token string) {
	t.Helper()
	entry, err := json.Marshal(identityclient.Entry{
		Issuer: execIssuer, ClientID: execClientID, IDToken: token,
		// A little in the past: the CLI refuses a receive time in its future.
		ReceivedAt: time.Now().Add(-5 * time.Second).UTC(),
	})
	if err != nil {
		t.Fatalf("identity: encode the cache entry: %v", err)
	}
	name := identityclient.CacheFileName(execIssuer, execClientID)
	res, err := compose.AgentRunStdin(compose.SvcAgent1, entry,
		"sh", "-c", `umask 077 && mkdir -p "$1" && cat > "$1/$2"`, "sh", dir, name)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if res.Exit != 0 {
		t.Fatalf("identity: seed the login cache: exit %d (%s)", res.Exit, firstLine(res.Stderr))
	}
	t.Cleanup(func() { _, _ = compose.AgentRunRaw(compose.SvcAgent1, "rm", "-rf", dir) })
}

// identityExec runs `warden identity exec` in agent-1 with the cache at dir
// and child as the supervised command. Nothing secret is on the argv.
func identityExec(t testing.TB, dir string, child ...string) compose.Result {
	t.Helper()
	args := append([]string{"/opt/warden/warden", "identity",
		"--issuer", execIssuer, "--client-id", execClientID, "--cache-dir", dir,
		"exec", "--worker", envWorkerArg, "--ca", compose.AgentCABundle, "--"}, child...)
	return agentExec(t, args...)
}

// execCurl is the child command that requests host over https through the
// environment exec built; it prints the HTTP and CONNECT status.
func execCurl(host string) []string {
	return []string{"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{http_connect}",
		"--max-time", compose.AgentCurlMaxTime, "https://" + host + "/"}
}

// sweep fails the test when text holds token or any JWT-shaped string. It
// reports only where and how long, never the match.
func sweep(t testing.TB, what, text, token string) {
	t.Helper()
	if token != "" && strings.Contains(text, token) {
		t.Errorf("%s contains the alice token", what)
	}
	if m := jwtShaped.FindString(text); m != "" {
		t.Errorf("%s contains a JWT-shaped string (%d chars)", what, len(m))
	}
}

// validEventsFor returns the valid allow events of email on host, newest first.
func validEventsFor(t testing.TB, host, email string) []analytics.Event {
	t.Helper()
	var out []analytics.Event
	for _, e := range statusEvents(t, host, "valid") {
		if e.UserEmail == email {
			out = append(out, e)
		}
	}
	return out
}

// TestIdentityExecAttribution: a curl child of `warden identity exec` reaches
// the allowed host and the control plane attributes the request to alice, the
// same user (same sub) as the `identity env` path.
func TestIdentityExecAttribution(t *testing.T) {
	requireStack(t)
	token := dexToken(t, smokeUser)
	dir := execCache()
	seedCache(t, dir, token)

	before := len(validEventsFor(t, allowedHost, smokeEmail))
	res := identityExec(t, dir, execCurl(allowedHost)...)
	sweep(t, "exec output", res.Stdout+res.Stderr, token)
	status := strings.TrimSpace(res.Stdout)
	if res.Exit != 0 || !strings.HasPrefix(status, "200 ") {
		t.Fatalf("exec curl: exit %d, status %q; want exit 0, 200 (stderr: %s)", res.Exit, status, firstLine(res.Stderr))
	}
	execEv := waitEvent(t, "a new valid event for "+smokeEmail+" from exec", func() (analytics.Event, bool) {
		if evs := validEventsFor(t, allowedHost, smokeEmail); len(evs) > before {
			return evs[0], true
		}
		return analytics.Event{}, false
	})
	if execEv.UserSub == "" {
		t.Errorf("user_sub is empty")
	}
	for _, g := range []string{"warden-admins", "eng"} {
		if !slices.Contains(execEv.UserGroups, g) {
			t.Errorf("user_groups = %v, want it to contain %q", execEv.UserGroups, g)
		}
	}
	if execEv.Decision != "allow" {
		t.Errorf("decision = %q, want allow", execEv.Decision)
	}

	// The env path with the same token: the same user, by sub.
	before = len(validEventsFor(t, allowedHost, smokeEmail))
	envStatus, envRes := routedCurl(t, token, allowedHost)
	sweep(t, "env-path output", envRes.Stdout+envRes.Stderr, token)
	if envRes.Exit != 0 || !strings.HasPrefix(envStatus, "200 ") {
		t.Fatalf("env-path curl: exit %d, status %q; want exit 0, 200 (stderr: %s)", envRes.Exit, envStatus, firstLine(envRes.Stderr))
	}
	envEv := waitEvent(t, "a new valid event for "+smokeEmail+" from env", func() (analytics.Event, bool) {
		if evs := validEventsFor(t, allowedHost, smokeEmail); len(evs) > before {
			return evs[0], true
		}
		return analytics.Event{}, false
	})
	if envEv.UserSub != execEv.UserSub {
		t.Errorf("exec and env attribute to different subs (%q vs %q)", execEv.UserSub, envEv.UserSub)
	}
}

// TestIdentityExecChildSecrets: the child that makes an attributed request
// holds no token. It reports its own initial environment and argv from /proc
// (what exec handed it), then curls the allowed host with that environment.
func TestIdentityExecChildSecrets(t *testing.T) {
	requireStack(t)
	token := dexToken(t, smokeUser)
	dir := execCache()
	seedCache(t, dir, token)

	script := `tr '\0' '\n' < /proc/$$/environ; echo; echo ARGV; tr '\0' '\n' < /proc/$$/cmdline; echo; echo CURL-$((6*7)); exec "$@"`
	before := len(validEventsFor(t, allowedHost, smokeEmail))
	res := identityExec(t, dir, append([]string{"sh", "-c", script, "sh"}, execCurl(allowedHost)...)...)
	report, curlOut, ok := strings.Cut(res.Stdout, execMarker)
	if !ok {
		t.Fatalf("the child did not report (exit %d, stderr: %s)", res.Exit, firstLine(res.Stderr))
	}
	if status := strings.TrimSpace(curlOut); res.Exit != 0 || !strings.HasPrefix(status, "200 ") {
		t.Fatalf("child curl: exit %d, status %q; want exit 0, 200 (stderr: %s)", res.Exit, status, firstLine(res.Stderr))
	}
	// The same child's request carried alice: the token went through the
	// forwarder, not through anything the child holds.
	waitEvent(t, "a new valid event for "+smokeEmail+" from the reporting child", func() (analytics.Event, bool) {
		if evs := validEventsFor(t, allowedHost, smokeEmail); len(evs) > before {
			return evs[0], true
		}
		return analytics.Event{}, false
	})
	envPart, argvPart, _ := strings.Cut(report, "\nARGV\n")

	sweep(t, "the child's environment", envPart, token)
	sweep(t, "the child's argv", argvPart, token)
	sweep(t, "exec stderr", res.Stderr, token)

	env := map[string]string{}
	for _, line := range strings.Split(envPart, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			env[k] = v
		}
	}
	for k := range env {
		if strings.HasPrefix(k, "WARDEN_IDENTITY_") {
			t.Errorf("the child's environment has %s", k)
		}
	}
	// The proxy is the loopback forwarder with the per-run credential, not
	// the worker and not a session token.
	for _, k := range []string{"HTTPS_PROXY", "https_proxy"} {
		v := env[k]
		if !strings.HasPrefix(v, "http://"+identityclient.ProxyClientUser+":") || !strings.Contains(v, "@127.0.0.1:") {
			t.Errorf("%s does not point at the loopback forwarder with the per-run credential", k)
		}
		if strings.Contains(v, "session") || strings.Contains(v, compose.SvcWorker1) {
			t.Errorf("%s carries a session credential or the worker address", k)
		}
	}
	// The agent's own plain-http proxy (worker-1) is removed, not inherited.
	for _, k := range []string{"HTTP_PROXY", "http_proxy"} {
		if _, ok := env[k]; ok {
			t.Errorf("the child inherited %s", k)
		}
	}
}

// TestIdentityExecNoLogin: with an empty cache and no terminal, exec exits 2
// (login required) and never starts the child.
func TestIdentityExecNoLogin(t *testing.T) {
	requireStack(t)
	dir := execCache()
	t.Cleanup(func() { _, _ = compose.AgentRunRaw(compose.SvcAgent1, "rm", "-rf", dir) })
	res := identityExec(t, dir, "echo", "child-started")
	if res.Exit != 2 {
		t.Errorf("exec with no login: exit %d, want 2 (stderr: %s)", res.Exit, firstLine(res.Stderr))
	}
	if strings.Contains(res.Stdout, "child-started") {
		t.Errorf("exec started the child with no login")
	}
}
