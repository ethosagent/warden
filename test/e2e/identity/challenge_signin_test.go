//go:build e2e

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/test/harness/compose"
)

// L2 identity challenge mode against real Dex (#558). worker-1 is switched to
// `challenge` for the test (a settings save as admin alice, undone when it
// ends). A curl agent behind `warden identity exec --challenge` asks for an
// allowed host with no login: the worker answers 407 with a sign-in URL, the
// client prints it on stderr and runs the --signin-notify hook, the test signs
// the code in as alice through Dex's device page like a browser would (a cookie
// jar, form posts, no automation), the client's poll stores the token, and the
// retry is allowed and attributed to alice. After `warden identity logout` the
// next call is challenged with a NEW code.
//
// The client runs in the signin-client service (deploy/compose/
// docker-compose.e2e-identity.yml), which shares dex's network namespace so it
// reaches Dex at the public issuer URL and worker-1 over cp-net; agent-1 still
// has no route to Dex. No assertion prints a token, device code or user code.

const (
	signInService  = "signin-client"
	signInClientID = "warden-cli"
	// signInScript is the supervised child: it retries one curl a second until
	// the request is allowed, printing "attempt N: <http_code> <http_connect>".
	// A 407 on the CONNECT shows as "000 407".
	signInScript = `i=0; while [ "$i" -lt 60 ]; do i=$((i+1)); ` +
		`out=$(curl -sS -o /dev/null -w '%{http_code} %{http_connect}' --max-time 10 https://` + allowedHost + `/ 2>/dev/null); ` +
		`echo "attempt $i: $out"; case "$out" in 200*) exit 0;; esac; sleep 1; done; exit 1`
	signInWait = 120 * time.Second
)

// signInLine is the sign-in line exec prints on stderr.
var signInLine = regexp.MustCompile(`warden: sign in at (\S+) \(code ([A-Z0-9-]+)\)`)

// formAction finds the action of the first form of a Dex page.
var formAction = regexp.MustCompile(`(?is)<form[^>]*\baction="([^"]+)"`)

// syncBuf is a buffer a running command writes while the test reads it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// signInContainer returns the signin-client container, restarting it when it
// lost Dex's network namespace (it shares it: a dex restart, which
// TestDexRestartSurvival does, strands it).
func signInContainer(t testing.TB) string {
	t.Helper()
	cid := serviceContainer(t, signInService)
	probe := func() bool {
		res := compose.Run(".", compose.ProbeDeadline, "docker", "exec", cid, "curl", "-fsS", "-o", "/dev/null", dexURL+discoveryPath)
		return res.Exit == 0
	}
	if probe() {
		return cid
	}
	if res := compose.Run(".", compose.ComposeDeadline, "docker", "restart", cid); res.Exit != 0 {
		t.Fatalf("identity: restart %s: exit %d: %s", signInService, res.Exit, firstLine(res.Stderr))
	}
	if err := compose.PollUntil(compose.StackDeadline, func() (bool, string) { return probe(), "dex not reachable from " + signInService }); err != nil {
		t.Fatalf("identity: %s cannot reach dex after a restart: %v", signInService, err)
	}
	return cid
}

// clientArgs is the `docker exec` argv of one `warden identity` command in the
// client container, with the login cache in cache.
func clientArgs(cid, cache string, tail ...string) []string {
	return append([]string{"exec", cid, "/opt/warden/warden", "identity",
		"--issuer", dexURL, "--client-id", signInClientID, "--cache-dir", cache}, tail...)
}

// execTail is `exec --challenge` with extra flags and the child command.
func execTail(extra []string, child ...string) []string {
	tail := []string{"exec", "--worker", envWorkerArg, "--ca", compose.AgentCABundle, "--challenge"}
	tail = append(tail, extra...)
	tail = append(tail, "--")
	return append(tail, child...)
}

// bgClient is a `warden identity exec` running in the background.
type bgClient struct {
	stdout, stderr *syncBuf
	done           chan error
}

func startClient(t *testing.T, args []string) *bgClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*signInWait)
	t.Cleanup(cancel)
	root, err := compose.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = root
	c := &bgClient{stdout: &syncBuf{}, stderr: &syncBuf{}, done: make(chan error, 1)}
	cmd.Stdout, cmd.Stderr = c.stdout, c.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("identity: start the sign-in client: %v", err)
	}
	go func() { c.done <- cmd.Wait() }()
	return c
}

// waitSignIn waits for the sign-in line and returns its URL and code.
func (c *bgClient) waitSignIn(t *testing.T) (string, string) {
	t.Helper()
	var m []string
	err := compose.PollUntil(signInWait, func() (bool, string) {
		m = signInLine.FindStringSubmatch(c.stderr.String())
		return m != nil, "no sign-in line on stderr yet"
	})
	if err != nil {
		t.Fatalf("identity: the client printed no sign-in line within %s; stderr: %s", signInWait, firstLine(c.stderr.String()))
	}
	return m[1], m[2]
}

// wait returns the command's exit code once it ends.
func (c *bgClient) wait(t *testing.T) int {
	t.Helper()
	select {
	case err := <-c.done:
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("identity: the sign-in client: %v", err)
	case <-time.After(signInWait):
		t.Fatalf("identity: the sign-in client did not finish within %s; stdout: %s", signInWait, c.stdout.String())
	}
	return -1
}

// setIdentityMode saves worker-1's served identity mode as admin and undoes it
// when the test ends. It reads the settings document, changes only
// identity.defaultMode and writes it back.
func setIdentityMode(t *testing.T, cs *consoleSession, mode string) {
	t.Helper()
	put := func(m string) string {
		code, body := cs.mustDo(t, http.MethodGet, "/dashboard/api/settings", nil, false)
		if code != http.StatusOK {
			t.Fatalf("GET /dashboard/api/settings: status %d", code)
		}
		var doc struct {
			Settings map[string]any `json:"settings"`
		}
		if err := json.Unmarshal(body, &doc); err != nil || doc.Settings == nil {
			t.Fatalf("decode the settings document: %v", err)
		}
		id, _ := doc.Settings["identity"].(map[string]any)
		if id == nil {
			t.Fatal("the control plane serves no identity block")
		}
		prev, _ := id["defaultMode"].(string)
		id["defaultMode"] = m
		b, err := json.Marshal(doc.Settings)
		if err != nil {
			t.Fatal(err)
		}
		if code, resp := cs.mustDo(t, http.MethodPost, "/dashboard/api/settings", b, true); code != http.StatusOK {
			t.Fatalf("POST /dashboard/api/settings (identity %s): status %d (body %.200s)", m, code, resp)
		}
		return prev
	}
	prev := put(mode)
	t.Cleanup(func() {
		put(prev)
		waitAnonymous(t, "200 200")
	})
}

// waitAnonymous polls an anonymous request from agent-1 until the "<http_code>
// <http_connect>" it prints is want: "000 407" while challenge is on, "200 200"
// once attribute is back.
func waitAnonymous(t testing.TB, want string) {
	t.Helper()
	err := compose.PollUntil(policyWait, func() (bool, string) {
		res := agentExec(t, "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{http_connect}",
			"--max-time", compose.AgentCurlMaxTime, "https://"+allowedHost+"/")
		got := strings.TrimSpace(res.Stdout)
		return got == want, "status " + got
	})
	if err != nil {
		t.Fatalf("identity: an anonymous request from agent-1 never read %q within %s: %v", want, policyWait, err)
	}
}

// approveDevice signs user in on Dex's device page the way a browser does: it
// opens the verification URL, submits the user code, follows Dex to the LDAP
// login form, posts the user's credentials and follows Dex back to its
// "Login Successful" page. Errors name URLs without their query.
func approveDevice(t testing.TB, verificationURL, user string) {
	t.Helper()
	password := devEnv(t, "DEX_TEST_PASSWORD")
	b, err := newBrowser()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	cur, err := url.Parse(verificationURL)
	if err != nil {
		t.Fatalf("identity: the sign-in URL does not parse")
	}
	code := cur.Query().Get("user_code")
	method, form := http.MethodGet, url.Values(nil)
	for i := 0; i < 3*maxHops; i++ {
		status, body, next, err := hop(b, method, cur, form)
		if err != nil {
			t.Fatalf("identity: approve the device code: %v", err)
		}
		if next != nil {
			cur, method, form = next, http.MethodGet, nil
			continue
		}
		page := string(body)
		if status != http.StatusOK {
			t.Fatalf("identity: dex answered %d at %s", status, noQuery(cur))
		}
		if strings.Contains(page, "Login Successful") {
			return
		}
		m := formAction.FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("identity: dex page at %s has no form and is not the success page", noQuery(cur))
		}
		ref, err := url.Parse(html.UnescapeString(m[1]))
		if err != nil {
			t.Fatalf("identity: a dex form action is not a URL")
		}
		cur = cur.ResolveReference(ref)
		method = http.MethodPost
		if strings.Contains(page, `name="user_code"`) {
			form = url.Values{"user_code": {code}}
		} else {
			form = url.Values{"login": {user}, "password": {password}}
		}
	}
	t.Fatalf("identity: dex did not reach the success page within %d steps (last %s)", 3*maxHops, noQuery(cur))
}

// inTunnelScript is signInScript for the in-tunnel challenge: curl prints the
// response body (the worker's 403 JSON, one line) followed by
// "HTTPSTATUS:<code> CONNECT:<connect code>", so the test reads the link from
// what the agent's own request received.
const inTunnelScript = `i=0; while [ "$i" -lt 60 ]; do i=$((i+1)); ` +
	`out=$(curl -sS -w ' HTTPSTATUS:%{http_code} CONNECT:%{http_connect}' --max-time 10 https://` + allowedHost + `/ 2>/dev/null); ` +
	`echo "attempt $i: $out"; case "$out" in *HTTPSTATUS:200*) exit 0;; esac; sleep 1; done; exit 1`

// inTunnelAttempt is one printed attempt of inTunnelScript.
var inTunnelAttempt = regexp.MustCompile(`(?m)^attempt \d+: (.*) HTTPSTATUS:(\d+) CONNECT:(\d+)$`)

// TestChallengeInTunnel is the in-tunnel sign-in loop (#621) on the Dex stack: a
// curl agent behind `exec --challenge-in-tunnel`. Its FIRST request gets the
// CONNECT 200 and then a 403 whose body names the sign-in link, the one the
// client also prints on stderr; the test signs in as alice on Dex's device page;
// the retry is allowed and attributed to alice. After logout the next call is
// challenged again, in the tunnel, with a new code. A client that does not ask
// still gets the 407 (waitAnonymous). The worker never gives the agent the
// device_code, and no token, device code or user code is logged.
func TestChallengeInTunnel(t *testing.T) {
	requireStack(t)
	admin := loginAs(t, "alice")
	cid := signInContainer(t)
	cache := fmt.Sprintf("/tmp/warden-intunnel-%d", time.Now().UnixNano())
	t.Cleanup(func() { compose.Run(".", compose.ComposeDeadline, "docker", "exec", cid, "rm", "-rf", cache) })

	setIdentityMode(t, admin, "challenge")
	// A client that does not ask for the in-tunnel challenge still gets the 407.
	waitAnonymous(t, "000 407")

	validBefore := len(validEventsFor(t, allowedHost, smokeEmail))
	denyBefore := len(denyEvents(t, allowedHost, "identity_required"))

	// 1. No login: the first call gets a CONNECT 200 and a 403 that names the link.
	first := startClient(t, clientArgs(cid, cache, execTail([]string{"--challenge-in-tunnel"}, "sh", "-c", inTunnelScript)...))
	signInURL, signInCode := first.waitSignIn(t)
	if !strings.HasPrefix(signInURL, dexURL+"/device?user_code=") || !strings.HasSuffix(signInURL, signInCode) {
		t.Fatalf("the sign-in URL is not Dex's device page with the code (%s)", noQuery(mustParse(t, signInURL)))
	}
	waitDeny(t, allowedHost, "identity_required", denyBefore)

	// 2. The user signs in as alice on Dex's device page.
	approveDevice(t, signInURL, smokeUser)

	// 3. The poll stores the token and the retry is allowed.
	if code := first.wait(t); code != 0 {
		t.Fatalf("the retrying child exited %d; stdout: %s", code, first.stdout.String())
	}
	attempts := inTunnelAttempt.FindAllStringSubmatch(first.stdout.String(), -1)
	if len(attempts) < 2 {
		t.Fatalf("want a challenged first call and an allowed retry, got %d attempts", len(attempts))
	}
	body, status, connect := attempts[0][1], attempts[0][2], attempts[0][3]
	if status != "403" || connect != "200" {
		t.Errorf("the first call read HTTP %s over CONNECT %s, want 403 over 200 (the challenge inside the tunnel)", status, connect)
	}
	var tb struct {
		Type  string `json:"type"`
		Error struct{ Type, Code, Message string }
	}
	if err := json.Unmarshal([]byte(body), &tb); err != nil {
		t.Fatalf("the first call's body is not the challenge JSON: %v", err)
	}
	if tb.Type != "error" || tb.Error.Type != "identity_required" || tb.Error.Code != "identity_required" {
		t.Errorf("the first call's error = %s/%s/%s, want error/identity_required/identity_required", tb.Type, tb.Error.Type, tb.Error.Code)
	}
	if !strings.Contains(tb.Error.Message, signInURL) || !strings.Contains(tb.Error.Message, signInCode) {
		t.Errorf("the 403 message does not show the sign-in link and code the client printed")
	}
	if strings.Contains(body, "device_code") || strings.Contains(body, "token_endpoint") {
		t.Errorf("the agent's 403 body names a device_code or token_endpoint")
	}
	if last := attempts[len(attempts)-1]; last[2] != "200" {
		t.Errorf("the last call read HTTP %s, want 200", last[2])
	}
	ev := waitEvent(t, "a new valid event for "+smokeEmail+" after the sign-in", func() (e analytics.Event, ok bool) {
		if evs := validEventsFor(t, allowedHost, smokeEmail); len(evs) > validBefore {
			return evs[0], true
		}
		return e, false
	})
	if ev.UserEmail != smokeEmail || ev.UserSub == "" || ev.Decision != "allow" {
		t.Errorf("the allowed call is attributed to %q (sub set: %v, decision %q), want %s", ev.UserEmail, ev.UserSub != "", ev.Decision, smokeEmail)
	}

	// 4. Nothing printed, logged or stored holds a token, a device code or the user code.
	entry := readLogin(t, cid, cache)
	surfaces := map[string]string{
		"client stderr": first.stderr.String(),
		"worker-1 logs": workerLogs(t),
		"control plane events": func() string {
			b, _ := json.Marshal(cpTraffic(t, "limit=1000"))
			return string(b)
		}(),
	}
	for name, text := range surfaces {
		sweep(t, name, text, entry.IDToken)
		if entry.RefreshToken != "" && strings.Contains(text, entry.RefreshToken) {
			t.Errorf("%s contains the refresh token", name)
		}
		if strings.Contains(text, "device_code") {
			t.Errorf("%s contains a device_code", name)
		}
	}
	for _, name := range []string{"worker-1 logs", "control plane events"} {
		if strings.Contains(surfaces[name], signInCode) {
			t.Errorf("%s contains the user code", name)
		}
	}

	// 5. After logout the next call is challenged again, in the tunnel, with a new code.
	if res := compose.Run(".", compose.AgentTimeout, "docker", clientArgs(cid, cache, "logout")...); res.Exit != 0 {
		t.Fatalf("identity: logout: exit %d: %s", res.Exit, firstLine(res.Stderr))
	}
	second := compose.Run(".", compose.AgentTimeout, "docker", clientArgs(cid, cache, execTail([]string{"--challenge-in-tunnel"},
		"curl", "-sS", "-w", " HTTPSTATUS:%{http_code} CONNECT:%{http_connect}", "--max-time", "10", "https://"+allowedHost+"/")...)...)
	m := inTunnelAttempt.FindStringSubmatch("attempt 1: " + strings.TrimSpace(second.Stdout))
	if m == nil || m[2] != "403" || m[3] != "200" {
		t.Fatalf("the call after logout read %q, want a 403 over a CONNECT 200", firstLine(second.Stdout))
	}
	sm := signInLine.FindStringSubmatch(second.Stderr)
	if sm == nil {
		t.Fatalf("the call after logout printed no sign-in line; stderr: %s", firstLine(second.Stderr))
	}
	if sm[2] == signInCode || sm[1] == signInURL {
		t.Errorf("the call after logout got the old sign-in code, want a new one")
	}
	if !strings.Contains(m[1], sm[1]) {
		t.Errorf("the 403 after logout does not show the new link")
	}
	sweep(t, "second client stderr", second.Stderr, entry.IDToken)
}

// TestChallengeSignInFlow is the whole sign-in loop on the Dex stack.
func TestChallengeSignInFlow(t *testing.T) {
	requireStack(t)
	admin := loginAs(t, "alice")
	cid := signInContainer(t)
	cache := fmt.Sprintf("/tmp/warden-challenge-%d", time.Now().UnixNano())
	hookFile := cache + ".hook"
	t.Cleanup(func() { compose.Run(".", compose.ComposeDeadline, "docker", "exec", cid, "rm", "-rf", cache, hookFile) })

	setIdentityMode(t, admin, "challenge")
	waitAnonymous(t, "000 407")

	validBefore := len(validEventsFor(t, allowedHost, smokeEmail))
	denyBefore := len(denyEvents(t, allowedHost, "identity_required"))

	// 1. No login: the first call is refused and the user is told where to sign in.
	hook := `printf %s "$WARDEN_SIGNIN_URL" > ` + hookFile
	first := startClient(t, clientArgs(cid, cache, execTail([]string{"--signin-notify", hook}, "sh", "-c", signInScript)...))
	signInURL, signInCode := first.waitSignIn(t)
	if !strings.HasPrefix(signInURL, dexURL+"/device?user_code=") || !strings.HasSuffix(signInURL, signInCode) {
		t.Fatalf("the sign-in URL is not Dex's device page with the code (%s)", noQuery(mustParse(t, signInURL)))
	}
	waitDeny(t, allowedHost, "identity_required", denyBefore)

	// 2. The user signs in as alice on Dex's device page.
	approveDevice(t, signInURL, smokeUser)

	// 3. The poll stores the token and the retry is allowed.
	if code := first.wait(t); code != 0 {
		t.Fatalf("the retrying child exited %d; stdout: %s", code, first.stdout.String())
	}
	attempts := regexp.MustCompile(`(?m)^attempt \d+: (.*)$`).FindAllStringSubmatch(first.stdout.String(), -1)
	if len(attempts) < 2 {
		t.Fatalf("want a refused first call and an allowed retry, got attempts %v", attempts)
	}
	if got := strings.TrimSpace(attempts[0][1]); got != "000 407" {
		t.Errorf("the first call read %q, want 000 407 (refused with a sign-in challenge)", got)
	}
	if got := strings.TrimSpace(attempts[len(attempts)-1][1]); !strings.HasPrefix(got, "200 ") {
		t.Errorf("the last call read %q, want 200", got)
	}
	ev := waitEvent(t, "a new valid event for "+smokeEmail+" after the sign-in", func() (e analytics.Event, ok bool) {
		if evs := validEventsFor(t, allowedHost, smokeEmail); len(evs) > validBefore {
			return evs[0], true
		}
		return e, false
	})
	if ev.UserEmail != smokeEmail || ev.UserSub == "" || ev.Decision != "allow" {
		t.Errorf("the allowed call is attributed to %q (sub set: %v, decision %q), want %s", ev.UserEmail, ev.UserSub != "", ev.Decision, smokeEmail)
	}
	if hook, _ := readInClient(cid, hookFile); hook != signInURL {
		t.Errorf("--signin-notify got a different URL than stderr")
	}

	// 4. Nothing printed, logged or stored on the way holds a token or a device code.
	entry := readLogin(t, cid, cache)
	surfaces := map[string]string{
		"first client stdout": first.stdout.String(),
		"first client stderr": first.stderr.String(),
		"worker-1 logs":       workerLogs(t),
		"control plane events": func() string {
			b, _ := json.Marshal(cpTraffic(t, "limit=1000"))
			return string(b)
		}(),
	}
	for name, text := range surfaces {
		sweep(t, name, text, entry.IDToken)
		if entry.RefreshToken != "" && strings.Contains(text, entry.RefreshToken) {
			t.Errorf("%s contains the refresh token", name)
		}
		if strings.Contains(text, "device_code") {
			t.Errorf("%s contains a device_code", name)
		}
	}
	for _, name := range []string{"worker-1 logs", "control plane events"} {
		if strings.Contains(surfaces[name], signInCode) {
			t.Errorf("%s contains the user code", name)
		}
	}

	// 5. After logout the next call is challenged again, with a new code.
	if res := compose.Run(".", compose.AgentTimeout, "docker", clientArgs(cid, cache, "logout")...); res.Exit != 0 {
		t.Fatalf("identity: logout: exit %d: %s", res.Exit, firstLine(res.Stderr))
	}
	second := compose.Run(".", compose.AgentTimeout, "docker", clientArgs(cid, cache, execTail(nil,
		"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{http_connect}", "--max-time", "10", "https://"+allowedHost+"/")...)...)
	if second.Exit == 0 {
		t.Errorf("a call after logout succeeded (stdout %q)", strings.TrimSpace(second.Stdout))
	}
	if got := strings.TrimSpace(second.Stdout); got != "000 407" {
		t.Errorf("the call after logout read %q, want 000 407", got)
	}
	m := signInLine.FindStringSubmatch(second.Stderr)
	if m == nil {
		t.Fatalf("the call after logout printed no sign-in line; stderr: %s", firstLine(second.Stderr))
	}
	if m[2] == signInCode || m[1] == signInURL {
		t.Errorf("the call after logout got the old sign-in code, want a new one")
	}
	if resp, err := hostClient.Get(m[1]); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("the new sign-in URL does not open on Dex")
	} else {
		_ = resp.Body.Close()
	}
	sweep(t, "second client stderr", second.Stderr, entry.IDToken)
}

func mustParse(t testing.TB, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("identity: unparsable URL")
	}
	return u
}

// readInClient returns the content of a file in the client container.
func readInClient(cid, path string) (string, error) {
	res := compose.Run(".", compose.ComposeDeadline, "docker", "exec", cid, "cat", path)
	if res.Exit != 0 {
		return "", fmt.Errorf("cat %s: exit %d", path, res.Exit)
	}
	return res.Stdout, nil
}

// readLogin returns the login the client cached, for the leak sweep only.
func readLogin(t testing.TB, cid, dir string) identityclient.Entry {
	t.Helper()
	raw, err := readInClient(cid, dir+"/"+identityclient.CacheFileName(dexURL, signInClientID))
	if err != nil {
		t.Fatalf("identity: no login was cached: %v", err)
	}
	var e identityclient.Entry
	if err := json.Unmarshal([]byte(raw), &e); err != nil || e.IDToken == "" {
		t.Fatalf("identity: the cached login is not usable")
	}
	return e
}
