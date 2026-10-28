//go:build e2e

package identity

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/harness/compose"
)

// Break-glass against the real reference stack (W-P1-OPS1-10): with Dex
// stopped and the CP restarted, workers still pull /policy, /auth/login answers
// 503 idp_unavailable, and an operator signs in at /auth/breakglass over the
// published TLS port. The L1 twin is TestControlPlaneBreakGlassDegraded.

const (
	breakGlassUser    = "breakglass-e2e"
	breakGlassHashEnv = "WARDEN_BREAKGLASS_HASH"
	// breakGlassConfigBlock is inserted right after the top-level `console:`
	// line of configs/config.e2e-identity-cp.yaml, so these keys land inside
	// it whatever top-level blocks follow.
	breakGlassConfigBlock = `
  adminAudit:
    enabled: true
  breakGlass:
    enabled: true
    username: ` + breakGlassUser + `
    passwordHashEnv: ` + breakGlassHashEnv + `
    sessionTTL: 10m
`
	breakGlassOverride = `services:
  control-plane:
    environment:
      - ` + breakGlassHashEnv + `
    volumes:
      - %s:/etc/warden/config.yaml:ro
`
	cpConfigPath = "configs/config.e2e-identity-cp.yaml"
)

// identityComposeArgs renders `docker compose` for the identity stack plus
// any extra -f files (the same chain as E2E_IDENTITY_COMPOSE in the Makefile).
func identityComposeArgs(extraFiles []string, args ...string) []string {
	full := []string{"compose"}
	for _, f := range append(append([]string{}, compose.ComposeFiles...),
		"deploy/compose/docker-compose.identity.yml", "deploy/compose/docker-compose.e2e-identity.yml") {
		full = append(full, "-f", f)
	}
	for _, f := range extraFiles {
		full = append(full, "-f", f)
	}
	return append(full, args...)
}

// devEnvList is the caller's environment plus every KEY=VALUE of
// deploy/compose/dex/.env.example the caller has not set (what the Makefile's
// E2E_IDENTITY_LOAD_ENV does), plus extra.
func devEnvList(t testing.TB, extra ...string) []string {
	t.Helper()
	root, err := compose.RepoRoot()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	f, err := os.Open(filepath.Join(root, devEnvFile))
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	defer f.Close()
	env := os.Environ()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") && os.Getenv(k) == "" {
			env = append(env, k+"="+v)
		}
	}
	return append(env, extra...)
}

// recreateCP force-recreates only the control-plane service (state volume kept)
// with the extra compose files and env, and waits for it to be healthy.
func recreateCP(t testing.TB, extraFiles []string, env []string) error {
	t.Helper()
	root, err := compose.RepoRoot()
	if err != nil {
		return err
	}
	res := compose.RunEnv(root, env, compose.UpDeadline, "docker",
		identityComposeArgs(extraFiles, "up", "-d", "--no-deps", "--no-build", "--force-recreate", "--wait", compose.SvcCP)...)
	if res.Exit != 0 {
		return fmt.Errorf("docker compose up %s: exit %d: %s", compose.SvcCP, res.Exit, firstLine(res.Stderr))
	}
	return nil
}

// breakGlassOverrideFiles writes the break-glass CP config (the identity config
// plus the break-glass block) and a compose override mounting it, into a
// world-readable temp dir (the CP container user is not this user). It returns
// the override's path relative to the repo root's absolute form.
func breakGlassOverrideFiles(t *testing.T) string {
	t.Helper()
	root, err := compose.RepoRoot()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	base, err := os.ReadFile(filepath.Join(root, cpConfigPath))
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if !bytes.Contains(base, []byte("\nconsole:\n")) {
		t.Fatalf("identity: %s has no top-level console: block to extend", cpConfigPath)
	}
	dir, err := os.MkdirTemp("", "warden-breakglass-")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("identity: %v", err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	head, tail, _ := bytes.Cut(base, []byte("\nconsole:\n"))
	body := slices.Concat(head, []byte("\nconsole:\n"), []byte(breakGlassConfigBlock[1:]), tail)
	if err := os.WriteFile(cfg, body, 0o644); err != nil {
		t.Fatalf("identity: %v", err)
	}
	override := filepath.Join(dir, "override.yml")
	if err := os.WriteFile(override, fmt.Appendf(nil, breakGlassOverride, cfg), 0o644); err != nil {
		t.Fatalf("identity: %v", err)
	}
	return override
}

// perRunPassword is a fresh random password; it is never logged.
func perRunPassword(t testing.TB) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("identity: %v", err)
	}
	return hex.EncodeToString(b)
}

// breakGlassPost POSTs a login to /auth/breakglass with the session's client.
func breakGlassPost(t testing.TB, cs *consoleSession, user, password string) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": user, "password": password})
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	code, b, err := cs.do(http.MethodPost, "/auth/breakglass", body, false)
	if err != nil {
		t.Fatalf("identity: POST /auth/breakglass: %v", err)
	}
	return code, b
}

// breakGlassLogLines returns the CP log lines that are the breakglass_login
// ERROR event (text or JSON handler).
func breakGlassLogLines(t testing.TB, cp string) []string {
	t.Helper()
	res := compose.Run(".", compose.ComposeDeadline, "docker", "logs", cp)
	if res.Exit != 0 {
		t.Fatalf("identity: docker logs: exit %d: %s", res.Exit, firstLine(res.Stderr))
	}
	var out []string
	for _, line := range strings.Split(res.Stdout+"\n"+res.Stderr, "\n") {
		if !strings.Contains(line, "breakglass_login") {
			continue
		}
		if (strings.Contains(line, "level=ERROR") || strings.Contains(line, `"level":"ERROR"`)) &&
			(strings.Contains(line, "msg=breakglass_login") || strings.Contains(line, `"msg":"breakglass_login"`)) {
			out = append(out, line)
		}
	}
	return out
}

// policyETag GETs /policy with worker-1's token and returns its ETag.
func policyETag(t testing.TB) string {
	t.Helper()
	c, err := newBrowser()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, compose.CPBase+"/policy", nil)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+(&compose.Target{}).WorkerToken(1))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("identity: GET /policy: %v", redactURLError(err))
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") == "" {
		t.Fatalf("GET /policy: status %d etag %q, want 200 with an ETag", resp.StatusCode, resp.Header.Get("ETag"))
	}
	return resp.Header.Get("ETag")
}

type workerRow struct {
	ProxyID    string `json:"proxyID"`
	LastSeen   string `json:"lastSeen"`
	Online     bool   `json:"online"`
	PolicyETag string `json:"policyETag"`
}

// worker1 reads worker-1's registry row through an admin session.
func worker1(t testing.TB, cs *consoleSession) (workerRow, bool) {
	t.Helper()
	code, body := cs.mustDo(t, http.MethodGet, "/dashboard/api/workers", nil, false)
	if code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/workers: status %d, want 200", code)
	}
	var ws []workerRow
	if err := json.Unmarshal(body, &ws); err != nil {
		t.Fatalf("workers list is not JSON: %v", err)
	}
	for _, w := range ws {
		if w.ProxyID == compose.SvcWorker1 {
			return w, true
		}
	}
	return workerRow{}, false
}

// TestBreakGlassDexDown proves the emergency login on real Dex: with Dex
// stopped and the CP restarted (break-glass on, TLS from the e2e certs), the
// worker keeps pulling /policy and heartbeating, /auth/login is 503
// idp_unavailable, and the break-glass login yields an admin session, one ERROR
// log line and an audit row; a wrong password leaves one denied row. The stack
// is restored afterwards (Dex up, the CP back on its normal config).
func TestBreakGlassDexDown(t *testing.T) {
	requireStack(t)

	password := perRunPassword(t)
	hash, err := controlplane.HashPassword(password, rand.Reader)
	if err != nil {
		t.Fatalf("identity: hash the break-glass password: %v", err)
	}
	override := breakGlassOverrideFiles(t)
	dex := serviceContainer(t, "dex")
	docker := func(args ...string) error {
		if res := compose.Run(".", compose.ComposeDeadline, "docker", args...); res.Exit != 0 {
			return fmt.Errorf("docker %s: exit %d: %s", strings.Join(args, " "), res.Exit, firstLine(res.Stderr))
		}
		return nil
	}
	t.Cleanup(func() {
		if err := docker("start", dex); err != nil {
			t.Errorf("restore Dex: %v", err)
			return
		}
		if err := compose.PollUntil(restoreDeadline, func() (bool, string) {
			code, _, err := compose.PlainGet(dexURL + discoveryPath)
			return err == nil && code == http.StatusOK, fmt.Sprintf("dex discovery: status %d err %v", code, err)
		}); err != nil {
			t.Errorf("restore Dex: %v", err)
			return
		}
		// Back to the normal identity CP config, no break-glass.
		if err := recreateCP(t, nil, devEnvList(t)); err != nil {
			t.Errorf("restore the CP: %v", err)
			return
		}
		if err := waitStackReady(); err != nil {
			t.Errorf("restore the stack: %v", err)
		}
	})

	before := policyETag(t)

	if err := docker("stop", "-t", "5", dex); err != nil {
		t.Fatal(err)
	}
	if err := recreateCP(t, []string{override}, devEnvList(t, breakGlassHashEnv+"="+hash)); err != nil {
		t.Fatalf("restart the CP with break-glass: %v", err)
	}
	cp := serviceContainer(t, compose.SvcCP)
	if err := waitCPHealthy(); err != nil {
		t.Fatalf("the CP did not come back with Dex down: %v", err)
	}

	// The worker is still served: /policy answers with the same ETag.
	if after := policyETag(t); after != before {
		t.Errorf("policy ETag changed across the restart: %q -> %q", before, after)
	}
	code, body := bearerGet(t, "/auth/login")
	var login struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &login)
	if code != http.StatusServiceUnavailable || login.Error != "idp_unavailable" {
		t.Errorf("GET /auth/login with Dex down: status %d error %q, want 503 idp_unavailable", code, login.Error)
	}

	// Break-glass login over the published TLS port, trusting the lab CA.
	op, err := newBrowser()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	cs := &consoleSession{client: op}
	if code, body := breakGlassPost(t, cs, breakGlassUser, password); code != http.StatusOK {
		t.Fatalf("POST /auth/breakglass: status %d, want 200 (body %.200s)", code, body)
	}
	code, body = cs.mustDo(t, http.MethodGet, "/auth/me", nil, false)
	var me struct {
		Role       string `json:"role"`
		AuthMethod string `json:"authMethod"`
		CSRF       string `json:"csrf"`
	}
	if err := json.Unmarshal(body, &me); err != nil || code != http.StatusOK {
		t.Fatalf("GET /auth/me: status %d, decode error %v", code, err)
	}
	if me.AuthMethod != "breakglass" || me.Role != "admin" {
		t.Errorf("/auth/me: authMethod %q role %q, want breakglass admin", me.AuthMethod, me.Role)
	}
	cs.csrf = me.CSRF

	// The worker re-registers with the restarted CP and keeps heartbeating
	// while Dex is down, on the same policy version.
	var first workerRow
	if err := compose.PollUntil(compose.StackDeadline, func() (bool, string) {
		w, ok := worker1(t, cs)
		first = w
		return ok && w.Online && w.PolicyETag == strings.Trim(before, `"`), fmt.Sprintf("worker-1 row %+v (found %v), want online on ETag %s", w, ok, strings.Trim(before, `"`))
	}); err != nil {
		t.Errorf("worker-1 after the CP restart: %v", err)
	}
	if err := compose.PollUntil(compose.StackDeadline, func() (bool, string) {
		w, ok := worker1(t, cs)
		return ok && w.Online && w.LastSeen > first.LastSeen, fmt.Sprintf("worker-1 lastSeen %q, want later than %q", w.LastSeen, first.LastSeen)
	}); err != nil {
		t.Errorf("worker-1 heartbeat: %v", err)
	}

	// One ERROR line so far: the successful login.
	if lines := breakGlassLogLines(t, cp); len(lines) != 1 || !strings.Contains(lines[0], "ok") {
		t.Errorf("after the login the CP log has %d breakglass_login ERROR lines (%q), want exactly 1 with outcome ok", len(lines), lines)
	}
	if n := len(auditRows(t, cs, "ok")); n != 1 {
		t.Errorf("audit rows auth.breakglass outcome ok = %d, want 1", n)
	}

	// A wrong password: 401 and one denied audit row.
	other, err := newBrowser()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if code, _ := breakGlassPost(t, &consoleSession{client: other}, breakGlassUser, perRunPassword(t)); code != http.StatusUnauthorized {
		t.Errorf("POST /auth/breakglass with a wrong password: status %d, want 401", code)
	}
	if rows := auditRows(t, cs, "denied"); len(rows) != 1 {
		t.Errorf("audit rows auth.breakglass outcome denied = %d, want 1", len(rows))
	}
}

// auditRows lists the auth.breakglass admin-audit rows with the outcome.
func auditRows(t testing.TB, cs *consoleSession, outcome string) []string {
	t.Helper()
	code, body := cs.mustDo(t, http.MethodGet, "/dashboard/api/admin-audit?action=auth.breakglass&outcome="+outcome, nil, false)
	if code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/admin-audit: status %d, want 200 (body %.200s)", code, body)
	}
	var out struct {
		Entries []struct {
			Outcome string `json:"outcome"`
			Action  string `json:"action"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("admin audit list is not JSON: %v", err)
	}
	var rows []string
	for _, e := range out.Entries {
		if e.Action == "auth.breakglass" && e.Outcome == outcome {
			rows = append(rows, e.Outcome)
		}
	}
	return rows
}
