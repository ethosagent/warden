//go:build integration

package integration

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/worker"
	"github.com/ethosagent/warden/test/harness"
)

const (
	agentRegAgent    = "claude-code"
	agentRegUpstream = "upstream.agentreg.test"
	agentRegDeadline = 30 * time.Second
)

// TestAgentRegistryKillSwitch proves the agent registry's done-when sentence
// on a real process pair: a control plane (the real binary, with a state dir)
// and a worker bound to claude-code. The agent is registered with the offline
// CLI, traffic flows, the agent is disabled and the worker refuses a new
// CONNECT with 403 agent_disabled and cuts the tunnel that was open, then the
// agent is enabled again and traffic recovers. No JWK coordinate may appear in
// anything the processes or the CLI print.
//
// The control plane and the CLI are the shipped binary. The worker is
// worker.Run in this process, because a shipped worker's SSRF-safe dialer
// rightly refuses the loopback upstream; the assembly-only Overrides.Dialer
// seam maps the fake upstream host to it (the same seam test/security uses).
// Nothing leaves loopback and nothing waits on a fixed sleep: each step polls
// the observable result against a deadline.
func TestAgentRegistryKillSwitch(t *testing.T) {
	bin := buildWarden(t)
	root := t.TempDir()
	logs := &syncBuffer{}

	// A raw-TCP echo upstream on loopback.
	upstream := startEchoUpstream(t)

	// The control plane: HTTPS from a throwaway CA, a state dir (which turns
	// the agent registry on) and a shared worker token.
	ca := harness.NewTestCA(t, "agentreg-integration")
	caCert, caKey := ca.WriteFiles(root, "cp-ca")
	stateDir := filepath.Join(root, "state")
	cpAddr := freeAddr(t)
	cpCfg := filepath.Join(root, "cp.yaml")
	writeFile(t, cpCfg, fmt.Sprintf(`policy:
  allowlist:
    - domain: %s
listen: %s
console:
  adminAudit:
    enabled: true
`, agentRegUpstream, cpAddr))
	const tokenEnv = "WARDEN_AGENTREG_IT_TOKEN"
	const token = "agentreg-integration-shared-token"
	cp := exec.Command(bin, "control-plane", "--config", cpCfg, "--state-dir", stateDir,
		"--listen", cpAddr, "--legacy-token-env", tokenEnv,
		"--ca-cert", caCert, "--ca-key", caKey, "--tls-host", "127.0.0.1")
	cp.Env = append(os.Environ(), tokenEnv+"="+token)
	cp.Stdout, cp.Stderr = logs, logs
	if err := cp.Start(); err != nil {
		t.Fatalf("start control plane: %v", err)
	}
	defer func() {
		_ = cp.Process.Kill()
		_, _ = cp.Process.Wait()
	}()
	waitCPReady(t, cpAddr, ca.Pool())

	// The worker, bound to claude-code (what --agent-id sets). It pulls policy
	// over HTTPS with the shared token.
	t.Setenv(tokenEnv, token)
	w := startBoundWorker(t, root, cpAddr, caCert, upstream, logs)

	// Register the agent with the offline CLI.
	x := newAgentKey(t)
	jwkFile := filepath.Join(root, "agent.jwk.json")
	writeFile(t, jwkFile, fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, x))
	var cliOut strings.Builder
	cliOut.WriteString(runCLI(t, bin, "control-plane", "agent", "register", "--state-dir", stateDir,
		"--id", agentRegAgent, "--display-name", "Claude Code", "--groups", "warden-agents",
		"--jwk-file", jwkFile))

	// The registration must have reached the control plane's served policy
	// (the CLI write is picked up on a poll) before the worker can see it.
	waitServedAgent(t, cpAddr, ca.Pool(), token, agentRegAgent, "active")

	// Traffic flows through the bound worker, and a tunnel stays open.
	waitConnect(t, w.proxyAddr, http.StatusOK, "traffic flows for the registered agent")
	open := openTunnel(t, w.proxyAddr)
	defer func() { _ = open.Close() }()
	echoOnce(t, open, "before")

	// Disable. The worker refuses a new CONNECT with agent_disabled and cuts
	// the open tunnel within a few seconds of the first refusal.
	cliOut.WriteString(runCLI(t, bin, "control-plane", "agent", "disable", "--state-dir", stateDir,
		"--id", agentRegAgent, "--revision", "1"))
	body := waitConnect(t, w.proxyAddr, http.StatusForbidden, "a new CONNECT is refused after the disable")
	if !strings.Contains(body, `"agent_disabled"`) {
		t.Errorf("disabled CONNECT body = %q, want error agent_disabled", body)
	}
	waitTunnelClosed(t, open, 5*time.Second)

	// Enable again: traffic recovers.
	cliOut.WriteString(runCLI(t, bin, "control-plane", "agent", "enable", "--state-dir", stateDir,
		"--id", agentRegAgent, "--revision", "2"))
	waitConnect(t, w.proxyAddr, http.StatusOK, "traffic recovers after the enable")
	again := openTunnel(t, w.proxyAddr)
	defer func() { _ = again.Close() }()
	echoOnce(t, again, "after")

	// The CLI's listings carry key ids and thumbprint prefixes, so the leak
	// scan below has something to find if a coordinate slipped in.
	list := runCLI(t, bin, "control-plane", "agent", "list", "--state-dir", stateDir)
	listJSON := runCLI(t, bin, "control-plane", "agent", "list", "--state-dir", stateDir, "--json")
	var rows []struct {
		Keys []struct {
			KID       string `json:"kid"`
			JKTPrefix string `json:"jktPrefix"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(listJSON), &rows); err != nil || len(rows) != 1 || len(rows[0].Keys) != 1 {
		t.Fatalf("agent list --json = %q (%v), want one agent with one key", listJSON, err)
	}
	kid := rows[0].Keys[0].KID
	if kid == "" || !strings.Contains(list, kid) || !strings.Contains(listJSON, kid) {
		t.Errorf("agent list does not show the key id %q:\n%s", kid, list)
	}
	cliOut.WriteString(list + listJSON)

	// A JWK with a private member is refused naming the field path, and the
	// refusal prints neither member.
	badFile := filepath.Join(root, "bad.jwk.json")
	writeFile(t, badFile, fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"d":%q}`, x, "cHJpdmF0ZS1zZWVkLW5vdC1yZWFs"))
	badOut, badCode := runCLIFail(t, bin, "control-plane", "agent", "register", "--state-dir", stateDir,
		"--id", "bad-agent", "--groups", "warden-agents", "--jwk-file", badFile)
	if badCode != 1 {
		t.Errorf("register with a private member exited %d, want 1:\n%s", badCode, badOut)
	}
	if !strings.Contains(badOut, "keys[0].d") {
		t.Errorf("refusal does not name keys[0].d:\n%s", badOut)
	}
	if strings.Contains(badOut, "cHJpdmF0ZS1zZWVkLW5vdC1yZWFs") || strings.Contains(badOut, x) {
		t.Errorf("refusal echoes key material:\n%s", badOut)
	}
	cliOut.WriteString(badOut)

	// No JWK coordinate in any captured output, and the scan is not vacuous:
	// the worker's own lines about the kill switch are there.
	out := logs.String()
	for _, want := range []string{`"agent":"claude-code"`, `"reason":"agent_disabled"`, "bound agent is disabled in the registry"} {
		if !strings.Contains(out, want) {
			t.Errorf("captured logs lack %s", want)
		}
	}
	all := out + cliOut.String()
	for _, leak := range []string{`"x":`, `"d":`, x} {
		if strings.Contains(all, leak) {
			t.Errorf("captured control-plane, worker or CLI output contains JWK material %q", leak)
		}
	}
}

// waitServedAgent polls the control plane's GET /policy, as a worker does,
// until registeredAgents lists id with status.
func waitServedAgent(t *testing.T, addr string, pool *x509.CertPool, token, id, status string) {
	t.Helper()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	deadline := time.Now().Add(agentRegDeadline)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/policy", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if resp, err := client.Do(req); err == nil {
			var wire struct {
				RegisteredAgents []struct {
					ID     string `json:"id"`
					Status string `json:"status"`
				} `json:"registeredAgents"`
			}
			dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&wire)
			_ = resp.Body.Close()
			if dec == nil {
				for _, a := range wire.RegisteredAgents {
					if a.ID == id && a.Status == status {
						return
					}
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the control plane never served %s as %s within %s", id, status, agentRegDeadline)
}

// runCLIFail runs the CLI expecting a non-zero exit and returns its combined
// output and exit code.
func runCLIFail(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("%s %s: want a non-zero exit, got %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return string(out), ee.ExitCode()
}

// boundWorker is a running in-process worker.
type boundWorker struct{ proxyAddr string }

func startBoundWorker(t *testing.T, root, cpAddr, caCert, upstream string, logs io.Writer) boundWorker {
	t.Helper()
	dir := filepath.Join(root, "worker")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "worker.yaml")
	writeFile(t, cfg, fmt.Sprintf(`logging:
  level: info
  format: json

controlPlane:
  endpoint: https://%s/policy
  caCert: %s
  tokenEnv: WARDEN_AGENTREG_IT_TOKEN
  longPollWait: 5s
  heartbeatInterval: 1s
`, cpAddr, caCert))
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = proxyLn.Close()
		t.Fatal(err)
	}
	ready := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- worker.Run(ctx, logs, worker.Params{
			ConfigPath:    cfg,
			DBPath:        filepath.Join(dir, "analytics.db"),
			AgentID:       agentRegAgent,
			Version:       "integration",
			ProxyListener: proxyLn,
			AdminListener: adminLn,
			OnReady:       func(_, _ string) { close(ready) },
			Overrides:     &worker.Overrides{Dialer: &mapDialer{host: agentRegUpstream, addr: upstream}},
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(agentRegDeadline):
			t.Error("worker did not stop")
		}
	})
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("worker exited before it was ready: %v\n%s", err, logs)
	case <-time.After(agentRegDeadline):
		t.Fatalf("worker not ready within %s", agentRegDeadline)
	}
	return boundWorker{proxyAddr: proxyLn.Addr().String()}
}

// connect sends one CONNECT through the worker and returns the status and the
// response body (empty for a 200).
func rawConnect(addr string) (net.Conn, int, string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, 0, "", err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "CONNECT " + agentRegUpstream + ":443 HTTP/1.1\r\nHost: " + agentRegUpstream + ":443\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, 0, "", err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, 0, "", err
	}
	var body []byte
	if resp.StatusCode != http.StatusOK {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
	}
	_ = resp.Body.Close()
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, resp.StatusCode, string(body), nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// waitConnect polls a CONNECT until it answers want, and returns that body.
func waitConnect(t *testing.T, addr string, want int, what string) string {
	t.Helper()
	deadline := time.Now().Add(agentRegDeadline)
	last := "no answer"
	for time.Now().Before(deadline) {
		conn, status, body, err := rawConnect(addr)
		if err == nil {
			_ = conn.Close()
			if status == want {
				return body
			}
			last = fmt.Sprintf("status %d %s", status, body)
		} else {
			last = err.Error()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: never got %d within %s (last: %s)", what, want, agentRegDeadline, last)
	return ""
}

func openTunnel(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, status, body, err := rawConnect(addr)
	if err != nil || status != http.StatusOK {
		t.Fatalf("open tunnel: status %d err %v body %q", status, err, body)
	}
	return conn
}

func echoOnce(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := io.WriteString(c, msg+"\n"); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != msg {
		t.Fatalf("echo through the tunnel = %q, %v; want %q", line, err, msg)
	}
}

// waitTunnelClosed waits until the worker has cut the open tunnel.
func waitTunnelClosed(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	buf := make([]byte, 64)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, err := c.Read(buf)
		var ne net.Error
		if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
			return // EOF or reset: the worker closed it
		}
	}
	t.Fatalf("the open tunnel was not closed within %s of the first refusal", within)
}

func startEchoUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// waitCPReady polls the control plane's TLS listener until it answers.
func waitCPReady(t *testing.T, addr string, pool *x509.CertPool) {
	t.Helper()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	deadline := time.Now().Add(agentRegDeadline)
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("control plane not ready within %s", agentRegDeadline)
}

// newAgentKey returns the JWK x coordinate of a fresh Ed25519 public key.
func newAgentKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mapDialer routes the one fake upstream host to the loopback echo server. It
// is the assembly-only Overrides.Dialer seam, never a way around the SSRF
// guard in a shipped binary.
type mapDialer struct{ host, addr string }

var _ proxy.Dialer = (*mapDialer)(nil)

func (m *mapDialer) Dial(network, addr string) (net.Conn, error) {
	if h, _, err := net.SplitHostPort(addr); err != nil || h != m.host {
		return nil, fmt.Errorf("integration: no fake upstream for %q", addr)
	}
	return net.Dial(network, m.addr)
}

func (m *mapDialer) DialTLS(string, string, *tls.Config) (*tls.Conn, error) {
	return nil, errors.New("integration: this test tunnels raw TCP only")
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
