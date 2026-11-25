package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// recordingWorker answers every CONNECT 200 and records each head.
type recordingWorker struct {
	ln    net.Listener
	mu    sync.Mutex
	heads []string
}

func newRecordingWorker(t *testing.T) *recordingWorker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &recordingWorker{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				var head strings.Builder
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					head.WriteString(l)
					if l == "\r\n" {
						break
					}
				}
				w.mu.Lock()
				w.heads = append(w.heads, head.String())
				w.mu.Unlock()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				_, _ = io.Copy(c, br)
			}()
		}
	}()
	return w
}

func (w *recordingWorker) Heads() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.heads...)
}

// runningForward is `warden identity forward` running in the background.
type runningForward struct {
	t      *testing.T
	listen string
	health string
	stderr *syncBuf
	stop   chan os.Signal
	done   chan struct{}
	err    error
	worker *recordingWorker
}

func startForward(t *testing.T, a *agentRigCmd, extra ...string) *runningForward {
	t.Helper()
	worker := newRecordingWorker(t)
	f := &runningForward{t: t, listen: freeAddr(t), health: freeAddr(t), stderr: &syncBuf{}, stop: make(chan os.Signal, 1), done: make(chan struct{})}
	d := a.deps()
	d.signals = func() (<-chan os.Signal, func()) { return f.stop, func() {} }
	root := &cobra.Command{Use: "warden"}
	root.AddCommand(newIdentityCmdWith(d))
	root.SetOut(io.Discard)
	root.SetErr(f.stderr)
	args := []string{"identity", "forward", "--listen", f.listen, "--worker", worker.ln.Addr().String(),
		"--health-listen", f.health, "--agent-key-file", a.keyFile, "--subject-token-file", a.subjectFile}
	root.SetArgs(append(args, extra...))
	go func() { f.err = root.Execute(); close(f.done) }()
	t.Cleanup(func() {
		select {
		case f.stop <- os.Interrupt:
		default:
		}
		select {
		case <-f.done:
		case <-time.After(10 * time.Second):
			t.Error("identity forward did not stop")
		}
	})
	// Wait for the listener.
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", f.listen)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("forwarder never listened; stderr:\n%s", f.stderr)
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.worker = worker
	return f
}

func (f *runningForward) healthz() (int, string) {
	f.t.Helper()
	resp, err := http.Get("http://" + f.health + "/healthz")
	if err != nil {
		f.t.Fatalf("healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct{ State string }
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.State
}

func (f *runningForward) waitHealth(state string) {
	f.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, got := f.healthz(); got == state {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("healthz never reached %s; stderr:\n%s", state, f.stderr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// connect sends a CONNECT through the forwarder and returns the status line
// and header block.
func (f *runningForward) connect(extra string) (net.Conn, string) {
	f.t.Helper()
	c, err := net.Dial("tcp", f.listen)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n"+extra+"\r\n"); err != nil {
		f.t.Fatal(err)
	}
	br := bufio.NewReader(c)
	var head strings.Builder
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			f.t.Fatalf("read head: %v (%q)", err, head.String())
		}
		head.WriteString(l)
		if l == "\r\n" {
			return c, head.String()
		}
	}
}

func headerOf(head, name string) string {
	for _, l := range strings.Split(head, "\r\n") {
		if n, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(n, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func TestIdentityForwardInjectsWardenToken(t *testing.T) {
	a := newAgentCmdRig(t)
	if _, _, err := a.enroll(t); err != nil {
		t.Fatal(err)
	}
	f := startForward(t, a)
	f.waitHealth("valid")
	if code, _ := f.healthz(); code != 200 {
		t.Errorf("healthz status %d, want 200", code)
	}
	c, head := f.connect("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("session:client-own")) + "\r\n")
	if !strings.HasPrefix(head, "HTTP/1.1 200") {
		t.Fatalf("head %q", head)
	}
	_ = c.Close()
	heads := f.worker.Heads()
	if len(heads) != 1 {
		t.Fatalf("worker saw %d CONNECTs", len(heads))
	}
	raw, err := base64.StdEncoding.DecodeString(headerOf(heads[0], "Proxy-Authorization")[len("Basic "):])
	if err != nil || !strings.HasPrefix(string(raw), "session:eyJ") {
		t.Fatalf("worker auth = %q (%v), want session:<Warden token>", raw, err)
	}
	token := strings.TrimPrefix(string(raw), "session:")
	if strings.Contains(heads[0], "client-own") {
		t.Error("the client's own Proxy-Authorization reached the worker")
	}
	if a.cp.calls.Load() != 1 {
		t.Errorf("%d exchanges, want 1", a.cp.calls.Load())
	}
	// Plain methods are refused.
	cc, err := net.Dial("tcp", f.listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	_, _ = io.WriteString(cc, "GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n")
	line, _ := bufio.NewReader(cc).ReadString('\n')
	if !strings.Contains(line, "405") {
		t.Errorf("GET answered %q, want 405", line)
	}

	f.stop <- os.Interrupt
	select {
	case <-f.done:
		if f.err != nil {
			t.Fatalf("identity forward: %v", f.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("identity forward did not stop on SIGINT")
	}
	logs := f.stderr.String()
	for _, secret := range []string{token, a.subject, wardenSecretMarker, "client-own"} {
		if strings.Contains(logs, secret) {
			t.Errorf("stderr contains a secret: %q", secret)
		}
	}
	for _, want := range []string{"forwarder_start", "tunnel_open", "token_rotated", "state=valid"} {
		if !strings.Contains(logs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, logs)
		}
	}
}

func TestIdentityForwardRetriesInsteadOfExiting(t *testing.T) {
	a := newAgentCmdRig(t)
	if _, _, err := a.enroll(t); err != nil {
		t.Fatal(err)
	}
	// The control plane has no signing key yet (503): the forwarder reports
	// cp_unreachable, answers CONNECTs 503 and keeps trying.
	a.cp.status.Store(503)
	f := startForward(t, a)
	f.waitHealth("cp_unreachable")
	if code, _ := f.healthz(); code != 503 {
		t.Errorf("healthz status %d, want 503", code)
	}
	_, head := f.connect("")
	if !strings.HasPrefix(head, "HTTP/1.1 503") || headerOf(head, "X-Warden-Forwarder-Reason") != "cp_unreachable" {
		t.Fatalf("head %q, want 503 cp_unreachable", head)
	}
	if n := len(f.worker.Heads()); n != 0 {
		t.Errorf("worker saw %d CONNECTs with no token", n)
	}
	select {
	case <-f.done:
		t.Fatalf("the forwarder exited during the signer window: %v", f.err)
	default:
	}
	// The key is published: the next exchange succeeds without a restart.
	a.cp.status.Store(0)
	f.waitHealth("valid")
	if c, head := f.connect(""); !strings.HasPrefix(head, "HTTP/1.1 200") {
		t.Fatalf("head %q after recovery", head)
	} else {
		_ = c.Close()
	}
}

func TestIdentityForwardExchangeDenied(t *testing.T) {
	a := newAgentCmdRig(t)
	if _, _, err := a.enroll(t); err != nil {
		t.Fatal(err)
	}
	a.cp.status.Store(401)
	a.cp.code.Store("invalid_client")
	f := startForward(t, a)
	f.waitHealth("exchange_denied")
	_, head := f.connect("")
	if !strings.HasPrefix(head, "HTTP/1.1 503") || headerOf(head, "X-Warden-Forwarder-Reason") != "exchange_denied" {
		t.Fatalf("head %q, want 503 exchange_denied", head)
	}
	logs := f.stderr.String()
	if !strings.Contains(logs, "state=exchange_denied") || strings.Count(logs, "state=exchange_denied") != 1 {
		t.Errorf("exchange_denied must be logged once:\n%s", logs)
	}
	if strings.Contains(logs, "CP-DESC-MARKER") {
		t.Error("the control plane's error text reached the logs")
	}
}

func TestIdentityForwardClientCredential(t *testing.T) {
	a := newAgentCmdRig(t)
	if _, _, err := a.enroll(t); err != nil {
		t.Fatal(err)
	}
	a.env["FWD_CRED"] = "per-run-secret-value"
	f := startForward(t, a, "--client-credential-env", "FWD_CRED")
	f.waitHealth("valid")
	if _, head := f.connect(""); !strings.HasPrefix(head, "HTTP/1.1 407") {
		t.Fatalf("no credential: head %q, want 407", head)
	}
	good := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("wx:per-run-secret-value")) + "\r\n"
	c, head := f.connect(good)
	if !strings.HasPrefix(head, "HTTP/1.1 200") {
		t.Fatalf("with the credential: head %q", head)
	}
	_ = c.Close()
	for _, h := range f.worker.Heads() {
		if strings.Contains(h, "per-run-secret-value") || strings.Contains(h, base64.StdEncoding.EncodeToString([]byte("wx:per-run-secret-value"))) {
			t.Error("the client credential reached the worker")
		}
	}
	if strings.Contains(f.stderr.String(), "per-run-secret-value") {
		t.Error("the client credential reached the logs")
	}
}

func TestIdentityForwardFlagErrors(t *testing.T) {
	a := newAgentCmdRig(t)
	if _, _, err := a.enroll(t); err != nil {
		t.Fatal(err)
	}
	base := []string{"identity", "forward", "--agent-key-file", a.keyFile, "--subject-token-file", a.subjectFile}
	for name, args := range map[string][]string{
		"no listen":      {"--worker", "127.0.0.1:1"},
		"no worker":      {"--listen", "127.0.0.1:0"},
		"bad worker":     {"--listen", "127.0.0.1:0", "--worker", "no-port"},
		"bad listen":     {"--listen", "nope", "--worker", "127.0.0.1:1"},
		"zero tunnels":   {"--listen", "127.0.0.1:0", "--worker", "127.0.0.1:1", "--max-tunnels", "0"},
		"unset cred":     {"--listen", "127.0.0.1:0", "--worker", "127.0.0.1:1", "--client-credential-env", "NOT_SET_ANYWHERE"},
		"missing key":    {"--listen", "127.0.0.1:0", "--worker", "127.0.0.1:1", "--agent-key-file", a.keyFile + ".missing"},
		"extra argument": {"--listen", "127.0.0.1:0", "--worker", "127.0.0.1:1", "stray"},
	} {
		if _, _, err := a.run(append(append([]string{}, base...), args...)...); err == nil {
			t.Errorf("%s: forward started", name)
		}
	}
}
