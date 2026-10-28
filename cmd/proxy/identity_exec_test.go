package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/identityclient"
)

// The child of these tests is this test binary re-executed in helper mode.
const helperEnv = "WARDEN_TEST_EXEC_HELPER"

// TestMain runs the helper child when the binary is re-executed by exec.
func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(execHelper(mode))
	}
	os.Exit(m.Run())
}

// probedEnv are the variables the env helper reports. The child looks each
// one up by name, because rule X3 bans enumerating the environment even in
// tests; the list covers the allowlist, everything exec sets and every
// variable the tests expect to stay behind.
var probedEnv = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TMPDIR", "TZ", "LANG", "LC_ALL", "LC_TIME",
	"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
	"SSL_CERT_FILE", "ANTHROPIC_API_KEY", "EDITOR", "NOT_SET_HERE",
	identityclient.EnvIssuer, identityclient.EnvClientID, identityclient.EnvAudience, identityclient.EnvScopes,
	identityclient.EnvCacheDir, "WARDEN_IDENTITY_TOKEN",
}

// execHelper plays the supervised child.
//
//	env      print the probedEnv variables that are set and argv, one line each
//	wait     print READY and block until killed
//	connect  CONNECT through HTTPS_PROXY the way a client would and print the status line
//	connect-retry  like connect, repeated every 200 ms until the status is 200 (at most 100 tries)
func execHelper(mode string) int {
	switch mode {
	case "env":
		for _, k := range probedEnv {
			if v, ok := os.LookupEnv(k); ok {
				fmt.Println("ENV " + k + "=" + v)
			}
		}
		for _, a := range os.Args {
			fmt.Println("ARG " + a)
		}
	case "wait":
		fmt.Println("READY")
		select {}
	case "connect-retry":
		for range 100 {
			line := connectOnce()
			fmt.Println("STATUS " + line)
			if strings.Contains(line, " 200") {
				return 0
			}
			time.Sleep(200 * time.Millisecond)
		}
		return 1
	case "connect":
		u, err := url.Parse(os.Getenv("HTTPS_PROXY"))
		if err != nil {
			fmt.Println("BAD " + err.Error())
			return 1
		}
		pw, _ := u.User.Password()
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			fmt.Println("BAD " + err.Error())
			return 1
		}
		defer func() { _ = conn.Close() }()
		auth := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pw))
		fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
		line, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Println("STATUS " + strings.TrimSpace(line))
	}
	return 0
}

// connectOnce CONNECTs through HTTPS_PROXY and returns the status line.
func connectOnce() string {
	u, err := url.Parse(os.Getenv("HTTPS_PROXY"))
	if err != nil {
		return "BAD " + err.Error()
	}
	pw, _ := u.User.Password()
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		return "BAD " + err.Error()
	}
	defer func() { _ = conn.Close() }()
	auth := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pw))
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(line)
}

// syncBuf is a bytes.Buffer safe for the copier goroutine and the test.
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

// execResult is one `identity exec` run.
type execResult struct {
	stdout, stderr string
	err            error
}

// runExec runs `warden identity exec <args>`; the child is the helper in mode.
// It returns after the command ends.
func (r *rig) runExec(mode string, sigs chan os.Signal, args ...string) execResult {
	r.t.Helper()
	wait, _ := r.startExec(mode, sigs, nil, args...)
	return wait()
}

// startExec starts the command in the background; the returned func waits for
// it. out receives the child's stdout while it runs.
func (r *rig) startExec(mode string, sigs chan os.Signal, out *syncBuf, args ...string) (func() execResult, *syncBuf) {
	r.t.Helper()
	d := r.deps()
	// The parent holds the identity settings too, so the tests see that
	// WARDEN_IDENTITY_* stays behind. The helper mode reaches the child only
	// through --env, which every run passes.
	parent := map[string]string{"PATH": os.Getenv("PATH"), helperEnv: mode}
	for k, v := range r.env {
		parent[k] = v
	}
	for k, v := range r.parent {
		parent[k] = v
	}
	d.lookupEnv = func(k string) (string, bool) {
		v, ok := parent[k]
		return v, ok
	}
	if sigs != nil {
		d.signals = func() (<-chan os.Signal, func()) { return sigs, func() {} }
	}
	if out == nil {
		out = &syncBuf{}
	}
	d.tune = nil
	root := &cobra.Command{Use: "warden"}
	root.AddCommand(newIdentityCmdWith(d))
	var errb syncBuf
	root.SetOut(out)
	root.SetErr(&errb)
	root.SetArgs(append([]string{"identity", "exec", "--env", helperEnv}, args...))
	ch := make(chan error, 1)
	go func() { ch <- root.Execute() }()
	return func() execResult {
		err := <-ch
		return execResult{out.String(), errb.String(), err}
	}, out
}

func TestIdentityExec(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := newIdP(t)

	t.Run("child env and argv hold the loopback proxy and no token", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		e := r.loggedIn()
		res := r.runExec("env", nil, "--worker", "127.0.0.1:9", "--", self, "-test.run=NONE", "arg-one")
		if res.err != nil {
			t.Fatalf("exec: %v\n%s", res.err, res.stderr)
		}
		var proxy string
		for _, l := range strings.Split(res.stdout, "\n") {
			if v, ok := strings.CutPrefix(l, "ENV HTTPS_PROXY="); ok {
				proxy = v
			}
		}
		u, perr := url.Parse(proxy)
		if perr != nil || u.User.Username() != "wx" || u.Hostname() != "127.0.0.1" || u.Port() == "" {
			t.Fatalf("HTTPS_PROXY = %q", proxy)
		}
		cred, _ := u.User.Password()
		if len(cred) != 32 {
			t.Errorf("credential = %q, want 32 hex characters (128 bits)", cred)
		}
		for _, want := range []string{"ENV https_proxy=" + proxy, "ENV NO_PROXY=localhost,127.0.0.1,::1", "ARG arg-one"} {
			if !strings.Contains(res.stdout, want) {
				t.Errorf("child output lacks %q", want)
			}
		}
		for _, secret := range []string{e.IDToken, e.RefreshToken, testRefresh, testAccess, testDeviceCode} {
			if strings.Contains(res.stdout, secret) || strings.Contains(res.stderr, secret) {
				t.Errorf("a token or secret reached the child or stderr: %.12s", secret)
			}
		}
		if strings.Contains(res.stdout, "WARDEN_IDENTITY_") {
			t.Error("WARDEN_IDENTITY_* reached the child")
		}
	})

	t.Run("only allowlisted variables reach the child unless named with --env", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		r.loggedIn()
		r.parent = map[string]string{
			"HOME": "/home/u", "LANG": "C.UTF-8", "LC_TIME": "C", "TERM": "xterm",
			"ANTHROPIC_API_KEY": "sk-test-key", "EDITOR": "vi",
			"HTTPS_PROXY": "http://user:pw@corp:3128", "WARDEN_IDENTITY_TOKEN": "parent-token",
		}
		res := r.runExec("env", nil, "--worker", "127.0.0.1:9", "--", self, "-test.run=NONE")
		if res.err != nil {
			t.Fatalf("exec: %v\n%s", res.err, res.stderr)
		}
		for _, want := range []string{"ENV HOME=/home/u", "ENV LANG=C.UTF-8", "ENV LC_TIME=C", "ENV TERM=xterm", "ENV PATH="} {
			if !strings.Contains(res.stdout, want) {
				t.Errorf("child output lacks %q", want)
			}
		}
		for _, gone := range []string{"ANTHROPIC_API_KEY", "EDITOR", "corp:3128", "WARDEN_IDENTITY_", "parent-token"} {
			if strings.Contains(res.stdout, gone) {
				t.Errorf("%s reached the child without --env", gone)
			}
		}
		if !strings.Contains(res.stderr, "HTTPS_PROXY was replaced") || strings.Contains(res.stderr, "pw@corp") {
			t.Errorf("stderr = %q, want the override warning without the old value", res.stderr)
		}

		res = r.runExec("env", nil, "--worker", "127.0.0.1:9", "--env", "ANTHROPIC_API_KEY", "--env", "NOT_SET_HERE", "--", self, "-test.run=NONE")
		if res.err != nil {
			t.Fatalf("exec --env: %v\n%s", res.err, res.stderr)
		}
		if !strings.Contains(res.stdout, "ENV ANTHROPIC_API_KEY=sk-test-key") {
			t.Error("--env ANTHROPIC_API_KEY did not reach the child")
		}
		if strings.Contains(res.stdout, "EDITOR") || strings.Contains(res.stdout, "NOT_SET_HERE") {
			t.Error("an unnamed or unset variable reached the child")
		}
		if !strings.Contains(res.stderr, "NOT_SET_HERE") {
			t.Errorf("stderr = %q, want a warning for the unset --env NOT_SET_HERE", res.stderr)
		}
	})

	t.Run("--env refuses proxy, identity and invalid names before any child starts", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		r.loggedIn()
		r.parent = map[string]string{"HTTPS_PROXY": "http://x", "WARDEN_IDENTITY_TOKEN": "parent-token"}
		marker := filepath.Join(t.TempDir(), "started")
		for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "WARDEN_IDENTITY_TOKEN", "warden_identity_cache_dir", "KEY=value", "1BAD", ""} {
			res := r.runExec("env", nil, "--worker", "127.0.0.1:9", "--env", name, "--", "touch", marker)
			if res.err == nil || !strings.Contains(res.err.Error(), "--env") {
				t.Errorf("--env %q: err = %v", name, res.err)
			}
		}
		if _, err := os.Stat(marker); err == nil {
			t.Error("the child started")
		}
	})

	t.Run("a non-loopback listen is refused before any child starts", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		r.loggedIn()
		marker := filepath.Join(t.TempDir(), "started")
		for _, listen := range []string{"0.0.0.0:0", "192.0.2.1:0", "[::]:0", "example.com:0"} {
			res := r.runExec("env", nil, "--worker", "127.0.0.1:9", "--listen", listen, "--", "touch", marker)
			if res.err == nil || !strings.Contains(res.err.Error(), "loopback") {
				t.Errorf("--listen %s: err = %v", listen, res.err)
			}
		}
		if _, err := os.Stat(marker); err == nil {
			t.Error("the child started")
		}
	})

	t.Run("the child's exit code is the exit code", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		r.loggedIn()
		res := r.runExec("env", nil, "--worker", "127.0.0.1:9", "--", "sh", "-c", "exit 7")
		if exitCode(res.err) != 7 {
			t.Errorf("exit = %d (%v), want 7", exitCode(res.err), res.err)
		}
		res = r.runExec("env", nil, "--worker", "127.0.0.1:9", "--", "true")
		if res.err != nil {
			t.Errorf("exit 0 returned %v", res.err)
		}
	})

	t.Run("a child killed by SIGTERM exits 143", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		r.loggedIn()
		sigs := make(chan os.Signal, 1)
		wait, out := r.startExec("wait", sigs, nil, "--worker", "127.0.0.1:9", "--", self, "-test.run=NONE")
		waitFor(t, func() bool { return strings.Contains(out.String(), "READY") })
		sigs <- syscall.SIGTERM
		res := wait()
		if exitCode(res.err) != 143 {
			t.Errorf("exit = %d (%v), want 143", exitCode(res.err), res.err)
		}
	})

	t.Run("no cached login on a non-terminal exits 2 without starting the child", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		marker := filepath.Join(t.TempDir(), "started")
		res := r.runExec("env", nil, "--worker", "127.0.0.1:9", "--", "touch", marker)
		if exitCode(res.err) != 2 {
			t.Errorf("exit = %d (%v), want 2", exitCode(res.err), res.err)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Error("the child started")
		}
		if strings.Contains(res.stdout, "ENV ") {
			t.Errorf("child output: %q", res.stdout)
		}
	})

	t.Run("a missing command or worker is a usage error", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		if res := r.runExec("env", nil, "--worker", "127.0.0.1:9"); res.err == nil {
			t.Error("exec with no command succeeded")
		}
		if res := r.runExec("env", nil, "--", "true"); res.err == nil {
			t.Error("exec with no --worker succeeded")
		}
		if res := r.runExec("env", nil, "--worker", "no-port", "--", "true"); res.err == nil {
			t.Error("exec with a bad --worker succeeded")
		}
	})

	t.Run("exec takes no token flag", func(t *testing.T) {
		c, _, err := newIdentityCmd().Find([]string{"exec"})
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"token", "token-stdin", "token-file", "id-token"} {
			if c.Flags().Lookup(n) != nil {
				t.Errorf("exec has --%s", n)
			}
		}
	})

	t.Run("the forwarder stops when the child exits", func(t *testing.T) {
		r := newRig(t, p.srv.URL)
		r.loggedIn()
		res := r.runExec("env", nil, "--worker", "127.0.0.1:9", "--", self, "-test.run=NONE")
		var addr string
		for _, l := range strings.Split(res.stdout, "\n") {
			if v, ok := strings.CutPrefix(l, "ENV HTTPS_PROXY="); ok {
				u, _ := url.Parse(v)
				addr = u.Host
			}
		}
		if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			t.Errorf("%s still accepts connections after exec returned", addr)
		}
	})
}

// TestIdentityExecThroughForwarder runs a client child through the loopback
// proxy to a fake worker, which must see the user's token as session:<token>.
func TestIdentityExecThroughForwarder(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := newIdP(t)
	r := newRig(t, p.srv.URL)
	e := r.loggedIn()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	heads := make(chan string, 4)
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
				heads <- head.String()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
			}()
		}
	}()

	res := r.runExec("connect", nil, "--worker", ln.Addr().String(), "--", self, "-test.run=NONE")
	if res.err != nil {
		t.Fatalf("exec: %v\n%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "STATUS HTTP/1.1 200") {
		t.Fatalf("child output = %q", res.stdout)
	}
	head := <-heads
	want := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+e.IDToken))
	if !strings.Contains(head, want) {
		t.Errorf("worker saw %q, want %s", head, want)
	}
	if !strings.HasPrefix(head, "CONNECT example.com:443 ") {
		t.Errorf("worker head = %q", head)
	}
	if strings.Contains(res.stdout+res.stderr, e.IDToken) {
		t.Error("the ID token reached the child's output or stderr")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
