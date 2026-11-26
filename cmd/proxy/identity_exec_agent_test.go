package main

import (
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/ethosagent/warden/internal/identityclient"
)

// agentExecArgs are the flags that point exec at the rig's agent and worker.
func agentExecArgs(a *agentRigCmd, worker string, extra ...string) []string {
	return append([]string{"--agent-key-file", a.keyFile, "--subject-token-file", a.subjectFile, "--worker", worker}, extra...)
}

func TestIdentityExecAgentToken(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a := newAgentCmdRig(t)
	if _, _, err := a.enroll(t); err != nil {
		t.Fatal(err)
	}
	pemKey, err := os.ReadFile(a.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	w := newRecordingWorker(t)
	args := append(agentExecArgs(a, w.ln.Addr().String(), "--ca", "/etc/ssl/certs/ca.pem"), "--", self, "-test.run=NONE", "arg-one")
	res := a.runExec("env-connect", nil, args...)
	if res.err != nil {
		t.Fatalf("exec: %v\n%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "STATUS HTTP/1.1 200") {
		t.Fatalf("child output = %q", res.stdout)
	}
	heads := w.Heads()
	if len(heads) != 1 {
		t.Fatalf("worker saw %d CONNECTs, want 1", len(heads))
	}
	auth := headerOf(heads[0], "Proxy-Authorization")
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil || !strings.HasPrefix(string(raw), "session:eyJ") {
		t.Fatalf("worker auth = %q (%v), want session:<Warden token>", raw, err)
	}
	token := strings.TrimPrefix(string(raw), "session:")
	if a.cp.calls.Load() != 1 {
		t.Errorf("%d exchanges, want 1", a.cp.calls.Load())
	}
	// Neither token, the subject, the key nor any path to them reaches the
	// child's env or argv (the helper printed both), or stderr.
	body := token[strings.Index(token, ".")+1:]
	leaks := []string{token, a.subject, a.keyFile, a.subjectFile, wardenSecretMarker, "WARDEN_IDENTITY_", identityclient.EnvAgentID}
	leaks = append(leaks, secretWindows("pem body", string(pemKey), 16)...)
	leaks = append(leaks, secretWindows("token", token, 16)...)
	leaks = append(leaks, secretWindows("token", a.subject, 16)...)
	leaks = append(leaks, body)
	for _, secret := range leaks {
		if strings.Contains(res.stdout, secret) || strings.Contains(res.stderr, secret) {
			t.Errorf("a secret reached the child or stderr: %.12q", secret)
		}
	}
	for _, want := range []string{"ENV HTTPS_PROXY=http://wx:", "ARG arg-one", "ENV SSL_CERT_FILE=/etc/ssl/certs/ca.pem"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("child output lacks %q", want)
		}
	}
	// The forwarder's credential, not the token, is what the child holds.
	if strings.Contains(res.stdout, "session:") {
		t.Error("the child saw the session user")
	}
}

func TestIdentityExecAgentRefusals(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	touch, err := exec.LookPath("touch")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("exchange denied exits 4 and the child never starts", func(t *testing.T) {
		a := newAgentCmdRig(t)
		if _, _, err := a.enroll(t); err != nil {
			t.Fatal(err)
		}
		a.cp.status.Store(401)
		a.cp.code.Store("invalid_client")
		marker := filepath.Join(t.TempDir(), "started")
		res := a.runExec("env", nil, append(agentExecArgs(a, "127.0.0.1:9"), "--", touch, marker)...)
		if got := exitCode(res.err); res.err == nil || got != 4 {
			t.Fatalf("exit = %d (%v), want 4", got, res.err)
		}
		if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the child ran: stat err = %v", err)
		}
		if res.stdout != "" || strings.Contains(res.stderr+res.err.Error(), "CP-DESC-MARKER") {
			t.Errorf("stdout %q, stderr %q: want nothing from the child and no control plane text", res.stdout, res.stderr)
		}
		if a.cp.calls.Load() != 1 {
			t.Errorf("%d exchanges, want 1 (a denial is not retried)", a.cp.calls.Load())
		}
	})

	t.Run("no login and no terminal exits 2 without starting the child", func(t *testing.T) {
		p := newIdP(t)
		a := newAgentCmdRig(t)
		a.env[identityclient.EnvIssuer] = p.srv.URL
		if _, _, err := a.enroll(t); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(t.TempDir(), "started")
		// The login cache is the subject: no --subject-token-file, and no login.
		res := a.runExec("env", nil, "--agent-key-file", a.keyFile, "--worker", "127.0.0.1:9", "--", touch, marker)
		if got := exitCode(res.err); res.err == nil || got != 2 {
			t.Fatalf("exit = %d (%v), want 2", got, res.err)
		}
		if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the child ran: stat err = %v", err)
		}
	})

	t.Run("a sign-in challenge flag is refused with an agent", func(t *testing.T) {
		a := newAgentCmdRig(t)
		res := a.runExec("env", nil, append(agentExecArgs(a, "127.0.0.1:9", "--challenge"), "--", self)...)
		if res.err == nil || !strings.Contains(res.err.Error(), "--agent-id cannot be combined") {
			t.Fatalf("err = %v", res.err)
		}
		if a.cp.calls.Load() != 0 {
			t.Error("an exchange was attempted")
		}
	})
}

func TestIdentityExecRunAsRefusals(t *testing.T) {
	touch, err := exec.LookPath("touch")
	if err != nil {
		t.Fatal(err)
	}
	notRoot := func() int { return 1000 }

	for _, tc := range []struct{ name, spec, want string }{
		{"not root", "65534:65534", "needs exec to run as root"},
		{"root uid", "0:65534", "must not be 0"},
		{"root gid", "65534:0", "must not be 0"},
		{"no gid", "65534", "want uid:gid"},
		{"names", "nobody:nogroup", "decimal number"},
		{"too many", "1:2:3", "want uid:gid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgentCmdRig(t)
			if _, _, err := a.enroll(t); err != nil {
				t.Fatal(err)
			}
			a.euid = notRoot
			if tc.name != "not root" {
				a.euid = func() int { return 0 }
			}
			marker := filepath.Join(t.TempDir(), "started")
			res := a.runExec("env", nil, append(agentExecArgs(a, "127.0.0.1:9", "--run-as", tc.spec), "--", touch, marker)...)
			if res.err == nil || !strings.Contains(res.err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", res.err, tc.want)
			}
			if exitCode(res.err) == 0 {
				t.Error("exit code 0")
			}
			if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the child ran: stat err = %v", err)
			}
			if a.cp.calls.Load() != 0 {
				t.Error("an exchange happened before the refusal")
			}
		})
	}

	t.Run("a failed credential change fails closed", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Log("running as root: the real run-as test below covers the privileged path")
			return
		}
		// exec believes it is root but the kernel refuses setgroups/setuid: the
		// start fails and no child runs, not even as the unprivileged parent.
		a := newAgentCmdRig(t)
		if _, _, err := a.enroll(t); err != nil {
			t.Fatal(err)
		}
		a.euid = func() int { return 0 }
		marker := filepath.Join(t.TempDir(), "started")
		res := a.runExec("env", nil, append(agentExecArgs(a, "127.0.0.1:9", "--run-as", "65534:65534"), "--", touch, marker)...)
		if res.err == nil || !errors.Is(res.err, syscall.EPERM) {
			t.Fatalf("err = %v, want EPERM from the credential change", res.err)
		}
		if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the child ran after a failed credential change: stat err = %v", err)
		}
	})
}

// TestIdentityExecRunAs runs the real thing when the test itself runs as root:
// the child has the requested uid and gid, no groups, cannot open the agent
// key, the subject file or a 0600 file, still reaches the worker through the
// forwarder with the Warden token, and does not inherit HOME, USER, LOGNAME or
// SHELL. Without root it only logs; with WARDEN_TEST_REQUIRE_ROOT=1 it fails
// instead, so a root run cannot pass by doing nothing:
//
//	go test -race -c -o /tmp/proxy.test ./cmd/proxy && sudo -n env WARDEN_TEST_REQUIRE_ROOT=1 /tmp/proxy.test -test.run '^TestIdentityExecRunAs$' -test.v
func TestIdentityExecRunAs(t *testing.T) {
	if v, _ := os.LookupEnv("WARDEN_TEST_REQUIRE_ROOT"); v == "1" && (os.Geteuid() != 0 || !identityclient.RunAsSupported) {
		t.Fatal("WARDEN_TEST_REQUIRE_ROOT=1 but this test is not running as root on Linux")
	}
	if os.Geteuid() != 0 || !identityclient.RunAsSupported {
		t.Log("not root on Linux: the privileged child is not started here; refusals are covered by TestIdentityExecRunAsRefusals")
		return
	}
	const uid, gid = 65534, 65533
	// The child must be able to reach and run the test binary and nothing else
	// of the rig: a 0755 directory holds the binary and one readable control
	// file; the key and cache stay where exec made them (0600 files).
	pub, err := os.MkdirTemp("", "runas-pub-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pub) })
	if err := os.Chmod(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(pub, "child")
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.OpenFile(bin, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	_ = src.Close()
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(pub, "control.txt")
	if err := os.WriteFile(control, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := newAgentCmdRig(t)
	// Key and subject in the world-traversable directory: only the file mode
	// protects them from the child.
	keyDir := filepath.Join(pub, "agents")
	a.keyFile = filepath.Join(keyDir, "agent-1.key")
	if _, _, err := a.enroll(t); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyDir, 0o755); err != nil { // loosen the directory so only the file mode is tested
		t.Fatal(err)
	}
	a.subjectFile = filepath.Join(pub, "subject")
	if err := os.WriteFile(a.subjectFile, []byte(a.subject+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loginCache := filepath.Join(pub, "cache.json")
	if err := os.WriteFile(loginCache, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := newRecordingWorker(t)
	a.parent = map[string]string{"HOME": "/root", "USER": "root", "LOGNAME": "root", "SHELL": "/bin/sh"}
	res := a.runExec("run-as", nil, append(agentExecArgs(a, w.ln.Addr().String(), "--run-as", strconv.Itoa(uid)+":"+strconv.Itoa(gid)),
		"--", bin, "-test.run=NONE", a.keyFile, a.subjectFile, loginCache, control)...)
	if res.err != nil {
		t.Fatalf("exec: %v\n%s", res.err, res.stderr)
	}
	// The child still reaches the worker through the forwarder, which adds the
	// Warden token; the account variables of the parent are gone.
	if !strings.Contains(res.stdout, "STATUS HTTP/1.1 200") {
		t.Errorf("the run-as child could not CONNECT through the forwarder:\n%s\n%s", res.stdout, res.stderr)
	}
	if heads := w.Heads(); len(heads) != 1 {
		t.Errorf("worker saw %d CONNECTs, want 1", len(heads))
	} else if raw, derr := base64.StdEncoding.DecodeString(strings.TrimPrefix(headerOf(heads[0], "Proxy-Authorization"), "Basic ")); derr != nil || !strings.HasPrefix(string(raw), "session:eyJ") {
		t.Errorf("worker auth = %q (%v), want session:<Warden token>", raw, derr)
	}
	for _, gone := range []string{"ENV HOME=", "ENV USER=", "ENV LOGNAME=", "ENV SHELL="} {
		if strings.Contains(res.stdout, gone) {
			t.Errorf("the run-as child inherited %s", gone)
		}
	}
	for _, want := range []string{
		"IDS uid=65534 euid=65534 gid=65533 egid=65533 groups=[]",
		"OPEN " + control + " ok",
		"OPEN " + a.keyFile + " denied",
		"OPEN " + a.subjectFile + " denied",
		"OPEN " + loginCache + " denied",
	} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("child output lacks %q:\n%s", want, res.stdout)
		}
	}
}

// TestAgentKeyAndCacheAreOwnerOnly pins the file modes that --run-as relies on:
// the key and the login cache are readable by their owner alone, in a
// directory only the owner can enter, so another uid cannot open them.
func TestAgentKeyAndCacheAreOwnerOnly(t *testing.T) {
	p := newIdP(t)
	a := newAgentCmdRig(t)
	a.env[identityclient.EnvIssuer] = p.srv.URL
	if _, _, err := a.enroll(t); err != nil {
		t.Fatal(err)
	}
	a.loggedIn()
	check := func(path string, want fs.FileMode) {
		t.Helper()
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s mode = %04o, want %04o", path, got, want)
		}
	}
	check(a.keyFile, 0o600)
	check(filepath.Dir(a.keyFile), 0o700)
	check(a.cacheDir, 0o700)
	entries, err := os.ReadDir(a.cacheDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("cache dir: %v, %d entries", err, len(entries))
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		st, err := os.Stat(filepath.Join(a.cacheDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("cache file %s mode = %04o, want no group or other access", e.Name(), st.Mode().Perm())
		}
	}
}

// TestIdentityExecRunAsRefusesReachableSecrets: --run-as is refused, before any
// exchange or child, when the run-as identity could read the key, the subject
// file or the cache. The test user's own uid and gid are the target, so no root
// is needed (the effective uid is injected).
func TestIdentityExecRunAsRefusesReachableSecrets(t *testing.T) {
	if os.Getuid() == 0 {
		t.Log("running as root: uid 0 is not a valid --run-as target; TestCheckRunAsAccess covers the rule")
		return
	}
	touch, err := exec.LookPath("touch")
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	for _, tc := range []struct {
		name, spec, want string
		prep             func(a *agentRigCmd)
	}{
		{"key owned by the run-as uid", uid + ":" + gid, "agent key file", nil},
		{"key readable by everyone", "1:2", "readable by everyone", func(a *agentRigCmd) {
			_ = os.Chmod(a.keyFile, 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgentCmdRig(t)
			if _, _, err := a.enroll(t); err != nil {
				t.Fatal(err)
			}
			if tc.prep != nil {
				tc.prep(a)
			}
			a.euid = func() int { return 0 }
			marker := filepath.Join(t.TempDir(), "started")
			res := a.runExec("env", nil, append(agentExecArgs(a, "127.0.0.1:9", "--run-as", tc.spec), "--", touch, marker)...)
			if res.err == nil || !strings.Contains(res.err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", res.err, tc.want)
			}
			if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the child ran: stat err = %v", err)
			}
			if a.cp.calls.Load() != 0 {
				t.Error("an exchange happened before the refusal")
			}
		})
	}
}
