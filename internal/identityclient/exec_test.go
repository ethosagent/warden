package identityclient_test

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
)

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestBuildChildEnv(t *testing.T) {
	const proxy = "http://wx:cred@127.0.0.1:4000"
	parent := []string{
		"PATH=/bin", "HOME=/h",
		"ALL_PROXY=http://x", "all_proxy=http://x", "HTTP_PROXY=http://x", "http_proxy=http://x",
		"HTTPS_PROXY=http://user:pw@x", "https_proxy=http://x", "No_Proxy=other",
		"WARDEN_IDENTITY_ISSUER=https://idp", "WARDEN_IDENTITY_CLIENT_SECRET_VAR=s",
		"SSL_CERT_FILE=/old",
	}

	t.Run("inherited proxy and identity variables are removed", func(t *testing.T) {
		env, _ := identityclient.BuildChildEnv(parent, proxy, identityclient.ChildEnvOptions{})
		m := envMap(env)
		for _, k := range []string{"ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "No_Proxy", "WARDEN_IDENTITY_ISSUER", "WARDEN_IDENTITY_CLIENT_SECRET_VAR"} {
			if _, ok := m[k]; ok {
				t.Errorf("%s survived", k)
			}
		}
		if m["PATH"] != "/bin" || m["HOME"] != "/h" || m["SSL_CERT_FILE"] != "/old" {
			t.Errorf("unrelated variables changed: %v", m)
		}
		if m["HTTPS_PROXY"] != proxy || m["https_proxy"] != proxy {
			t.Errorf("HTTPS_PROXY = %q, https_proxy = %q", m["HTTPS_PROXY"], m["https_proxy"])
		}
		for _, k := range []string{"NO_PROXY", "no_proxy"} {
			if m[k] != "localhost,127.0.0.1,::1" {
				t.Errorf("%s = %q", k, m[k])
			}
		}
		if n := strings.Count(strings.Join(env, "\n"), "HTTPS_PROXY="); n != 1 {
			t.Errorf("HTTPS_PROXY appears %d times", n)
		}
	})

	t.Run("override warning is emitted without the old value", func(t *testing.T) {
		_, warns := identityclient.BuildChildEnv(parent, proxy, identityclient.ChildEnvOptions{})
		if len(warns) != 1 || !strings.Contains(warns[0], "HTTPS_PROXY") {
			t.Fatalf("warnings = %q", warns)
		}
		if strings.Contains(warns[0], "pw") {
			t.Errorf("warning leaks the inherited value: %q", warns[0])
		}
		_, warns = identityclient.BuildChildEnv([]string{"PATH=/bin"}, proxy, identityclient.ChildEnvOptions{})
		if len(warns) != 0 {
			t.Errorf("warning without an inherited HTTPS_PROXY: %q", warns)
		}
	})

	t.Run("HTTP_PROXY only with include-http", func(t *testing.T) {
		env, _ := identityclient.BuildChildEnv(parent, proxy, identityclient.ChildEnvOptions{IncludeHTTP: true})
		m := envMap(env)
		if m["HTTP_PROXY"] != proxy || m["http_proxy"] != proxy {
			t.Errorf("HTTP_PROXY = %q, http_proxy = %q", m["HTTP_PROXY"], m["http_proxy"])
		}
		if _, ok := m["ALL_PROXY"]; ok {
			t.Error("ALL_PROXY survived")
		}
	})

	t.Run("CA variables with ca", func(t *testing.T) {
		env, _ := identityclient.BuildChildEnv(parent, proxy, identityclient.ChildEnvOptions{CA: "/ca.pem"})
		m := envMap(env)
		for _, v := range identityclient.CAVars("/ca.pem") {
			if m[v.Name] != "/ca.pem" {
				t.Errorf("%s = %q", v.Name, m[v.Name])
			}
		}
		if n := strings.Count(strings.Join(env, "\n"), "SSL_CERT_FILE="); n != 1 {
			t.Errorf("SSL_CERT_FILE appears %d times", n)
		}
	})
}

func TestProxyCredentialAndURL(t *testing.T) {
	a, err := identityclient.NewProxyCredential(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := identityclient.NewProxyCredential(nil)
	if len(a) != 32 || a == b {
		t.Errorf("credentials %q %q: want 128 distinct random bits", a, b)
	}
	if _, err := identityclient.NewProxyCredential(strings.NewReader("short")); err == nil {
		t.Error("a short random source was accepted")
	}
	u := identityclient.LoopbackProxyURL(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4000}, a)
	if u != "http://wx:"+a+"@127.0.0.1:4000" {
		t.Errorf("url = %q", u)
	}
}

// fakeProc is a child that records the signals it receives and exits on demand.
type fakeProc struct {
	mu       sync.Mutex
	got      []os.Signal
	exit     chan struct{}
	code     int
	killedBy os.Signal
}

func newFakeProc() *fakeProc { return &fakeProc{exit: make(chan struct{})} }

func (p *fakeProc) Signal(s os.Signal) error {
	p.mu.Lock()
	p.got = append(p.got, s)
	p.mu.Unlock()
	return nil
}

func (p *fakeProc) Wait() (int, os.Signal, error) {
	<-p.exit
	return p.code, p.killedBy, nil
}

func (p *fakeProc) signals() []os.Signal {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]os.Signal(nil), p.got...)
}

// sentinelSeen is true once the forwarded list has the signals that were
// expected to pass plus the SIGTERM sentinel.
func sentinelSeen(p *fakeProc, send []os.Signal) bool {
	want := 1
	for _, s := range send {
		if s == syscall.SIGTERM || s == syscall.SIGHUP {
			want++
		}
	}
	return len(p.signals()) >= want
}

func TestExecSignals(t *testing.T) {
	run := func(t *testing.T, terminal bool, send ...os.Signal) []os.Signal {
		t.Helper()
		p := newFakeProc()
		ch := make(chan os.Signal, len(send))
		done := make(chan int, 1)
		go func() {
			code, err := identityclient.Run(context.Background(), identityclient.ExecSpec{
				Start: func() (identityclient.Process, error) { return p, nil }, Signals: ch, StdinIsTerminal: terminal,
			})
			if err != nil {
				t.Error(err)
			}
			done <- code
		}()
		// Signals are handled in order: once the trailing SIGTERM sentinel is
		// forwarded, every earlier signal has been decided.
		for _, s := range append(send, syscall.SIGTERM) {
			ch <- s
		}
		deadline := time.Now().Add(5 * time.Second)
		for len(p.signals()) == 0 || p.signals()[len(p.signals())-1] != syscall.SIGTERM || !sentinelSeen(p, send) {
			if time.Now().After(deadline) {
				t.Fatal("signals not consumed")
			}
			time.Sleep(time.Millisecond)
		}
		close(p.exit)
		<-done
		got := p.signals()
		return got[:len(got)-1]
	}

	t.Run("SIGTERM and SIGHUP are forwarded", func(t *testing.T) {
		for _, term := range []bool{false, true} {
			got := run(t, term, syscall.SIGTERM, syscall.SIGHUP)
			if !reflect.DeepEqual(got, []os.Signal{syscall.SIGTERM, syscall.SIGHUP}) {
				t.Errorf("terminal=%v forwarded %v", term, got)
			}
		}
	})
	t.Run("SIGINT and SIGQUIT only without a terminal", func(t *testing.T) {
		if got := run(t, false, syscall.SIGINT, syscall.SIGQUIT); len(got) != 2 {
			t.Errorf("no terminal: forwarded %v", got)
		}
		if got := run(t, true, syscall.SIGINT, syscall.SIGQUIT); len(got) != 0 {
			t.Errorf("terminal: forwarded %v", got)
		}
	})
	t.Run("other signals are not forwarded", func(t *testing.T) {
		if got := run(t, false, syscall.SIGUSR1); len(got) != 0 {
			t.Errorf("forwarded %v", got)
		}
	})
}

func TestExecExitCodes(t *testing.T) {
	cases := []struct {
		name string
		p    *fakeProc
		want int
	}{
		{"exit code", &fakeProc{exit: make(chan struct{}), code: 7}, 7},
		{"zero", &fakeProc{exit: make(chan struct{})}, 0},
		{"killed by SIGTERM", &fakeProc{exit: make(chan struct{}), code: -1, killedBy: syscall.SIGTERM}, 143},
		{"killed by SIGKILL", &fakeProc{exit: make(chan struct{}), code: -1, killedBy: syscall.SIGKILL}, 137},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			close(tc.p.exit)
			code, err := identityclient.Run(context.Background(), identityclient.ExecSpec{
				Start: func() (identityclient.Process, error) { return tc.p, nil },
			})
			if err != nil || code != tc.want {
				t.Errorf("code = %d, err = %v; want %d", code, err, tc.want)
			}
		})
	}
	t.Run("start failure", func(t *testing.T) {
		_, err := identityclient.Run(context.Background(), identityclient.ExecSpec{
			Start: func() (identityclient.Process, error) { return nil, errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("err = %v", err)
		}
	})
}

// TestExecClosedSignalChannel checks that a closed channel and a nil channel
// both leave Run waiting for the child alone and returning its code. A busy
// loop on a closed channel is not observable as a failure here; the guard is
// the `ok` check in Run.
func TestExecClosedSignalChannel(t *testing.T) {
	closed := make(chan os.Signal)
	close(closed)
	for name, ch := range map[string]<-chan os.Signal{"closed": closed, "nil": nil} {
		t.Run(name, func(t *testing.T) {
			p := newFakeProc()
			p.code = 5
			go func() {
				time.Sleep(20 * time.Millisecond)
				close(p.exit)
			}()
			code, err := identityclient.Run(context.Background(), identityclient.ExecSpec{
				Start: func() (identityclient.Process, error) { return p, nil }, Signals: ch,
			})
			if err != nil || code != 5 {
				t.Errorf("code = %d, err = %v", code, err)
			}
		})
	}
}
