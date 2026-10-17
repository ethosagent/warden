package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/proxy"
)

// The transparent-mode worker wiring (#376): the local-only proxy block must
// reach proxy.Config intact (mode + both listeners), the interception
// listeners must actually serve and report their bound addresses, a failed
// transparent bind must close the harness's injected listeners, and QUIC/ECH
// bypass posture must WARN at startup exactly when the listeners bind.

// transCfg renders a local-only config in the given interception mode from the
// given CA paths (writeTestCA once per test — the caller may need the same CA
// to trust the minted leaves); the transparent listeners bind loopback port 0
// so nothing collides. plain controls proxy.transparent.httpListen.
func transCfg(t *testing.T, mode config.ProxyMode, plain bool) string {
	t.Helper()
	certPath, keyPath := writeTestCA(t)
	return transCfgWithCA(t, mode, plain, certPath, keyPath)
}

// transCfgWithCA is transCfg over caller-owned CA paths.
func transCfgWithCA(t *testing.T, mode config.ProxyMode, plain bool, certPath, keyPath string) string {
	t.Helper()
	cfg := fmt.Sprintf(`
policy:
  allowlist:
    - domain: backend.test
tls:
  caCert: %s
  caKey: %s
proxy:
  mode: %s
  transparent:
    httpsListen: "127.0.0.1:0"
`, certPath, keyPath, mode)
	if plain {
		cfg += `    httpListen: "127.0.0.1:0"
`
	}
	cfg += `
logging:
  level: info
  format: text
`
	return cfg
}

// TestRun_TransparentModeReachesProxy guards the assembly: the parsed proxy
// block must land in proxy.Config (mode + both listeners). Dropping any field
// from the literal silently reverts the worker to forward mode.
func TestRun_TransparentModeReachesProxy(t *testing.T) {
	var got proxy.Config
	orig := newProxy
	newProxy = func(cfg proxy.Config) (*proxy.Proxy, error) {
		got = cfg
		return orig(cfg)
	}
	t.Cleanup(func() { newProxy = orig })

	for _, tc := range []struct {
		name     string
		mode     config.ProxyMode
		plain    bool
		wantMode config.ProxyMode
		wantHTTP bool
	}{
		{"both", config.ProxyModeBoth, true, config.ProxyModeBoth, true},
		{"transparent", config.ProxyModeTransparent, false, config.ProxyModeTransparent, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runUntilCtxDone(t, runParams(t, writeConfig(t, transCfg(t, tc.mode, tc.plain)))); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got.Mode != tc.wantMode {
				t.Errorf("cfg.Mode = %q, want %q", got.Mode, tc.wantMode)
			}
			if got.TransparentHTTPSListen == "" {
				t.Error("cfg.TransparentHTTPSListen is empty; the httpsListen key never reached the proxy")
			}
			if tc.wantHTTP && got.TransparentHTTPListen == "" {
				t.Error("cfg.TransparentHTTPListen is empty; the httpListen key never reached the proxy")
			}
			if !tc.wantHTTP && got.TransparentHTTPListen != "" {
				t.Errorf("cfg.TransparentHTTPListen = %q, want empty (plain HTTP is opt-in)", got.TransparentHTTPListen)
			}
		})
	}
}

// TestRun_TransparentListenersServeAndReport boots a real worker in transparent
// mode and proves the interception listeners exist end to end: OnTransparentReady
// reports the bound addresses before any client dials, an SNI handshake against
// the reported :443 address is terminated by the worker's own CA, and a clean
// ctx shutdown returns nil.
func TestRun_TransparentListenersServeAndReport(t *testing.T) {
	caCertPath, caKeyPath := writeTestCA(t)
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse CA cert")
	}

	p := runParams(t, writeConfig(t, transCfgWithCA(t, config.ProxyModeBoth, true, caCertPath, caKeyPath)))
	ready := make(chan [2]string, 1)
	p.OnTransparentReady = func(httpsAddr, httpAddr string) { ready <- [2]string{httpsAddr, httpAddr} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, io.Discard, p) }()

	var addrs [2]string
	select {
	case addrs = <-ready:
	case err := <-errCh:
		t.Fatalf("Run returned before OnTransparentReady: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnTransparentReady")
	}
	if addrs[0] == "" || addrs[1] == "" {
		t.Fatalf("OnTransparentReady = %q, want both listeners bound", addrs)
	}

	// The reported :443 address terminates TLS: the worker minted a leaf for the
	// SNI name and the handshake verifies against its CA. A worker that dropped
	// the mode (or the listeners) on the floor fails here with a refused dial or
	// a handshake error instead.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addrs[0],
		&tls.Config{ServerName: "backend.test", RootCAs: roots, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("TLS handshake against the reported transparent addr: %v", err)
	}
	_ = conn.Close()

	// Plain HTTP is opt-in but configured here: the reported :80 address answers.
	httpConn, err := net.DialTimeout("tcp", addrs[1], 5*time.Second)
	if err != nil {
		t.Fatalf("dial the reported plain-HTTP addr: %v", err)
	}
	_ = httpConn.Close()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Run to return after cancel")
	}
}

// TestRun_TransparentBindFailureClosesInjectedListeners proves a failed
// transparent bind never leaks the harness's ports: the httpsListen collision
// surfaces as Run's error and both injected listeners come back closed.
func TestRun_TransparentBindFailureClosesInjectedListeners(t *testing.T) {
	// Occupy the port the transparent listener will ask for.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })

	certPath, keyPath := writeTestCA(t)
	cfg := fmt.Sprintf(`
policy:
  allowlist:
    - domain: backend.test
tls:
  caCert: %s
  caKey: %s
proxy:
  mode: transparent
  transparent:
    httpsListen: %s
logging:
  level: warn
  format: text
`, certPath, keyPath, held.Addr().String())

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen admin: %v", err)
	}
	for name, ln := range map[string]net.Listener{"proxy": proxyLn, "admin": adminLn} {
		if tcp, ok := ln.(*net.TCPListener); ok {
			_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))
		} else {
			t.Fatalf("%s listener is not a TCP listener", name)
		}
	}

	p := Params{
		ConfigPath:    writeConfig(t, cfg),
		DBPath:        t.TempDir() + "/warden.db",
		Version:       "test",
		ProxyListener: proxyLn,
		AdminListener: adminLn,
	}
	err = Run(context.Background(), io.Discard, p)
	if err == nil || !strings.Contains(err.Error(), "transparent https listen") {
		t.Fatalf("Run = %v, want the transparent https bind error", err)
	}
	for name, ln := range map[string]net.Listener{"proxy": proxyLn, "admin": adminLn} {
		if _, aerr := ln.Accept(); !errors.Is(aerr, net.ErrClosed) {
			t.Errorf("%s listener Accept after failed boot = %v, want net.ErrClosed (listener leaked)", name, aerr)
		}
	}
}

// TestRun_QuicBypassWarnsInTransparentModes pins the startup WARN: a mode that
// binds the interception listeners says UDP 443 must be blocked or redirected;
// forward mode stays silent (the deployment concern does not exist there).
func TestRun_QuicBypassWarnsInTransparentModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    config.ProxyMode
		wantLog bool
	}{
		{"transparent", config.ProxyModeTransparent, true},
		{"both", config.ProxyModeBoth, true},
		{"forward", config.ProxyModeForward, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg string
			if tc.mode == config.ProxyModeForward {
				cfg = `
policy:
  allowlist:
    - domain: backend.test
logging:
  level: info
  format: text
`
			} else {
				cfg = transCfg(t, tc.mode, false)
			}
			var out syncBuffer
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- Run(ctx, &out, runParams(t, writeConfig(t, cfg))) }()
			if tc.wantLog {
				waitForLog(t, &out, "UDP 443")
			} else {
				waitForLog(t, &out, "proxy listening")
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run returned error on clean shutdown: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after ctx cancel")
			}
			got := out.String()
			if tc.wantLog {
				if !strings.Contains(got, "QUIC") || !strings.Contains(got, "UDP 443") {
					t.Fatalf("transparent-mode boot must WARN about QUIC/ECH bypass; got:\n%s", got)
				}
			} else if strings.Contains(got, "UDP 443") {
				t.Fatalf("forward-mode boot must not warn about QUIC; got:\n%s", got)
			}
		})
	}
}
