package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// cacheWorkerEnv is what a restartable pinned worker needs: a signing key, a TLS
// control plane that can be closed, a state dir and the config naming them.
type cacheWorkerEnv struct {
	t     *testing.T
	sg    *signer.LocalSigner
	clk   *clocktest.Fake
	state string
	cfg   string
	cp    *bundleCP
	srv   *httptest.Server
	base  bundle.Bundle
}

func newCacheWorkerEnv(t *testing.T, maxAge string) *cacheWorkerEnv {
	t.Helper()
	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := keys.Thumbprint(pin)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &cacheWorkerEnv{t: t, sg: sg, clk: clocktest.NewFake(bundleStart.Add(time.Minute)), state: state, cp: &bundleCP{}}
	e.srv = httptest.NewTLSServer(e.cp)
	t.Cleanup(e.srv.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_TEST_CACHE_TOKEN", "tok")
	age := ""
	if maxAge != "" {
		age = "\n  bundleCacheMaxAge: " + maxAge
	}
	e.cfg = writeConfig(t, fmt.Sprintf(`
policy:
  allowlist:
    - domain: local-only.test
logging:
  level: info
  format: json
controlPlane:
  endpoint: %s/policy
  tokenEnv: WARDEN_TEST_CACHE_TOKEN
  caCert: %s
  longPollWait: 50ms
  heartbeatInterval: 1h
  stateDir: %s
  bundleKeys:
    - {kty: OKP, crv: Ed25519, x: %s, kid: %s}%s
`, e.srv.URL, caPath, e.state, pin.X, kid, age))
	e.base = bundle.Bundle{IssuedAt: bundleStart, ExpiresAt: bundleStart.Add(12 * time.Hour), CPID: "cp"}
	return e
}

func (e *cacheWorkerEnv) serve(seq int64, domain string) {
	e.t.Helper()
	e.servePolicy(seq, `{"allowlist":[{"domain":"`+domain+`"}]}`)
}

func (e *cacheWorkerEnv) servePolicy(seq int64, policy string) {
	e.t.Helper()
	b := e.base
	b.Seq, b.PolicyVersion = seq, seq
	b.Policy = json.RawMessage(policy)
	raw, err := bundle.Sign(context.Background(), b, nil, e.sg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.cp.set(raw, fmt.Sprintf("e%d", seq))
}

// run boots the worker and returns its proxy address, logs and a stop func.
func (e *cacheWorkerEnv) run() (proxyAddr string, logs *syncBuffer, stop func()) {
	e.t.Helper()
	p := runParams(e.t, e.cfg)
	p.Overrides = &Overrides{Clock: e.clk}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	p.ProxyListener = ln
	ready := make(chan string, 1)
	p.OnReady = func(string, string) { ready <- ln.Addr().String() }
	logs = &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, logs, p) }()
	stop = func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(10 * time.Second):
			e.t.Error("worker did not stop")
		}
	}
	select {
	case proxyAddr = <-ready:
	case err := <-errCh:
		e.t.Fatalf("Run returned before ready: %v", err)
	case <-time.After(10 * time.Second):
		e.t.Fatal("timed out waiting for the worker")
	}
	return proxyAddr, logs, stop
}

// connectStatus issues a raw CONNECT to the worker's proxy and returns the status.
func connectTo(t *testing.T, proxyAddr, host string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (e *cacheWorkerEnv) cacheFile() string { return config.BundleCachePath(e.state) }

// primeCache runs a worker against the live control plane until it has cached
// seq 5, then stops it and the control plane.
func (e *cacheWorkerEnv) primeCache() {
	e.t.Helper()
	e.serve(5, "cached.test")
	e.primeServed()
}

func (e *cacheWorkerEnv) primeServed() {
	e.t.Helper()
	addr, _, stop := e.run()
	await(e.t, 10*time.Second, "the worker to enforce and cache seq 5", func() bool {
		_, err := os.Stat(e.cacheFile())
		return err == nil && connectTo(e.t, addr, "cached.test") != http.StatusForbidden
	})
	stop()
	e.srv.Close()
}

func TestWorkerBootFromBundleCache(t *testing.T) {
	e := newCacheWorkerEnv(t, "")
	e.primeCache()

	fi, err := os.Stat(e.cacheFile())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file = %v, %v, want mode 0600", fi, err)
	}
	if di, err := os.Stat(filepath.Dir(e.cacheFile())); err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir = %v, %v, want mode 0700", di, err)
	}

	// Restart with the control plane down: seq 5 comes from the cache.
	addr, logs, stop := e.run()
	defer stop()
	if got := connectTo(t, addr, "cached.test"); got == http.StatusForbidden {
		t.Fatalf("the cached policy is not enforced: CONNECT cached.test = %d", got)
	}
	if got := connectTo(t, addr, "other.test"); got != http.StatusForbidden {
		t.Fatalf("CONNECT other.test = %d, want 403", got)
	}
	if got := connectTo(t, addr, "local-only.test"); got != http.StatusForbidden {
		t.Fatalf("the local allowlist leaked into a managed worker: %d", got)
	}
	if !strings.Contains(logs.String(), "enforcing the cached last-known-good signed bundle") {
		t.Errorf("no cache boot log:\n%s", logs)
	}
}

// A worker booted from a seq 5 cache rejects a control plane that then serves a
// valid seq 3 as a rollback. (A control plane up at boot is the live path: the
// cache is read only when the boot pull fails.)
func TestWorkerBootFromBundleCacheRejectsRollback(t *testing.T) {
	e := newCacheWorkerEnv(t, "")
	e.primeCache()

	var up atomic.Bool
	cp := &bundleCP{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		cp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	e.cp, e.srv = cp, srv
	e.cfg = rewriteEndpoint(t, e.cfg, srv)

	addr, logs, stop := e.run()
	defer stop()
	if got := connectTo(t, addr, "cached.test"); got == http.StatusForbidden {
		t.Fatal("the cached seq 5 policy was not enforced")
	}

	// The control plane comes back, serving an older (but validly signed) seq 3.
	e.serve(3, "rolledback.test")
	up.Store(true)
	await(t, 10*time.Second, "the rollback to be rejected", func() bool {
		e.clk.Advance(time.Second) // the long-poll's retry backoff
		return strings.Contains(logs.String(), `"reason":"rollback"`)
	})
	if got := connectTo(t, addr, "rolledback.test"); got != http.StatusForbidden {
		t.Fatalf("a rolled-back bundle was enforced: %d", got)
	}
	if got := connectTo(t, addr, "cached.test"); got == http.StatusForbidden {
		t.Fatal("the cached seq 5 policy was lost")
	}
}

func rewriteEndpoint(t *testing.T, cfgPath string, srv *httptest.Server) string {
	t.Helper()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(l, "  endpoint:"):
			l = "  endpoint: " + srv.URL + "/policy"
		case strings.HasPrefix(l, "  caCert:"):
			ca := filepath.Join(t.TempDir(), "ca2.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			l = "  caCert: " + ca
		}
		out = append(out, l)
	}
	return writeConfig(t, strings.Join(out, "\n"))
}

func TestWorkerBundleCacheFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		maxAge string
		damage func(t *testing.T, e *cacheWorkerEnv)
		want   string
	}{
		{"too old", "1m", func(_ *testing.T, e *cacheWorkerEnv) { e.clk.Advance(time.Hour) }, "older than"},
		{"corrupt", "", func(t *testing.T, e *cacheWorkerEnv) {
			if err := os.WriteFile(e.cacheFile(), []byte("garbage"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "malformed"},
		{"tampered", "", func(t *testing.T, e *cacheWorkerEnv) {
			raw, err := os.ReadFile(e.cacheFile())
			if err != nil {
				t.Fatal(err)
			}
			var env bundle.Envelope
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatal(err)
			}
			p := []byte(env.Payload)
			p[len(p)/2] ^= 1
			env.Payload = string(p)
			out, _ := json.Marshal(env)
			if err := os.WriteFile(e.cacheFile(), out, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "bad_signature"},
		{"key no longer pinned", "", func(t *testing.T, e *cacheWorkerEnv) {
			other, err := signer.GenerateLocal(keys.AlgEdDSA)
			if err != nil {
				t.Fatal(err)
			}
			pin, err := keys.PublicJWK(other.Public(), keys.AlgEdDSA)
			if err != nil {
				t.Fatal(err)
			}
			kid, _ := keys.Thumbprint(pin)
			raw, _ := os.ReadFile(e.cfg)
			lines := strings.Split(string(raw), "\n")
			for i, l := range lines {
				if strings.Contains(l, "bundleKeys") {
					lines[i+1] = fmt.Sprintf("    - {kty: OKP, crv: Ed25519, x: %s, kid: %s}", pin.X, kid)
				}
			}
			e.cfg = writeConfig(t, strings.Join(lines, "\n"))
		}, "unknown_kid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newCacheWorkerEnv(t, tc.maxAge)
			e.primeCache()
			tc.damage(t, e)
			addr, logs, stop := e.run()
			defer stop()
			if got := connectTo(t, addr, "cached.test"); got != http.StatusForbidden {
				t.Fatalf("CONNECT cached.test = %d, want 403 (fail closed)", got)
			}
			out := logs.String()
			if n := strings.Count(out, "starting FAIL-CLOSED"); n != 1 || !strings.Contains(out, tc.want) {
				t.Fatalf("want one fail-closed WARN mentioning %q, got %d:\n%s", tc.want, n, out)
			}
		})
	}
}

// Without stateDir, or with bundleCacheMaxAge 0, nothing is written and the
// worker boots fail-closed as before.
func TestWorkerBundleCacheOffWritesNothing(t *testing.T) {
	for name, maxAge := range map[string]string{"max age 0": "0"} {
		t.Run(name, func(t *testing.T) {
			e := newCacheWorkerEnv(t, maxAge)
			e.serve(5, "cached.test")
			addr, _, stop := e.run()
			await(t, 10*time.Second, "the worker to enforce seq 5", func() bool {
				return connectTo(t, addr, "cached.test") != http.StatusForbidden
			})
			stop()
			if ents, _ := os.ReadDir(e.state); len(ents) != 0 {
				t.Fatalf("state dir written with the cache off: %v", ents)
			}
			e.srv.Close()
			addr, logs, stop2 := e.run()
			defer stop2()
			if got := connectTo(t, addr, "cached.test"); got != http.StatusForbidden {
				t.Fatalf("CONNECT = %d, want 403 (fail closed)", got)
			}
			if !strings.Contains(logs.String(), "starting FAIL-CLOSED") {
				t.Fatalf("no fail-closed log:\n%s", logs)
			}
		})
	}
}

// With the control plane UP at boot but serving a valid, older seq 3, the seq 5
// cache is the rollback floor: the pull is rejected and the worker enforces the
// cache.
func TestWorkerBootCacheIsRollbackFloorWhenCPUp(t *testing.T) {
	e := newCacheWorkerEnv(t, "")
	e.primeCache()

	cp := &bundleCP{}
	srv := httptest.NewTLSServer(cp)
	t.Cleanup(srv.Close)
	e.cp, e.srv = cp, srv
	e.cfg = rewriteEndpoint(t, e.cfg, srv)
	e.serve(3, "rolledback.test")

	addr, logs, stop := e.run()
	defer stop()
	if got := connectTo(t, addr, "rolledback.test"); got != http.StatusForbidden {
		t.Fatalf("a rolled-back bundle was enforced at boot: %d", got)
	}
	if got := connectTo(t, addr, "cached.test"); got == http.StatusForbidden {
		t.Fatal("the cached seq 5 policy was not enforced")
	}
	if !strings.Contains(logs.String(), "enforcing the cached last-known-good signed bundle") {
		t.Errorf("no cache boot log:\n%s", logs)
	}
}

// A worker booted from the cache whose aws secret backend cannot get
// credentials (the sidecar is not cached) still starts and enforces the cached
// policy; secret resolution fails closed.
func TestWorkerBootFromBundleCacheWithoutAWSCredentials(t *testing.T) {
	e := newCacheWorkerEnv(t, "")
	e.servePolicy(5, `{"allowlist":[{"domain":"cached.test"}],"settings":{"secrets":{"backend":"aws","region":"us-east-1"}}}`)
	// A secrets: mapping makes the cache prefetch at startup, which is what used
	// to crash a cache boot without credentials.
	raw, err := os.ReadFile(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = writeConfig(t, string(raw)+"\nsecrets:\n  - placeholder: aws_secret_001\n    envVar: WARDEN_UNUSED_CACHE_SECRET\n")
	// The priming run has a working aws client holding the secret; the restarted
	// one does not.
	prime := newFakeAWSClient()
	if _, err := prime.CreateSecret("warden/aws_secret_001", "real-secret-value"); err != nil {
		t.Fatal(err)
	}
	withFakeAWSClient(t, prime, nil)
	e.primeServed()
	withFakeAWSClient(t, nil, errors.New("no credentials"))

	addr, logs, stop := e.run()
	defer stop()
	if got := connectTo(t, addr, "cached.test"); got == http.StatusForbidden {
		t.Fatal("the cached policy was not enforced")
	}
	if got := connectTo(t, addr, "other.test"); got != http.StatusForbidden {
		t.Fatalf("other.test = %d, want 403", got)
	}
	if !strings.Contains(logs.String(), "running from the bundle cache without AWS credentials") {
		t.Errorf("no ERROR about the missing credentials:\n%s", logs)
	}
	if strings.Contains(logs.String(), "real-secret-value") {
		t.Errorf("a secret resolved without credentials:\n%s", logs)
	}
}
