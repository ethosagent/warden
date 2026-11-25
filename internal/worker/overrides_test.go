package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/test/fakes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// TestOverridesAreNotConfigurable pins the security property the Overrides
// seam rests on: the assembly-only collaborator types (the upstream dialer,
// a root-CA pool, the clock) are reachable from GO CODE ONLY. Two guards:
//
//  1. No field anywhere inside config.Policy — walked recursively through
//     nested structs, slices, arrays, maps and pointers — carries an override
//     type, so no YAML key can exist for it (the schema is strict-parsed).
//  2. No file in cmd/proxy so much as mentions Overrides, so no flag or wiring
//     in the CLI can set one — today in run.go, and in any file added later.
func TestOverridesAreNotConfigurable(t *testing.T) {
	bad := map[reflect.Type]string{
		reflect.TypeOf((*proxy.Dialer)(nil)).Elem():     "proxy.Dialer",
		reflect.TypeOf(&x509.CertPool{}):                "*x509.CertPool",
		reflect.TypeOf((*clock.Clock)(nil)).Elem():      "clock.Clock",
		reflect.TypeOf((*sdkmetric.Reader)(nil)).Elem(): "sdkmetric.Reader",
		reflect.TypeOf((*AnalyticsFlusher)(nil)).Elem(): "worker.AnalyticsFlusher",
		reflect.TypeOf(&proxy.Inflight{}):               "*proxy.Inflight",
		// Overrides.BeforeTerminal is a plain func(); the walk checks every
		// field's TYPE before its kind switch, so a func-typed config field is
		// caught by this entry like any other.
		reflect.TypeOf((*func())(nil)).Elem(): "func()",
	}
	var walk func(rt reflect.Type, path string)
	seen := map[reflect.Type]bool{}
	walk = func(rt reflect.Type, path string) {
		if rt == nil || seen[rt] {
			return
		}
		seen[rt] = true
		if name, hit := bad[rt]; hit {
			t.Fatalf("config.Policy carries override type %s at %s", name, path)
		}
		switch rt.Kind() {
		case reflect.Struct:
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				walk(f.Type, path+"."+f.Name)
			}
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(rt.Elem(), path+"[*]")
		case reflect.Map:
			walk(rt.Key(), path+"(key)")
			walk(rt.Elem(), path+"(value)")
		}
	}
	walk(reflect.TypeOf(config.Policy{}), "config.Policy")

	entries, err := os.ReadDir("../../cmd/proxy")
	if err != nil {
		t.Fatalf("read cmd/proxy: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join("../../cmd/proxy", e.Name()))
		if err != nil {
			t.Fatalf("read cmd/proxy/%s: %v", e.Name(), err)
		}
		if bytes.Contains(src, []byte("Overrides")) {
			t.Errorf("cmd/proxy/%s mentions Overrides; the assembly seams are Go-only and must never be reachable from the CLI", e.Name())
		}
	}
}

// mappingDialer is the harness-style test dialer: it routes ONE allowlisted
// name to a local fake upstream the SafeDialer would rightly refuse (a
// loopback address), counting every dial. DialTLS hands the proxy's own
// tls.Config through — keeping its RootCAs (the UpstreamRootCAs override) and
// rewriting only SNI to the fake upstream's cert identity — so the scenario
// below proves BOTH dialer overrides reached the proxy: if either regresses,
// the handshake or the routing fails and the proxied request is not a 200.
type mappingDialer struct {
	from   string // the allowlisted name the proxy dials
	toAddr string // the fake upstream's loopback address

	mu    sync.Mutex
	dials int
}

func (m *mappingDialer) Dial(network, addr string) (net.Conn, error) {
	m.count()
	return nil, fmt.Errorf("mappingDialer: unexpected plain dial to %s", addr)
}

func (m *mappingDialer) DialTLS(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	m.count()
	if addr != m.from {
		return nil, fmt.Errorf("mappingDialer: unexpected upstream %q", addr)
	}
	if cfg == nil || cfg.RootCAs == nil {
		return nil, errors.New("mappingDialer: proxy handed a tls.Config without RootCAs; Overrides.UpstreamRootCAs never reached the upstream TLS config")
	}
	handshake := cfg.Clone()
	handshake.ServerName = "127.0.0.1" // the fake upstream's cert identity
	raw, err := net.Dial(network, m.toAddr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, handshake)
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func (m *mappingDialer) count() {
	m.mu.Lock()
	m.dials++
	m.mu.Unlock()
}

func (m *mappingDialer) countDials() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dials
}

// TestRun_OverridesDialerMapsFakeUpstream is the end-to-end proof of the
// assembly-only overrides: a worker whose Overrides.Dialer maps
// fake.upstream.test:443 onto a local TLS server (which the production
// SafeDialer exists to BLOCK) serves a 200 through the full path — agent HTTPS
// request → worker MITM termination → policy allow → mapping dialer → fake
// upstream. The dialer keeps the RootCAs the proxy built from
// Overrides.UpstreamRootCAs, so a regression in either override breaks the
// request instead of the test.
func TestRun_OverridesDialerMapsFakeUpstream(t *testing.T) {
	// The fake upstream: a loopback TLS server, unreachable through the
	// SafeDialer by design — only the override can get here.
	ping := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pong from the fake upstream"))
	}))
	defer ping.Close()

	// The worker's MITM CA: with it, the worker terminates TLS for the mapped
	// name, so the request rides the inspected HTTP path (not a raw tunnel).
	caCertPath, caKeyPath := writeTestCA(t)
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse CA cert")
	}

	// The override root pool trusting the fake upstream's own certificate.
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(ping.Certificate())

	dialer := &mappingDialer{
		from:   "fake.upstream.test:443",
		toAddr: strings.TrimPrefix(ping.URL, "https://"),
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen admin: %v", err)
	}

	p := Params{
		Config: &fakes.FakeConfigProvider{Policy: config.Policy{
			Allowlist: []config.AllowlistEntry{{Domain: "fake.upstream.test"}},
			LogLevel:  "error",
			LogFormat: "text",
		}},
		DBPath:        filepath.Join(t.TempDir(), "warden.db"),
		CACert:        caCertPath,
		CAKey:         caKeyPath,
		Version:       "test",
		ProxyListener: proxyLn,
		AdminListener: adminLn,
		Overrides: &Overrides{
			Dialer:          dialer,
			UpstreamRootCAs: upstreamRoots,
		},
	}
	ready := make(chan [2]string, 1)
	p.OnReady = func(proxyAddr, _ string) { ready <- [2]string{proxyAddr, ""} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, io.Discard, p) }()

	var proxyAddr string
	select {
	case addrs := <-ready:
		proxyAddr = addrs[0]
	case err := <-errCh:
		t.Fatalf("Run returned before OnReady: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}

	// The agent's view: CONNECT the proxy for the allowlisted name and speak
	// HTTPS through the tunnel. The leaf the worker mints is trusted via its
	// CA; ALPN is pinned to http/1.1 so the request rides handleHTTP, the one
	// path that dials upstream through the injected dialer.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://" + proxyAddr) },
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			},
		},
	}
	resp, err := client.Get("https://fake.upstream.test/ping")
	if err != nil {
		cancel()
		t.Fatalf("GET through the worker proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "pong from the fake upstream" {
		cancel()
		t.Fatalf("GET through the worker proxy = %d %q, want 200 %q", resp.StatusCode, body, "pong from the fake upstream")
	}
	if n := dialer.countDials(); n != 1 {
		t.Errorf("mapping dialer used %d times, want 1", n)
	}

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

// TestRun_OverridesDialerMapsFakeUpstreamH2 is the h2 leg of the same proof:
// a client that negotiates ALPN h2 with the worker rides handleGRPC, which
// terminates HTTP/2 and re-originates it upstream over a SECOND h2 hop. That
// upstream dial must carry Overrides.UpstreamRootCAs exactly like the HTTP/1.1
// path (the gRPC dial site builds its config through upstreamTLSConfig), so
// the mapping dialer rejects a RootCAs-less config and the scenario fails if
// the h2 path ever regresses to a hand-rolled tls.Config.
func TestRun_OverridesDialerMapsFakeUpstreamH2(t *testing.T) {
	// The fake upstream serves HTTP/2 (EnableHTTP2), so the upstream leg
	// genuinely negotiates h2 through the mapping dialer.
	upstreamProto := make(chan string, 1)
	pong := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case upstreamProto <- r.Proto:
		default:
		}
		_, _ = w.Write([]byte("pong over h2 from the fake upstream"))
	}))
	pong.EnableHTTP2 = true
	pong.StartTLS()
	defer pong.Close()

	caCertPath, caKeyPath := writeTestCA(t)
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse CA cert")
	}

	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(pong.Certificate())

	dialer := &mappingDialer{
		from:   "fake.upstream.test:443",
		toAddr: strings.TrimPrefix(pong.URL, "https://"),
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen admin: %v", err)
	}

	p := Params{
		Config: &fakes.FakeConfigProvider{Policy: config.Policy{
			Allowlist: []config.AllowlistEntry{{Domain: "fake.upstream.test"}},
			LogLevel:  "error",
			LogFormat: "text",
		}},
		DBPath:        filepath.Join(t.TempDir(), "warden.db"),
		CACert:        caCertPath,
		CAKey:         caKeyPath,
		Version:       "test",
		ProxyListener: proxyLn,
		AdminListener: adminLn,
		Overrides: &Overrides{
			Dialer:          dialer,
			UpstreamRootCAs: upstreamRoots,
		},
	}
	ready := make(chan [2]string, 1)
	p.OnReady = func(proxyAddr, _ string) { ready <- [2]string{proxyAddr, ""} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, io.Discard, p) }()

	var proxyAddr string
	select {
	case addrs := <-ready:
		proxyAddr = addrs[0]
	case err := <-errCh:
		t.Fatalf("Run returned before OnReady: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}

	// The agent offers ONLY h2, so the worker's MITM handshake negotiates h2 and
	// the request takes the handleGRPC path. ForceAttemptHTTP2 lets the
	// transport negotiate ALPN despite the custom TLSClientConfig.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             func(*http.Request) (*url.URL, error) { return url.Parse("http://" + proxyAddr) },
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2"},
			},
		},
	}
	resp, err := client.Get("https://fake.upstream.test/ping")
	if err != nil {
		cancel()
		t.Fatalf("GET over h2 through the worker proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("GET over h2 through the worker proxy = %d %q, want 200", resp.StatusCode, body)
	}
	if string(body) != "pong over h2 from the fake upstream" {
		cancel()
		t.Fatalf("body = %q, want the fake upstream's pong", body)
	}
	if got := resp.Proto; got != "HTTP/2.0" {
		cancel()
		t.Fatalf("agent-side negotiated proto = %q, want HTTP/2.0", got)
	}
	select {
	case got := <-upstreamProto:
		if got != "HTTP/2.0" {
			cancel()
			t.Fatalf("upstream leg negotiated %q, want HTTP/2.0", got)
		}
	default:
		cancel()
		t.Fatal("the fake upstream never served a request")
	}
	if n := dialer.countDials(); n != 1 {
		cancel()
		t.Errorf("mapping dialer used %d times, want 1", n)
	}

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

// TestRun_OverridesOnAnalyticsWriterFlushesAnalytics pins the analytics drain
// seam: Run calls Overrides.OnAnalyticsWriter exactly once with the assembled
// async writer, and Flush through that handle persists an already-made request's
// event IMMEDIATELY — no outwaiting the async writer's 250ms flush tick. This is
// what lets the L1 harness read events back deterministically (h.Events()).
func TestRun_OverridesOnAnalyticsWriterFlushesAnalytics(t *testing.T) {
	pong := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	defer pong.Close()

	caCertPath, caKeyPath := writeTestCA(t)
	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse CA cert")
	}
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(pong.Certificate())

	dialer := &mappingDialer{
		from:   "fake.upstream.test:443",
		toAddr: strings.TrimPrefix(pong.URL, "https://"),
	}
	dbPath := filepath.Join(t.TempDir(), "warden.db")

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen admin: %v", err)
	}

	var flusher AnalyticsFlusher
	var flushCalls int
	inflight := proxy.NewInflight()
	p := Params{
		Config: &fakes.FakeConfigProvider{Policy: config.Policy{
			Allowlist: []config.AllowlistEntry{{Domain: "fake.upstream.test"}},
			LogLevel:  "error",
			LogFormat: "text",
		}},
		DBPath:        dbPath,
		CACert:        caCertPath,
		CAKey:         caKeyPath,
		Version:       "test",
		ProxyListener: proxyLn,
		AdminListener: adminLn,
		Overrides: &Overrides{
			Dialer:          dialer,
			UpstreamRootCAs: upstreamRoots,
			Inflight:        inflight,
			OnAnalyticsWriter: func(f AnalyticsFlusher) {
				flushCalls++
				flusher = f
			},
		},
	}
	ready := make(chan [2]string, 1)
	p.OnReady = func(proxyAddr, _ string) { ready <- [2]string{proxyAddr, ""} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, io.Discard, p) }()

	var proxyAddr string
	select {
	case addrs := <-ready:
		proxyAddr = addrs[0]
	case err := <-errCh:
		t.Fatalf("Run returned before OnReady: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://" + proxyAddr) },
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"http/1.1"},
			},
		},
	}
	resp, err := client.Get("https://fake.upstream.test/ping")
	if err != nil {
		cancel()
		t.Fatalf("GET through the worker proxy: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("GET through the worker proxy = %d, want 200", resp.StatusCode)
	}
	if n := dialer.countDials(); n != 1 {
		cancel()
		t.Errorf("mapping dialer used %d times, want 1", n)
	}

	// The seam's whole point: the drain handle arrived, and flushing it makes the
	// request's event readable from the worker's DB without any wait.
	if flushCalls != 1 {
		cancel()
		t.Fatalf("OnAnalyticsWriter called %d times, want exactly 1", flushCalls)
	}
	if flusher == nil {
		cancel()
		t.Fatal("OnAnalyticsWriter never handed over the analytics flusher; h.Events() could never drain the queue")
	}
	// The allow event is recorded after the response is relayed (#363), so wait
	// for the request's terminal bookkeeping before flushing, as the harness does.
	idleCtx, idleCancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = inflight.WaitIdle(idleCtx)
	idleCancel()
	if err != nil {
		cancel()
		t.Fatalf("wait for the request's terminal bookkeeping: %v (in flight: %v)", err, inflight.InFlight())
	}
	if err := flusher.Flush(); err != nil {
		cancel()
		t.Fatalf("flush analytics: %v", err)
	}

	st, err := analytics.NewSQLiteStore("file:"+dbPath+"?_pragma=busy_timeout(10000)", 0)
	if err != nil {
		cancel()
		t.Fatalf("open the worker's analytics DB after Flush: %v", err)
	}
	defer func() { _ = st.Close() }()
	evs, err := st.GetEvents(analytics.EventFilter{})
	if err != nil {
		cancel()
		t.Fatalf("read events after Flush: %v", err)
	}
	if len(evs) != 1 {
		cancel()
		t.Fatalf("after Flush the DB holds %d events, want exactly 1 (the request above, persisted on demand)", len(evs))
	}
	if evs[0].Domain != "fake.upstream.test" || evs[0].Decision != "allow" {
		t.Errorf("flushed event = %s/%s, want fake.upstream.test/allow", evs[0].Domain, evs[0].Decision)
	}

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

// writeTestCA generates a throwaway RSA CA (the proxy accepts RSA CA keys
// only), writes cert and key as PEM, and returns both paths — enough for the
// worker to mint MITM leaves a test client trusts.
func writeTestCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "warden-worker-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	certPath = filepath.Join(t.TempDir(), "ca.pem")
	keyPath = filepath.Join(t.TempDir(), "ca-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// nopDialer is an egress override that is never dialed: the WARN test only
// needs the seam to be set.
type nopDialer struct{}

func (nopDialer) Dial(string, string) (net.Conn, error) { return nil, errors.New("nopDialer") }
func (nopDialer) DialTLS(string, string, *tls.Config) (*tls.Conn, error) {
	return nil, errors.New("nopDialer")
}

// TestRun_EgressOverridesWarnTestHooksActive: setting either egress override
// (the dialer that replaces the SafeDialer, the root pool that replaces the
// system roots) logs one "test hooks active" WARN naming the hook, so a worker
// started with them outside a test is visible. A worker without them stays
// silent, and the line carries no address or key material.
func TestRun_EgressOverridesWarnTestHooksActive(t *testing.T) {
	const cfg = "policy:\n  allowlist:\n    - domain: api.example.test\nlogging:\n  level: info\n  format: text\n"
	run := func(t *testing.T, o *Overrides, want string) string {
		t.Helper()
		var out syncBuffer
		p := runParams(t, writeConfig(t, cfg))
		p.Overrides = o
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, &out, p) }()
		waitForLog(t, &out, want)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Run returned error on clean shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after ctx cancel")
		}
		return out.String()
	}

	t.Run("dialer", func(t *testing.T) {
		logged := run(t, &Overrides{Dialer: nopDialer{}}, "test hooks active")
		requireHooksWarn(t, logged, "Dialer")
	})
	t.Run("root pool", func(t *testing.T) {
		logged := run(t, &Overrides{UpstreamRootCAs: x509.NewCertPool()}, "test hooks active")
		requireHooksWarn(t, logged, "UpstreamRootCAs")
	})
	t.Run("clock only is silent", func(t *testing.T) {
		logged := run(t, &Overrides{Clock: clock.Real()}, "proxy listening")
		if strings.Contains(logged, "test hooks active") {
			t.Fatalf("a non-egress override must not log the hook WARN; got:\n%s", logged)
		}
	})
	t.Run("production default is silent", func(t *testing.T) {
		logged := run(t, nil, "proxy listening")
		if strings.Contains(logged, "test hooks active") {
			t.Fatalf("a worker with no overrides must not log the hook WARN; got:\n%s", logged)
		}
	})
}

// requireHooksWarn asserts the log holds exactly one "test hooks active" WARN
// whose only attribute besides time, level and msg is hooks=<want>: no address,
// port or PEM marker can ride on it.
func requireHooksWarn(t *testing.T, logged, want string) {
	t.Helper()
	var lines []string
	for _, l := range strings.Split(logged, "\n") {
		if strings.Contains(l, "test hooks active") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("want exactly one test-hooks WARN, got %d in:\n%s", len(lines), logged)
	}
	rest := lines[0]
	i := strings.Index(rest, `msg="`)
	if i < 0 {
		t.Fatalf("WARN line has no msg attribute: %s", lines[0])
	}
	j := strings.Index(rest[i+5:], `"`)
	rest = strings.TrimSpace(rest[i+5+j+1:])
	if rest != "hooks="+want {
		t.Fatalf("WARN attributes after msg = %q, want exactly %q; line: %s", rest, "hooks="+want, lines[0])
	}
	if !strings.Contains(lines[0], "level=WARN") {
		t.Fatalf("test-hooks line is not a WARN: %s", lines[0])
	}
}

// TestRun_OverridesClockReachesProxy pins that Overrides.Clock is handed to the
// proxy as its identity-validity clock (proxy.Config.IdentityClock), and that
// without the override the proxy keeps the production default (nil = time.Now).
func TestRun_OverridesClockReachesProxy(t *testing.T) {
	const cfg = "policy:\n  allowlist:\n    - domain: api.example.test\nlogging:\n  level: error\n  format: text\n"
	capture := func(t *testing.T, o *Overrides) proxy.Config {
		t.Helper()
		var got proxy.Config
		orig := newProxy
		newProxy = func(c proxy.Config) (*proxy.Proxy, error) {
			got = c
			return orig(c)
		}
		t.Cleanup(func() { newProxy = orig })
		p := runParams(t, writeConfig(t, cfg))
		p.Overrides = o
		if err := runUntilCtxDone(t, p); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return got
	}

	t.Run("override", func(t *testing.T) {
		start := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
		fake := clocktest.NewFake(start)
		got := capture(t, &Overrides{Clock: fake})
		if got.IdentityClock == nil {
			t.Fatal("proxy.Config.IdentityClock is nil: Overrides.Clock did not reach the proxy")
		}
		if !got.IdentityClock().Equal(start) {
			t.Fatalf("IdentityClock() = %v, want the fake clock's %v", got.IdentityClock(), start)
		}
		fake.Advance(time.Hour)
		if want := start.Add(time.Hour); !got.IdentityClock().Equal(want) {
			t.Fatalf("after Advance IdentityClock() = %v, want %v", got.IdentityClock(), want)
		}
	})
	t.Run("production default", func(t *testing.T) {
		if got := capture(t, nil); got.IdentityClock != nil {
			t.Fatal("IdentityClock is set without Overrides.Clock")
		}
	})
}
