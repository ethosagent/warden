package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dnstest"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// TestUnreachableResolverErr pins the hook's error classification: a not-found
// answer (NXDOMAIN / no data), even wrapped, is NOT a reachability failure;
// timeouts, temporary transport errors, and anything unrecognizable are.
func TestUnreachableResolverErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"nxdomain",
			&net.DNSError{Err: "no such host", Name: "x.test", IsNotFound: true},
			false,
		},
		{
			"wrapped nxdomain",
			fmt.Errorf("lookup x.test: %w", &net.DNSError{Err: "no such host", Name: "x.test", IsNotFound: true}),
			false,
		},
		{
			"timeout",
			&net.DNSError{Err: "i/o timeout", Name: "x.test", IsTimeout: true, IsTemporary: true},
			true,
		},
		{
			"temporary (connection refused)",
			&net.DNSError{Err: "read udp: connection refused", Name: "x.test", IsTemporary: true},
			true,
		},
		{
			"unclassified dns error defaults to firing",
			&net.DNSError{Err: "malformed response", Name: "x.test"},
			true,
		},
		{"non-dns error defaults to firing", errors.New("dial udp: network unreachable"), true},
	}
	for _, tc := range tests {
		if got := unreachableResolverErr(tc.err); got != tc.want {
			t.Errorf("%s: unreachableResolverErr = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestNewUpstreamResolver_LookupsGoToStub proves a resolver built by
// NewUpstreamResolver sends its queries to the CONFIGURED server: the stub
// answers the pinned A record and counts the question it received.
func TestNewUpstreamResolver_LookupsGoToStub(t *testing.T) {
	stub := dnstest.New(t, map[string]string{"public.stub.test": "93.184.216.34"})
	res := NewUpstreamResolver(stub.Addr(), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := res.LookupIPAddr(ctx, "public.stub.test")
	if err != nil {
		t.Fatalf("LookupIPAddr: %v", err)
	}
	if len(addrs) != 1 || addrs[0].IP.String() != "93.184.216.34" {
		t.Fatalf("resolved %v, want [93.184.216.34]", addrs)
	}
	if stub.Queries.Load() == 0 {
		t.Fatal("stub received no queries; lookup bypassed the configured resolver")
	}
}

// TestNewUpstreamResolver_UnreachableNoFallback proves the failure semantics:
// against a dead resolver every lookup fails (no silent fallback to the system
// resolver) and the one-time hook fires exactly once, no matter how many
// lookups fail.
func TestNewUpstreamResolver_UnreachableNoFallback(t *testing.T) {
	var hooked atomic.Int64
	// 127.0.0.1:1 refuses fast (same trick the worker boot tests use).
	res := NewUpstreamResolver("127.0.0.1:1", func(_ error) { hooked.Add(1) })

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := res.LookupIPAddr(ctx, "public.stub.test")
		cancel()
		if err == nil {
			t.Fatal("want lookup failure against an unreachable resolver (no silent fallback)")
		}
	}
	if got := hooked.Load(); got != 1 {
		t.Fatalf("onUnreachable fired %d times, want exactly 1", got)
	}
}

// TestNewUpstreamResolver_NilHookAllowsFailure proves a nil hook is safe: the
// lookup still fails cleanly when the configured resolver is unreachable.
func TestNewUpstreamResolver_NilHookAllowsFailure(t *testing.T) {
	res := NewUpstreamResolver("127.0.0.1:1", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := res.LookupIPAddr(ctx, "public.stub.test"); err == nil {
		t.Fatal("want lookup failure against an unreachable resolver")
	}
}

// TestNewUpstreamResolver_ErrorNamesConfiguredServer proves a failed lookup
// blames the CONFIGURED server: Go stamps *net.DNSError.Server from
// /etc/resolv.conf even though this resolver's Dial redirects the exchange to
// the configured address, so without a rewrite the error text — the WARN line,
// per-request 502s, analytics — names a server this resolver never talks to,
// and whoever debugs an outage chases the wrong resolver. The rewrite must
// keep the error type usable (errors.As) and the classification fields
// (IsNotFound etc.) intact.
func TestNewUpstreamResolver_ErrorNamesConfiguredServer(t *testing.T) {
	const dead = "127.0.0.1:1" // refuses fast (the boot-test trick)
	var hookErr atomic.Value   // error text the one-shot WARN line would log
	res := NewUpstreamResolver(dead, func(err error) { hookErr.Store(err.Error()) })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := res.LookupIPAddr(ctx, "dead.resolver.test")
	if err == nil {
		t.Fatal("want lookup failure against an unreachable resolver")
	}

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("errors.As(*net.DNSError) = false, got %T: %v", err, err)
	}
	if dnsErr.Server != dead {
		t.Fatalf("DNSError.Server = %q, want the configured %s", dnsErr.Server, dead)
	}
	if !strings.Contains(err.Error(), dead) {
		t.Fatalf("error text %q does not name the configured resolver %s", err, dead)
	}
	for _, sys := range resolvConfDNSServers(t) {
		if sys == dead {
			continue // indistinguishable from the configured one; nothing to prove
		}
		if strings.Contains(err.Error(), sys) {
			t.Fatalf("error text %q names system resolver %s from /etc/resolv.conf; the configured resolver must be blamed instead", err, sys)
		}
	}
	// The one-shot hook must fire with the same rewritten error the caller
	// sees — it becomes the operator-facing WARN line.
	if got, _ := hookErr.Load().(string); !strings.Contains(got, dead) {
		t.Fatalf("onUnreachable error text %q does not name the configured resolver %s", got, dead)
	}
}

// resolvConfDNSServers returns the "host:port" DNS servers /etc/resolv.conf
// advertises (port defaulting to 53), so a test can assert the configured
// resolver's errors never name them. Best-effort: a missing or unreadable file
// (some CI runners have none) yields nil and its assertions are vacuous.
func resolvConfDNSServers(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Logf("/etc/resolv.conf unreadable (%v); skipping system-server assertions", err)
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		host, port, err := net.SplitHostPort(fields[1])
		if err != nil {
			host, port = fields[1], "53"
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	return out
}

// TestNewUpstreamResolver_NXDOMAINDoesNotFireHook proves the one-shot warning
// distinguishes an outage from an answer: against a HEALTHY stub, a lookup for
// an unknown name fails with NXDOMAIN (the server answered "no such name") and
// onUnreachable must stay silent — a typo'd hostname must not consume the
// one-shot and silence a later real outage.
func TestNewUpstreamResolver_NXDOMAINDoesNotFireHook(t *testing.T) {
	var hooked atomic.Int64
	stub := dnstest.New(t, nil) // reachable, but knows no names: NXDOMAIN for all
	res := NewUpstreamResolver(stub.Addr(), func(_ error) { hooked.Add(1) })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, err := res.LookupIPAddr(ctx, "missing.stub.test")
	cancel()
	if err == nil {
		t.Fatal("want lookup failure for a name the resolver does not know")
	}
	if got := hooked.Load(); got != 0 {
		t.Fatalf("onUnreachable fired %d times on NXDOMAIN; a not-found answer is not an outage", got)
	}
}

// TestSafeDialer_UpstreamResolverEndToEnd dials a NAME through a SafeDialer
// whose resolver points at the stub: the name resolves via the stub to the
// echo listener's loopback address, the blocklist lets it through via
// allowPrivate, and the TCP connection lands on the echo server. This is the
// "upstream dials resolve via that server" acceptance path (DialTLS shares the
// same resolve seam through safeHostAndIPs).
func TestSafeDialer_UpstreamResolverEndToEnd(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // accept is proof enough; drop the conn
		}
	}()

	_, port, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatalf("split echo addr: %v", err)
	}
	stub := dnstest.New(t, map[string]string{"echo.stub.test": "127.0.0.1"})
	res := NewUpstreamResolver(stub.Addr(), nil)
	d, err := NewSafeDialerWithResolver(5*time.Second, []string{"127.0.0.0/8"}, res)
	if err != nil {
		t.Fatalf("NewSafeDialerWithResolver: %v", err)
	}

	conn, err := d.Dial("tcp", "echo.stub.test:"+port)
	if err != nil {
		t.Fatalf("Dial via stub resolver: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if stub.Queries.Load() == 0 {
		t.Fatal("stub received no queries; the dial did not resolve via the configured resolver")
	}
}

// TestSafeDialer_UnreachableResolverFailsClosed dials a name through a
// SafeDialer whose configured resolver is dead: the dial must fail with a
// resolution error (surfacing to the request path like any upstream-connect
// failure), never fall back to the system resolver.
func TestSafeDialer_UnreachableResolverFailsClosed(t *testing.T) {
	res := NewUpstreamResolver("127.0.0.1:1", nil)
	d, err := NewSafeDialerWithResolver(2*time.Second, []string{"127.0.0.0/8"}, res)
	if err != nil {
		t.Fatalf("NewSafeDialerWithResolver: %v", err)
	}
	_, err = d.Dial("tcp", "echo.stub.test:80")
	if err == nil {
		t.Fatal("want dial failure when the configured resolver is unreachable")
	}
	if !strings.Contains(err.Error(), "safedial: resolve") {
		t.Fatalf("want a resolution error, got %v", err)
	}
}

// TestSafeDialer_NilResolverKeepsDefault pins the back-compat contract: a nil
// resolver (both constructors) leaves the dialer on net.DefaultResolver —
// byte-identical to the behavior before dns.upstreamResolver existed.
func TestSafeDialer_NilResolverKeepsDefault(t *testing.T) {
	d, err := NewSafeDialer(2*time.Second, nil)
	if err != nil {
		t.Fatalf("NewSafeDialer: %v", err)
	}
	if d.resolver != nil {
		t.Fatalf("NewSafeDialer resolver = %v, want nil (net.DefaultResolver)", d.resolver)
	}
	d2, err := NewSafeDialerWithResolver(2*time.Second, nil, nil)
	if err != nil {
		t.Fatalf("NewSafeDialerWithResolver: %v", err)
	}
	if d2.resolver != nil {
		t.Fatalf("NewSafeDialerWithResolver(nil) resolver = %v, want nil", d2.resolver)
	}
}

// TestSafeDialer_IPLiteralSkipsConfiguredResolver proves an IP-literal target
// never touches the configured resolver (no pointless DNS for literals), so
// existing behavior for IP destinations is unchanged.
func TestSafeDialer_IPLiteralSkipsConfiguredResolver(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer func() { _ = echo.Close() }()
	stub := dnstest.New(t, nil)
	res := NewUpstreamResolver(stub.Addr(), nil)
	d, err := NewSafeDialerWithResolver(2*time.Second, []string{"127.0.0.0/8"}, res)
	if err != nil {
		t.Fatalf("NewSafeDialerWithResolver: %v", err)
	}
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	conn, err := d.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("Dial IP literal: %v", err)
	}
	_ = conn.Close()
	if stub.Queries.Load() != 0 {
		t.Fatalf("stub received %d queries for an IP-literal dial, want 0", stub.Queries.Load())
	}
}

// TestProxy_UpstreamResolverReachesDialPath is the proxy.New-level wiring test
// for dns.upstreamResolver: a request through a proxy whose Config.
// UpstreamResolver points at the stub must reach a local backend AND leave the
// stub's query counter above zero. It fails if proxy.New stops passing
// cfg.UpstreamResolver into its SafeDialer (the lookups would fall to
// net.DefaultResolver, which cannot resolve the stub-only name, and the
// request would come back 502 with the stub silent).
func TestProxy_UpstreamResolverReachesDialPath(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	// The stub is the ONLY resolver that knows the target name. It answers
	// loopback, which the SafeDialer's SSRF blocklist (production wiring passes
	// no allowPrivate) rejects BEFORE any TCP dial — the seam below requires
	// that rejection to have happened, then stands in for the unreachable
	// upstream so the request completes end to end.
	stub := dnstest.New(t, map[string]string{"backend.stub.test": "127.0.0.1"})

	certFile := filepath.Join(t.TempDir(), "ca.crt")
	keyFile := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(certFile, caCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "backend.stub.test", Port: 443}}}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  &fakes.FakeAnalyticsStore{},
		CACertPath: certFile,
		CAKeyPath:  keyFile,
		// The wiring under test: the stub-backed resolver reaches New's dialer.
		UpstreamResolver: NewUpstreamResolver(stub.Addr(), nil),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 100; i++ {
		if p.Addr() != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy did not start")
	}

	// Wrap — never replace — the real dialer: the real call IS the assertion.
	// It must reject the loopback answer (SSRF protection); only then may the
	// test stand in for the upstream so the request can complete. A resolution
	// failure (nil resolver under a wiring regression) is surfaced untouched.
	var realDialErr atomic.Value // last error string from the real dial path
	real := p.dialTLS
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		conn, err := real(network, addr, cfg)
		if err == nil {
			return conn, nil
		}
		realDialErr.Store(err.Error())
		if !strings.Contains(err.Error(), "SSRF protection") {
			return nil, err
		}
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.stub.test", caCertPEM)
	req, _ := http.NewRequest("GET", "https://backend.stub.test/wired", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatalf("read response through proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request through the proxy: got %d, want 200 (the dial path did not reach the backend)", resp.StatusCode)
	}
	rb.mu.Lock()
	gotMethod, gotPath := rb.method, rb.path
	rb.mu.Unlock()
	if gotMethod != "GET" || gotPath != "/wired" {
		t.Fatalf("backend saw %s %s, want GET /wired", gotMethod, gotPath)
	}
	if stub.Queries.Load() == 0 {
		t.Fatal("stub received no queries; the proxy's dial path ignored Config.UpstreamResolver")
	}
	if dialErr, _ := realDialErr.Load().(string); !strings.Contains(dialErr, "blocked (SSRF protection)") {
		t.Fatalf("real dial path error = %q, want the loopback answer blocked (SSRF protection); the configured resolver's answer never reached the dial path", dialErr)
	}
}
