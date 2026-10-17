package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/secrets"
)

// countingFetcher records how many times each placeholder is fetched and returns
// a versioned value, so a test can prove a freshly-built cache (with a new TTL)
// re-fetches rather than serving a previous cache's entry.
type countingFetcher struct {
	mu      sync.Mutex
	calls   map[string]int
	version int
}

func (f *countingFetcher) Fetch(placeholder string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[placeholder]++
	return placeholder + "-v" + itoa(f.version), nil
}

func (f *countingFetcher) count(placeholder string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[placeholder]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestProxy_SetSecrets_RaceFree drives the hot-path secret read (p.secrets() →
// GetSecret) concurrently with SetSecrets swapping in freshly-built caches. Under
// `go test -race` the atomic pointer must show no data race.
func TestProxy_SetSecrets_RaceFree(t *testing.T) {
	fetcher := &countingFetcher{}
	seed, err := secrets.NewCache(fetcher, time.Hour, []string{"ph"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    seed,
		Analytics:  &syncStore{},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: rebuild + swap the cache with alternating TTLs.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ttls := []time.Duration{time.Hour, time.Minute, time.Second}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				c, cErr := secrets.NewCache(fetcher, ttls[i%len(ttls)], []string{"ph"})
				if cErr == nil {
					p.SetSecrets(c)
				}
				i++
			}
		}
	}()

	// Readers: snapshot the live provider and resolve a placeholder.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = p.secrets().GetSecret("ph")
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestProxy_SetSecrets_SwapsTTL verifies SetSecrets swaps in a cache that honors
// the NEW TTL: the seeded cache (1h TTL) serves a stale value without re-fetching,
// while a swapped-in cache (0 TTL) re-fetches on every read.
func TestProxy_SetSecrets_SwapsTTL(t *testing.T) {
	fetcher := &countingFetcher{}
	// Seed: a long TTL. Prefetch fetches once; subsequent reads are cached.
	seed, err := secrets.NewCache(fetcher, time.Hour, []string{"ph"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    seed,
		Analytics:  &syncStore{},
	})
	if err != nil {
		t.Fatal(err)
	}

	base := fetcher.count("ph") // 1 from prefetch
	// Long-TTL reads do not re-fetch.
	_, _ = p.secrets().GetSecret("ph")
	_, _ = p.secrets().GetSecret("ph")
	if got := fetcher.count("ph"); got != base {
		t.Fatalf("long-TTL cache re-fetched: count went %d→%d", base, got)
	}

	// Swap in a fresh cache with a 0 TTL (everything is immediately expired).
	fetcher.version = 1
	fresh, err := secrets.NewCache(fetcher, 0, []string{"ph"})
	if err != nil {
		t.Fatal(err)
	}
	p.SetSecrets(fresh)

	before := fetcher.count("ph")
	v1, _ := p.secrets().GetSecret("ph")
	v2, _ := p.secrets().GetSecret("ph")
	after := fetcher.count("ph")
	if after-before < 2 {
		t.Fatalf("0-TTL cache did not re-fetch on each read: count went %d→%d", before, after)
	}
	if v1 != "ph-v1" || v2 != "ph-v1" {
		t.Fatalf("expected re-fetched v1 values, got %q %q", v1, v2)
	}
}

// TestProxy_Secrets_SeededUntouched confirms a worker that never swaps reads the
// seeded provider through the atomic pointer (back-compat for a local-only worker
// whose apply loop never runs).
func TestProxy_Secrets_SeededUntouched(t *testing.T) {
	seed := newEmptySecrets()
	seed.Values["ph"] = "seeded-value"
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    seed,
		Analytics:  &syncStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.secrets() != seed {
		t.Fatal("expected seeded secret provider through atomic pointer")
	}
	if v, _ := p.secrets().GetSecret("ph"); v != "seeded-value" {
		t.Fatalf("seeded provider value = %q, want seeded-value", v)
	}
}

// --- Issue #372: placeholder swap inside HTTP Basic auth (git over HTTPS) ---

func basicHeader(userpass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userpass))
}

// sendThroughSwapProxy sends req through a MITM proxy configured with one
// placeholder→secret pair and returns the headers/path the backend saw plus the
// recorded analytics events.
func sendThroughSwapProxy(t *testing.T, req *http.Request) (http.Header, string, []analytics.Event) {
	t.Helper()
	return sendThroughSwapProxyWithSecrets(t, req,
		map[string]string{"PLACEHOLDER_001": "real-secret-value"}, []string{"PLACEHOLDER_001"})
}

// sendThroughSwapProxyWithSecrets is sendThroughSwapProxy for an arbitrary set
// of placeholder→secret pairs (placeholders lists the names to swap).
func sendThroughSwapProxyWithSecrets(t *testing.T, req *http.Request, secrets map[string]string, placeholders []string) (http.Header, string, []analytics.Event) {
	t.Helper()
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)
	p, store := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM,
		secrets, placeholders)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}
	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.headers.Clone(), rb.path, store.snapshot()
}

func TestHTTP_BasicAuthSwap(t *testing.T) {
	const real = "real-secret-value"
	tests := []struct {
		name, header, want string
		swapped            bool
	}{
		{"placeholder in username", basicHeader("PLACEHOLDER_001:pw"), basicHeader(real + ":pw"), true},
		{"placeholder in password", basicHeader("user:PLACEHOLDER_001"), basicHeader("user:" + real), true},
		{"password with colon suffix", basicHeader("user:PLACEHOLDER_001:extra"), basicHeader("user:" + real + ":extra"), true},
		{"git x-access-token", basicHeader("x-access-token:PLACEHOLDER_001"), basicHeader("x-access-token:" + real), true},
		{"lowercase scheme", "basic " + base64.StdEncoding.EncodeToString([]byte("u:PLACEHOLDER_001")), "basic " + base64.StdEncoding.EncodeToString([]byte("u:"+real)), true},
		{"no placeholder untouched", basicHeader("user:other"), basicHeader("user:other"), false},
		{"malformed base64 untouched", "Basic !!!not-base64!!!", "Basic !!!not-base64!!!", false},
		{"no colon untouched", basicHeader("PLACEHOLDER_001"), basicHeader("PLACEHOLDER_001"), false},
		{"bearer still swapped", "Bearer PLACEHOLDER_001", "Bearer " + real, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
			req.Header.Set("Authorization", tc.header)
			hdr, _, events := sendThroughSwapProxy(t, req)
			if got := hdr.Get("Authorization"); got != tc.want {
				t.Fatalf("Authorization = %q, want %q", got, tc.want)
			}
			hasRef := false
			for _, e := range events {
				if strings.Contains(e.SecretRef, "sha256:") {
					hasRef = true
				}
				if strings.Contains(e.SecretRef, real) || eventContains(t, e, real) || eventContains(t, e, base64.StdEncoding.EncodeToString([]byte("user:"+real))) {
					t.Fatalf("event leaks secret: %+v", e)
				}
			}
			if hasRef != tc.swapped {
				t.Fatalf("secret ref recorded = %v, want %v (events %+v)", hasRef, tc.swapped, events)
			}
		})
	}
}

func TestHTTP_BasicAuthSwap_MultiSecret(t *testing.T) {
	// Two placeholders in one Basic credential are both swapped.
	secrets := map[string]string{
		"PLACEHOLDER_001": "real-user-value",
		"PLACEHOLDER_002": "real-pass-value",
	}
	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	req.Header.Set("Authorization", basicHeader("PLACEHOLDER_001:PLACEHOLDER_002"))
	hdr, _, _ := sendThroughSwapProxyWithSecrets(t, req, secrets, []string{"PLACEHOLDER_001", "PLACEHOLDER_002"})
	if got := hdr.Get("Authorization"); got != basicHeader("real-user-value:real-pass-value") {
		t.Fatalf("Authorization = %q, want %q", got, basicHeader("real-user-value:real-pass-value"))
	}
}

func TestHTTP_BasicAuthSwap_CustomHeaderNotDecoded(t *testing.T) {
	// A Basic value in a non-Authorization header is NOT decoded (raw match only).
	v := basicHeader("x:PLACEHOLDER_001")
	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	req.Header.Set("X-Custom-Auth", v)
	hdr, _, _ := sendThroughSwapProxy(t, req)
	if got := hdr.Get("X-Custom-Auth"); got != v {
		t.Fatalf("X-Custom-Auth = %q, want unchanged %q", got, v)
	}
}

func TestHTTP_BasicAuthSwap_ProxyAuthorizationUntouched(t *testing.T) {
	// Proxy-Authorization is addressed to Warden itself: never decoded or swapped,
	// and stripped before the upstream write (#396).
	v := basicHeader("user:PLACEHOLDER_001")
	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	req.Header.Set("Proxy-Authorization", v)
	req.Header.Set("Authorization", basicHeader("user:PLACEHOLDER_001"))
	hdr, _, _ := sendThroughSwapProxy(t, req)
	if got := hdr.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("Proxy-Authorization reached the upstream: %q", got)
	}
	if got := hdr.Get("Authorization"); got != basicHeader("user:real-secret-value") {
		t.Fatalf("Authorization not swapped: %q", got)
	}
}

func TestHTTP_BasicAuthSwap_GitUploadPack(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://backend.test/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("User-Agent", "git/2.43.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Git-Protocol", "version=2")
	req.Header.Set("Authorization", basicHeader("x-access-token:PLACEHOLDER_001"))
	hdr, path, events := sendThroughSwapProxy(t, req)
	if path != "/org/repo.git/info/refs?service=git-upload-pack" {
		t.Fatalf("path = %q", path)
	}
	if got := hdr.Get("Authorization"); got != basicHeader("x-access-token:real-secret-value") {
		t.Fatalf("Authorization = %q", got)
	}
	found := false
	for _, e := range events {
		if strings.Contains(e.SecretRef, "sha256:") && containsStr(e.SwappedRefs, "PLACEHOLDER_001") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected SecretRef + SwappedRefs on event, got %+v", events)
	}
}
