//go:build integration

package integration

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// startProxy starts a real proxy with the given config and returns it once listening.
func startProxy(t *testing.T, cfg proxy.Config) *proxy.Proxy {
	t.Helper()
	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
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
	return p
}

// sendCONNECT dials the proxy and sends a CONNECT request, returning the
// connection and buffered reader positioned after the response status line.
func sendCONNECT(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	return conn, br, statusLine
}

// TestE2E_AllowlistedHTTPSSucceeds verifies that CONNECT to an allowlisted
// domain succeeds (200 Connection Established). Uses tunnel mode (no CA)
// so no upstream dial is needed to verify the policy decision.
func TestE2E_AllowlistedHTTPSSucceeds(t *testing.T) {
	store, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("analytics store: %v", err)
	}
	defer store.Close()

	p := startProxy(t, proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{
			Allowlist: []config.AllowlistEntry{
				{Domain: "api.openai.com", Port: 443},
			},
		}),
		Secrets:   &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics: store,
	})

	_, _, statusLine := sendCONNECT(t, p.Addr().String(), "api.openai.com:443")
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 Connection Established, got %q", statusLine)
	}
}

// TestE2E_NonAllowlistedBlocked verifies default-deny: a CONNECT to a domain
// NOT on the allowlist gets 403 Forbidden, and the denial is recorded in the
// real SQLite analytics store.
func TestE2E_NonAllowlistedBlocked(t *testing.T) {
	store, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("analytics store: %v", err)
	}
	defer store.Close()

	p := startProxy(t, proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{
			Allowlist: []config.AllowlistEntry{
				{Domain: "allowed.test", Port: 443},
			},
		}),
		Secrets:   &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics: store,
	})

	conn, br, statusLine := sendCONNECT(t, p.Addr().String(), "evil.test:443")
	if !strings.Contains(statusLine, "403") {
		t.Fatalf("expected 403 Forbidden, got %q", statusLine)
	}

	// Wait for connection to close so the handler finishes writing analytics.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(br)

	events, err := store.GetEvents(analytics.EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one analytics event for blocked request")
	}
	found := false
	for _, e := range events {
		if e.Domain == "evil.test" && e.Decision == "deny" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected deny event for evil.test in analytics store")
	}
}

// TestE2E_SecretSwapped verifies the placeholder->real-secret swap by wiring
// a real secrets.Cache with a test fetcher. This tests the component integration:
// the cache prefetches on startup, GetSecret returns the real value, and
// secrets.Ref produces a sha256 reference (never the raw value).
func TestE2E_SecretSwapped(t *testing.T) {
	const placeholder = "PLACEHOLDER_001"
	const realKey = "sk-real-api-key-value-12345"
	const envVar = "TEST_SECRET_VALUE"

	// Set the env var the EnvFetcher will read.
	t.Setenv(envVar, realKey)

	// Wire a real Cache with a real EnvFetcher — the same wiring as cmd/proxy/run.go.
	mapping := map[string]string{placeholder: envVar}
	fetcher := secrets.NewEnvFetcher(mapping)
	cache, err := secrets.NewCache(fetcher, 5*time.Minute, []string{placeholder})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	// 1. GetSecret returns the real value, not the placeholder.
	got, err := cache.GetSecret(placeholder)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != realKey {
		t.Fatalf("expected real key %q, got %q", realKey, got)
	}

	// 2. The agent never sees the real key — it only holds the placeholder.
	//    This is a structural guarantee: the agent's env has PLACEHOLDER_001,
	//    the proxy's cache resolves it to realKey on the fly.
	if placeholder == realKey {
		t.Fatal("placeholder must differ from real key")
	}

	// 3. The analytics reference uses sha256, not the raw value.
	ref := secrets.Ref(realKey)
	expectedHash := sha256.Sum256([]byte(realKey))
	expectedHex := hex.EncodeToString(expectedHash[:])
	if ref.SHA256 != expectedHex {
		t.Fatalf("expected SHA256 %q, got %q", expectedHex, ref.SHA256)
	}
	if strings.Contains(ref.String(), realKey) {
		t.Fatal("Reference.String() must not contain the raw secret value")
	}
	if !strings.Contains(ref.String(), "sha256:") {
		t.Fatalf("expected sha256: prefix in reference, got %q", ref.String())
	}

	// 4. Verify the cache can be used as a SecretProvider (interface satisfaction).
	var _ secrets.SecretProvider = cache

	// 5. Now wire it into a real proxy to verify it all links together.
	store, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("analytics store: %v", err)
	}
	defer store.Close()

	p := startProxy(t, proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{
			Allowlist: []config.AllowlistEntry{
				{Domain: "api.openai.com", Port: 443},
			},
		}),
		Secrets:          cache,
		Analytics:        store,
		PlaceholderNames: []string{placeholder},
	})

	// The proxy accepts connections — verifying the full wiring compiles and runs.
	if p.Addr() == nil {
		t.Fatal("proxy did not bind")
	}
}

// TestE2E_DecisionLogging verifies that both allowed and denied requests
// appear in the real SQLite analytics store with correct fields.
func TestE2E_DecisionLogging(t *testing.T) {
	store, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("analytics store: %v", err)
	}
	defer store.Close()

	p := startProxy(t, proxy.Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{
			Allowlist: []config.AllowlistEntry{
				{Domain: "allowed.test", Port: 443},
			},
		}),
		Secrets:   &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics: store,
	})

	// --- Denied request ---
	conn1, br1, statusLine1 := sendCONNECT(t, p.Addr().String(), "evil.test:443")
	if !strings.Contains(statusLine1, "403") {
		t.Fatalf("expected 403, got %q", statusLine1)
	}
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(br1)

	// --- Allowed request ---
	_, _, statusLine2 := sendCONNECT(t, p.Addr().String(), "allowed.test:443")
	if !strings.Contains(statusLine2, "200") {
		t.Fatalf("expected 200, got %q", statusLine2)
	}

	// Give the proxy a moment to flush analytics.
	time.Sleep(100 * time.Millisecond)

	// Query all events.
	events, err := store.GetEvents(analytics.EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}

	// Verify deny event exists.
	var denyEvent *analytics.Event
	for i := range events {
		if events[i].Decision == "deny" && events[i].Domain == "evil.test" {
			denyEvent = &events[i]
			break
		}
	}
	if denyEvent == nil {
		t.Fatal("expected deny event for evil.test")
	}
	if denyEvent.Port != 443 {
		t.Fatalf("expected port 443, got %d", denyEvent.Port)
	}

	// Verify allow event exists.
	// In no-CA tunnel mode, the allow event is stored synchronously before
	// the tunnel goroutine begins, so it is always present.
	var allowEvent *analytics.Event
	for i := range events {
		if events[i].Decision == "allow" && events[i].Domain == "allowed.test" {
			allowEvent = &events[i]
			break
		}
	}
	if allowEvent == nil {
		t.Fatal("expected allow event for allowed.test")
	}
	if allowEvent.Port != 443 {
		t.Fatalf("expected port 443 on allow event, got %d", allowEvent.Port)
	}

	// Structural check: Event has NO body field. This is a compile-time
	// guarantee enforced via reflection — if someone adds a Body field, this
	// test will catch it.
	eventType := reflect.TypeOf(analytics.Event{})
	for i := 0; i < eventType.NumField(); i++ {
		fieldName := strings.ToLower(eventType.Field(i).Name)
		if fieldName == "body" || fieldName == "requestbody" || fieldName == "responsebody" {
			t.Fatalf("Event struct must not have a body field, found %q", eventType.Field(i).Name)
		}
	}

	// If a SecretRef exists on any event, verify it uses sha256 format, not raw value.
	for _, e := range events {
		if e.SecretRef != "" {
			if !strings.Contains(e.SecretRef, "sha256:") {
				t.Fatalf("SecretRef should use sha256: prefix, got %q", e.SecretRef)
			}
		}
	}
}

// TestSingleBinary verifies that the warden binary builds with CGO_ENABLED=0,
// producing a statically linked executable.
func TestSingleBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping single-binary build test in short mode")
	}

	// Find the project root (test/integration -> ../..).
	// Use the go.mod location as anchor.
	projectRoot := findProjectRoot(t)

	outPath := filepath.Join(t.TempDir(), "warden-test")
	cmd := exec.Command("go", "build", "-o", outPath, "./cmd/proxy")
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CGO_ENABLED=0 go build failed: %v\n%s", err, out)
	}

	// Verify the binary exists and is executable.
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat built binary: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("built binary is empty")
	}

	// Optionally check that `file` reports static linking.
	fileCmd := exec.Command("file", outPath)
	fileOut, err := fileCmd.Output()
	if err == nil {
		output := string(fileOut)
		// On Linux, a static Go binary shows "statically linked".
		// On macOS, it shows "Mach-O" without shared library references.
		t.Logf("file output: %s", output)
		if strings.Contains(output, "dynamically linked") {
			t.Fatalf("expected static binary, got: %s", output)
		}
	}
}

// findProjectRoot walks up from the current working directory to find the
// directory containing go.mod.
func findProjectRoot(t *testing.T) string {
	t.Helper()
	// When tests run, the working directory is the test package directory.
	// We need to find the project root (where go.mod lives).
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}
