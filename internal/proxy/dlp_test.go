package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// startTestProxyWithDLP mirrors startTestProxyWithResponseScan but injects the
// outbound request-body DLP scanner (MCP + response scan stay nil) plus an
// optional secret provider + placeholder names (so the pre-swap ordering can be
// exercised) and an optional live metrics emitter. A nil dlp disables DLP.
func startTestProxyWithDLP(t *testing.T, allowedDomains []string, caCertPEM, caKeyPEM []byte, dlp *DLPScanner, secretValues map[string]string, placeholderNames []string, metrics *observability.Metrics) (*Proxy, *syncStore) {
	t.Helper()
	var entries []config.AllowlistEntry
	for _, d := range allowedDomains {
		entries = append(entries, config.AllowlistEntry{Domain: d, Port: 443})
	}
	store := &syncStore{}
	cfg := Config{
		ListenAddr:       "127.0.0.1:0",
		Policy:           policy.NewEvaluator(config.Policy{Allowlist: entries}),
		Secrets:          &fakes.FakeSecretProvider{Values: secretValues},
		Analytics:        store,
		AgentID:          "agent",
		DLP:              dlp,
		PlaceholderNames: placeholderNames,
		Metrics:          metrics,
	}
	if len(caCertPEM) > 0 {
		certFile := filepath.Join(t.TempDir(), "ca.crt")
		keyFile := filepath.Join(t.TempDir(), "ca.key")
		if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, caKeyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		cfg.CACertPath = certFile
		cfg.CAKeyPath = keyFile
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
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
	return p, store
}

// doPostThroughProxy sends one POST with the given content-type + body through
// the proxy and returns the response status. It reads and discards the response
// body so the keep-alive conn is left clean.
func doPostThroughProxy(t *testing.T, p *Proxy, caCertPEM []byte, contentType, body string) int {
	t.Helper()
	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("POST", "https://backend.test/ingest", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = int64(len(body))
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	_ = readAllResp(resp)
	return resp.StatusCode
}

func backendBody(rb *recordingBackend) string {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.body
}

// eventContains reports whether the value string appears anywhere in the event's
// serialized (JSON) form — the leak-hygiene assertion that a swapped secret value
// never lands in a recorded event.
func eventContains(t *testing.T, ev analytics.Event, value string) bool {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return strings.Contains(string(b), value)
}

const dlpAKIA = "AKIAIOSFODNN7EXAMPLE" // a foreign AWS key (credential_leak, high)

// Test 1: mode:off is byte-identical — a planted AKIA key forwards with NO DLP
// fields on the event (no added read, nothing recorded).
func TestDLP_OffByteIdentical(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	// DLP nil => stage is a no-op.
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	body := fmt.Sprintf(`{"note":"key %s here"}`, dlpAKIA)
	if status := doPostThroughProxy(t, p, caCertPEM, "application/json", body); status != 200 {
		t.Fatalf("off must forward; got %d", status)
	}
	if got := backendBody(rb); got != body {
		t.Fatalf("off: backend body not byte-identical: got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", ss.snapshot())
	}
	if len(ev.DataClasses) != 0 || ev.DLPAction != "" || ev.DLPPartial || ev.DLPEncoded {
		t.Fatalf("off must populate NO dlp fields, got %+v", ev)
	}
}

// Test 2: monitor detects the planted key, forwards the body UNCHANGED, and the
// allow event carries the finding (DataClasses non-empty, DLPAction=monitor).
func TestDLP_MonitorDetectsAndForwards(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)
	metrics, handler := newMetrics(t)

	dlp := NewDLPScanner("monitor", false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, metrics)
	p.dialTLS = dialBackend(backendLn)

	body := fmt.Sprintf(`{"note":"key %s here"}`, dlpAKIA)
	if status := doPostThroughProxy(t, p, caCertPEM, "application/json", body); status != 200 {
		t.Fatalf("monitor must forward; got %d", status)
	}
	if got := backendBody(rb); got != body {
		t.Fatalf("monitor must not mutate the body: got %q, want %q", got, body)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", ss.snapshot())
	}
	if ev.DLPAction != "monitor" {
		t.Fatalf("expected DLPAction=monitor, got %q", ev.DLPAction)
	}
	if !containsStr(ev.DataClasses, "credentials") {
		t.Fatalf("expected DataClasses to include credentials, got %v", ev.DataClasses)
	}
	if ev.DLPPartial {
		t.Fatalf("scannable in-cap body must not be partial: %+v", ev)
	}
	m := scrapeMetrics(t, handler)
	if !strings.Contains(m, `kind="dlp_credential_leak"`) {
		t.Fatalf("expected dlp_credential_leak metric:\n%s", m)
	}
}

// Test 3: ordering — DLP scans the PRE-SWAP body. A configured placeholder NAME
// is not altered by dlpScan and still swaps downstream; a foreign AKIA is
// detected; the real swapped secret value (itself credential-shaped) is NOT
// detected (it never reaches the scanner) and appears in NO event.
func TestDLP_PreSwapOrdering(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	const placeholder = "PLACEHOLDER_SECRET"
	const realSecret = "AKIAREALSECRET000000" // AKIA-form: would trip the detector IF scanned
	dlp := NewDLPScanner("monitor", false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp,
		map[string]string{placeholder: realSecret}, []string{placeholder}, nil)
	p.dialTLS = dialBackend(backendLn)

	// Pre-swap body: the inert placeholder NAME + a foreign key.
	body := fmt.Sprintf(`{"auth":"%s","note":"foreign %s"}`, placeholder, dlpAKIA)
	if status := doPostThroughProxy(t, p, caCertPEM, "application/json", body); status != 200 {
		t.Fatalf("must forward; got %d", status)
	}
	// Backend must have received the SWAPPED body (placeholder -> real value),
	// proving swapSecrets still ran after dlpScan left the placeholder intact.
	got := backendBody(rb)
	if !strings.Contains(got, realSecret) {
		t.Fatalf("placeholder was not swapped downstream: %q", got)
	}
	if strings.Contains(got, placeholder) {
		t.Fatalf("placeholder name still present after swap: %q", got)
	}
	if !strings.Contains(got, dlpAKIA) {
		t.Fatalf("foreign key should pass through unmutated (monitor): %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", ss.snapshot())
	}
	// The foreign key is detected (pre-swap body had it).
	if !containsStr(ev.DataClasses, "credentials") {
		t.Fatalf("expected credentials from foreign key, got %v", ev.DataClasses)
	}
	// The real swapped secret VALUE must never appear in the event.
	if eventContains(t, *ev, realSecret) {
		t.Fatalf("real secret value leaked into event: %+v", ev)
	}
	if ev.SecretRef == "" {
		t.Fatalf("expected a secret-by-reference on the swap event, got %+v", ev)
	}
}

// Test 4: an over-cap (>1 MB) body is scanned on its first 1 MB, flags
// DLPPartial, and is otherwise forwarded unchanged.
func TestDLP_OverCapPartial(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	dlp := NewDLPScanner("monitor", false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	// AKIA in the first 1 MB, then pad well past the 1 MB scan cap (still under the
	// 10 MB body limit).
	body := dlpAKIA + " " + strings.Repeat("a", (1<<20)+4096)
	if status := doPostThroughProxy(t, p, caCertPEM, "text/plain", body); status != 200 {
		t.Fatalf("over-cap must forward; got %d", status)
	}
	if got := backendBody(rb); got != body {
		t.Fatalf("over-cap body not byte-intact at upstream (len got %d want %d)", len(got), len(body))
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", ss.snapshot())
	}
	if !ev.DLPPartial {
		t.Fatalf("over-cap body must flag DLPPartial, got %+v", ev)
	}
	if !containsStr(ev.DataClasses, "credentials") {
		t.Fatalf("expected credentials from first 1 MB, got %v", ev.DataClasses)
	}
}

// Test 5: a non-scannable content-type (application/octet-stream) is NOT scanned
// (no body read for scanning), flagged partial/unscanned, and forwarded.
func TestDLP_NonScannableSkipped(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	dlp := NewDLPScanner("monitor", false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	body := fmt.Sprintf("binary blob with %s inside", dlpAKIA)
	if status := doPostThroughProxy(t, p, caCertPEM, "application/octet-stream", body); status != 200 {
		t.Fatalf("non-scannable must forward; got %d", status)
	}
	if got := backendBody(rb); got != body {
		t.Fatalf("non-scannable body not byte-intact: got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", ss.snapshot())
	}
	if !ev.DLPPartial {
		t.Fatalf("non-scannable body must flag DLPPartial, got %+v", ev)
	}
	if len(ev.DataClasses) != 0 {
		t.Fatalf("non-scannable body must not be scanned (no classes), got %v", ev.DataClasses)
	}
	if ev.DLPAction != "monitor" {
		t.Fatalf("expected DLPAction=monitor (DLP saw the request), got %q", ev.DLPAction)
	}
}

// Test 6 (regression): an over-cap (>10 MB) body with NO placeholders and NO MCP
// is FORWARDED, not 413'd — DLP is fail-open and must never turn an over-cap body
// into a block, even in monitor mode. The body is NOT scanned (over the buffer
// cap), so DLPPartial is flagged and DataClasses stays empty. The contrast run
// (DLP off) proves DLP-on did not change forward-vs-block.
func TestDLP_OverCapForwardsNot413(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)

	// A body strictly larger than the 10 MB swap buffer, no placeholders/MCP.
	body := strings.Repeat("a", maxBodySwapSize+4096)

	// DLP monitor: must forward (fail-open), not 413.
	backendLn, rb := startBackend(t, caCert, caKey)
	dlp := NewDLPScanner("monitor", false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	if status := doPostThroughProxy(t, p, caCertPEM, "application/json", body); status != 200 {
		t.Fatalf("over-cap body under DLP monitor must FORWARD (fail-open), got %d", status)
	}
	if got := backendBody(rb); got != body {
		t.Fatalf("over-cap body must reach upstream intact (len got %d want %d)", len(got), len(body))
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", ss.snapshot())
	}
	if !ev.DLPPartial {
		t.Fatalf("over-cap forward must flag DLPPartial, got %+v", ev)
	}
	if len(ev.DataClasses) != 0 {
		t.Fatalf("over-cap body must not be scanned (no classes), got %v", ev.DataClasses)
	}

	// Contrast: DLP off — the same request also forwards, proving DLP-on did not
	// change the forward-vs-block outcome.
	backendLn2, rb2 := startBackend(t, caCert, caKey)
	p2, _ := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, map[string]string{}, nil, nil)
	p2.dialTLS = dialBackend(backendLn2)
	if status := doPostThroughProxy(t, p2, caCertPEM, "application/json", body); status != 200 {
		t.Fatalf("DLP-off contrast must also forward the same body, got %d", status)
	}
	if got := backendBody(rb2); got != body {
		t.Fatalf("DLP-off contrast: over-cap body not intact at upstream")
	}
}

// Test 7: an unknown-length / chunked request (ContentLength -1) under DLP
// monitor is FORWARDED without reading — Phase 1 does not stream-scan chunked
// bodies, so DLPPartial is flagged, DataClasses stays empty, and it never 413s.
func TestDLP_UnknownLengthForwards(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	dlp := NewDLPScanner("monitor", false, false)
	p, ss := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp, map[string]string{}, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	body := fmt.Sprintf(`{"note":"chunked %s here"}`, dlpAKIA)
	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("POST", "https://backend.test/ingest", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Force chunked framing: no Content-Length reaches the proxy (ContentLength -1).
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	_ = readAllResp(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("chunked body under DLP monitor must forward, got %d", resp.StatusCode)
	}
	if got := backendBody(rb); got != body {
		t.Fatalf("chunked body must reach upstream intact: got %q want %q", got, body)
	}
	time.Sleep(50 * time.Millisecond)
	ev := findEvent(ss.snapshot(), "https", "allow")
	if ev == nil {
		t.Fatalf("expected https allow event, got %+v", ss.snapshot())
	}
	if !ev.DLPPartial {
		t.Fatalf("unknown-length body must flag DLPPartial, got %+v", ev)
	}
	if len(ev.DataClasses) != 0 {
		t.Fatalf("unknown-length body must not be scanned (no classes), got %v", ev.DataClasses)
	}
	if ev.DLPAction != "monitor" {
		t.Fatalf("expected DLPAction=monitor (DLP saw the request), got %q", ev.DLPAction)
	}
}

// Test 8: the swap 413 contract is unchanged by DLP. An over-cap (>10 MB) body
// with a placeholder configured still 413s — swapSecrets' own contract — proving
// DLP (which runs first and is fail-open) did not pre-empt or alter that path.
func TestDLP_SwapContractStill413s(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	dlp := NewDLPScanner("monitor", false, false)
	p, _ := startTestProxyWithDLP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, dlp,
		map[string]string{"PLACEHOLDER_001": "real-secret-value"}, []string{"PLACEHOLDER_001"}, nil)
	p.dialTLS = dialBackend(backendLn)

	bigBody := strings.Repeat("A", maxBodySwapSize+1)
	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("POST", "https://backend.test/v1/chat", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(bigBody))
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 413 {
		t.Fatalf("swap contract: over-cap body with a placeholder must still 413, got %d", resp.StatusCode)
	}
	if got := backendBody(rb); got != "" {
		t.Fatalf("upstream must not receive an over-cap swap body, got %d bytes", len(got))
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
