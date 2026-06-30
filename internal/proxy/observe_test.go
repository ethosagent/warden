package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// syncBuf is a goroutine-safe buffer for capturing slog output written from the
// proxy's connection-handling goroutines.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestObservabilityWiring_DenyEmitsMetricAndLog drives a CONNECT to a
// non-allowlisted domain through a proxy wired with a live OTel emitter and a
// JSON logger, then asserts the deny metric is scrapeable and the decision is
// logged — without the raw domain ever becoming a metric label.
func TestObservabilityWiring_DenyEmitsMetricAndLog(t *testing.T) {
	metrics, handler, shutdown, err := observability.New(observability.Config{
		Enabled:        true,
		ServiceName:    "warden-test",
		MetricsEnabled: true,
	})
	if err != nil {
		t.Fatalf("observability.New: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	logs := &syncBuf{}
	logger, _ := observability.NewLogger(logs, "info", "json")

	entries := []config.AllowlistEntry{{Domain: "allowed.example.com", Port: 443}}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: entries}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  &fakes.FakeAnalyticsStore{},
		Metrics:    metrics,
		Logger:     logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	waitForAddr(t, p)

	const rawDomain = "exfil-target.evil.example.com"
	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", rawDomain, rawDomain)
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "403") {
		t.Fatalf("expected 403, got %q", resp)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(br)

	// Metric assertions: deny counter present, raw domain never a label.
	body := scrapeMetrics(t, handler)
	if !strings.Contains(body, "warden_requests_total") {
		t.Fatalf("requests_total missing:\n%s", body)
	}
	if !strings.Contains(body, `decision="deny"`) {
		t.Fatalf("deny decision label missing:\n%s", body)
	}
	if !strings.Contains(body, "warden_blocked_total") {
		t.Fatalf("blocked_total missing:\n%s", body)
	}
	if strings.Contains(body, rawDomain) || strings.Contains(body, "domain=") {
		t.Fatalf("raw domain leaked into metrics (cardinality violation):\n%s", body)
	}

	// Log assertions: one structured deny record carrying the bounded fields.
	out := logs.String()
	if !strings.Contains(out, "egress decision") {
		t.Fatalf("decision log missing:\n%s", out)
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["decision"] == "deny" && rec["domain"] == rawDomain {
			found = true
			if rec["level"] != "WARN" {
				t.Errorf("deny should log at WARN, got %v", rec["level"])
			}
		}
	}
	if !found {
		t.Fatalf("no deny decision record with domain field:\n%s", out)
	}
}

func waitForAddr(t *testing.T, p *Proxy) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if p.Addr() != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
}

func scrapeMetrics(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
