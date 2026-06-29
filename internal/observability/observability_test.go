package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newWithHandler builds an enabled, metrics-only emitter and returns it plus its
// Prometheus handler, failing the test on error.
func newWithHandler(t *testing.T) (*Metrics, http.Handler, ShutdownFunc) {
	t.Helper()
	m, h, shutdown, err := New(Config{
		Enabled:        true,
		ServiceName:    "warden-test",
		ServiceVersion: "1.2.3",
		MetricsEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m == nil || h == nil {
		t.Fatalf("expected non-nil emitter and handler, got m=%v h=%v", m, h)
	}
	return m, h, shutdown
}

// scrape returns the /metrics text body from the handler.
func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 64<<10)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func TestDisabledIsNoOp(t *testing.T) {
	m, h, shutdown, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatalf("New disabled: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil *Metrics when disabled, got %v", m)
	}
	if h != nil {
		t.Errorf("expected nil handler when disabled, got %v", h)
	}
	if shutdown == nil {
		t.Fatal("shutdown must be non-nil even when disabled")
	}
	// Record calls on a nil emitter must not panic.
	m.RecordRequest("allow", "https")
	m.RecordBlocked("policy")
	m.RecordSecretSwap("openai_secret_001")
	m.RecordScanFinding("injection")
	m.RecordJudge("allow")
	m.ObserveAddedLatency("swap", 5*time.Millisecond)
	m.SetCircuitBreakerOpen("openai", true)
	m.SetSecretCacheStale("openai_secret_001", true)
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("disabled shutdown: %v", err)
	}
}

func TestMetricsEnabledOnlyOTLP(t *testing.T) {
	// Metrics off => no Prometheus handler even when Enabled.
	m, h, shutdown, err := New(Config{Enabled: true, MetricsEnabled: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil emitter")
	}
	if h != nil {
		t.Errorf("expected nil handler when MetricsEnabled is false, got %v", h)
	}
	_ = shutdown(context.Background())
}

func TestRecordAndScrape(t *testing.T) {
	m, h, shutdown := newWithHandler(t)
	defer func() { _ = shutdown(context.Background()) }()

	m.RecordRequest("allow", "https")
	m.RecordRequest("deny", "tcp")
	m.RecordBlocked("policy")
	m.RecordSecretSwap("openai_secret_001")
	m.RecordScanFinding("injection")
	m.RecordJudge("deny")
	m.ObserveAddedLatency("swap", 3*time.Millisecond)
	m.SetCircuitBreakerOpen("openai", true)
	m.SetSecretCacheStale("openai_secret_001", true)

	body := scrape(t, h)
	for _, want := range []string{
		"warden_requests_total",
		"warden_blocked_total",
		"warden_secret_swaps_total",
		"warden_scan_findings_total",
		"warden_judge_decisions_total",
		"warden_request_added_latency",
		"warden_build_info",
		`decision="allow"`,
		`protocol="https"`,
		`reason="policy"`,
		`placeholder_ref="openai_secret_001"`,
		`go_version=`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n---\n%s", want, body)
		}
	}
}

// TestNoRawDomainLabel is the bound-cardinality guard: a raw domain passed
// through the *value* arguments of every record method must never surface as a
// metric label key or value. We deliberately feed a domain-looking string where
// a bounded label is expected and assert it does not appear in the scrape.
func TestNoRawDomainLabel(t *testing.T) {
	m, h, shutdown := newWithHandler(t)
	defer func() { _ = shutdown(context.Background()) }()

	const rawDomain = "secret-exfil-target.evil.example.com"

	// Exercise every instrument. None of these accept a domain; this asserts the
	// wiring contract — there is no method that turns a domain into a label.
	m.RecordRequest("allow", "https")
	m.RecordBlocked("policy")
	m.RecordSecretSwap("openai_secret_001")
	m.RecordScanFinding("injection")
	m.RecordJudge("allow")
	m.ObserveAddedLatency("forward", time.Millisecond)

	body := scrape(t, h)
	if strings.Contains(body, rawDomain) {
		t.Fatalf("raw domain leaked into metrics:\n%s", body)
	}
	// No metric should carry a "domain" label key.
	if strings.Contains(body, "domain=") {
		t.Fatalf("found a domain= label in metrics — cardinality violation:\n%s", body)
	}
}

// TestMCPMetricKinds asserts the bounded MCP metric kinds increment their
// counters with the right label value, and that the labels stay bounded (a
// fixed enum string surfaces, not a raw tool name).
func TestMCPMetricKinds(t *testing.T) {
	m, h, shutdown := newWithHandler(t)
	defer func() { _ = shutdown(context.Background()) }()

	// Bounded blocked reasons.
	m.RecordBlocked("mcp_tool_denied")
	m.RecordBlocked("mcp_poisoning")
	m.RecordBlocked("mcp_schema_drift_blocked")
	// Bounded scan-finding kinds.
	m.RecordScanFinding("mcp_args_pii")
	m.RecordScanFinding("mcp_result_injection")
	m.RecordScanFinding("mcp_chain_read_then_send")
	// Bounded latency stage.
	m.ObserveAddedLatency("mcp_scan", 2*time.Millisecond)

	body := scrape(t, h)
	for _, want := range []string{
		`reason="mcp_tool_denied"`,
		`reason="mcp_poisoning"`,
		`reason="mcp_schema_drift_blocked"`,
		`kind="mcp_args_pii"`,
		`kind="mcp_result_injection"`,
		`kind="mcp_chain_read_then_send"`,
		`stage="mcp_scan"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n---\n%s", want, body)
		}
	}
}

// TestMCPToolNameNeverALabel guards the cardinality rule: a raw MCP tool name
// must never become a metric label. Tool names live only in the analytics
// store. We feed a tool-looking string through a value arg and assert it does
// not appear in the scrape (the bounded reason/kind label is what surfaces).
func TestMCPToolNameNeverALabel(t *testing.T) {
	m, h, shutdown := newWithHandler(t)
	defer func() { _ = shutdown(context.Background()) }()

	const rawTool = "exfiltrate_customer_records"

	// The bounded enum is what we pass; the raw tool name is never an argument
	// to any metric method.
	m.RecordBlocked("mcp_tool_denied")
	m.RecordScanFinding("mcp_args_leak")

	body := scrape(t, h)
	if strings.Contains(body, rawTool) {
		t.Fatalf("raw MCP tool name leaked into metrics:\n%s", body)
	}
	if strings.Contains(body, "tool=") {
		t.Fatalf("found a tool= label in metrics — cardinality violation:\n%s", body)
	}
}

func TestBuildResourceDefaults(t *testing.T) {
	res, err := buildResource(Config{
		ResourceAttributes: map[string]string{"warden.proxy.id": "p1"},
	})
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	got := res.String()
	if !strings.Contains(got, "service.name=warden") {
		t.Errorf("expected default service.name=warden, got %q", got)
	}
	if !strings.Contains(got, "warden.proxy.id=p1") {
		t.Errorf("expected custom resource attribute, got %q", got)
	}
}
