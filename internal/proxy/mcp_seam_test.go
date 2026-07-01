package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// fakeMCPGateway is a package-local fake MCPGateway that forces a Deny on every
// request. It exists only to prove the proxy's hot path depends on the MCPGateway
// interface (not the concrete *gateway.Gateway): swapping this in must deny a
// request the real backend would have allowed. Its atomic counter also lets the
// test assert the interface method was actually invoked.
type fakeMCPGateway struct {
	onRequestCalls int
}

func (f *fakeMCPGateway) OnRequest(sessionKey, method, url string, hdr http.Header, body []byte) gateway.Verdict {
	f.onRequestCalls++
	return gateway.Verdict{Action: gateway.Deny, Reason: "fake_deny", Tool: "fake"}
}

func (f *fakeMCPGateway) OnResponse(sessionKey string, status int, hdr http.Header, body []byte) gateway.Verdict {
	return gateway.Verdict{Action: gateway.Pass}
}

func (f *fakeMCPGateway) MaxResponseScanBytes() int { return 1 << 20 }

func (f *fakeMCPGateway) Close() error { return nil }

// TestProxy_MCPGateway_InterfaceSeam_ForcesDeny proves the request hot path
// depends only on the MCPGateway interface. A proxy is booted with a real
// gateway that ALLOWS exec_cmd (so the request would forward, 200). A fake
// MCPGateway that forces Deny is then swapped in via SetMCPGateway; the same
// request must now be denied (403), and the fake's OnRequest must have run —
// demonstrating the proxy invoked the interface, not a concrete type.
func TestProxy_MCPGateway_InterfaceSeam_ForcesDeny(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	rb := &mcpBackend{respStatus: 200}
	backendLn := startMCPBackend(t, caCert, caKey, rb)

	// Boot with a real gateway that ALLOWS exec_cmd.
	p, ss := startTestProxyWithMCP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, allowExecCmdConfig(), nil)
	p.dialTLS = dialBackend(backendLn)

	// Sanity: before the swap the real gateway allows exec_cmd (200).
	if status := postMCP(t, p.Addr().String(), caCertPEM, mcpExecCmdBody); status != 200 {
		t.Fatalf("before swap: expected 200 (allowed), got %d", status)
	}

	// Swap in the fake purely through the MCPGateway interface.
	fake := &fakeMCPGateway{}
	p.SetMCPGateway(fake)

	// After the swap the fake forces Deny → 403, with an mcp deny event.
	if status := postMCP(t, p.Addr().String(), caCertPEM, mcpExecCmdBody); status != 403 {
		t.Fatalf("after swap: expected 403 (fake deny), got %d", status)
	}
	if fake.onRequestCalls == 0 {
		t.Fatal("expected the fake MCPGateway.OnRequest to be invoked via the interface")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if findEvent(ss.snapshot(), "mcp", "deny") != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected mcp deny event from the fake gateway, got %+v", ss.snapshot())
}

// TestProxy_NilMetricsRecorder_HotPathNoPanic proves an untyped-nil
// MetricsRecorder never panics on the hot path: New substitutes a nopMetrics, so
// every RecordRequest/RecordBlocked call is a safe no-op. It drives a TCP deny
// (which records both) directly through storeDeny.
func TestProxy_NilMetricsRecorder_HotPathNoPanic(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		Metrics:    nil, // untyped-nil interface — must be substituted by New
	})
	if err != nil {
		t.Fatal(err)
	}
	// If Metrics were a non-nil interface wrapping nothing this would panic.
	p.storeDeny("example.com", 443, "tcp", "unsupported_protocol")
	p.cfg.Metrics.RecordRequest("allow", "https")
	p.cfg.Metrics.ObserveAddedLatency("mcp_scan", time.Second)
}

// TestProxy_SetMCPGateway_UntypedNilDisables proves that swapping to an
// untyped-nil MCPGateway makes mcpGateway() return a real nil (not a non-nil
// interface wrapping a nil pointer), so the hot path treats MCP as disabled.
func TestProxy_SetMCPGateway_UntypedNilDisables(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		MCP:        &fakeMCPGateway{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.mcpGateway() == nil {
		t.Fatal("expected the configured fake gateway before disabling")
	}

	var disabled MCPGateway // untyped-nil interface
	p.SetMCPGateway(disabled)
	if gw := p.mcpGateway(); gw != nil {
		t.Fatalf("expected nil gateway after untyped-nil swap, got %T", gw)
	}
}
