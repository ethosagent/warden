package proxy

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/mcp/ws"
)

// In enforce mode a denied WS tools/call is held and dropped: the backend never
// receives it, not even briefly before the Close.
func TestWS_EnforceDeniedCallNeverReachesBackend(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	be := &wsBackend{}
	backendLn := startWSBackend(t, caCert, caKey, be)

	p, ss := startTestProxyWithMCP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, enforceMCPConfig(), nil)
	p.dialTLS = dialBackend(backendLn)

	tlsClient, br := wsUpgradeThroughProxy(t, p, caCertPEM)
	denied := ws.Frame{
		Fin: true, Opcode: ws.OpcodeText, Masked: true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: []byte(mcpExecCmdBody),
	}
	if _, err := tlsClient.Write(frameWire(denied)); err != nil {
		t.Fatal(err)
	}
	if !readUntilClose(t, br) {
		t.Fatal("expected a Close frame to the client on enforce deny")
	}
	select {
	case got := <-be.gotText:
		t.Fatalf("denied message reached the backend: %q", got)
	case <-time.After(300 * time.Millisecond):
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if findEvent(ss.snapshot(), "mcp", "deny") != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected mcp deny event, got %+v", ss.snapshot())
}

// In enforce mode a poisoned SSE event is held and never written to the agent;
// the benign event before it arrives unchanged.
func TestMCP_SSEEnforcePoisonedEventNeverReachesAgent(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	benign := sseEvent(`{"jsonrpc":"2.0","id":"0","result":{}}`)
	rb := &mcpBackend{respStatus: 200, respCT: "text/event-stream", respBody: benign + sseEvent(mcpPoisonedList), chunked: true}
	backendLn := startMCPBackend(t, caCert, caKey, rb)

	p, ss := startTestProxyWithMCP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, enforceMCPConfig(), nil)
	p.dialTLS = dialBackend(backendLn)

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	req, _ := http.NewRequest("POST", "https://backend.test/mcp", strings.NewReader(mcpToolsList))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(mcpToolsList))
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != benign {
		t.Fatalf("agent received %q, want only the benign event %q", got, benign)
	}
	time.Sleep(50 * time.Millisecond)
	if ev := findEvent(ss.snapshot(), "mcp", "deny"); ev == nil || ev.Reason != "mcp_poisoning" {
		t.Fatalf("expected mcp_poisoning deny event, got %+v", ss.snapshot())
	}
}

// modeBlindGW scans (it embeds the MCPGateway interface) but, unlike the
// concrete gateway, does not expose Enforcing().
type modeBlindGW struct{ MCPGateway }

// A scanning gateway whose mode is unknown is HELD (fail safe), never silently
// downgraded to forward-then-scan; a gateway that reports monitor is not held.
func TestHoldMCP_UnknownModeFailsSafe(t *testing.T) {
	monitor := enforceMCPConfig()
	monitor.Mode = "monitor"
	p, _ := startTestProxyWithMCP(t, []string{"backend.test"}, nil, nil, monitor, nil)
	real := p.cfg.MCP

	if p.holdMCP(real) {
		t.Fatal("monitor-mode gateway must not be held")
	}
	if !p.holdMCP(modeBlindGW{real}) {
		t.Fatal("scanning gateway with unknown mode must be held")
	}
	p2, _ := startTestProxyWithMCP(t, []string{"backend.test"}, nil, nil, enforceMCPConfig(), nil)
	if !p2.holdMCP(p2.cfg.MCP) {
		t.Fatal("enforce-mode gateway must be held")
	}
}
