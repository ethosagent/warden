package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/mcp/ws"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/test/fakes"
)

// scanningDecorator wraps a *gateway.Gateway, implementing MCPGateway purely by
// delegation. It is NOT the concrete *gateway.Gateway, so the old
// gw.(*gateway.Gateway) assertion would have left the pump's GW nil and silently
// forwarded frames unscanned. It opts into the WS-scan capability by promoting
// ScansWSFrames/Enforcing (both delegated), modelling a future audit/metrics
// decorator that must still drive frame scanning through the interface.
type scanningDecorator struct {
	inner *gateway.Gateway
	reqN  atomic.Int64
}

func (d *scanningDecorator) OnRequest(sessionKey, method, url string, hdr http.Header, body []byte) gateway.Verdict {
	d.reqN.Add(1)
	return d.inner.OnRequest(sessionKey, method, url, hdr, body)
}

func (d *scanningDecorator) OnResponse(sessionKey string, status int, hdr http.Header, body []byte) gateway.Verdict {
	return d.inner.OnResponse(sessionKey, status, hdr, body)
}

func (d *scanningDecorator) MaxResponseScanBytes() int { return d.inner.MaxResponseScanBytes() }
func (d *scanningDecorator) Close() error              { return d.inner.Close() }
func (d *scanningDecorator) ScansWSFrames()            { d.inner.ScansWSFrames() }
func (d *scanningDecorator) Enforcing() bool           { return d.inner.Enforcing() }

// nonScanningGateway is an MCPGateway that does NOT provide the WS-scan capability
// (no ScansWSFrames marker) but does expose the live mode via Enforcing. It models
// a gateway/decorator that cannot scan WS frames, exercising the fail-closed
// (enforce) and logged-downgrade (monitor/off) branches.
type nonScanningGateway struct{ enforcing bool }

func (g nonScanningGateway) OnRequest(string, string, string, http.Header, []byte) gateway.Verdict {
	return gateway.Verdict{Action: gateway.Pass}
}

func (g nonScanningGateway) OnResponse(string, int, http.Header, []byte) gateway.Verdict {
	return gateway.Verdict{Action: gateway.Pass}
}

func (g nonScanningGateway) MaxResponseScanBytes() int { return 1 << 20 }
func (g nonScanningGateway) Close() error              { return nil }
func (g nonScanningGateway) Enforcing() bool           { return g.enforcing }

// startWSSeamProxy builds a proxy allowlisting backend.test with a caller-supplied
// MCP gateway, logger, and metrics (all optional except gw), mirroring
// startTestProxyWithMCP but letting the WS-seam tests inject a decorator/fake
// gateway and capture logs/metrics.
func startWSSeamProxy(t *testing.T, caCertPEM, caKeyPEM []byte, gw MCPGateway, logger *slog.Logger, metrics *observability.Metrics) (*Proxy, *syncStore) {
	t.Helper()
	store := &syncStore{}
	certFile := filepath.Join(t.TempDir(), "ca.crt")
	keyFile := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, caKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: "backend.test", Port: 443},
		}}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
		AgentID:    "agent",
		MCP:        gw,
		Logger:     logger,
		Metrics:    metrics,
		CACertPath: certFile,
		CAKeyPath:  keyFile,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	waitForAddr(t, p)
	return p, store
}

// wsUpgradeStatus performs the WebSocket upgrade handshake through the proxy and
// returns the raw status line plus the reader/conn, WITHOUT asserting a 101 — so a
// fail-closed refusal (502) can be inspected.
func wsUpgradeStatus(t *testing.T, p *Proxy, caCertPEM []byte) (statusLine string, br *bufio.Reader, conn *tls.Conn) {
	t.Helper()
	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	_, _ = io.WriteString(tlsClient,
		"GET /mcp HTTP/1.1\r\nHost: backend.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	r := bufio.NewReader(tlsClient)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	return line, r, tlsClient
}

// TestWS_DecoratorScansFrames is the core bug-fix proof: a decorator that wraps
// *gateway.Gateway (NOT the concrete type) still gets WS frames scanned. A denied
// tools/call sent as a frame is caught THROUGH the wrapper — under the old
// concrete assertion it would have forwarded verbatim, unscanned.
func TestWS_DecoratorScansFrames(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	be := &wsBackend{}
	backendLn := startWSBackend(t, caCert, caKey, be)

	real := gateway.New(enforceMCPConfig(), scan.NewScanner(), nil)
	dec := &scanningDecorator{inner: real}
	p, ss := startWSSeamProxy(t, caCertPEM, caKeyPEM, dec, nil, nil)
	p.dialTLS = dialBackend(backendLn)

	tlsClient, br := wsUpgradeThroughProxy(t, p, caCertPEM)

	denied := frameWire(deniedTextFrame())
	if _, err := tlsClient.Write(denied); err != nil {
		t.Fatal(err)
	}

	if !readUntilClose(t, br) {
		t.Fatal("expected a Close frame — a decorator over the gateway must still drive WS frame scanning")
	}
	if !waitForDecisionEvent(t, ss, "mcp", "deny") {
		t.Fatalf("expected mcp deny event through the decorator, got %+v", ss.snapshot())
	}
	if dec.reqN.Load() == 0 {
		t.Fatal("decorator OnRequest never called — frame scan bypassed the interface")
	}
}

// TestWS_EnforceFailsClosedWithoutScanCapability proves fail-closed: a gateway
// lacking the WS-scan capability, in enforce mode, causes the 101 to be REFUSED —
// the client gets a 502, the pump never runs (backend receives no frames), and a
// blocked decision (event + metric) is recorded.
func TestWS_EnforceFailsClosedWithoutScanCapability(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	be := &wsBackend{}
	backendLn := startWSBackend(t, caCert, caKey, be)

	metrics, handler, shutdown, err := observability.New(observability.Config{
		Enabled: true, ServiceName: "warden-test", MetricsEnabled: true,
	})
	if err != nil {
		t.Fatalf("observability.New: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	p, ss := startWSSeamProxy(t, caCertPEM, caKeyPEM, nonScanningGateway{enforcing: true}, nil, metrics)
	p.dialTLS = dialBackend(backendLn)

	status, _, conn := wsUpgradeStatus(t, p, caCertPEM)
	t.Cleanup(func() { _ = conn.Close() })
	if !strings.Contains(status, "502") {
		t.Fatalf("expected 502 refusal in enforce mode, got %q", status)
	}

	if !waitForDecisionEvent(t, ss, "mcp", "deny") {
		t.Fatalf("expected a blocked mcp deny event, got %+v", ss.snapshot())
	}
	ev := findEvent(ss.snapshot(), "mcp", "deny")
	if ev.Reason != "mcp_ws_unscannable" {
		t.Fatalf("expected reason mcp_ws_unscannable, got %q", ev.Reason)
	}
	select {
	case f := <-be.gotText:
		t.Fatalf("pump ran on a refused upgrade: backend received frame %q", f)
	case <-time.After(200 * time.Millisecond):
	}

	body := scrapeMetrics(t, handler)
	if !strings.Contains(body, "warden_blocked_total") {
		t.Fatalf("blocked_total metric missing:\n%s", body)
	}
}

// TestWS_MonitorDowngradeLogsOnce proves the monitor/off downgrade: a gateway
// lacking the WS-scan capability, NOT enforcing, forwards frames pass-through
// (today's behavior) and logs the degraded control EXACTLY ONCE across multiple
// upgrades.
func TestWS_MonitorDowngradeLogsOnce(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	be := &wsBackend{}
	backendLn := startWSBackend(t, caCert, caKey, be)

	logs := &syncBuf{}
	logger, _ := observability.NewLogger(logs, "info", "json")

	p, ss := startWSSeamProxy(t, caCertPEM, caKeyPEM, nonScanningGateway{enforcing: false}, logger, nil)
	p.dialTLS = dialBackend(backendLn)

	const upgrades = 3
	for i := 0; i < upgrades; i++ {
		tlsClient, _ := wsUpgradeThroughProxy(t, p, caCertPEM) // asserts 101 pass-through
		allowed := ws.Frame{
			Fin: true, Opcode: ws.OpcodeText, Masked: true,
			MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte(mcpReadFileBody),
		}
		if _, err := tlsClient.Write(frameWire(allowed)); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-be.gotText:
			if string(got) != mcpReadFileBody {
				t.Fatalf("forwarded payload mismatch: %q", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("backend did not receive pass-through frame")
		}
		_ = tlsClient.Close()
	}

	if !waitForDecisionEvent(t, ss, "mcp", "allow") {
		t.Fatalf("expected pass-through allow events, got %+v", ss.snapshot())
	}
	if n := strings.Count(logs.String(), "forwarding frames unscanned"); n != 1 {
		t.Fatalf("expected downgrade WARN logged exactly once across %d upgrades, got %d:\n%s",
			upgrades, n, logs.String())
	}
}

// deniedTextFrame builds a masked text frame carrying a denied tools/call.
func deniedTextFrame() ws.Frame {
	return ws.Frame{
		Fin: true, Opcode: ws.OpcodeText, Masked: true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: []byte(mcpExecCmdBody),
	}
}

// waitForEvent polls the store up to 2s for a proto+decision event.
func waitForDecisionEvent(t *testing.T, ss *syncStore, proto, decision string) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if findEvent(ss.snapshot(), proto, decision) != nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
