package proxy

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/test/fakes"
)

// A WebSocket upgrade whose query held a placeholder records its events (the
// enforce refusal, and the pumped session's deny) with the agent's query only.
func TestEvents_WSQuerySwapNeverRendersTheValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gw     func() MCPGateway
		denied bool
	}{
		{"refused", func() MCPGateway { return nonScanningGateway{enforcing: true} }, false},
		{"pumped_deny", func() MCPGateway {
			return &scanningDecorator{inner: gateway.New(enforceMCPConfig(), scan.NewScanner(), nil)}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
			backendLn := startWSBackend(t, caCert, caKey, &wsBackend{})
			logs := &echoLogBuf{}
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
			if err := os.WriteFile(certFile, caCertPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyFile, caKeyPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			store := &syncStore{}
			p, err := New(Config{
				ListenAddr: "127.0.0.1:0",
				Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
					{Domain: "backend.test", Port: 443},
				}}),
				Secrets:          &fakes.FakeSecretProvider{Values: map[string]string{echoPlaceholder: echoTestValue}},
				PlaceholderNames: []string{echoPlaceholder},
				Analytics:        store,
				AgentID:          "agent",
				MCP:              tc.gw(),
				Logger:           slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
				CACertPath:       certFile,
				CAKeyPath:        keyFile,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go func() { _ = p.Serve(ctx) }()
			waitForAddr(t, p)
			p.dialTLS = dialBackend(backendLn)

			conn := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
			t.Cleanup(func() { _ = conn.Close() })
			_, _ = io.WriteString(conn, "GET /mcp?a="+echoPlaceholder+" HTTP/1.1\r\nHost: backend.test\r\nUpgrade: websocket\r\n"+
				"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
			br := bufio.NewReader(conn)
			if _, err := br.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			if tc.denied {
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
				}
				_, _ = conn.Write(frameWire(deniedTextFrame()))
				readUntilClose(t, br)
			}
			if !waitForDecisionEvent(t, store, "mcp", "deny") {
				t.Fatalf("no mcp deny event: %+v", store.snapshot())
			}
			for _, ev := range store.snapshot() {
				assertEventURLClean(t, ev)
			}
			if !strings.Contains(string(logs.bytes()), "a="+echoPlaceholder) {
				t.Fatalf("expected the original query in the log: %s", logs.bytes())
			}
			requireNoValue(t, "log output", logs.bytes())
		})
	}
}
