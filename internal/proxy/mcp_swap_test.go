package proxy

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/test/fakes"
)

func newAllowAllEvaluator() *policy.Evaluator {
	return policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "host"}}})
}

func newEmptySecrets() *fakes.FakeSecretProvider {
	return &fakes.FakeSecretProvider{Values: map[string]string{}}
}

// newMCPGateway builds a gateway from cfg with a scanner honoring its PII config,
// matching how the worker rebuilds one from distributed settings.
func newMCPGateway(cfg config.MCPConfig) *gateway.Gateway {
	return gateway.New(cfg, scan.NewScanner(scan.WithPhonePII(cfg.Scan.PII.Phone)), nil)
}

// allowExecCmdConfig is an enforce config that permits exec_cmd, so a request the
// stricter enforceMCPConfig() denies is allowed before the swap.
func allowExecCmdConfig() config.MCPConfig {
	c := enforceMCPConfig()
	c.Tools = config.MCPToolsConfig{Allow: []string{"exec_cmd"}}
	return c
}

// TestProxy_SetMCPGateway_RaceFree drives the hot-path read (mcpGateway → the
// gateway's OnRequest) concurrently with SetMCPGateway. Under `go test -race`
// the atomic pointer must show no data race.
func TestProxy_SetMCPGateway_RaceFree(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		MCP:        newMCPGateway(enforceMCPConfig()),
	})
	if err != nil {
		t.Fatal(err)
	}

	gwA := newMCPGateway(enforceMCPConfig())
	gwB := newMCPGateway(allowExecCmdConfig())

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: alternate the gateway (including nil to exercise the disabled path).
	wg.Add(1)
	go func() {
		defer wg.Done()
		// MCPGateway (not *gateway.Gateway) so the nil element is an untyped-nil
		// interface — exercising the disabled path — not a typed-nil *gateway.Gateway
		// that would read back as a non-nil interface wrapping a nil pointer.
		gws := []MCPGateway{gwA, gwB, nil}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				p.SetMCPGateway(gws[i%len(gws)])
				i++
			}
		}
	}()

	// Readers: snapshot the live gateway and call the hot-path entry point.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if gw := p.mcpGateway(); gw != nil {
						_ = gw.OnRequest("agent:host", "POST",
							"https://host/mcp", http.Header{}, []byte(mcpReadFileBody))
					}
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestProxy_SetMCPGateway_SwapsBehavior verifies a runtime swap changes the
// gateway the hot path enforces: exec_cmd is allowed (forwarded, 200) under the
// first gateway, then denied (403) after swapping to the stricter config.
func TestProxy_SetMCPGateway_SwapsBehavior(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	rb := &mcpBackend{respStatus: 200}
	backendLn := startMCPBackend(t, caCert, caKey, rb)

	// Boot with a gateway that ALLOWS exec_cmd.
	p, ss := startTestProxyWithMCP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, allowExecCmdConfig(), nil)
	p.dialTLS = dialBackend(backendLn)

	// Before swap: exec_cmd is allowed and forwarded.
	if status := postMCP(t, p.Addr().String(), caCertPEM, mcpExecCmdBody); status != 200 {
		t.Fatalf("before swap: expected 200 (allowed), got %d", status)
	}
	time.Sleep(50 * time.Millisecond)
	if findEvent(ss.snapshot(), "mcp", "allow") == nil {
		t.Fatalf("before swap: expected mcp allow event, got %+v", ss.snapshot())
	}

	// Swap to the stricter gateway (allows only read_file → denies exec_cmd).
	p.SetMCPGateway(newMCPGateway(enforceMCPConfig()))

	// After swap: exec_cmd is denied with 403.
	if status := postMCP(t, p.Addr().String(), caCertPEM, mcpExecCmdBody); status != 403 {
		t.Fatalf("after swap: expected 403 (denied), got %d", status)
	}
	time.Sleep(50 * time.Millisecond)
	if findEvent(ss.snapshot(), "mcp", "deny") == nil {
		t.Fatalf("after swap: expected mcp deny event, got %+v", ss.snapshot())
	}
}

// TestProxy_NilMCPGateway_NoOp confirms a proxy constructed with no gateway loads
// nil through the atomic pointer (MCP disabled — today's behavior), and that
// swapping to nil disables a previously-configured gateway.
func TestProxy_NilMCPGateway_NoOp(t *testing.T) {
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    newEmptySecrets(),
		Analytics:  &syncStore{},
		MCP:        nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.mcpGateway() != nil {
		t.Fatal("expected nil gateway when MCP not configured")
	}

	gw := newMCPGateway(enforceMCPConfig())
	p.SetMCPGateway(gw)
	if p.mcpGateway() != gw {
		t.Fatal("expected swapped-in gateway")
	}
	p.SetMCPGateway(nil)
	if p.mcpGateway() != nil {
		t.Fatal("expected nil after disabling swap")
	}
}

// postMCP issues a single JSON-RPC POST through the proxy and returns the status.
func postMCP(t *testing.T, proxyAddr string, caCertPEM []byte, body string) int {
	t.Helper()
	tlsClient := dialProxyAndConnect(t, proxyAddr, "backend.test", caCertPEM)
	req, _ := http.NewRequest("POST", "https://backend.test/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}
