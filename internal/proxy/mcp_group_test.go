package proxy

import (
	"bufio"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/scan"
)

// W-P1-GPOL-11: a tool gated to a group is decided with the request's subject
// on HTTP/1.1 and h2, and with the upgrade's subject on every WebSocket frame.

const mcpPayBody = `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"pay","arguments":{}}}`

func payGateway() *gateway.Gateway {
	return gateway.New(config.MCPConfig{
		Enabled: true,
		Mode:    "enforce",
		Tools: config.MCPToolsConfig{
			Allow:       []string{"pay"},
			Constraints: map[string]config.MCPToolConstraints{"pay": {AllowWhen: &config.MCPToolCondition{Groups: []string{"finance"}}}},
		},
	}, scan.NewScanner(), nil)
}

func groupMCPEnv(t *testing.T) *idEnv {
	t.Helper()
	e := newIDEnvCfg(t, IdentityModeAttribute, func(c *Config) { c.MCP = payGateway() })
	e.v.Set("tok-fin", identity.Claims{Sub: "fran", Groups: []string{"finance"}, Expiry: e.clk.now().Add(time.Hour)}, identity.StatusValid, "")
	return e
}

var mcpGroupCases = []struct {
	name string
	tok  string
	want int
}{
	{"finance", "tok-fin", 200},
	{"eng", "tok-alice", 403},
	{"anonymous", "", 403},
	{"invalid", "tok-bad", 403},
}

func TestMCPGroupCondition_HTTP(t *testing.T) {
	e := groupMCPEnv(t)

	t.Run("h1", func(t *testing.T) {
		for _, tc := range mcpGroupCases {
			c := e.h1("") // a denied MCP request may close the connection
			extra := "Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(mcpPayBody)) + "\r\n"
			if tc.tok != "" {
				extra += "X-Warden-Identity: Bearer " + tc.tok + "\r\n"
			}
			_, _ = io.WriteString(c.tc, "POST /mcp HTTP/1.1\r\nHost: "+idHost+"\r\n"+extra+"\r\n"+mcpPayBody)
			resp, err := http.ReadResponse(c.br, nil)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("h1 %s: status = %d, want %d", tc.name, resp.StatusCode, tc.want)
			}
		}
	})

	t.Run("h2", func(t *testing.T) {
		cc := e.h2("")
		for _, tc := range mcpGroupCases {
			req, _ := http.NewRequest("POST", "https://"+idHost+"/mcp", strings.NewReader(mcpPayBody))
			req.Header.Set("Content-Type", "application/json")
			if tc.tok != "" {
				req.Header.Set("X-Warden-Identity", "Bearer "+tc.tok)
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("h2 %s: status = %d, want %d", tc.name, resp.StatusCode, tc.want)
			}
		}
	})
}

func TestMCPGroupCondition_WebSocket(t *testing.T) {
	e := groupMCPEnv(t)
	_, _, caCert, caKey := generateTestCA(t)

	// upgrade opens a WebSocket with hdr and sends one gated tools/call frame;
	// it reports whether the backend received the frame.
	upgrade := func(hdr string) bool {
		be := &wsBackend{}
		e.p.dialTLS = dialBackend(startWSBackend(t, caCert, caKey, be))
		conn, br, status := e.connect("")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status = %q", status)
		}
		tc := e.tlsOver(conn, br, "http/1.1")
		_, _ = io.WriteString(tc, "GET /mcp HTTP/1.1\r\nHost: "+idHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+hdr+"\r\n")
		r := bufio.NewReader(tc)
		line, err := r.ReadString('\n')
		if err != nil || !strings.Contains(line, "101") {
			t.Fatalf("upgrade status = %q, %v", line, err)
		}
		for {
			l, err := r.ReadString('\n')
			if err != nil || l == "\r\n" {
				break
			}
		}
		f := deniedTextFrame()
		f.Payload = []byte(mcpPayBody)
		_, _ = tc.Write(frameWire(f))
		select {
		case <-be.gotText:
			return true
		case <-time.After(500 * time.Millisecond):
			return false
		}
	}

	if !upgrade("X-Warden-Identity: Bearer tok-fin\r\n") {
		t.Error("finance upgrade: gated tool call was not forwarded")
	}
	if upgrade("X-Warden-Identity: Bearer tok-alice\r\n") {
		t.Error("eng upgrade: gated tool call reached the backend")
	}
	if upgrade("") {
		t.Error("anonymous upgrade: gated tool call reached the backend")
	}
}
