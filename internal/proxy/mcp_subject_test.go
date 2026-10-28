package proxy

import (
	"bufio"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// W-P1-GPOL-04: the verified subject reaches the MCP gateway through
// RequestMeta on every transport. The gateway ignores it for now; these tests
// pin the plumbing with a recording fake.

// metaGateway records the RequestMeta of every OnRequest and passes everything.
type metaGateway struct {
	mu    sync.Mutex
	metas []gateway.RequestMeta
}

func (g *metaGateway) OnRequest(_, _, _ string, _ http.Header, _ []byte, meta gateway.RequestMeta) gateway.Verdict {
	g.mu.Lock()
	g.metas = append(g.metas, meta)
	g.mu.Unlock()
	return gateway.Verdict{Action: gateway.Pass}
}

func (g *metaGateway) OnResponse(string, int, http.Header, []byte) gateway.Verdict {
	return gateway.Verdict{Action: gateway.Pass}
}
func (g *metaGateway) MaxResponseScanBytes() int { return 1 << 20 }
func (g *metaGateway) Close() error              { return nil }
func (g *metaGateway) ScansWSFrames()            {}

// waitMetas blocks until n requests were recorded and returns a copy.
func (g *metaGateway) waitMetas(t *testing.T, n int) []gateway.RequestMeta {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		if len(g.metas) >= n {
			out := append([]gateway.RequestMeta(nil), g.metas...)
			g.mu.Unlock()
			return out
		}
		g.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("gateway saw fewer than %d requests", n)
	return nil
}

func subjectOf(t *testing.T, m gateway.RequestMeta) string {
	t.Helper()
	if m.Subject == nil {
		return ""
	}
	return m.Subject.Sub
}

func TestMCPSeam_SubjectReachesGateway(t *testing.T) {
	gw := &metaGateway{}
	e := newIDEnvCfg(t, IdentityModeAttribute, func(c *Config) { c.MCP = gw })

	cases := []struct {
		name string
		tok  string
		want string
	}{
		{"valid", "tok-alice", "alice"},
		{"none", "", ""},
		{"invalid", "tok-bad", ""},
		{"expired", "tok-expired", ""},
	}

	t.Run("h1", func(t *testing.T) {
		c := e.h1("")
		for i, tc := range cases {
			extra := "Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(mcpExecCmdBody)) + "\r\n"
			if tc.tok != "" {
				extra += "X-Warden-Identity: Bearer " + tc.tok + "\r\n"
			}
			_, _ = io.WriteString(c.tc, "POST /mcp HTTP/1.1\r\nHost: "+idHost+"\r\n"+extra+"\r\n"+mcpExecCmdBody)
			resp, err := http.ReadResponse(c.br, nil)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			got := gw.waitMetas(t, i+1)[i]
			if s := subjectOf(t, got); s != tc.want {
				t.Errorf("h1 %s: subject = %q, want %q", tc.name, s, tc.want)
			}
		}
	})

	t.Run("h2", func(t *testing.T) {
		base := len(gw.waitMetas(t, 0))
		cc := e.h2("")
		for i, tc := range cases {
			req, _ := http.NewRequest("POST", "https://"+idHost+"/mcp", strings.NewReader(mcpExecCmdBody))
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
			got := gw.waitMetas(t, base+i+1)[base+i]
			if s := subjectOf(t, got); s != tc.want {
				t.Errorf("h2 %s: subject = %q, want %q", tc.name, s, tc.want)
			}
		}
	})
}

func TestMCPWS_SubjectFromUpgrade(t *testing.T) {
	gw := &metaGateway{}
	e := newIDEnvCfg(t, IdentityModeAttribute, func(c *Config) { c.MCP = gw })
	_, _, caCert, caKey := generateTestCA(t)
	be := &wsBackend{}
	e.p.dialTLS = dialBackend(startWSBackend(t, caCert, caKey, be))

	upgrade := func(hdr string) func(string) {
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
		send := func(body string) {
			f := deniedTextFrame()
			f.Payload = []byte(body)
			_, _ = tc.Write(frameWire(f))
		}
		return send
	}

	// Valid identity on the upgrade: every frame carries alice, even after the
	// token's expiry passes (the subject is fixed for the connection).
	send := upgrade("X-Warden-Identity: Bearer tok-alice\r\n")
	send(mcpExecCmdBody)
	e.clk.advance(2 * time.Hour)
	send(mcpExecCmdBody)
	got := gw.waitMetas(t, 2)
	for i, m := range got {
		if s := subjectOf(t, m); s != "alice" {
			t.Errorf("frame %d subject = %q, want alice", i, s)
		}
	}

	// No identity on the upgrade: frames carry a nil subject.
	send = upgrade("")
	send(mcpExecCmdBody)
	got = gw.waitMetas(t, 3)
	if m := got[2]; m.Subject != nil {
		t.Errorf("anonymous upgrade frame subject = %+v, want nil", m.Subject)
	}
}
