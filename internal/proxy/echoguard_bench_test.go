package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"testing"

	"github.com/ethosagent/warden/internal/mcp/ws"
)

// BenchmarkNoSwapRequest is the #389 no-regression proof: a request that carries no
// placeholder, through a proxy that HAS placeholders configured, must cost the same
// with the echo guard as without it (it records, scans and rewrites nothing). It
// uses only APIs present before the guard so the identical file runs on the base
// commit; compare base and new interleaved (see the PR notes).
func BenchmarkNoSwapRequest(b *testing.B) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(b)
	backendLn, _ := startBackend(b, caCert, caKey)
	names := []string{"WARDEN_PLACEHOLDER_001", "WARDEN_PLACEHOLDER_002"}
	values := map[string]string{names[0]: "sk-real-secret-value-1", names[1]: "sk-real-secret-value-2"}
	p, _ := startTestProxyWithSecrets(b, []string{"backend.test"}, caCertPEM, caKeyPEM, values, names)
	p.dialTLS = func(_, _ string, _ *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}
	tlsClient := dialProxyAndConnect(b, p.Addr().String(), "backend.test", caCertPEM)
	br := bufio.NewReader(tlsClient)
	req, err := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer not-a-placeholder")
	req.Header.Set("Accept-Encoding", "gzip")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := req.Write(tlsClient); err != nil {
			b.Fatal(err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// BenchmarkWSEchoGuardFrames prices the armed WebSocket frame guard (#399) per
// frame: a clean frame pays one needle scan plus the hold-back suffix scan, a
// frame carrying the value pays the scan and stops the pump. When the upgrade
// request swapped nothing the guard is never built and the pump runs with Echo
// nil — BenchmarkPumpEcho in internal/mcp/ws proves that side costs nothing.
func BenchmarkWSEchoGuardFrames(b *testing.B) {
	s := &requestScope{echoSecrets: []echoSecret{{name: "k", value: echoTestValue}}}
	g := (&Proxy{}).newWSEchoGuard(s)
	payload := []byte(`{"jsonrpc":"2.0","id":"2","result":{"content":[{"type":"text","text":"ok"}]}}`)
	for _, tc := range []struct {
		name  string
		frame ws.Frame
		want  bool // whether the guard must let the frame through
	}{
		{"clean", ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: payload}, true},
		{"hit", ws.Frame{Fin: true, Opcode: ws.OpcodeText,
			Payload: []byte(`{"note":"token ` + echoTestValue + `"}`)}, false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.frame.Payload)))
			for i := 0; i < b.N; i++ {
				clear, ok := g.Guard(tc.frame)
				if ok != tc.want || (ok && len(clear) != 1) {
					b.Fatalf("Guard = (%d frames, %v), want (%d, %v)", len(clear), ok, 1, tc.want)
				}
			}
		})
	}
}
