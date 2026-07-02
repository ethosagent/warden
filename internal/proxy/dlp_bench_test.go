package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/observability"
)

// benchBody builds a JSON-ish body of approximately n bytes with a single
// planted AKIA key near the front, so the scanner does real matching work rather
// than bailing on an empty body. The filler is space-separated words (prose-like)
// rather than one long token, so it does not degenerate into a giant base64 block
// that the scanner would decode — the numbers then reflect realistic bodies.
func benchBody(n int) string {
	prefix := `{"key":"` + dlpAKIA + `","pad":"`
	suffix := `"}`
	if n <= len(prefix)+len(suffix) {
		return prefix + suffix
	}
	fill := strings.Repeat("lorem ipsum dolor sit amet ", 1+(n-len(prefix)-len(suffix))/27)
	fill = fill[:n-len(prefix)-len(suffix)]
	return prefix + fill + suffix
}

// BenchmarkDLPScan measures the dlpScan stage in isolation across 1 KB / 100 KB /
// 1 MB request bodies. It builds a minimal requestScope with a pre-read body (so
// only the scan + finding-record cost is timed, not TLS or upstream I/O) and runs
// the real stage through a monitor-mode DLP scanner.
func BenchmarkDLPScan(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KB", 1 << 10},
		{"100KB", 100 << 10},
		{"1MB", 1 << 20},
	}
	for _, sz := range sizes {
		body := []byte(benchBody(sz.n))
		b.Run(sz.name, func(b *testing.B) {
			p := &Proxy{cfg: Config{
				Metrics: nopMetrics{},
				Logger:  observability.DiscardLogger(),
				DLP:     NewDLPScanner(config.DLPConfig{Mode: "monitor"}, false, false),
			}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Fresh scope per iteration with the body already buffered
				// (bodyRead=true), so the shared read is not re-timed and only the
				// scan path runs.
				req, _ := http.NewRequest("POST", "https://backend.test/ingest", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				s := &requestScope{req: req, reqBody: body, bodyRead: true}
				if p.dlpScan(s) {
					b.Fatal("dlpScan must never end the session in monitor mode")
				}
			}
		})
	}
}

// BenchmarkHandleHTTP_DLPOff / _DLPMonitor are the end-to-end off-vs-monitor
// delta: the same POST-with-body request driven through a real proxy, once with
// DLP disabled and once in monitor mode, so the added per-request cost of the
// dlpScan stage is directly comparable.
func BenchmarkHandleHTTP_DLPOff(b *testing.B) {
	benchHandleHTTPDLP(b, nil)
}

func BenchmarkHandleHTTP_DLPMonitor(b *testing.B) {
	benchHandleHTTPDLP(b, NewDLPScanner(config.DLPConfig{Mode: "monitor"}, false, false))
}

func benchHandleHTTPDLP(b *testing.B, dlp *DLPScanner) {
	b.Helper()
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(b)
	backendLn, _ := startBackend(b, caCert, caKey)

	p, _ := startTestProxyWithSecrets(b, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)
	// Set the DLP scanner directly on the running proxy. Benchmarks do not run
	// under -race (the gate runs `go test -bench` without it), and it is set once
	// before any request is issued below, so no concurrent hot-path read observes
	// a torn write.
	p.cfg.DLP = dlp
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(b, p.Addr().String(), "backend.test", caCertPEM)
	br := bufio.NewReader(tlsClient)
	body := benchBody(4096)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "https://backend.test/ingest", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(body))
		if err := req.Write(tlsClient); err != nil {
			b.Fatalf("write: %v", err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			b.Fatalf("read: %v", err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			b.Fatalf("drain: %v", err)
		}
		_ = resp.Body.Close()
	}
}
