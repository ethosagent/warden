package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
)

// BenchmarkHandleHTTP drives a plain GET end-to-end through a real warden proxy
// (CONNECT + MITM TLS) to an httptest-style TLS backend, over a single
// keep-alive client connection. It is the aggregate before/after for D1-D3: per
// iteration the proxy reads the request, runs the allow-policy, forwards it to
// the upstream, and relays the response.
//
// Warm parts (kept OUT of the timed loop): the leaf cert for "backend.test" is
// minted once during the CONNECT/TLS handshake in dialProxyAndConnect, so keygen
// (D2) is not in the hot loop. What IS in the loop and will move with later
// phases: the per-request upstream TLS dial (D3, still redialed every request
// today) and the analytics StoreEvent write (D1). NOTE: the analytics store here
// is the in-memory syncStore, so this captures the request-goroutine call cost
// of recording an event, NOT the SQLite fsync cost — that is measured in
// isolation by BenchmarkStoreEvent.
func BenchmarkHandleHTTP(b *testing.B) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(b)
	backendLn, _ := startBackend(b, caCert, caKey)

	p, _ := startTestProxyWithSecrets(b, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)
	// Redirect the proxy's upstream dial to the in-process backend, matching the
	// existing http_test.go end-to-end tests.
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(b, p.Addr().String(), "backend.test", caCertPEM)
	br := bufio.NewReader(tlsClient)

	// One reusable bodyless GET; writing it repeatedly over the keep-alive conn
	// is safe and keeps client-side allocation out of the measurement.
	req, err := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
	if err != nil {
		b.Fatalf("new request: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := req.Write(tlsClient); err != nil {
			b.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			b.Fatalf("read response: %v", err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			b.Fatalf("drain body: %v", err)
		}
		_ = resp.Body.Close()
	}
}
