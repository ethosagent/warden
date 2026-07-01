package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// grpcTestBackend records the metadata + content-type of the received request
// and returns a gRPC-style response with a trailer, over real HTTP/2.
type grpcTestBackend struct {
	server         *httptest.Server
	gotAuth        string
	gotContentType string
	gotPath        string
}

// startGRPCBackend spins up a real HTTP/2 backend (StartTLS + EnableHTTP2) whose
// handler records the received Authorization metadata + Content-Type, writes a
// small body, and sets a grpc-status trailer to exercise trailer forwarding.
func startGRPCBackend(t *testing.T) *grpcTestBackend {
	t.Helper()
	be := &grpcTestBackend{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		be.gotAuth = r.Header.Get("Authorization")
		be.gotContentType = r.Header.Get("Content-Type")
		be.gotPath = r.URL.Path

		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "grpc-response-body")
		w.Header().Set("Grpc-Status", "0")
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	be.server = srv
	t.Cleanup(srv.Close)
	return be
}

// dialGRPCClient performs the CONNECT + client TLS handshake with ALPN "h2" and
// returns an HTTP/2 client connection ready for RoundTrip. It mirrors
// dialProxyAndConnect's CONNECT bootstrap but adds NextProtos h2 (required for
// the proxy to negotiate HTTP/2 termination).
func dialGRPCClient(t *testing.T, proxyAddr, domain string, caCertPEM []byte) *http2.ClientConn {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", domain, domain)
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		_ = conn.Close()
		t.Fatalf("expected 200 from CONNECT, got %q", resp)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)
	tlsClient := tls.Client(&bufferedTLSConn{Reader: br, Conn: conn}, &tls.Config{
		ServerName: domain,
		RootCAs:    caPool,
		NextProtos: []string{"h2"},
	})
	if err := tlsClient.Handshake(); err != nil {
		_ = conn.Close()
		t.Fatalf("client TLS handshake: %v", err)
	}
	if got := tlsClient.ConnectionState().NegotiatedProtocol; got != "h2" {
		_ = conn.Close()
		t.Fatalf("expected ALPN h2, got %q", got)
	}
	t.Cleanup(func() { _ = tlsClient.Close() })

	cc, err := (&http2.Transport{}).NewClientConn(tlsClient)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("new h2 client conn: %v", err)
	}
	return cc
}

func TestGRPC_SecretSwapAndForward(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	be := startGRPCBackend(t)
	backendAddr := strings.TrimPrefix(be.server.URL, "https://")

	secretValues := map[string]string{"PLACEHOLDER_001": "real-secret-value"}
	p, store := startTestProxyWithSecrets(t, []string{"grpc.test"}, caCertPEM, caKeyPEM, secretValues, []string{"PLACEHOLDER_001"})
	// The gRPC path dials upstream over HTTP/2, which REQUIRES ALPN h2 on the
	// upstream conn — unlike the HTTP-path overrides, this override sets NextProtos.
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}

	cc := dialGRPCClient(t, p.Addr().String(), "grpc.test", caCertPEM)

	req, err := http.NewRequest("POST", "https://grpc.test/pkg.Svc/Method", strings.NewReader("request-body"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")

	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "grpc-response-body" {
		t.Fatalf("body mismatch: got %q", body)
	}

	// The grpc-status trailer must round-trip to the client (read after body).
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("expected grpc-status trailer 0, got %q", got)
	}

	// The backend must have received the REAL secret, never the placeholder.
	if be.gotAuth != "Bearer real-secret-value" {
		t.Fatalf("backend did not receive swapped secret: got %q", be.gotAuth)
	}
	if strings.Contains(be.gotAuth, "PLACEHOLDER_001") {
		t.Fatalf("placeholder leaked to backend: %q", be.gotAuth)
	}
	if be.gotPath != "/pkg.Svc/Method" {
		t.Fatalf("path not forwarded: got %q", be.gotPath)
	}

	// An analytics event must exist with grpc/allow and the RequestURI in the URL.
	// It must never carry the raw secret value.
	events := waitForEvent(t, store, func(e eventLike) bool {
		return e.Protocol == "grpc" && e.Decision == "allow" && strings.Contains(e.URL, "/pkg.Svc/Method")
	})
	for _, e := range events {
		if strings.Contains(e.SecretRef, "real-secret-value") || strings.Contains(e.URL, "real-secret-value") {
			t.Fatalf("raw secret leaked into analytics event: %+v", e)
		}
	}
}

func TestGRPC_NonGRPCHTTP2Protocol(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	be := startGRPCBackend(t)
	backendAddr := strings.TrimPrefix(be.server.URL, "https://")

	p, store := startTestProxyWithSecrets(t, []string{"grpc.test"}, caCertPEM, caKeyPEM, map[string]string{}, nil)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	}

	cc := dialGRPCClient(t, p.Addr().String(), "grpc.test", caCertPEM)

	// Plain HTTP/2 request (NOT application/grpc) must log Protocol "http2".
	req, err := http.NewRequest("GET", "https://grpc.test/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	waitForEvent(t, store, func(e eventLike) bool {
		return e.Protocol == "http2" && e.Decision == "allow"
	})
}

// eventLike is the subset of analytics fields the gRPC assertions inspect.
type eventLike struct {
	Protocol  string
	Decision  string
	URL       string
	SecretRef string
}

// waitForEvent polls the syncStore until an event matching pred appears (or the
// deadline elapses), returning the matching events. ServeConn dispatches streams
// concurrently, so the analytics write may lag the client's RoundTrip return.
func waitForEvent(t *testing.T, store *syncStore, pred func(eventLike) bool) []eventLike {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var matched []eventLike
		for _, e := range store.snapshot() {
			el := eventLike{Protocol: e.Protocol, Decision: e.Decision, URL: e.URL, SecretRef: e.SecretRef}
			if pred(el) {
				matched = append(matched, el)
			}
		}
		if len(matched) > 0 {
			return matched
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching analytics event; got %+v", store.snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
