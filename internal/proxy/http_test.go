package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// recordingBackend captures the HTTP request received by a TLS backend server.
type recordingBackend struct {
	mu      sync.Mutex
	method  string
	path    string
	headers http.Header
	body    string

	statusCode int
	respBody   string
}

// startBackend creates a TLS backend server that records the first HTTP request
// and responds with the configured status/body. It generates a self-signed cert
// signed by the provided CA.
func startBackend(t *testing.T, caCert *x509.Certificate, caKey interface{}) (net.Listener, *recordingBackend) {
	t.Helper()

	backendKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	backendTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "backend.test"},
		DNSNames:     []string{"backend.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	backendCertDER, err := x509.CreateCertificate(rand.Reader, backendTemplate, caCert, &backendKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	backendTLSCert := tls.Certificate{
		Certificate: [][]byte{backendCertDER},
		PrivateKey:  backendKey,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	rb := &recordingBackend{
		statusCode: 200,
		respBody:   "ok",
	}

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				tlsSrv := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{backendTLSCert}})
				if err := tlsSrv.Handshake(); err != nil {
					return
				}
				defer tlsSrv.Close()

				backendBR := bufio.NewReader(tlsSrv)
				for {
					req, err := http.ReadRequest(backendBR)
					if err != nil {
						return
					}

					rb.mu.Lock()
					rb.method = req.Method
					rb.path = req.URL.RequestURI()
					rb.headers = req.Header.Clone()
					bodyBytes, _ := io.ReadAll(req.Body)
					rb.body = string(bodyBytes)
					req.Body.Close()
					sc := rb.statusCode
					body := rb.respBody
					rb.mu.Unlock()

					resp := &http.Response{
						StatusCode:    sc,
						Status:        fmt.Sprintf("%d OK", sc),
						Proto:         "HTTP/1.1",
						ProtoMajor:    1,
						ProtoMinor:    1,
						Header:        http.Header{},
						Body:          io.NopCloser(strings.NewReader(body)),
						ContentLength: int64(len(body)),
					}
					_ = resp.Write(tlsSrv)
				}
			}()
		}
	}()

	return ln, rb
}

// startTestProxyWithSecrets creates a test proxy with secret provider and placeholder names.
func startTestProxyWithSecrets(t *testing.T, allowedDomains []string, caCertPEM, caKeyPEM []byte, secretValues map[string]string, placeholderNames []string) (*Proxy, *syncStore) {
	t.Helper()
	var entries []config.AllowlistEntry
	for _, d := range allowedDomains {
		entries = append(entries, config.AllowlistEntry{Domain: d, Port: 443})
	}
	store := &syncStore{}
	cfg := Config{
		ListenAddr:       "127.0.0.1:0",
		Policy:           policy.NewEvaluator(config.Policy{Allowlist: entries}),
		Secrets:          &fakes.FakeSecretProvider{Values: secretValues},
		Analytics:        store,
		PlaceholderNames: placeholderNames,
	}
	if len(caCertPEM) > 0 {
		certFile := filepath.Join(t.TempDir(), "ca.crt")
		keyFile := filepath.Join(t.TempDir(), "ca.key")
		if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, caKeyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		cfg.CACertPath = certFile
		cfg.CAKeyPath = keyFile
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 100; i++ {
		if p.Addr() != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy did not start")
	}
	return p, store
}

// dialProxyAndConnect dials the proxy, sends CONNECT, performs TLS handshake,
// and returns the TLS connection ready for HTTP requests.
func dialProxyAndConnect(t *testing.T, proxyAddr string, domain string, caCertPEM []byte) *tls.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", domain, domain)
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		conn.Close()
		t.Fatalf("expected 200 from CONNECT, got %q", resp)
	}
	// Consume rest of CONNECT response headers
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
	})
	if err := tlsClient.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("client TLS handshake: %v", err)
	}
	t.Cleanup(func() { tlsClient.Close() })
	return tlsClient
}

// bufferedTLSConn wraps a net.Conn with a bufio.Reader so buffered data
// from the CONNECT response is available for the TLS handshake.
type bufferedTLSConn struct {
	io.Reader
	net.Conn
}

func (c *bufferedTLSConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

func TestHTTP_SecretSwapInHeaders(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	secretValues := map[string]string{"PLACEHOLDER_001": "real-secret-value"}
	p, ss := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)

	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Backend should have received the real secret
	rb.mu.Lock()
	authHeader := rb.headers.Get("Authorization")
	rb.mu.Unlock()

	if authHeader != "Bearer real-secret-value" {
		t.Fatalf("expected backend to see 'Bearer real-secret-value', got %q", authHeader)
	}

	// Analytics should contain sha256 reference, NOT the real secret
	time.Sleep(50 * time.Millisecond)
	events := ss.snapshot()
	if len(events) == 0 {
		t.Fatal("expected analytics event")
	}

	lastEvent := events[len(events)-1]
	if !strings.Contains(lastEvent.SecretRef, "sha256:") {
		t.Fatalf("expected SecretRef to contain 'sha256:', got %q", lastEvent.SecretRef)
	}
	if strings.Contains(lastEvent.SecretRef, "real-secret-value") {
		t.Fatal("SecretRef must not contain the raw secret value")
	}
}

func TestHTTP_SecretSwapInQuery(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	secretValues := map[string]string{"PLACEHOLDER_001": "real-secret-value"}
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)

	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat?key=PLACEHOLDER_001", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	rb.mu.Lock()
	gotPath := rb.path
	rb.mu.Unlock()

	if !strings.Contains(gotPath, "key=real-secret-value") {
		t.Fatalf("expected backend URL query to contain 'key=real-secret-value', got %q", gotPath)
	}
}

func TestHTTP_SecretSwapInQuery_SpecialChars(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	secretValues := map[string]string{"PLACEHOLDER_001": "key&admin=true"}
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)

	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat?key=PLACEHOLDER_001", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	rb.mu.Lock()
	gotPath := rb.path
	rb.mu.Unlock()

	// The secret value "key&admin=true" must be URL-encoded so it stays as a
	// single query parameter value, NOT split into two params.
	if strings.Contains(gotPath, "key&admin") {
		t.Fatalf("secret value was injected raw (unescaped) into query string: %q", gotPath)
	}
	// url.Values.Encode() will produce key=key%26admin%3Dtrue
	if !strings.Contains(gotPath, "key%26admin%3Dtrue") && !strings.Contains(gotPath, "key%26admin=true") {
		// Be flexible: Go's url.Values.Encode() percent-encodes & and =
		t.Fatalf("expected properly encoded secret in query, got %q", gotPath)
	}
}

func TestHTTP_SecretSwapInBody(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	secretValues := map[string]string{"PLACEHOLDER_001": "real-secret-value"}
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)

	body := `{"key":"PLACEHOLDER_001"}`
	req, _ := http.NewRequest("POST", "https://backend.test/v1/chat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	rb.mu.Lock()
	gotBody := rb.body
	rb.mu.Unlock()

	expectedBody := `{"key":"real-secret-value"}`
	if gotBody != expectedBody {
		t.Fatalf("expected backend body %q, got %q", expectedBody, gotBody)
	}
}

func TestHTTP_NoSwapWithoutPlaceholders(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	// No placeholders configured
	secretValues := map[string]string{"PLACEHOLDER_001": "real-secret-value"}
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, nil)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)

	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	rb.mu.Lock()
	authHeader := rb.headers.Get("Authorization")
	rb.mu.Unlock()

	// Placeholder should NOT have been swapped
	if authHeader != "Bearer PLACEHOLDER_001" {
		t.Fatalf("expected placeholder to remain unchanged, got %q", authHeader)
	}
}

func TestHTTP_502OnUpstreamFailure(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)

	secretValues := map[string]string{}
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, nil)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return nil, fmt.Errorf("simulated upstream failure")
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)

	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 502 {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

func TestHTTP_DecisionLogging(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	secretValues := map[string]string{"PLACEHOLDER_001": "real-secret-value"}
	p, ss := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)

	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	req.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	time.Sleep(50 * time.Millisecond)
	events := ss.snapshot()

	// Find the HTTPS allow event
	var found *analytics.Event
	for i := range events {
		if events[i].Protocol == "https" && events[i].Decision == "allow" {
			found = &events[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected https/allow analytics event")
	}

	if found.Domain != "backend.test" {
		t.Fatalf("expected Domain='backend.test', got %q", found.Domain)
	}
	if found.Method != "GET" {
		t.Fatalf("expected Method='GET', got %q", found.Method)
	}
	if found.ResponseStatus != 200 {
		t.Fatalf("expected ResponseStatus=200, got %d", found.ResponseStatus)
	}
	if !strings.Contains(found.SecretRef, "sha256:") {
		t.Fatalf("expected SecretRef to contain 'sha256:', got %q", found.SecretRef)
	}
	if strings.Contains(found.SecretRef, "real-secret-value") {
		t.Fatal("SecretRef must not contain the raw secret value")
	}
}

func TestHTTP_KeepAlive(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	secretValues := map[string]string{"PLACEHOLDER_001": "real-secret-value"}
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	clientBR := bufio.NewReader(tlsClient)

	// Request 1
	req1, _ := http.NewRequest("GET", "https://backend.test/v1/req1", nil)
	req1.Header.Set("Authorization", "Bearer PLACEHOLDER_001")
	if err := req1.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp1, err := http.ReadResponse(clientBR, req1)
	if err != nil {
		t.Fatalf("response 1: %v", err)
	}
	io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != 200 {
		t.Fatalf("req1: expected 200, got %d", resp1.StatusCode)
	}

	// Request 2 on SAME connection
	req2, _ := http.NewRequest("POST", "https://backend.test/v1/req2", strings.NewReader(`{"key":"PLACEHOLDER_001"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.ContentLength = int64(len(`{"key":"PLACEHOLDER_001"}`))
	if err := req2.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.ReadResponse(clientBR, req2)
	if err != nil {
		t.Fatalf("response 2: %v", err)
	}
	io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("req2: expected 200, got %d", resp2.StatusCode)
	}

	// Verify backend saw the second request with swapped body
	rb.mu.Lock()
	gotBody := rb.body
	gotPath := rb.path
	rb.mu.Unlock()

	if gotPath != "/v1/req2" {
		t.Fatalf("expected backend path /v1/req2, got %q", gotPath)
	}
	expectedBody := `{"key":"real-secret-value"}`
	if gotBody != expectedBody {
		t.Fatalf("expected backend body %q, got %q", expectedBody, gotBody)
	}
}

func TestHTTP_ConnectionClose(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, map[string]string{}, nil)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	clientBR := bufio.NewReader(tlsClient)

	req, _ := http.NewRequest("GET", "https://backend.test/v1/chat", nil)
	req.Header.Set("Connection", "close")
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(clientBR, req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// The proxy should close the connection after this response.
	// A subsequent read should fail.
	tlsClient.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	_, err = tlsClient.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed after Connection: close")
	}
}

func TestHTTP_OversizeBody413(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, rb := startBackend(t, caCert, caKey)

	secretValues := map[string]string{"PLACEHOLDER_001": "real-secret-value"}
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, secretValues, []string{"PLACEHOLDER_001"})
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)

	// Create a body larger than 10MB
	bigBody := strings.Repeat("A", maxBodySwapSize+1)
	req, _ := http.NewRequest("POST", "https://backend.test/v1/chat", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(bigBody))
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 413 {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}

	// Backend should NOT have received the request
	rb.mu.Lock()
	gotMethod := rb.method
	rb.mu.Unlock()
	if gotMethod != "" {
		t.Fatal("backend should not have received the oversized request")
	}
}
