package proxy

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
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

type syncStore struct {
	mu     sync.Mutex
	events []analytics.Event
}

func (s *syncStore) StoreEvent(e analytics.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func (s *syncStore) GetEvents(filter analytics.EventFilter) ([]analytics.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]analytics.Event, len(s.events))
	copy(out, s.events)
	return out, nil
}

func (s *syncStore) snapshot() []analytics.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]analytics.Event, len(s.events))
	copy(out, s.events)
	return out
}

func generateTestCA(t *testing.T) (certPEM, keyPEM []byte, cert *x509.Certificate, key crypto.PrivateKey) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, cert, caKey
}

func startTestProxy(t *testing.T, allowedDomains []string, caCertPEM, caKeyPEM []byte) (*Proxy, *fakes.FakeAnalyticsStore) {
	t.Helper()
	var entries []config.AllowlistEntry
	for _, d := range allowedDomains {
		entries = append(entries, config.AllowlistEntry{Domain: d, Port: 443})
	}
	store := &fakes.FakeAnalyticsStore{}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: entries}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
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

func TestServe_DenyUnknownDomain(t *testing.T) {
	store := &syncStore{}
	entries := []config.AllowlistEntry{{Domain: "allowed.example.com", Port: 443}}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: entries}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
	})
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

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "403") {
		t.Fatalf("expected 403, got %q", resp)
	}

	// Wait for connection to close to ensure handleConn has completed.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(br)

	events := store.snapshot()
	if len(events) == 0 {
		t.Fatal("expected analytics event")
	}
	if events[0].Decision != "deny" {
		t.Fatalf("expected deny, got %q", events[0].Decision)
	}
}

func TestServe_AllowAndTunnel(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	p, _ := startTestProxy(t, []string{"echo.test"}, nil, nil)
	p.dialFunc = func(network, addr string) (net.Conn, error) {
		return net.Dial("tcp", echoLn.Addr().String())
	}

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200, got %q", resp)
	}
	// Consume rest of the HTTP response headers
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	payload := "hello echo\n"
	fmt.Fprint(conn, payload)
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != payload {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}
}

func TestServe_InvalidCONNECT(t *testing.T) {
	p, _ := startTestProxy(t, []string{"allowed.example.com"}, nil, nil)

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n")
	buf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := conn.Read(buf)
	if n > 0 {
		t.Fatalf("expected no response data, got %q", buf[:n])
	}
	if err == nil {
		t.Fatal("expected read error (connection closed)")
	}
}

func TestServe_GracefulShutdown(t *testing.T) {
	p, _ := startTestProxy(t, []string{"allowed.example.com"}, nil, nil)
	_ = p // proxy is running

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	p2, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "x", Port: 443}}}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  &fakes.FakeAnalyticsStore{},
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() { done <- p2.Serve(ctx) }()
	for i := 0; i < 100; i++ {
		if p2.Addr() != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func TestServe_AnalyticsOnAllow(t *testing.T) {
	discardLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer discardLn.Close()
	go func() {
		for {
			c, err := discardLn.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	store := &syncStore{}
	entries := []config.AllowlistEntry{{Domain: "allowed.example.com", Port: 443}}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: entries}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
	})
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

	p.dialFunc = func(network, addr string) (net.Conn, error) {
		return net.Dial("tcp", discardLn.Addr().String())
	}

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT allowed.example.com:443 HTTP/1.1\r\nHost: allowed.example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200, got %q", resp)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadAll(br)

	events := store.snapshot()
	if len(events) == 0 {
		t.Fatal("expected analytics event")
	}
	if events[0].Decision != "allow" {
		t.Fatalf("expected allow, got %q", events[0].Decision)
	}
}

func TestTLS_RoundTrip(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)

	// Create a backend TLS server
	backendKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	backendTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
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

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()

	go func() {
		for {
			raw, err := backendLn.Accept()
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
				br := bufio.NewReader(tlsSrv)
				// Read request
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				fmt.Fprint(tlsSrv, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
			}()
		}
	}()

	p, _ := startTestProxy(t, []string{"backend.test"}, caCertPEM, caKeyPEM)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT backend.test:443 HTTP/1.1\r\nHost: backend.test:443\r\n\r\n")
	plainBR := bufio.NewReader(conn)
	resp, err := plainBR.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200 from CONNECT, got %q", resp)
	}
	// Consume rest of CONNECT response
	for {
		line, err := plainBR.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	// TLS handshake with the proxy's generated cert
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: "backend.test",
		RootCAs:    caPool,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsClient.Close()

	fmt.Fprint(tlsClient, "GET /v1/chat HTTP/1.1\r\nHost: backend.test\r\n\r\n")
	tlsBR := bufio.NewReader(tlsClient)
	respLine, err := tlsBR.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(respLine, "200") {
		t.Fatalf("expected 200 from backend, got %q", respLine)
	}
}

func TestTLS_HostHeaderRecheck(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	p, _ := startTestProxy(t, []string{"allowed.example.com"}, caCertPEM, caKeyPEM)
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT allowed.example.com:443 HTTP/1.1\r\nHost: allowed.example.com:443\r\n\r\n")
	plainBR := bufio.NewReader(conn)
	resp, err := plainBR.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200 from CONNECT, got %q", resp)
	}
	for {
		line, err := plainBR.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: "allowed.example.com",
		RootCAs:    caPool,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsClient.Close()

	// Send request with mismatched Host header
	fmt.Fprint(tlsClient, "GET /v1/chat HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")

	// The proxy should close the connection
	buf := make([]byte, 128)
	tlsClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := tlsClient.Read(buf)
	if n > 0 {
		// If we got data, that's unexpected — the proxy should have dropped the connection
		t.Fatalf("expected no data, got %q", buf[:n])
	}
	if err == nil {
		t.Fatal("expected read error (connection closed)")
	}
}

func TestTLS_NonTLSFallback(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	certFile := filepath.Join(t.TempDir(), "ca.crt")
	keyFile := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, caKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	store := &syncStore{}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "fallback.test", Port: 443}}}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
		CACertPath: certFile,
		CAKeyPath:  keyFile,
	})
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

	p.dialFunc = func(network, addr string) (net.Conn, error) {
		return net.Dial("tcp", echoLn.Addr().String())
	}

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT fallback.test:443 HTTP/1.1\r\nHost: fallback.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200, got %q", resp)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	payload := "plaintext data\n"
	fmt.Fprint(conn, payload)
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != payload {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}

	// Close connection to let the proxy handler finish, then check events.
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	events := store.snapshot()
	if len(events) == 0 {
		t.Fatal("expected analytics event")
	}
	found := false
	for _, e := range events {
		if e.Protocol == "tcp" && e.Decision == "allow" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected tcp/allow analytics event")
	}
}

func TestTLS_BackwardCompat(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	// No CACertPath/CAKeyPath — backward compat mode
	p, _ := startTestProxy(t, []string{"compat.test"}, nil, nil)
	p.dialFunc = func(network, addr string) (net.Conn, error) {
		return net.Dial("tcp", echoLn.Addr().String())
	}

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT compat.test:443 HTTP/1.1\r\nHost: compat.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200, got %q", resp)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	payload := "backward compat test\n"
	fmt.Fprint(conn, payload)
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != payload {
		t.Fatalf("echo mismatch: got %q, want %q", got, payload)
	}
}

func TestTLS_UnknownProtocolForwarding(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)

	// Self-signed TLS echo backend.
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
	}
	backendCertDER, err := x509.CreateCertificate(rand.Reader, backendTemplate, backendTemplate, &backendKey.PublicKey, backendKey)
	if err != nil {
		t.Fatal(err)
	}
	backendTLSCert := tls.Certificate{Certificate: [][]byte{backendCertDER}, PrivateKey: backendKey}

	backendLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{backendTLSCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	// Build proxy manually (like TestTLS_NonTLSFallback).
	certFile := filepath.Join(t.TempDir(), "ca.crt")
	keyFile := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, caKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	store := &syncStore{}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "rawproto.test", Port: 443}}}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
		CACertPath: certFile,
		CAKeyPath:  keyFile,
	})
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

	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT rawproto.test:443 HTTP/1.1\r\nHost: rawproto.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200, got %q", resp)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	// TLS handshake with proxy's generated cert.
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: "rawproto.test",
		RootCAs:    caPool,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsClient.Close()

	// Send non-HTTP binary bytes.
	payload := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if _, err := tlsClient.Write(payload); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(tlsClient, buf); err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	for i := range payload {
		if buf[i] != payload[i] {
			t.Fatalf("echo mismatch at byte %d: got %02x, want %02x", i, buf[i], payload[i])
		}
	}

	tlsClient.Close()
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	events := store.snapshot()
	found := false
	for _, e := range events {
		if e.Protocol == "raw" && e.Decision == "allow" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected raw/allow analytics event, got %v", events)
	}
}

func TestTLS_HTTP2ProtocolForwarding(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)

	// Self-signed TLS echo backend.
	backendKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	backendTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(201),
		Subject:      pkix.Name{CommonName: "backend.test"},
		DNSNames:     []string{"backend.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	backendCertDER, err := x509.CreateCertificate(rand.Reader, backendTemplate, backendTemplate, &backendKey.PublicKey, backendKey)
	if err != nil {
		t.Fatal(err)
	}
	backendTLSCert := tls.Certificate{Certificate: [][]byte{backendCertDER}, PrivateKey: backendKey}

	backendLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{backendTLSCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	// Build proxy manually (like TestTLS_NonTLSFallback).
	certFile := filepath.Join(t.TempDir(), "ca.crt")
	keyFile := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, caKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	store := &syncStore{}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "grpc.test", Port: 443}}}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  store,
		CACertPath: certFile,
		CAKeyPath:  keyFile,
	})
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

	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	}

	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT grpc.test:443 HTTP/1.1\r\nHost: grpc.test:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("expected 200, got %q", resp)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	// TLS handshake with proxy's generated cert.
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: "grpc.test",
		RootCAs:    caPool,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsClient.Close()

	// Send HTTP/2 connection preface.
	payload := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := tlsClient.Write(payload); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(tlsClient, buf); err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}

	tlsClient.Close()
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	events := store.snapshot()
	found := false
	for _, e := range events {
		if e.Protocol == "http2" && e.Decision == "allow" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected http2/allow analytics event, got %v", events)
	}
}
