package proxy

import (
	"bufio"
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
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingDialer wraps an inner dialTLS func, counting every call so a test can
// assert how many upstream TLS dials a keep-alive session performed. This is the
// D3 proof seam: reuse means N requests to one host cost ONE dial.
func countingDialer(inner func(network, addr string, cfg *tls.Config) (*tls.Conn, error), n *int32) func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	return func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		atomic.AddInt32(n, 1)
		return inner(network, addr, cfg)
	}
}

// startEphemeralBackend serves exactly ONE HTTP request per accepted TCP conn,
// then closes that conn. With sendClose=false the response carries NO
// Connection: close header, so a proxy that reads it sees a keep-alive-eligible
// (!closeAfter) response even though the conn is already dead — exactly like an
// origin with a 0s idle keep-alive timeout. That drives the stale-reused-conn
// redial path. With sendClose=true the response carries Connection: close, so the
// proxy's closeAfter fires and reuse must not survive.
func startEphemeralBackend(t testing.TB, caCert *x509.Certificate, caKey interface{}, sendClose bool) net.Listener {
	t.Helper()

	backendKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(300),
		Subject:      pkix.Name{CommonName: "backend.test"},
		DNSNames:     []string{"backend.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &backendKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srvCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: backendKey}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = raw.Close() }()
				tlsSrv := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{srvCert}})
				if err := tlsSrv.Handshake(); err != nil {
					return
				}
				br := bufio.NewReader(tlsSrv)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_, _ = io.ReadAll(req.Body)
				_ = req.Body.Close()
				resp := &http.Response{
					StatusCode:    200,
					Status:        "200 OK",
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        http.Header{},
					Body:          io.NopCloser(strings.NewReader("ok")),
					ContentLength: 2,
					Close:         sendClose,
				}
				_ = resp.Write(tlsSrv)
				// Return: conn closes — one request per conn.
			}()
		}
	}()

	return ln
}

// TestReuse_KeepAliveNRequestsOneDial is the D3 proof: N sequential !closeAfter
// requests over ONE client TLS session to one host dial the upstream EXACTLY
// once.
func TestReuse_KeepAliveNRequestsOneDial(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn, _ := startBackend(t, caCert, caKey)

	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)
	var dials int32
	p.dialTLS = countingDialer(dialBackend(backendLn), &dials)

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	br := bufio.NewReader(tlsClient)

	const n = 5
	for i := 0; i < n; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
		if err := req.Write(tlsClient); err != nil {
			t.Fatalf("request %d write: %v", i, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("request %d read: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Fatalf("expected exactly 1 upstream dial for %d keep-alive requests, got %d", n, got)
	}
}

// TestReuse_CloseAfterForcesRedial: a response with Connection: close ends reuse.
// The next client request must dial the upstream again (2 requests → 2 dials),
// in contrast to the single dial the keep-alive path shows.
func TestReuse_CloseAfterForcesRedial(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendLn := startEphemeralBackend(t, caCert, caKey, true /* sendClose */)

	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)
	var dials int32
	p.dialTLS = countingDialer(dialBackend(backendLn), &dials)

	// Each request runs on its own client session because the Connection: close
	// response ends the prior session — exactly the point: reuse does not survive
	// closeAfter.
	for i := 0; i < 2; i++ {
		tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
		br := bufio.NewReader(tlsClient)
		req, _ := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
		if err := req.Write(tlsClient); err != nil {
			t.Fatalf("request %d write: %v", i, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("request %d read: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Fatalf("expected 2 dials (no reuse across Connection: close), got %d", got)
	}
}

// TestReuse_StaleConnRedialsOnce: a reused conn that has gone stale (server
// closed the idle keep-alive) is transparently redialed EXACTLY once and the
// client still sees a correct response — no 502.
func TestReuse_StaleConnRedialsOnce(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	// One request per conn, NO Connection: close: the proxy carries the conn as
	// reusable, but it is already dead — the classic idle keep-alive close.
	backendLn := startEphemeralBackend(t, caCert, caKey, false)

	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)
	var dials int32
	p.dialTLS = countingDialer(dialBackend(backendLn), &dials)

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	br := bufio.NewReader(tlsClient)

	// Two requests on ONE client session. Request 1 dials. Request 2 reuses the
	// now-dead conn, detects it stale, and redials once — still succeeding.
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
		if err := req.Write(tlsClient); err != nil {
			t.Fatalf("request %d write: %v", i, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("request %d read: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: expected 200 (stale conn should redial, not 502), got %d", i, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "ok" {
			t.Fatalf("request %d: body %q", i, body)
		}
	}

	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Fatalf("expected 2 dials (1 initial + 1 stale redial), got %d", got)
	}
}

// TestReuse_FreshDialFailureNoRetry: a FRESH dial that fails is a real error —
// 502 to the client with NO retry (dialed exactly once).
func TestReuse_FreshDialFailureNoRetry(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)

	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)
	var dials int32
	p.dialTLS = countingDialer(func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		return nil, fmt.Errorf("dial refused")
	}, &dials)

	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	br := bufio.NewReader(tlsClient)
	req, _ := http.NewRequest(http.MethodGet, "https://backend.test/v1/chat", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 502 {
		t.Fatalf("expected 502 on fresh dial failure, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Fatalf("fresh dial failure must not retry: expected 1 dial, got %d", got)
	}
}

// TestReuse_NoCrossHostReuse: reuse is per-host. Two separate single-host
// sessions each dial their own upstream; a session to host A never reuses a conn
// to host B.
func TestReuse_NoCrossHostReuse(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	backendA, _ := startBackend(t, caCert, caKey)
	backendB, _ := startBackend(t, caCert, caKey)

	p, _ := startTestProxyWithSecrets(t, []string{"a.test", "b.test"}, caCertPEM, caKeyPEM, nil, nil)
	var dialsA, dialsB int32
	p.dialTLS = func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		switch host {
		case "a.test":
			atomic.AddInt32(&dialsA, 1)
			return tls.Dial("tcp", backendA.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		case "b.test":
			atomic.AddInt32(&dialsB, 1)
			return tls.Dial("tcp", backendB.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		default:
			return nil, fmt.Errorf("unexpected host %q", host)
		}
	}

	drive := func(domain string) {
		tlsClient := dialProxyAndConnect(t, p.Addr().String(), domain, caCertPEM)
		br := bufio.NewReader(tlsClient)
		for i := 0; i < 2; i++ {
			req, _ := http.NewRequest(http.MethodGet, "https://"+domain+"/v1/chat", nil)
			if err := req.Write(tlsClient); err != nil {
				t.Fatalf("%s request %d write: %v", domain, i, err)
			}
			resp, err := http.ReadResponse(br, req)
			if err != nil {
				t.Fatalf("%s request %d read: %v", domain, i, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}
	drive("a.test")
	drive("b.test")

	if a := atomic.LoadInt32(&dialsA); a != 1 {
		t.Fatalf("host a.test: expected 1 dial (2 keep-alive requests), got %d", a)
	}
	if b := atomic.LoadInt32(&dialsB); b != 1 {
		t.Fatalf("host b.test: expected 1 dial (2 keep-alive requests), got %d", b)
	}
}
