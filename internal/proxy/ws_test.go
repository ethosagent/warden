package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/mcp/ws"
)

// wsBackend records text frames it receives from the proxy and can push a
// server->client frame after the 101 handshake.
type wsBackend struct {
	push    []byte
	gotText chan []byte
}

// frameWire serializes a frame to its wire bytes.
func frameWire(f ws.Frame) []byte {
	var b strings.Builder
	_ = f.Write(stringWriter{&b})
	return []byte(b.String())
}

type stringWriter struct{ b *strings.Builder }

func (w stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

// startWSBackend starts a TLS listener that upgrades to WebSocket (responds 101)
// and then reads frames, recording text payloads. It mirrors startBackend's TLS
// setup but gives the handler raw control of the connection.
func startWSBackend(t *testing.T, caCert *x509.Certificate, caKey interface{}, b *wsBackend) net.Listener {
	t.Helper()
	b.gotText = make(chan []byte, 8)

	backendKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(301),
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
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: backendKey}

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
				tlsSrv := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{tlsCert}})
				if err := tlsSrv.Handshake(); err != nil {
					return
				}
				defer func() { _ = tlsSrv.Close() }()

				br := bufio.NewReader(tlsSrv)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				_, _ = io.WriteString(tlsSrv,
					"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				if b.push != nil {
					_, _ = tlsSrv.Write(b.push)
				}
				for {
					f, err := ws.ReadFrame(br)
					if err != nil {
						return
					}
					if f.Opcode == ws.OpcodeText {
						select {
						case b.gotText <- append([]byte(nil), f.Payload...):
						default:
						}
					}
					if f.Opcode == ws.OpcodeClose {
						return
					}
				}
			}()
		}
	}()
	return ln
}

// wsUpgradeThroughProxy performs the CONNECT + TLS + WebSocket upgrade handshake
// through the proxy and returns the client conn plus its buffered reader,
// positioned just after the 101 response headers.
func wsUpgradeThroughProxy(t *testing.T, p *Proxy, caCertPEM []byte) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	tlsClient := dialProxyAndConnect(t, p.Addr().String(), "backend.test", caCertPEM)
	_, _ = io.WriteString(tlsClient,
		"GET /mcp HTTP/1.1\r\nHost: backend.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

	br := bufio.NewReader(tlsClient)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "101") {
		t.Fatalf("expected 101 Switching Protocols, got %q", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	return tlsClient, br
}

// TestWS_EnforceDeniedToolCallBlocks drives a full 101 upgrade through the proxy
// and sends a masked text frame carrying a denied tools/call. In enforce mode
// the client must receive a Close(1008) and an mcp deny event must be recorded.
func TestWS_EnforceDeniedToolCallBlocks(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	be := &wsBackend{}
	backendLn := startWSBackend(t, caCert, caKey, be)

	p, ss := startTestProxyWithMCP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, enforceMCPConfig(), nil)
	p.dialTLS = dialBackend(backendLn)

	tlsClient, br := wsUpgradeThroughProxy(t, p, caCertPEM)

	denied := ws.Frame{
		Fin: true, Opcode: ws.OpcodeText, Masked: true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: []byte(mcpExecCmdBody),
	}
	if _, err := tlsClient.Write(frameWire(denied)); err != nil {
		t.Fatal(err)
	}

	if !readUntilClose(t, br) {
		t.Fatal("expected a Close frame to the client on enforce deny")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if findEvent(ss.snapshot(), "mcp", "deny") != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected mcp deny event, got %+v", ss.snapshot())
}

// TestWS_AllowedToolCallForwarded drives a 101 upgrade and sends a masked
// allowed tools/call. The frame must reach the backend and an mcp allow event
// must be recorded after the connection closes.
func TestWS_AllowedToolCallForwarded(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, caKey := generateTestCA(t)
	be := &wsBackend{}
	backendLn := startWSBackend(t, caCert, caKey, be)

	p, ss := startTestProxyWithMCP(t, []string{"backend.test"}, caCertPEM, caKeyPEM, enforceMCPConfig(), nil)
	p.dialTLS = dialBackend(backendLn)

	tlsClient, _ := wsUpgradeThroughProxy(t, p, caCertPEM)

	allowed := ws.Frame{
		Fin: true, Opcode: ws.OpcodeText, Masked: true,
		MaskKey: [4]byte{1, 2, 3, 4},
		Payload: []byte(mcpReadFileBody),
	}
	if _, err := tlsClient.Write(frameWire(allowed)); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-be.gotText:
		if string(got) != mcpReadFileBody {
			t.Fatalf("forwarded payload mismatch: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive forwarded text frame")
	}

	_ = tlsClient.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if findEvent(ss.snapshot(), "mcp", "allow") != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected mcp allow event, got %+v", ss.snapshot())
}

// readUntilClose reads frames until it sees a Close (returns true) or the
// connection ends / times out (returns false).
func readUntilClose(t *testing.T, br *bufio.Reader) bool {
	t.Helper()
	type res struct {
		f   ws.Frame
		err error
	}
	for i := 0; i < 8; i++ {
		ch := make(chan res, 1)
		go func() {
			f, err := ws.ReadFrame(br)
			ch <- res{f, err}
		}()
		select {
		case x := <-ch:
			if x.err != nil {
				return false
			}
			if x.f.Opcode == ws.OpcodeClose {
				return true
			}
		case <-time.After(3 * time.Second):
			return false
		}
	}
	return false
}
