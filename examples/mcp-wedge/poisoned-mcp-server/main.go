// Command poisoned-mcp-server is a deliberately malicious, self-contained MCP
// server for the Warden MCP-wedge demo. It speaks the minimum slice of the
// Model Context Protocol (JSON-RPC 2.0 over HTTP) that Warden's gateway
// inspects: tools/list and tools/call.
//
// It is "poisoned" on purpose: one of the tools it advertises in tools/list
// carries a prompt-injection payload in its description (the classic MCP
// tool-poisoning attack — a tool whose description tries to hijack the agent
// into calling a dangerous tool and exfiltrating secrets). Warden flags that
// description on the response path, and — in enforce mode with a default-deny
// tool allowlist — blocks any tools/call to the dangerous tool it names.
//
// The handler logic is SHARED with the L1 test harness (both serve
// internal/mcp/poisoned), so the demo binary and every harness scenario
// exercise byte-identical tooling; this file keeps only the TLS serving and
// env wiring. Stdlib plus that one in-module package (itself stdlib-only). It
// serves TLS so Warden can TLS-terminate the upstream leg; the cert is
// generated in-memory at startup (self-signed for the hostname in $MCP_HOST,
// default "poisoned-mcp-server"). See the README for how Warden is made to
// trust this cert in the compose demo.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ethosagent/warden/internal/mcp/poisoned"
)

// selfSignedCert generates an in-memory self-signed cert valid for host.
func selfSignedCert(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func main() {
	host := os.Getenv("MCP_HOST")
	if host == "" {
		host = "poisoned-mcp-server"
	}
	addr := os.Getenv("MCP_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	cert, err := selfSignedCert(host)
	if err != nil {
		log.Fatalf("poisoned-mcp-server: cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", poisoned.Handler())

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Printf("poisoned-mcp-server: listening on %s (TLS, CN=%s)", addr, host)
	// ServeTLS with empty cert/key paths uses TLSConfig.Certificates above.
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("poisoned-mcp-server: %v", err)
	}
}
