// Command poisoned-mcp-server is the standalone container for the Warden
// MCP-wedge demo. The MCP JSON-RPC logic — the poisoned tools/list and the
// tools/call handler — lives in internal/mcpwedge so the demo container and
// the e2e fake upstream (test/e2e/fakeupstream) serve byte-identical attack
// traffic; this main only adds the env knobs and TLS listener.
//
// It serves TLS so Warden can TLS-terminate the upstream leg; the cert is
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

	"github.com/ethosagent/warden/internal/mcpwedge"
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
	mux.Handle("/", mcpwedge.NewHandler())

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
