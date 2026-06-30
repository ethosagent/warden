package controlplane

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// MintServerTLS issues a short-lived server certificate for the control plane,
// signed by the given CA (typically the same proxy CA the deployment already
// uses). Workers trust it by adding that CA to their per-connection pool (see
// config.RemoteProvider.SetCACert), so HTTPS works without distributing a new
// trust root or altering any process-wide trust store.
//
// hosts is the SAN list (DNS names and/or IPs) the worker uses to reach the
// control plane, e.g. ["control-plane", "127.0.0.1"].
func MintServerTLS(caCertPath, caKeyPath string, hosts []string) (*tls.Config, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("controlplane: at least one TLS host (SAN) is required")
	}
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, err
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("controlplane: generate server key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("controlplane: serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"Warden Control Plane"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("controlplane: sign server cert: %w", err)
	}
	leaf := tls.Certificate{
		// Present the leaf plus the CA so a client validating against the CA root
		// always has a complete chain.
		Certificate: [][]byte{der, caCert.Raw},
		PrivateKey:  serverKey,
	}
	return &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}, nil
}

// loadCA reads and parses a PEM CA certificate and its private key. It accepts
// PKCS#8 and PKCS#1 RSA keys, mirroring the proxy's CA loading.
func loadCA(certPath, keyPath string) (*x509.Certificate, crypto.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("controlplane: read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("controlplane: no PEM block in CA cert %q", certPath)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("controlplane: parse CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("controlplane: read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("controlplane: no PEM block in CA key %q", keyPath)
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		return caCert, key, nil
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("controlplane: parse CA key (tried PKCS#8 and PKCS#1): %w", err)
	}
	return caCert, rsaKey, nil
}
