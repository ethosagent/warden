package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

func goodConfig(t *testing.T) Config {
	t.Helper()
	store, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return Config{
		ListenAddr: "127.0.0.1:8080",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "x"}}}),
		Secrets:    &fakeSecrets{},
		Analytics:  store,
	}
}

type fakeSecrets struct{}

func (fakeSecrets) GetSecret(string) (string, error) { return "", nil }
func (fakeSecrets) RefreshSecrets() error            { return nil }

func TestNew_OK(t *testing.T) {
	p, err := New(goodConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.ListenAddr() != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q", p.ListenAddr())
	}
}

func TestNew_MissingDeps(t *testing.T) {
	base := goodConfig(t)

	mutators := map[string]func(c *Config){
		"no addr":      func(c *Config) { c.ListenAddr = "" },
		"no policy":    func(c *Config) { c.Policy = nil },
		"no secrets":   func(c *Config) { c.Secrets = nil },
		"no analytics": func(c *Config) { c.Analytics = nil },
	}
	for name, mut := range mutators {
		c := base
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	host, port, err := SplitHostPort("api.openai.com:443")
	if err != nil || host != "api.openai.com" || port != 443 {
		t.Fatalf("SplitHostPort = %q,%d,%v", host, port, err)
	}
	if _, _, err := SplitHostPort("no-port"); err == nil {
		t.Error("expected error for missing port")
	}
	if _, _, err := SplitHostPort("host:notaport"); err == nil {
		t.Error("expected error for non-numeric port")
	}
}

func TestNew_NonCACert(t *testing.T) {
	// Generate an RSA key and create a non-CA certificate.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Not A CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := goodConfig(t)
	cfg.CACertPath = certFile
	cfg.CAKeyPath = keyFile

	_, err = New(cfg)
	if err == nil {
		t.Fatal("expected error for non-CA cert")
	}
	if !strings.Contains(err.Error(), "not a certificate authority") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_KeyMismatch(t *testing.T) {
	// Generate two separate RSA key pairs.
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create a CA cert signed with key1.
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key1.PublicKey, key1)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write key2's PEM (the WRONG key) to the key file.
	key2DER, err := x509.MarshalPKCS8PrivateKey(key2)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key2DER})

	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := goodConfig(t)
	cfg.CACertPath = certFile
	cfg.CAKeyPath = keyFile

	_, err = New(cfg)
	if err == nil {
		t.Fatal("expected error for mismatched key")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}
