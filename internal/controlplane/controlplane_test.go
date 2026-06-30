package controlplane

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePolicyFile writes a policy YAML (with a secrets block) and returns its path.
func writePolicyFile(t *testing.T, allowDomain string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "policy:\n  allowlist:\n    - domain: " + allowDomain + "\n" +
		"  denylist:\n    - domain: evil.example.com\n" +
		"secrets:\n  - placeholder: openai_secret_001\n    envVar: OPENAI_API_KEY\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPolicyServedExcludesSecrets is the core boundary guarantee: the policy the
// control plane serves carries allow/deny only — never the secrets block.
func TestPolicyServedExcludesSecrets(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["allowlist"]; !ok {
		t.Error("served policy missing allowlist")
	}
	if _, ok := raw["denylist"]; !ok {
		t.Error("served policy missing denylist")
	}
	if _, ok := raw["secrets"]; ok {
		t.Fatal("served policy LEAKED secrets across the boundary")
	}
}

func TestPolicyTokenAuth(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: "s3cret"})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// No token -> 401.
	resp, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}

	// Correct token -> 200.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/policy", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("with-token status = %d, want 200", resp2.StatusCode)
	}
}

// TestPolicyLastKnownGood verifies a mid-edit malformed policy file does not
// break workers: the last successfully-served policy is returned instead.
func TestPolicyLastKnownGood(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// First request caches last-known-good.
	r1, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", r1.StatusCode)
	}

	// Corrupt the file, then request again: still 200 from last-known-good.
	if err := os.WriteFile(path, []byte("{{{ not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	r2, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r2.Body.Close() }()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("after-corruption status = %d, want 200 (last-known-good)", r2.StatusCode)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r2.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["allowlist"]; !ok {
		t.Error("last-known-good policy missing allowlist")
	}
}

// TestMintServerTLS signs a server cert from a generated CA and verifies it
// chains to that CA for the requested hostname.
func TestMintServerTLS(t *testing.T) {
	caCertPath, caKeyPath, caCert := genTestCA(t)
	tlsCfg, err := MintServerTLS(caCertPath, caKeyPath, []string{"control-plane", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("got %d certs, want 1", len(tlsCfg.Certificates))
	}
	leaf, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "control-plane", Roots: roots}); err != nil {
		t.Fatalf("minted cert does not verify for control-plane: %v", err)
	}
}

// genTestCA generates an RSA CA, writes cert+key (PKCS#8) to temp files, and
// returns the paths and the parsed cert.
func genTestCA(t *testing.T) (certPath, keyPath string, caCert *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.crt")
	keyPath = filepath.Join(dir, "ca.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, caCert
}
