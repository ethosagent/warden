package proxy

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"
	"testing"
	"time"
)

// parseLeaf parses the first DER cert in a getOrCreateCert result.
func parseLeaf(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return c
}

// TestGetOrCreateCert_RemintOnExpiry asserts a cached leaf is re-minted once the
// injected clock advances within leafRenewSkew of NotAfter, and that a fresh
// leaf well inside its window is served from cache unchanged.
func TestGetOrCreateCert_RemintOnExpiry(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)

	// Deterministic clock. TTL 2h with a 1h skew: a cert minted at t0 must be
	// re-minted once now >= t0 + (TTL - skew) = t0 + 1h.
	base := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	current := base
	var mu sync.Mutex
	p.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	p.leafTTL = 2 * time.Hour

	const domain = "warm.example.com"

	first, err := p.getOrCreateCert(domain)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	firstLeaf := parseLeaf(t, first.Certificate[0])

	// Well inside the window (30m): cache hit returns the SAME pointer, no re-mint.
	mu.Lock()
	current = base.Add(30 * time.Minute)
	mu.Unlock()
	second, err := p.getOrCreateCert(domain)
	if err != nil {
		t.Fatalf("hit: %v", err)
	}
	if second != first {
		t.Fatalf("expected cache hit to return same *tls.Certificate pointer, got a new one")
	}

	// Past NotAfter-skew (90m > 60m): must re-mint a new leaf.
	mu.Lock()
	current = base.Add(90 * time.Minute)
	mu.Unlock()
	third, err := p.getOrCreateCert(domain)
	if err != nil {
		t.Fatalf("remint: %v", err)
	}
	if third == first {
		t.Fatalf("expected re-mint past expiry skew, got same certificate pointer")
	}
	thirdLeaf := parseLeaf(t, third.Certificate[0])
	if thirdLeaf.SerialNumber.Cmp(firstLeaf.SerialNumber) == 0 {
		t.Fatalf("expected re-minted leaf to have a new serial, both = %s", thirdLeaf.SerialNumber)
	}
	if !thirdLeaf.NotAfter.After(firstLeaf.NotAfter) {
		t.Fatalf("expected re-minted NotAfter %v to be later than original %v", thirdLeaf.NotAfter, firstLeaf.NotAfter)
	}
}

// TestGetOrCreateCert_ECDSAAndChain asserts the minted leaf uses an ECDSA P-256
// private key and still chains to the CA (the property a real TLS handshake
// depends on).
func TestGetOrCreateCert_ECDSAAndChain(t *testing.T) {
	caCertPEM, caKeyPEM, caCert, _ := generateTestCA(t)
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)

	cert, err := p.getOrCreateCert("ecdsa.example.com")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected leaf PrivateKey *ecdsa.PrivateKey, got %T", cert.PrivateKey)
	}

	leaf := parseLeaf(t, cert.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "ecdsa.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf did not verify against CA: %v", err)
	}
}

// TestGetOrCreateCert_Singleflight launches many concurrent misses for one fresh
// domain and asserts exactly one leaf was minted (a single distinct serial). Run
// under -race to catch cache/flight data races.
func TestGetOrCreateCert_Singleflight(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)

	const (
		domain = "stampede.example.com"
		n      = 64
	)
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		serial = map[string]struct{}{}
		start  = make(chan struct{})
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			cert, err := p.getOrCreateCert(domain)
			if err != nil {
				mu.Lock()
				serial["err:"+err.Error()] = struct{}{}
				mu.Unlock()
				return
			}
			leaf := parseLeaf(t, cert.Certificate[0])
			mu.Lock()
			serial[leaf.SerialNumber.String()] = struct{}{}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if len(serial) != 1 {
		t.Fatalf("expected exactly one minted leaf (one distinct serial), got %d: %v", len(serial), serial)
	}
}
