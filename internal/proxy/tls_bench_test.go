package proxy

import (
	"strconv"
	"testing"
)

// BenchmarkGetOrCreateCert measures the two paths of the leaf-cert cache.
//
//	hit  — the domain is already cached, so getOrCreateCert returns the stored
//	       *tls.Certificate with no crypto work. This is the common warm path.
//	miss — a fresh domain each iteration, so every call mints a new leaf:
//	       ECDSA P-256 keygen + x509 sign (per D2; was RSA-2048). A distinct
//	       domain per iteration keeps this a true miss so singleflight and the
//	       expiry re-mint check never short-circuit it.
//
// White-box (package proxy) because getOrCreateCert and certCache are
// unexported. The CA is loaded via the existing generateTestCA/startTestProxy
// harness rather than hand-rolled.
func BenchmarkGetOrCreateCert(b *testing.B) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(b)
	p, _ := startTestProxyWithSecrets(b, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)

	b.Run("hit", func(b *testing.B) {
		const domain = "warm.example.com"
		// Pre-warm the cache so the loop measures only the cache-hit lookup.
		if _, err := p.getOrCreateCert(domain); err != nil {
			b.Fatalf("prewarm: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p.getOrCreateCert(domain); err != nil {
				b.Fatalf("getOrCreateCert: %v", err)
			}
		}
	})

	b.Run("miss", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// A distinct domain each iteration forces a fresh keygen+sign. The
			// small strconv allocation is negligible against ECDSA P-256 keygen.
			if _, err := p.getOrCreateCert("miss-" + strconv.Itoa(i) + ".example.com"); err != nil {
				b.Fatalf("getOrCreateCert: %v", err)
			}
		}
	})
}
