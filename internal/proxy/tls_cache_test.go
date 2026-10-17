package proxy

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// The cert cache is keyed by client-chosen names (#376 review): in transparent
// mode any DNS name in a ClientHello that passes policy mints a leaf, so an
// attacker able to reach many names could grow the cache without bound. The
// cache must therefore be bounded, and — because leaves expire at their mint
// time plus the TTL — eviction must prefer the entry that expires first, so a
// bound never forces a live, still-fresh leaf out ahead of a dying one.

// certCacheLen counts the leaf cache the only way sync.Map allows.
func certCacheLen(p *Proxy) int {
	n := 0
	p.certCache.Range(func(_, _ any) bool { n++; return true })
	return n
}

// TestCertCache_BoundedUnderClientChosenNames mints more distinct names than
// the configured cap and asserts the cache never holds more than the cap, and
// that a still-cached name keeps serving its leaf unchanged (the bound did not
// disturb the lock-free hit path both modes share).
func TestCertCache_BoundedUnderClientChosenNames(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)
	p.certCacheCap = 4

	const minted = 12
	for i := range minted {
		if _, err := p.getOrCreateCert(nameN(i)); err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}
	if got := certCacheLen(p); got > 4 {
		t.Fatalf("cache grew to %d entries under a cap of 4", got)
	}
	// The most recent mints must still be cached: their re-request is a hit
	// (same certificate pointer, no re-mint).
	for i := minted - 2; i < minted; i++ {
		first, err := p.getOrCreateCert(nameN(i))
		if err != nil {
			t.Fatalf("re-request %d: %v", i, err)
		}
		second, err := p.getOrCreateCert(nameN(i))
		if err != nil {
			t.Fatalf("hit %d: %v", i, err)
		}
		if second != first {
			t.Fatalf("%s: expected cache hit, got a re-mint", nameN(i))
		}
	}
	if got := certCacheLen(p); got > 4 {
		t.Fatalf("cache grew to %d entries after re-requests", got)
	}
}

// nameN is a distinct LDH client-chosen name for cache-bound tests.
func nameN(i int) string {
	return "n" + strconv.Itoa(i) + ".client.test"
}

// TestCertCache_EvictsExpiringFirst pins the eviction ORDER with a controlled
// clock: the entry closest to NotAfter must be the one evicted, even when it
// was inserted LAST — an insertion-order bound would evict the first-inserted
// (longest-lived) leaf instead. leafTTL is varied per mint to decouple expiry
// order from insertion order.
func TestCertCache_EvictsExpiringFirst(t *testing.T) {
	caCertPEM, caKeyPEM, _, _ := generateTestCA(t)
	p, _ := startTestProxyWithSecrets(t, []string{"backend.test"}, caCertPEM, caKeyPEM, nil, nil)
	p.certCacheCap = 2

	// Deterministic clock, with every cached leaf still fresh at each step
	// (renew window = NotAfter - leafRenewSkew, i.e. 1h before expiry).
	base := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	current := base
	var mu sync.Mutex
	p.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}

	// First mint: a LONG-lived leaf (TTL 6h), inserted first.
	p.leafTTL = 6 * time.Hour
	lateFirst, err := p.getOrCreateCert("late.client.test")
	if err != nil {
		t.Fatalf("mint late: %v", err)
	}

	// Second mint: a SHORT-lived leaf (TTL 2h), inserted last but expiring
	// first (NotAfter base+2h vs base+6h).
	p.leafTTL = 2 * time.Hour
	earlyFirst, err := p.getOrCreateCert("early.client.test")
	if err != nil {
		t.Fatalf("mint early: %v", err)
	}

	// 30m in: every cached leaf is still fresh (early renews only at base+1h).
	// A third mint overflows the cap and must evict EXACTLY the short-lived one.
	mu.Lock()
	current = base.Add(30 * time.Minute)
	mu.Unlock()
	if _, err := p.getOrCreateCert("third.client.test"); err != nil {
		t.Fatalf("mint third: %v", err)
	}
	if got := certCacheLen(p); got != 2 {
		t.Fatalf("cache holds %d entries after eviction, want 2", got)
	}

	// The long-lived leaf survived (hit → same pointer): the bound did not
	// evict by insertion order.
	lateAgain, err := p.getOrCreateCert("late.client.test")
	if err != nil {
		t.Fatalf("late after evict: %v", err)
	}
	if lateAgain != lateFirst {
		t.Errorf("long-lived leaf was evicted (re-minted) although the short-lived one expires first")
	}

	// The short-lived leaf is gone: the same clock still VALIDATES it (base+30m
	// is inside its window), so a re-mint here proves it was EVICTED, not
	// expired.
	earlyAgain, err := p.getOrCreateCert("early.client.test")
	if err != nil {
		t.Fatalf("early after evict: %v", err)
	}
	if earlyAgain == earlyFirst {
		t.Errorf("shortest-lived leaf survived the eviction; want the expiring-first victim")
	}
	if got := certCacheLen(p); got != 2 {
		t.Errorf("cache holds %d entries at the end, want 2", got)
	}
}
