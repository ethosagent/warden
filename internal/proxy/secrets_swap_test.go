package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/secrets"
)

// countingFetcher records how many times each placeholder is fetched and returns
// a versioned value, so a test can prove a freshly-built cache (with a new TTL)
// re-fetches rather than serving a previous cache's entry.
type countingFetcher struct {
	mu      sync.Mutex
	calls   map[string]int
	version int
}

func (f *countingFetcher) Fetch(placeholder string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[placeholder]++
	return placeholder + "-v" + itoa(f.version), nil
}

func (f *countingFetcher) count(placeholder string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[placeholder]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestProxy_SetSecrets_RaceFree drives the hot-path secret read (p.secrets() →
// GetSecret) concurrently with SetSecrets swapping in freshly-built caches. Under
// `go test -race` the atomic pointer must show no data race.
func TestProxy_SetSecrets_RaceFree(t *testing.T) {
	fetcher := &countingFetcher{}
	seed, err := secrets.NewCache(fetcher, time.Hour, []string{"ph"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    seed,
		Analytics:  &syncStore{},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: rebuild + swap the cache with alternating TTLs.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ttls := []time.Duration{time.Hour, time.Minute, time.Second}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				c, cErr := secrets.NewCache(fetcher, ttls[i%len(ttls)], []string{"ph"})
				if cErr == nil {
					p.SetSecrets(c)
				}
				i++
			}
		}
	}()

	// Readers: snapshot the live provider and resolve a placeholder.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = p.secrets().GetSecret("ph")
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestProxy_SetSecrets_SwapsTTL verifies SetSecrets swaps in a cache that honors
// the NEW TTL: the seeded cache (1h TTL) serves a stale value without re-fetching,
// while a swapped-in cache (0 TTL) re-fetches on every read.
func TestProxy_SetSecrets_SwapsTTL(t *testing.T) {
	fetcher := &countingFetcher{}
	// Seed: a long TTL. Prefetch fetches once; subsequent reads are cached.
	seed, err := secrets.NewCache(fetcher, time.Hour, []string{"ph"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    seed,
		Analytics:  &syncStore{},
	})
	if err != nil {
		t.Fatal(err)
	}

	base := fetcher.count("ph") // 1 from prefetch
	// Long-TTL reads do not re-fetch.
	_, _ = p.secrets().GetSecret("ph")
	_, _ = p.secrets().GetSecret("ph")
	if got := fetcher.count("ph"); got != base {
		t.Fatalf("long-TTL cache re-fetched: count went %d→%d", base, got)
	}

	// Swap in a fresh cache with a 0 TTL (everything is immediately expired).
	fetcher.version = 1
	fresh, err := secrets.NewCache(fetcher, 0, []string{"ph"})
	if err != nil {
		t.Fatal(err)
	}
	p.SetSecrets(fresh)

	before := fetcher.count("ph")
	v1, _ := p.secrets().GetSecret("ph")
	v2, _ := p.secrets().GetSecret("ph")
	after := fetcher.count("ph")
	if after-before < 2 {
		t.Fatalf("0-TTL cache did not re-fetch on each read: count went %d→%d", before, after)
	}
	if v1 != "ph-v1" || v2 != "ph-v1" {
		t.Fatalf("expected re-fetched v1 values, got %q %q", v1, v2)
	}
}

// TestProxy_Secrets_SeededUntouched confirms a worker that never swaps reads the
// seeded provider through the atomic pointer (back-compat for a local-only worker
// whose apply loop never runs).
func TestProxy_Secrets_SeededUntouched(t *testing.T) {
	seed := newEmptySecrets()
	seed.Values["ph"] = "seeded-value"
	p, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     newAllowAllEvaluator(),
		Secrets:    seed,
		Analytics:  &syncStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.secrets() != seed {
		t.Fatal("expected seeded secret provider through atomic pointer")
	}
	if v, _ := p.secrets().GetSecret("ph"); v != "seeded-value" {
		t.Fatalf("seeded provider value = %q, want seeded-value", v)
	}
}
