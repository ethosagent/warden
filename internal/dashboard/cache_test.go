package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

func decodeAnalytics(t *testing.T, body []byte) analyticsResponse {
	t.Helper()
	var r analyticsResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode analytics: %v", err)
	}
	return r
}

// countingDataSource wraps a DataSource and records how many times GetEvents is
// called, so a test can prove the TTL cache avoids recomputation. It is
// concurrency-safe for the -race stampede test.
type countingDataSource struct {
	inner DataSource
	mu    sync.Mutex
	calls int
}

func (c *countingDataSource) GetEvents(f analytics.EventFilter) ([]analytics.Event, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.inner.GetEvents(f)
}

func (c *countingDataSource) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// fakeClock is a settable clock for driving cache expiry without real sleeps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// cacheTestServer builds a dashboard Server whose clock is the given fakeClock
// and whose data source counts GetEvents calls. It returns the http.Handler,
// the counter, and the clock.
func cacheTestServer(events []analytics.Event, clk *fakeClock) (http.Handler, *countingDataSource) {
	cds := &countingDataSource{inner: &fakeDataSource{events: events}}
	srv := NewServer(cds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.now = clk.now
	return srv.Handler(), cds
}

func rawGet(t *testing.T, h http.Handler, path string) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d", path, rec.Code)
	}
	return append([]byte(nil), rec.Body.Bytes()...)
}

// TestAnalyticsCacheHit: two identical requests inside the TTL trigger exactly
// one GetEvents call and return byte-identical bodies.
func TestAnalyticsCacheHit(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)}
	h, cds := cacheTestServer([]analytics.Event{
		{Timestamp: clk.now(), Domain: "a.com", Decision: "allow", Protocol: "https"},
	}, clk)

	first := rawGet(t, h, "/dashboard/api/analytics?range=1h")
	second := rawGet(t, h, "/dashboard/api/analytics?range=1h")

	if got := cds.count(); got != 1 {
		t.Fatalf("GetEvents called %d times, want 1 (cached)", got)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("cached body differs:\n first=%s\nsecond=%s", first, second)
	}
}

// TestAnalyticsCacheKeyCorrectness: distinct range/proxy keys recompute, and one
// key never serves another key's data.
func TestAnalyticsCacheKeyCorrectness(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)}
	h, cds := cacheTestServer([]analytics.Event{
		{Timestamp: clk.now(), Domain: "a.com", Decision: "allow", Protocol: "https", ProxyID: "worker-1"},
		{Timestamp: clk.now(), Domain: "b.com", Decision: "deny", Protocol: "https", ProxyID: "worker-1"},
		{Timestamp: clk.now(), Domain: "c.com", Decision: "allow", Protocol: "https", ProxyID: "worker-2"},
	}, clk)

	// Distinct range → separate compute.
	rawGet(t, h, "/dashboard/api/analytics?range=1h")
	rawGet(t, h, "/dashboard/api/analytics?range=1h") // hit
	if got := cds.count(); got != 1 {
		t.Fatalf("after two range=1h requests, GetEvents=%d, want 1", got)
	}
	rawGet(t, h, "/dashboard/api/analytics?range=24h")
	if got := cds.count(); got != 2 {
		t.Fatalf("range=24h should recompute, GetEvents=%d, want 2", got)
	}

	// Distinct proxy → separate compute, and the response reflects ONLY that
	// worker — never the fleet total under a different key.
	fleet := decodeAnalytics(t, rawGet(t, h, "/dashboard/api/analytics?range=1h&proxy=")) // hit of first key
	if got := cds.count(); got != 2 {
		t.Fatalf("empty proxy should reuse range=1h key, GetEvents=%d, want 2", got)
	}
	w1 := decodeAnalytics(t, rawGet(t, h, "/dashboard/api/analytics?range=1h&proxy=worker-1"))
	if got := cds.count(); got != 3 {
		t.Fatalf("proxy=worker-1 should recompute, GetEvents=%d, want 3", got)
	}
	rawGet(t, h, "/dashboard/api/analytics?range=1h&proxy=worker-1") // hit
	if got := cds.count(); got != 3 {
		t.Fatalf("repeat proxy=worker-1 should hit cache, GetEvents=%d, want 3", got)
	}

	if fleet.Totals.Requests != 3 {
		t.Fatalf("fleet totals = %d, want 3", fleet.Totals.Requests)
	}
	if w1.Totals.Requests != 2 || w1.SelectedProxy != "worker-1" {
		t.Fatalf("worker-1 view leaked fleet data: totals=%d selected=%q, want 2/worker-1",
			w1.Totals.Requests, w1.SelectedProxy)
	}
}

// TestAnalyticsCacheExpiry: advancing the clock past the TTL forces recompute.
func TestAnalyticsCacheExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)}
	h, cds := cacheTestServer([]analytics.Event{
		{Timestamp: clk.now(), Domain: "a.com", Decision: "allow", Protocol: "https"},
	}, clk)

	rawGet(t, h, "/dashboard/api/analytics?range=1h")
	rawGet(t, h, "/dashboard/api/analytics?range=1h")
	if got := cds.count(); got != 1 {
		t.Fatalf("before expiry GetEvents=%d, want 1", got)
	}

	// Just short of the TTL: still cached.
	clk.advance(analyticsCacheTTL - time.Nanosecond)
	rawGet(t, h, "/dashboard/api/analytics?range=1h")
	if got := cds.count(); got != 1 {
		t.Fatalf("within TTL GetEvents=%d, want 1", got)
	}

	// At/after the TTL: recompute.
	clk.advance(time.Nanosecond)
	rawGet(t, h, "/dashboard/api/analytics?range=1h")
	if got := cds.count(); got != 2 {
		t.Fatalf("after TTL GetEvents=%d, want 2 (recompute)", got)
	}
}

// TestAnalyticsCacheConcurrency: N concurrent identical requests are race-clean
// and, thanks to compute-under-lock, trigger exactly one GetEvents call; all
// responses are byte-identical. Run under -race.
func TestAnalyticsCacheConcurrency(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)}
	h, cds := cacheTestServer([]analytics.Event{
		{Timestamp: clk.now(), Domain: "a.com", Decision: "allow", Protocol: "https"},
	}, clk)

	const n = 20
	bodies := make([][]byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/dashboard/api/analytics?range=1h", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("goroutine %d: status %d", i, rec.Code)
				return
			}
			bodies[i] = append([]byte(nil), rec.Body.Bytes()...)
		}(i)
	}
	wg.Wait()

	if got := cds.count(); got != 1 {
		t.Fatalf("concurrent identical requests: GetEvents=%d, want 1 (singleflight)", got)
	}
	for i := 1; i < n; i++ {
		if !bytes.Equal(bodies[0], bodies[i]) {
			t.Fatalf("goroutine %d body differs from goroutine 0", i)
		}
	}
}

// TestMCPCacheHit: the MCP endpoint (the other unbounded 5s-refreshed view) is
// also cached — two identical requests trigger one GetEvents call.
func TestMCPCacheHit(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)}
	h, cds := cacheTestServer([]analytics.Event{
		{Timestamp: clk.now(), Domain: "a.com", Decision: "allow", Protocol: "mcp", Tool: "read_file"},
	}, clk)

	first := rawGet(t, h, "/dashboard/api/mcp")
	second := rawGet(t, h, "/dashboard/api/mcp")
	if got := cds.count(); got != 1 {
		t.Fatalf("MCP GetEvents called %d times, want 1 (cached)", got)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("MCP cached body differs")
	}

	// Different proxy selector is a different key → recompute.
	rawGet(t, h, "/dashboard/api/mcp?proxy=worker-9")
	if got := cds.count(); got != 2 {
		t.Fatalf("MCP proxy=worker-9 should recompute, GetEvents=%d, want 2", got)
	}
}
