package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
)

func TestSessionLimiterBucket(t *testing.T) {
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	l := newSessionLimiter(clk, 10, time.Minute)
	for i := 0; i < 10; i++ {
		if ok, _ := l.allow("s1"); !ok {
			t.Fatalf("call %d refused", i+1)
		}
	}
	ok, wait := l.allow("s1")
	if ok || wait != 6*time.Second {
		t.Fatalf("11th call = %v wait %v, want refused with 6s to the next token", ok, wait)
	}
	// One token every 6s.
	clk.Advance(6 * time.Second)
	if ok, _ := l.allow("s1"); !ok {
		t.Fatal("a token did not refill after 6s")
	}
	if ok, _ := l.allow("s1"); ok {
		t.Fatal("only one token should have refilled")
	}
	// A long idle never banks more than the burst.
	clk.Advance(time.Hour)
	for i := 0; i < 10; i++ {
		if ok, _ := l.allow("s1"); !ok {
			t.Fatalf("after idle, call %d refused", i+1)
		}
	}
	if ok, _ := l.allow("s1"); ok {
		t.Fatal("idle banked more than the burst")
	}
}

// TestSessionLimiterPrunes: past maxLimiterKeys, full buckets are dropped and
// a still-draining bucket is kept.
func TestSessionLimiterPrunes(t *testing.T) {
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	l := newSessionLimiter(clk, 2, time.Minute)
	l.allow("busy")
	l.allow("busy")
	for i := 0; len(l.buckets) < maxLimiterKeys; i++ {
		l.allow("idle-" + strconv.Itoa(i))
	}
	clk.Advance(31 * time.Second) // idle buckets (one token used) are full; busy is not
	l.allow("new")
	if len(l.buckets) != 2 {
		t.Fatalf("after prune %d buckets, want busy + new", len(l.buckets))
	}
	if _, ok := l.buckets["busy"]; !ok {
		t.Fatal("a draining bucket was pruned")
	}
}

// TestLimitQueryGenerateKeys: a Principal without a session is limited per
// subject, and the Retry-After header is whole seconds.
func TestLimitQueryGenerateKeys(t *testing.T) {
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	logger, _ := testLogger()
	s := &Server{cfg: Config{Logger: logger}, generateLimit: newSessionLimiter(clk, 1, time.Minute)}
	h := s.limitQueryGenerate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	send := func(p Principal, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	key := Principal{Kind: PrincipalAPIKey, Iss: "i", Sub: "u1"}
	if rec := send(key, http.MethodPost, queryGeneratePath); rec.Code != http.StatusOK {
		t.Fatalf("first = %d", rec.Code)
	}
	rec := send(key, http.MethodPost, queryGeneratePath)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("second = %d Retry-After %q, want 429 and 60", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := send(Principal{Kind: PrincipalAPIKey, Iss: "i", Sub: "u2"}, http.MethodPost, queryGeneratePath); rec.Code != http.StatusOK {
		t.Fatalf("another subject = %d, want 200", rec.Code)
	}
	// Only POST on the exact path is limited.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, queryGeneratePath},
		{http.MethodPost, "/dashboard/api/query"},
	} {
		if rec := send(key, c.method, c.path); rec.Code != http.StatusOK {
			t.Errorf("%s %s = %d, want passed through", c.method, c.path, rec.Code)
		}
	}
}

func TestFailureLimiter(t *testing.T) {
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	l := newFailureLimiter(clk, 15*time.Minute, 2, 3, 2)
	if limited, _ := l.limited("a"); limited {
		t.Fatal("fresh key limited")
	}
	l.fail("a")
	l.fail("a")
	limited, wait := l.limited("a")
	if !limited || wait != 15*time.Minute {
		t.Fatalf("a after 2 failures: limited=%v wait=%v", limited, wait)
	}
	if !l.firstLimited("a") || l.firstLimited("a") {
		t.Fatal("firstLimited must be true exactly once per window")
	}
	clk.Advance(10 * time.Minute)
	if _, wait := l.limited("a"); wait != 5*time.Minute {
		t.Errorf("wait after 10m = %v, want 5m", wait)
	}
	// Global ceiling: a third failure from b trips every key.
	l.fail("b")
	if limited, _ := l.limited("c"); !limited {
		t.Fatal("global ceiling not applied")
	}
	// Past the table size a new key still counts globally but takes no slot.
	l.fail("d")
	l.fail("e")
	if len(l.keys) > 2 {
		t.Fatalf("keys = %d, want at most 2", len(l.keys))
	}
	if l.firstLimited("zzz") {
		t.Error("firstLimited allocated past maxKeys")
	}
	clk.Advance(15 * time.Minute)
	if limited, _ := l.limited("a"); limited {
		t.Fatal("still limited after every window ended")
	}
	if len(l.keys) != 0 {
		t.Fatalf("expired keys not swept: %d", len(l.keys))
	}
}
