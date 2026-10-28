package controlplane

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// queryGenerateLimit is how many POST /dashboard/api/query/generate calls one
// console session may make per minute in oidc mode: each call spends LLM
// tokens. It is a token bucket, so a burst of ten is allowed and the bucket
// refills continuously at ten per minute.
const queryGenerateLimit = 10

// queryGeneratePath is the rate-limited route.
const queryGeneratePath = "/dashboard/api/query/generate"

// maxLimiterKeys bounds the per-session bucket map. Past it, buckets that have
// refilled completely (idle for a whole period) are dropped; they hold no state
// a fresh bucket would not.
const maxLimiterKeys = 4096

// sessionLimiter is a set of token buckets keyed by session. It ticks on the
// control plane's clock port, so tests advance time instead of sleeping.
type sessionLimiter struct {
	clk      clock.Clock
	capacity float64
	perSec   float64 // refill rate in tokens per second

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time // when tokens was last brought up to date
}

// newSessionLimiter allows n calls per period per key, with a burst of n.
func newSessionLimiter(clk clock.Clock, n int, period time.Duration) *sessionLimiter {
	return &sessionLimiter{
		clk: clk, capacity: float64(n), perSec: float64(n) / period.Seconds(),
		buckets: map[string]*bucket{},
	}
}

// allow takes one token from key's bucket. When the bucket is empty it reports
// false and how long until a token is available.
func (l *sessionLimiter) allow(key string) (bool, time.Duration) {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxLimiterKeys {
			l.pruneLocked(now)
		}
		b = &bucket{tokens: l.capacity, at: now}
		l.buckets[key] = b
	}
	l.refillLocked(b, now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
	return false, wait
}

func (l *sessionLimiter) refillLocked(b *bucket, now time.Time) {
	if elapsed := now.Sub(b.at).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.capacity, b.tokens+elapsed*l.perSec)
	}
	b.at = now
}

// pruneLocked drops every bucket that is full again.
func (l *sessionLimiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		l.refillLocked(b, now)
		if b.tokens >= l.capacity {
			delete(l.buckets, k)
		}
	}
}

// limitQueryGenerate applies the per-session query/generate rate limit. It runs
// inside requireRole, so the caller already has a Principal and at least the
// editor role; other routes pass through untouched. A refusal is 429
// {"error":"rate_limited"} with Retry-After in whole seconds.
func (s *Server) limitQueryGenerate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != queryGeneratePath {
			next.ServeHTTP(w, r)
			return
		}
		p, _ := PrincipalFrom(r.Context())
		key := p.SessionHash
		if key == "" {
			// A Principal not backed by a session (later auth kinds) is limited per
			// subject instead.
			key = p.Kind + "\x00" + p.Iss + "\x00" + p.Sub
		}
		if ok, wait := s.generateLimit.allow(key); !ok {
			s.cfg.Logger.Warn("console_rate_limited", "action", "query.generate", "sub", p.Sub,
				"session", shortHash(p.SessionHash))
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			writeAuthzJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// The break-glass failure limiter (W-P1-OPS1-08). Failures are counted per
// client address and across all addresses in fixed windows; a limited request
// never reaches argon2.
const (
	breakGlassWindow       = 15 * time.Minute
	breakGlassPerAddr      = 5
	breakGlassGlobal       = 20
	breakGlassLimiterAddrs = 4096
)

// failureLimiter counts login failures in fixed windows. Each address has its
// own window (started by its first failure) and one global window bounds the
// failures of all addresses together. Time comes from the injected clock;
// expired entries are swept on every call, so memory is bounded by the number
// of addresses that failed within one window (and by maxKeys).
type failureLimiter struct {
	clk     clock.Clock
	window  time.Duration
	perKey  int
	global  int
	maxKeys int

	mu          sync.Mutex
	keys        map[string]*failureEntry
	globalStart time.Time
	globalN     int
}

type failureEntry struct {
	start time.Time
	n     int
	// noted is set once the limited state of this address was reported for
	// audit in this window, so rate-limited requests add one row per window.
	noted bool
}

func newFailureLimiter(clk clock.Clock, window time.Duration, perKey, global, maxKeys int) *failureLimiter {
	return &failureLimiter{clk: clk, window: window, perKey: perKey, global: global, maxKeys: maxKeys, keys: map[string]*failureEntry{}}
}

// sweepLocked drops every window that has ended.
func (l *failureLimiter) sweepLocked(now time.Time) {
	for k, e := range l.keys {
		if !now.Before(e.start.Add(l.window)) {
			delete(l.keys, k)
		}
	}
	if l.globalN > 0 && !now.Before(l.globalStart.Add(l.window)) {
		l.globalN = 0
	}
}

// limited reports whether key may not try now, and how long until the limiting
// window ends.
func (l *failureLimiter) limited(key string) (bool, time.Duration) {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	var wait time.Duration
	if e, ok := l.keys[key]; ok && e.n >= l.perKey {
		wait = e.start.Add(l.window).Sub(now)
	}
	if l.globalN >= l.global {
		wait = max(wait, l.globalStart.Add(l.window).Sub(now))
	}
	return wait > 0, wait
}

// fail counts one failure for key.
func (l *failureLimiter) fail(key string) {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	if l.globalN == 0 {
		l.globalStart = now
	}
	l.globalN++
	e, ok := l.keys[key]
	if !ok {
		if len(l.keys) >= l.maxKeys {
			return // the global ceiling still counts it
		}
		e = &failureEntry{start: now}
		l.keys[key] = e
	}
	e.n++
}

// firstLimited reports true once per address and window: the first limited
// request of a window is the one that may write an audit row. With the table
// full, no further address is noted.
func (l *failureLimiter) firstLimited(key string) bool {
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	e, ok := l.keys[key]
	if !ok {
		if len(l.keys) >= l.maxKeys {
			return false
		}
		e = &failureEntry{start: now}
		l.keys[key] = e
	}
	if e.noted {
		return false
	}
	e.noted = true
	return true
}
