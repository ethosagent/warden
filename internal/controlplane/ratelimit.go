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
