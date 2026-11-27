// Package ratelimit is the per-key token bucket the control plane shares: the
// token endpoint (tokensvc) and the OAuth broker (oauthbroker) both throttle
// with it. It is a leaf: no other Warden package is imported, so neither
// consumer depends on the other.
package ratelimit

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// DefaultLimiterKeys is how many keys a Limiter tracks before it evicts the
// least recently used one.
const DefaultLimiterKeys = 10000

// RateLimiter decides whether one more event for key is allowed at now. When
// it is not, retryAfter is how long until the key has room again (never zero
// for a refusal). The Service takes the per-agent and per-user limiters through
// it; a nil RateLimiter allows everything.
type RateLimiter interface {
	Allow(key string, now time.Time) (ok bool, retryAfter time.Duration)
}

// Limiter is a token bucket per key with a bounded key table. A key's bucket
// holds up to limit tokens and refills at limit per window, so a quiet key may
// burst to limit and then settles at the configured rate. It is safe for
// concurrent use.
//
// The table is an LRU of at most maxKeys entries. A key idle for a whole
// window has a full bucket, which is exactly what a new key gets, so dropping
// it loses nothing; those are evicted first (from the cold end), and only when
// every tracked key is still active does the least recently used one go. A
// flood of distinct keys can therefore make room by evicting active keys, but
// it never grows memory past maxKeys.
type Limiter struct {
	limit   float64
	window  time.Duration
	perSec  float64
	maxKeys int

	mu      sync.Mutex
	entries map[string]*list.Element // value: *bucket
	order   *list.List               // front = most recently used
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// NewLimiter returns a Limiter allowing limit events per window per key, with
// DefaultLimiterKeys keys. It panics on a non-positive limit or window: both
// come from a validated rate string, never from a request.
func NewLimiter(limit int, window time.Duration) *Limiter {
	return NewLimiterSize(limit, window, DefaultLimiterKeys)
}

// NewLimiterSize is NewLimiter with an explicit key bound (at least 1).
func NewLimiterSize(limit int, window time.Duration, maxKeys int) *Limiter {
	if limit <= 0 || window <= 0 {
		panic("ratelimit: Limiter needs a positive limit and window")
	}
	if maxKeys < 1 {
		maxKeys = 1
	}
	return &Limiter{
		limit: float64(limit), window: window, perSec: float64(limit) / window.Seconds(),
		maxKeys: maxKeys, entries: map[string]*list.Element{}, order: list.New(),
	}
}

// Allow implements RateLimiter. now must not go backwards for a key; a
// backwards step is treated as no time passing.
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var b *bucket
	if el, ok := l.entries[key]; ok {
		l.order.MoveToFront(el)
		b, _ = el.Value.(*bucket)
		if dt := now.Sub(b.last); dt > 0 {
			b.tokens = math.Min(l.limit, b.tokens+dt.Seconds()*l.perSec)
			b.last = now
		}
	} else {
		l.evict(now)
		b = &bucket{key: key, tokens: l.limit, last: now}
		l.entries[key] = l.order.PushFront(b)
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration(math.Ceil((1 - b.tokens) / l.perSec * float64(time.Second)))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// Len is the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// evict makes room for one new key: first every idle key at the cold end of
// the list, then, if the table is still full, the least recently used key.
func (l *Limiter) evict(now time.Time) {
	for l.order.Len() > 0 {
		el := l.order.Back()
		b, _ := el.Value.(*bucket)
		idle := now.Sub(b.last) >= l.window
		if !idle && l.order.Len() < l.maxKeys {
			return
		}
		l.order.Remove(el)
		delete(l.entries, b.key)
	}
}
