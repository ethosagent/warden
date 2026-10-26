package oidc

import (
	"container/list"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

// resultCache is a bounded LRU of valid results, keyed by sha256(token).
type resultCache struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[[32]byte]*list.Element
}

type cacheEntry struct {
	key    [32]byte
	claims identity.Claims
	until  time.Time
}

func newResultCache(max int) *resultCache {
	return &resultCache{max: max, ll: list.New(), m: make(map[[32]byte]*list.Element)}
}

// get returns the cached claims, evicting the entry when it is past its time.
func (c *resultCache) get(k [32]byte, now time.Time) (identity.Claims, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[k]
	if !ok {
		return identity.Claims{}, false
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.until) {
		c.ll.Remove(el)
		delete(c.m, k)
		return identity.Claims{}, false
	}
	c.ll.MoveToFront(el)
	return e.claims, true
}

func (c *resultCache) put(k [32]byte, cl identity.Claims, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		e := el.Value.(*cacheEntry)
		e.claims, e.until = cl, until
		c.ll.MoveToFront(el)
		return
	}
	c.m[k] = c.ll.PushFront(&cacheEntry{key: k, claims: cl, until: until})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*cacheEntry).key)
	}
}

func (c *resultCache) drop(k [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		c.ll.Remove(el)
		delete(c.m, k)
	}
}
