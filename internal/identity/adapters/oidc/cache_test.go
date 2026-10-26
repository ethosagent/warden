package oidc

import (
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

func key(b byte) [32]byte { return [32]byte{b} }

func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newResultCache(2)
	c.put(key(1), identity.Claims{Sub: "a"}, now.Add(time.Hour))
	c.put(key(2), identity.Claims{Sub: "b"}, now.Add(time.Hour))
	if _, ok := c.get(key(1), now); !ok {
		t.Fatal("key 1 missing")
	}
	c.put(key(3), identity.Claims{Sub: "c"}, now.Add(time.Hour))
	if _, ok := c.get(key(2), now); ok {
		t.Error("key 2 should be evicted")
	}
	if _, ok := c.get(key(1), now); !ok {
		t.Error("key 1 should survive")
	}
}

func TestCacheExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newResultCache(2)
	c.put(key(1), identity.Claims{Sub: "a"}, now.Add(time.Minute))
	if _, ok := c.get(key(1), now.Add(time.Minute)); ok {
		t.Error("entry at its until time must be gone")
	}
	if len(c.m) != 0 {
		t.Error("expired entry not evicted")
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := newResultCache(8)
	now := time.Unix(1000, 0)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				k := key(byte(j % 20))
				c.put(k, identity.Claims{Sub: "x"}, now.Add(time.Hour))
				c.get(k, now)
				if j%50 == 0 {
					c.drop(k)
				}
			}
		}(i)
	}
	wg.Wait()
	if c.ll.Len() > 8 {
		t.Errorf("len = %d", c.ll.Len())
	}
}
