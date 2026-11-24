package agentreg

import (
	"sync"
	"time"
)

// DefaultCacheTTL bounds how long a process serves reads from its snapshot
// without asking the database. Every write through the same store invalidates
// at once; the TTL only bounds staleness against a writer in another process
// (the offline registry CLI, AREG-06, writes the same file while the control
// plane runs).
const DefaultCacheTTL = 5 * time.Second

// cache is a read-through snapshot of the whole registry: at most
// config.MaxRegisteredAgents small rows, so one load serves Get and List.
type cache struct {
	mu     sync.Mutex
	ttl    time.Duration
	loaded time.Time
	valid  bool
	byID   map[string]Agent
	list   []Agent
	gen    uint64 // bumped by invalidate; a load started before it is dropped
}

func (c *cache) get(now time.Time) (snapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid || c.ttl <= 0 || now.Sub(c.loaded) >= c.ttl {
		return snapshot{}, false
	}
	return snapshot{byID: c.byID, list: c.list}, true
}

// generation returns the token a load presents to put.
func (c *cache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// put stores a snapshot unless a write invalidated the cache since gen was
// read, so a load that raced a write never resurrects stale rows.
func (c *cache) put(gen uint64, now time.Time, list []Agent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen {
		return
	}
	c.byID = make(map[string]Agent, len(list))
	for _, a := range list {
		c.byID[a.ID] = a
	}
	c.list = list
	c.loaded = now
	c.valid = true
}

func (c *cache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.valid = false
	c.byID = nil
	c.list = nil
}

// snapshot is an immutable view; callers copy before returning to users.
type snapshot struct {
	byID map[string]Agent
	list []Agent
}

// clone deep-copies a so a caller mutating its result cannot corrupt the cache.
func clone(a Agent) Agent {
	out := a
	if a.Keys != nil {
		out.Keys = make([]Key, len(a.Keys))
		for i, k := range a.Keys {
			k.JWK = append([]byte(nil), k.JWK...)
			out.Keys[i] = k
		}
	}
	out.AllowedGroups = append([]string(nil), a.AllowedGroups...)
	out.AllowedScopes = append([]string(nil), a.AllowedScopes...)
	if len(a.AllowedGroups) == 0 {
		out.AllowedGroups = nil
	}
	if len(a.AllowedScopes) == 0 {
		out.AllowedScopes = nil
	}
	return out
}
